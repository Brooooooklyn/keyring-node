use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub struct Entry {
  inner: keyring::Entry,
}

#[napi]
impl Entry {
  #[napi(constructor)]
  /// Create an entry for the given service and username.
  ///
  /// The default credential builder is used.
  pub fn new(service: String, username: String) -> Result<Self> {
    Ok(Self {
      inner: keyring::Entry::new(&service, &username).map_err(anyhow::Error::from)?,
    })
  }

  #[napi(factory)]
  /// Create an entry for the given target, service, and username.
  ///
  /// The default credential builder is used.
  pub fn with_target(service: String, username: String, target: String) -> Result<Self> {
    Ok(Self {
      inner: keyring::Entry::new_with_target(&service, &username, &target)
        .map_err(anyhow::Error::from)?,
    })
  }

  #[napi]
  /// Set the password for this entry.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn set_password(&self, password: String) -> Result<()> {
    self
      .inner
      .set_password(&password)
      .map_err(anyhow::Error::from)?;
    Ok(())
  }

  #[napi]
  /// Retrieve the password saved for this entry.
  ///
  /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn get_password(&self) -> Option<String> {
    self.inner.get_password().ok()
  }

  #[napi]
  /// Delete the password for this entry.
  ///
  /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn delete_password(&self) -> bool {
    self
      .inner
      .delete_password()
      .map_err(anyhow::Error::from)
      .is_ok()
  }
}

#[napi(object)]
pub struct Credential {
  pub user: String,
  pub password: String,
}

pub struct FindCredentials {
  service: String,
}

#[napi]
impl Task for FindCredentials {
  type Output = Vec<Credential>;
  type JsValue = Vec<Credential>;

  #[inline]
  fn compute(&mut self) -> Result<Self::Output> {
    Ok(
      find_credentials_(&self.service)
        .map_err(anyhow::Error::from)?
        .into_iter()
        .map(|(user, password)| Credential { user, password })
        .collect(),
    )
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
/// find credentials by service name
pub fn find_credentials(service: String) -> Result<Vec<Credential>> {
  Ok(
    find_credentials_(&service)
      .map_err(anyhow::Error::from)?
      .into_iter()
      .map(|(user, password)| Credential { user, password })
      .collect(),
  )
}

#[napi]
/// find credentials by service name
pub fn find_credentials_async(
  service: String,
  signal: Option<AbortSignal>,
) -> AsyncTask<FindCredentials> {
  AsyncTask::with_optional_signal(FindCredentials { service }, signal)
}

#[cfg(target_os = "macos")]
fn find_credentials_(service: &str) -> std::result::Result<Vec<(String, String)>, anyhow::Error> {
  use std::{ffi::c_void, ptr};

  use core_foundation::{
    array::CFArray,
    base::{CFGetTypeID, CFRelease, CFType, FromVoid, TCFType},
    boolean::CFBoolean,
    dictionary::CFDictionary,
    string::CFString,
  };
  use security_framework::item::{Reference, SearchResult};
  use security_framework_sys::{
    base::errSecItemNotFound,
    item::{
      kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
      kSecMatchLimitAll, kSecReturnAttributes, kSecReturnRef,
    },
    keychain_item::SecItemCopyMatching,
  };

  let mut params = Vec::with_capacity(5);
  let k_service = CFString::new(service);
  params.push((
    unsafe { CFString::wrap_under_get_rule(kSecClass) },
    unsafe { CFType::wrap_under_get_rule(kSecClassGenericPassword.cast()) },
  ));
  params.push((
    unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
    k_service.as_CFType(),
  ));
  params.push((
    unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
    unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll).as_CFType() },
  ));
  params.push((
    unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
    CFBoolean::true_value().as_CFType(),
  ));
  params.push((
    unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
    CFBoolean::true_value().as_CFType(),
  ));
  let params = CFDictionary::from_CFType_pairs(&params);

  let mut ret = ptr::null();
  if let Err(err) = cvt(unsafe { SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret) }) {
    // not found is acceptable
    if err.code() == errSecItemNotFound {
      return Ok(vec![]);
    }
    return Err(anyhow::Error::from(err));
  };
  if ret.is_null() {
    //  SecItemCopyMatching returns NULL if no load_* was specified,
    //  causing a segfault.
    return Ok(vec![]);
  }
  let type_id = unsafe { CFGetTypeID(ret) };

  let mut items = vec![];

  if type_id == CFArray::<CFType>::type_id() {
    let array: CFArray<CFType> = unsafe { CFArray::wrap_under_create_rule(ret as *mut _) };
    items.extend(
      array
        .iter()
        .map(|item| unsafe { get_item(item.as_CFTypeRef()) }),
    );
  } else {
    items.push(unsafe { get_item(ret) });
    // This is a bit janky, but get_item uses wrap_under_get_rule
    // which bumps the refcount but we want create semantics
    unsafe { CFRelease(ret) };
  }
  let found = items
    .iter()
    .filter_map(|item| {
      match item {
        SearchResult::Ref(Reference::KeychainItem(keychain)) => {
          let dict: CFDictionary<CFString, *const c_void> =
            unsafe { CFDictionary::wrap_under_get_rule(keychain.as_CFTypeRef().cast()) };
          if let Some(account) = dict.find(unsafe { kSecAttrAccount }) {
            let account = unsafe { CFString::from_void(*account) };
            let account = account.to_string();
            if let Ok(password) =
              security_framework::passwords::get_generic_password(service, &account)
            {
              return Some((account.to_string(), unsafe {
                String::from_utf8_unchecked(password)
              }));
            }
          }
        }
        SearchResult::Dict(dict) => {
          if let Some(account) = dict.find(unsafe { kSecAttrAccount }.cast()) {
            let account = unsafe { CFString::from_void(*account) };
            let account = account.to_string();
            if let Ok(password) =
              security_framework::passwords::get_generic_password(service, &account)
            {
              return Some((account.to_string(), unsafe {
                String::from_utf8_unchecked(password)
              }));
            }
          }
        }
        _ => {}
      };
      None
    })
    .collect::<Vec<(String, String)>>();
  Ok(found)
}

#[cfg(target_os = "macos")]
unsafe fn get_item(
  item: core_foundation::base::CFTypeRef,
) -> security_framework::item::SearchResult {
  use core_foundation::{
    base::{CFGetTypeID, TCFType},
    data::CFData,
    dictionary::CFDictionary,
  };
  use security_framework::os::macos::keychain_item::SecKeychainItem;
  use security_framework::{
    certificate::SecCertificate,
    identity::SecIdentity,
    item::{Reference, SearchResult},
    key::SecKey,
  };

  let type_id = CFGetTypeID(item);

  if type_id == CFData::type_id() {
    let data = CFData::wrap_under_get_rule(item as *mut _);
    let mut buf = Vec::new();
    buf.extend_from_slice(data.bytes());
    return SearchResult::Data(buf);
  }

  if type_id == CFDictionary::<*const u8, *const u8>::type_id() {
    return SearchResult::Dict(CFDictionary::wrap_under_get_rule(item as *mut _));
  }

  if type_id == SecKeychainItem::type_id() {
    return SearchResult::Ref(Reference::KeychainItem(
      SecKeychainItem::wrap_under_get_rule(item as *mut _),
    ));
  }

  let reference = if type_id == SecCertificate::type_id() {
    Reference::Certificate(SecCertificate::wrap_under_get_rule(item as *mut _))
  } else if type_id == SecKey::type_id() {
    Reference::Key(SecKey::wrap_under_get_rule(item as *mut _))
  } else if type_id == SecIdentity::type_id() {
    Reference::Identity(SecIdentity::wrap_under_get_rule(item as *mut _))
  } else {
    // panic!("Got bad type from SecItemCopyMatching: {}", type_id);
    return SearchResult::Other;
  };

  SearchResult::Ref(reference)
}

#[cfg(target_os = "macos")]
#[allow(non_upper_case_globals)]
#[inline(always)]
fn cvt(
  err: core_foundation::base::OSStatus,
) -> std::result::Result<(), security_framework::base::Error> {
  use security_framework_sys::base::errSecSuccess;

  match err {
    errSecSuccess => Ok(()),
    err => Err(security_framework::base::Error::from_code(err)),
  }
}

#[cfg(target_os = "windows")]
fn find_credentials() {}
