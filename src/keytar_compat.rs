//! Drop-in keytar compatibility layer.
//!
//! These functions read and write credentials in the exact on-store format
//! node-keytar used on each platform, so an application can switch from
//! keytar to this library (or back) without migrating stored credentials:
//!
//! - macOS: keytar wrote generic passwords keyed by service/account in the
//!   login keychain, which is exactly what the default keychain store does,
//!   so the regular entry path is reused.
//! - Windows: keytar wrote generic credentials with target name
//!   `{service}/{account}` and a UTF-8 password blob (the default store uses
//!   `{user}.{service}` targets and UTF-16 blobs, which is why the regular
//!   entry path cannot see keytar credentials). One deliberate divergence:
//!   `findCredentials` enumerates with the filter `{service}/*`, where keytar
//!   used `{service}*` and therefore also matched unrelated services that
//!   merely share the prefix.
//! - Linux/FreeBSD: keytar wrote Secret Service items with the attributes
//!   `{service, account}` (the default store uses `{service, username}`).

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::entry::Credential;

#[cfg(target_os = "macos")]
mod imp {
  use napi::bindgen_prelude::*;

  fn entry(service: &str, account: &str) -> Result<keyring_core::Entry> {
    Ok(crate::entry_builder::create_entry(
      service, account, None, None,
    )?)
  }

  pub(super) fn get_password(service: &str, account: &str) -> Result<Option<String>> {
    crate::result::into_optional(entry(service, account)?.get_password())
  }

  pub(super) fn set_password(service: &str, account: &str, password: &str) -> Result<()> {
    entry(service, account)?
      .set_password(password)
      .map_err(anyhow::Error::from)?;
    Ok(())
  }

  pub(super) fn delete_password(service: &str, account: &str) -> Result<bool> {
    crate::result::into_deleted(entry(service, account)?.delete_credential())
  }

  pub(super) fn find_credentials(service: &str) -> Result<Vec<(String, String)>> {
    Ok(crate::entry::find_credentials_(service, None)?)
  }
}

#[cfg(target_os = "windows")]
mod imp {
  use napi::bindgen_prelude::*;
  use windows::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME};
  use windows::Win32::Security::Credentials::{
    CRED_ENUMERATE_FLAGS, CRED_FLAGS, CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, CREDENTIALW,
    CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW,
  };
  use windows::core::{PCWSTR, PWSTR};

  use crate::windows_util::{from_wstr, to_wstr};

  fn target_name(service: &str, account: &str) -> String {
    // keytar's credential identity on Windows.
    format!("{service}/{account}")
  }

  pub(super) fn get_password(service: &str, account: &str) -> Result<Option<String>> {
    let target = to_wstr(&target_name(service, account));
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    unsafe {
      if let Err(err) = CredReadW(
        PCWSTR::from_raw(target.as_ptr()),
        CRED_TYPE_GENERIC,
        None,
        &mut credential,
      ) {
        if err == ERROR_NOT_FOUND.to_hresult().into() {
          return Ok(None);
        }
        return Err(anyhow::anyhow!("Failed to read credential: {err:?}").into());
      }
      // keytar stored the password as UTF-8. A credential can carry no blob
      // at all, in which case building a slice would be undefined behavior.
      let password = if (*credential).CredentialBlob.is_null() {
        String::new()
      } else {
        let blob = std::slice::from_raw_parts(
          (*credential).CredentialBlob,
          (*credential).CredentialBlobSize as usize,
        );
        String::from_utf8_lossy(blob).into_owned()
      };
      CredFree(credential.cast());
      Ok(Some(password))
    }
  }

  pub(super) fn set_password(service: &str, account: &str, password: &str) -> Result<()> {
    let mut target = to_wstr(&target_name(service, account));
    let mut user = to_wstr(account);
    let blob = password.as_bytes();
    let credential = CREDENTIALW {
      Flags: CRED_FLAGS(0),
      Type: CRED_TYPE_GENERIC,
      TargetName: PWSTR::from_raw(target.as_mut_ptr()),
      Comment: PWSTR::null(),
      LastWritten: FILETIME::default(),
      CredentialBlobSize: blob.len() as u32,
      CredentialBlob: blob.as_ptr() as *mut u8,
      Persist: CRED_PERSIST_ENTERPRISE,
      AttributeCount: 0,
      Attributes: std::ptr::null_mut(),
      TargetAlias: PWSTR::null(),
      UserName: PWSTR::from_raw(user.as_mut_ptr()),
    };
    unsafe { CredWriteW(&credential, 0) }
      .map_err(|err| anyhow::anyhow!("Failed to write credential: {err:?}"))?;
    Ok(())
  }

  pub(super) fn delete_password(service: &str, account: &str) -> Result<bool> {
    let target = to_wstr(&target_name(service, account));
    unsafe {
      match CredDeleteW(PCWSTR::from_raw(target.as_ptr()), CRED_TYPE_GENERIC, None) {
        Ok(()) => Ok(true),
        Err(err) if err == ERROR_NOT_FOUND.to_hresult().into() => Ok(false),
        Err(err) => Err(anyhow::anyhow!("Failed to delete credential: {err:?}").into()),
      }
    }
  }

  pub(super) fn find_credentials(service: &str) -> Result<Vec<(String, String)>> {
    let filter = to_wstr(&format!("{service}/*"));
    let mut count: u32 = 0;
    let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
    unsafe {
      if let Err(err) = CredEnumerateW(
        PCWSTR::from_raw(filter.as_ptr()),
        Some(CRED_ENUMERATE_FLAGS::default()),
        &mut count,
        &mut credentials,
      ) {
        // On failure the output buffer was never allocated, so there is
        // nothing to CredFree (and the pointer may still be null).
        if err == ERROR_NOT_FOUND.to_hresult().into() {
          return Ok(vec![]);
        }
        return Err(anyhow::anyhow!("Failed to enumerate credentials: {err:?}").into());
      }
      let mut found = Vec::with_capacity(count as usize);
      for credential in std::slice::from_raw_parts(credentials, count as usize) {
        let Some(credential) = credential.as_ref() else {
          continue;
        };
        if credential.Type != CRED_TYPE_GENERIC {
          continue;
        }
        // Match keytar: skip credentials without a user name or a password
        // blob (the NULL blob would also be UB to slice).
        if credential.UserName.is_null() || credential.CredentialBlob.is_null() {
          continue;
        }
        let account = from_wstr(credential.UserName.as_ptr().cast());
        let blob = std::slice::from_raw_parts(
          credential.CredentialBlob,
          credential.CredentialBlobSize as usize,
        );
        found.push((account, String::from_utf8_lossy(blob).into_owned()));
      }
      CredFree(credentials.cast());
      Ok(found)
    }
  }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod imp {
  use std::collections::HashMap;

  use napi::bindgen_prelude::*;
  use secret_service::{EncryptionType, SearchItemsResult, blocking::SecretService};

  // keytar stored items through libsecret's generic schema; replicating the
  // schema attribute keeps items written here fully readable by keytar.
  const XDG_SCHEMA: &str = "org.freedesktop.Secret.Generic";

  fn connect() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh)
      .map_err(anyhow::Error::from)
      .map_err(Into::into)
  }

  fn keytar_attributes<'a>(service: &'a str, account: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([("service", service), ("account", account)])
  }

  pub(super) fn get_password(service: &str, account: &str) -> Result<Option<String>> {
    let secret_service = connect()?;
    let SearchItemsResult { locked, unlocked } = secret_service
      .search_items(keytar_attributes(service, account))
      .map_err(anyhow::Error::from)?;
    if let Some(item) = unlocked.first() {
      let secret = item.get_secret().map_err(anyhow::Error::from)?;
      return Ok(Some(String::from_utf8_lossy(&secret).into_owned()));
    }
    // keytar (libsecret) unlocks matching items before reading them.
    if let Some(item) = locked.first() {
      item.unlock().map_err(anyhow::Error::from)?;
      let secret = item.get_secret().map_err(anyhow::Error::from)?;
      return Ok(Some(String::from_utf8_lossy(&secret).into_owned()));
    }
    Ok(None)
  }

  pub(super) fn set_password(service: &str, account: &str, password: &str) -> Result<()> {
    let secret_service = connect()?;
    let collection = secret_service
      .get_default_collection()
      .map_err(anyhow::Error::from)?;
    if collection.is_locked().map_err(anyhow::Error::from)? {
      collection.unlock().map_err(anyhow::Error::from)?;
    }
    let mut attributes = keytar_attributes(service, account);
    attributes.insert("xdg:schema", XDG_SCHEMA);
    collection
      .create_item(
        &format!("{service}/{account}"),
        attributes,
        password.as_bytes(),
        true,
        "text/plain",
      )
      .map_err(anyhow::Error::from)?;
    Ok(())
  }

  pub(super) fn delete_password(service: &str, account: &str) -> Result<bool> {
    let secret_service = connect()?;
    let SearchItemsResult { locked, unlocked } = secret_service
      .search_items(keytar_attributes(service, account))
      .map_err(anyhow::Error::from)?;
    // keytar (secret_password_clear) removes every matching item, not just
    // the first one, so a duplicate in another collection cannot survive a
    // deletion that reported success.
    let mut deleted = false;
    for item in unlocked.iter() {
      item.delete().map_err(anyhow::Error::from)?;
      deleted = true;
    }
    // keytar (libsecret) unlocks matching items before deleting them; the
    // Secret Service may refuse to delete an item that is still locked.
    for item in locked.iter() {
      item.unlock().map_err(anyhow::Error::from)?;
      item.delete().map_err(anyhow::Error::from)?;
      deleted = true;
    }
    Ok(deleted)
  }

  pub(super) fn find_credentials(service: &str) -> Result<Vec<(String, String)>> {
    let secret_service = connect()?;
    let SearchItemsResult { locked, unlocked } = secret_service
      .search_items(HashMap::from([("service", service)]))
      .map_err(anyhow::Error::from)?;
    let mut found = Vec::new();
    for (item, was_locked) in unlocked
      .iter()
      .map(|i| (i, false))
      .chain(locked.iter().map(|i| (i, true)))
    {
      let attributes = item.get_attributes().map_err(anyhow::Error::from)?;
      // Only keytar-format items (the `account` attribute) are surfaced:
      // including `username` items from this library's main API would list
      // credentials that getPassword/deletePassword then cannot address.
      let Some(account) = attributes.get("account") else {
        continue;
      };
      if was_locked && item.unlock().is_err() {
        continue;
      }
      // Match keytar: an item whose secret cannot be loaded is skipped, not
      // an error that hides every other credential.
      let Ok(secret) = item.get_secret() else {
        continue;
      };
      found.push((
        account.clone(),
        String::from_utf8_lossy(&secret).into_owned(),
      ));
    }
    Ok(found)
  }
}

pub struct KeytarGetPassword {
  service: String,
  account: String,
}

#[napi]
impl Task for KeytarGetPassword {
  type Output = Option<String>;
  type JsValue = Option<String>;

  fn compute(&mut self) -> Result<Self::Output> {
    imp::get_password(&self.service, &self.account)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
/// keytar-compatible `getPassword`: reads the credential exactly where and
/// how node-keytar stored it on this platform.
pub fn keytar_get_password(
  service: String,
  account: String,
  signal: Option<AbortSignal>,
) -> AsyncTask<KeytarGetPassword> {
  AsyncTask::with_optional_signal(KeytarGetPassword { service, account }, signal)
}

pub struct KeytarSetPassword {
  service: String,
  account: String,
  password: String,
}

#[napi]
impl Task for KeytarSetPassword {
  type Output = ();
  type JsValue = ();

  fn compute(&mut self) -> Result<Self::Output> {
    imp::set_password(&self.service, &self.account, &self.password)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
/// keytar-compatible `setPassword`: writes the credential in node-keytar's
/// native on-store format so keytar itself could still read it back.
pub fn keytar_set_password(
  service: String,
  account: String,
  password: String,
  signal: Option<AbortSignal>,
) -> AsyncTask<KeytarSetPassword> {
  AsyncTask::with_optional_signal(
    KeytarSetPassword {
      service,
      account,
      password,
    },
    signal,
  )
}

pub struct KeytarDeletePassword {
  service: String,
  account: String,
}

#[napi]
impl Task for KeytarDeletePassword {
  type Output = bool;
  type JsValue = bool;

  fn compute(&mut self) -> Result<Self::Output> {
    imp::delete_password(&self.service, &self.account)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
/// keytar-compatible `deletePassword`: returns `true` when a credential was
/// deleted and `false` when there was none.
pub fn keytar_delete_password(
  service: String,
  account: String,
  signal: Option<AbortSignal>,
) -> AsyncTask<KeytarDeletePassword> {
  AsyncTask::with_optional_signal(KeytarDeletePassword { service, account }, signal)
}

pub struct KeytarFindCredentials {
  service: String,
}

#[napi]
impl Task for KeytarFindCredentials {
  type Output = Vec<Credential>;
  type JsValue = Vec<Credential>;

  fn compute(&mut self) -> Result<Self::Output> {
    Ok(
      imp::find_credentials(&self.service)?
        .into_iter()
        .map(|(account, password)| Credential { account, password })
        .collect(),
    )
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
/// keytar-compatible `findCredentials`: enumerates the credentials for a
/// service in node-keytar's native format (on Linux only keytar-format items
/// — those carrying an `account` attribute — are returned, never items
/// written by this library's main API).
pub fn keytar_find_credentials(
  service: String,
  signal: Option<AbortSignal>,
) -> AsyncTask<KeytarFindCredentials> {
  AsyncTask::with_optional_signal(KeytarFindCredentials { service }, signal)
}
