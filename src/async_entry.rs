use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(target_os = "linux")]
use crate::linux_credential_builder::LinuxCredentialBuilder;

#[napi]
pub struct AsyncEntry {
  inner: Arc<keyring_core::Entry>,
}

#[cfg(target_os = "linux")]
fn setup_linux_store() -> anyhow::Result<()> {
  let builder = LinuxCredentialBuilder::new()?;
  keyring_core::set_default_store(builder.get_store());
  Ok(())
}

#[cfg(target_os = "macos")]
fn setup_macos_store() -> anyhow::Result<()> {
  use apple_native_keyring_store::keychain::Store;
  use std::collections::HashMap;
  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(std::sync::Arc::new(store));
  Ok(())
}

#[cfg(target_os = "windows")]
fn setup_windows_store() -> anyhow::Result<()> {
  use windows_native_keyring_store::Store;
  use std::collections::HashMap;
  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(std::sync::Arc::new(store));
  Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn setup_bsd_store() -> anyhow::Result<()> {
  use dbus_secret_service_keyring_store::Store;
  use std::collections::HashMap;
  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(std::sync::Arc::new(store));
  Ok(())
}

#[napi]
impl AsyncEntry {
  #[napi(constructor)]
  /// Create an entry for the given service and username.
  ///
  /// The default credential builder is used.
  pub fn new(service: String, username: String) -> Result<Self> {
    #[cfg(target_os = "linux")]
    setup_linux_store()?;
    #[cfg(target_os = "macos")]
    setup_macos_store()?;
    #[cfg(target_os = "windows")]
    setup_windows_store()?;
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    setup_bsd_store()?;

    Ok(Self {
      inner: Arc::new(keyring_core::Entry::new(&service, &username).map_err(anyhow::Error::from)?),
    })
  }

  #[napi(factory)]
  /// Create an entry for the given target, service, and username.
  ///
  /// The default credential builder is used.
  pub fn with_target(target: String, service: String, username: String) -> Result<Self> {
    #[cfg(target_os = "linux")]
    setup_linux_store()?;
    #[cfg(target_os = "macos")]
    setup_macos_store()?;
    #[cfg(target_os = "windows")]
    setup_windows_store()?;
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    setup_bsd_store()?;

    Ok(Self {
      inner: Arc::new(
        keyring_core::Entry::new_with_modifiers(&service, &username, &{
          let mut mods = std::collections::HashMap::new();
          mods.insert("target", target.as_str());
          mods
        })
        .map_err(anyhow::Error::from)?,
      ),
    })
  }

  #[napi(ts_return_type = "Promise<void>")]
  /// Set the password for this entry.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn set_password(
    &self,
    password: String,
    signal: Option<AbortSignal>,
  ) -> AsyncTask<EntryTask> {
    AsyncTask::with_optional_signal(
      EntryTask {
        inner: self.inner.clone(),
        kind: TaskKind::SetPassword(password),
      },
      signal,
    )
  }

  #[napi(ts_return_type = "Promise<void>")]
  /// Set the secret for this entry.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn set_secret(&self, secret: &[u8], signal: Option<AbortSignal>) -> AsyncTask<EntryTask> {
    AsyncTask::with_optional_signal(
      EntryTask {
        inner: self.inner.clone(),
        kind: TaskKind::SetSecret(secret.to_vec()),
      },
      signal,
    )
  }

  #[napi(ts_return_type = "Promise<string | undefined>")]
  /// Retrieve the password saved for this entry.
  ///
  /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn get_password(&self, signal: Option<AbortSignal>) -> AsyncTask<PasswordTask> {
    AsyncTask::with_optional_signal(
      PasswordTask {
        inner: self.inner.clone(),
      },
      signal,
    )
  }

  #[napi(ts_return_type = "Promise<Uint8Array | undefined>")]
  /// Retrieve the secret saved for this entry.
  ///
  /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  pub fn get_secret(&self, signal: Option<AbortSignal>) -> AsyncTask<SecretTask> {
    AsyncTask::with_optional_signal(
      SecretTask {
        inner: self.inner.clone(),
      },
      signal,
    )
  }

  #[napi(ts_return_type = "Promise<boolean>")]
  /// Delete the underlying credential for this entry.
  ///
  /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
  ///
  /// Can return an [Ambiguous](Error::Ambiguous) error
  /// if there is more than one platform credential
  /// that matches this entry.  This can only happen
  /// on some platforms, and then only if a third-party
  /// application wrote the ambiguous credential.
  ///
  /// Note: This does _not_ affect the lifetime of the [Entry]
  /// structure, which is controlled by Rust.  It only
  /// affects the underlying credential store.
  pub fn delete_credential(&self, signal: Option<AbortSignal>) -> AsyncTask<EntryTask> {
    AsyncTask::with_optional_signal(
      EntryTask {
        inner: self.inner.clone(),
        kind: TaskKind::DeleteCredential,
      },
      signal,
    )
  }

  #[napi]
  /// Alias for `deleteCredential`
  pub fn delete_password(&self, signal: Option<AbortSignal>) -> AsyncTask<EntryTask> {
    self.delete_credential(signal)
  }
}

#[allow(clippy::enum_variant_names)]
enum TaskKind {
  SetPassword(String),
  SetSecret(Vec<u8>),
  DeleteCredential,
}

pub struct EntryTask {
  inner: Arc<keyring_core::Entry>,
  kind: TaskKind,
}

// Password task
pub struct PasswordTask {
  inner: Arc<keyring_core::Entry>,
}

#[napi]
impl Task for PasswordTask {
  type Output = Option<String>;
  type JsValue = Option<String>;

  fn compute(&mut self) -> Result<Self::Output> {
    Ok(self.inner.get_password().ok())
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

// Secret task
pub struct SecretTask {
  inner: Arc<keyring_core::Entry>,
}

#[napi]
impl Task for SecretTask {
  type Output = Option<Vec<u8>>;
  type JsValue = Option<Vec<u8>>;

  fn compute(&mut self) -> Result<Self::Output> {
    Ok(self.inner.get_secret().ok())
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

// Generic task for operations that don't return values or return booleans
#[napi]
impl Task for EntryTask {
  type Output = Option<bool>;
  type JsValue = Option<bool>;

  fn compute(&mut self) -> Result<Self::Output> {
    match self.kind {
      TaskKind::DeleteCredential => Ok(Some(self.inner.delete_credential().is_ok())),
      TaskKind::SetPassword(ref password) => {
        self
          .inner
          .set_password(password)
          .map_err(anyhow::Error::from)?;
        Ok(None)
      }
      TaskKind::SetSecret(ref secret) => {
        self.inner.set_secret(secret).map_err(anyhow::Error::from)?;
        Ok(None)
      }
    }
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}
