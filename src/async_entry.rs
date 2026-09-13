use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::entry_builder::create_entry;
use crate::options::EntryOptions;
use crate::result::{into_deleted, into_optional};

#[napi]
pub struct AsyncEntry {
  inner: Arc<keyring_core::Entry>,
}

#[napi]
impl AsyncEntry {
  #[napi(constructor)]
  /// Create an entry for the given service and username.
  ///
  /// The default credential builder is used.
  ///
  /// An optional [EntryOptions] bag controls platform-specific behavior; it is
  /// accepted on all platforms but currently only used on Linux, where it can
  /// pin the entry to a specific credential store.
  pub fn new(service: String, username: String, options: Option<EntryOptions>) -> Result<Self> {
    Ok(Self {
      inner: Arc::new(create_entry(&service, &username, None, options.as_ref())?),
    })
  }

  #[napi(factory)]
  /// Create an entry for the given target, service, and username.
  ///
  /// The default credential builder is used.
  ///
  /// An optional [EntryOptions] bag controls platform-specific behavior; it is
  /// accepted on all platforms but currently only used on Linux, where it can
  /// pin the entry to a specific credential store.
  pub fn with_target(
    target: String,
    service: String,
    username: String,
    options: Option<EntryOptions>,
  ) -> Result<Self> {
    Ok(Self {
      inner: Arc::new(create_entry(
        &service,
        &username,
        Some(&target),
        options.as_ref(),
      )?),
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
  /// Returns no password if there isn't one.
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
  /// Returns no secret if there isn't one.
  ///
  /// Rejects if the credential store cannot be read, for example when it is
  /// locked or inaccessible.
  ///
  /// Can reject with an [Ambiguous](Error::Ambiguous) error
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
  /// Resolves `true` if a credential was deleted, and `false` if there was no
  /// credential to delete.
  ///
  /// Rejects if the credential exists but could not be deleted, for example
  /// when the store is locked or inaccessible. A failed deletion is never
  /// reported as `false`, so a `false` result always means the credential is
  /// absent from the store.
  ///
  /// Can reject with an [Ambiguous](Error::Ambiguous) error
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

  #[napi(ts_return_type = "Promise<boolean>")]
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
    into_optional(self.inner.get_password())
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
    into_optional(self.inner.get_secret())
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
      TaskKind::DeleteCredential => into_deleted(self.inner.delete_credential()).map(Some),
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
