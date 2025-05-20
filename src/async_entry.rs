use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub struct AsyncEntry {
  inner: Arc<keyring::Entry>,
}

#[napi]
impl AsyncEntry {
  #[napi(constructor)]
  /// Create an entry for the given service and username.
  ///
  /// The default credential builder is used.
  pub fn new(service: String, username: String) -> Result<Self> {
    Ok(Self {
      inner: Arc::new(keyring::Entry::new(&service, &username).map_err(anyhow::Error::from)?),
    })
  }

  #[napi(factory)]
  /// Create an entry for the given target, service, and username.
  ///
  /// The default credential builder is used.
  pub fn with_target(target: String, service: String, username: String) -> Result<Self> {
    Ok(Self {
      inner: Arc::new(
        keyring::Entry::new_with_target(&target, &service, &username)
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
  pub fn get_password(&self, signal: Option<AbortSignal>) -> AsyncTask<EntryTask> {
    AsyncTask::with_optional_signal(
      EntryTask {
        inner: self.inner.clone(),
        kind: TaskKind::GetPassword,
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
  GetPassword,
  DeleteCredential,
}

pub struct EntryTask {
  inner: Arc<keyring::Entry>,
  kind: TaskKind,
}

#[napi]
impl Task for EntryTask {
  type Output = Option<Either<String, bool>>;
  type JsValue = Option<Either<String, bool>>;

  fn compute(&mut self) -> Result<Self::Output> {
    match self.kind {
      TaskKind::GetPassword => Ok(self.inner.get_password().ok().map(Either::A)),
      TaskKind::DeleteCredential => Ok(Some(Either::B(self.inner.delete_credential().is_ok()))),
      TaskKind::SetPassword(ref password) => {
        self
          .inner
          .set_password(password)
          .map_err(anyhow::Error::from)?;
        Ok(None)
      }
    }
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}
