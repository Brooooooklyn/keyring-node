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
  pub fn get_password(&self) -> Result<String> {
    Ok(self.inner.get_password().map_err(anyhow::Error::from)?)
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
  pub fn delete_password(&self) -> Result<()> {
    self.inner.delete_password().map_err(anyhow::Error::from)?;
    Ok(())
  }
}
