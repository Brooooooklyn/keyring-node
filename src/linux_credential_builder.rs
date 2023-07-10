use keyring::{
  credential::{CredentialApi, CredentialBuilderApi},
  keyutils::KeyutilsCredential,
  secret_service::SsCredential,
};

use std::any::Any;
use std::error::Error;

/// A custom builder that falls back to keyutils if secret-service is not available.
#[derive(Debug)]
pub struct LinuxCredentialBuilder {
  secret_service_missing: bool,
}

impl LinuxCredentialBuilder {
  pub fn new() -> Result<Self, Box<dyn Error>> {
    let ss = SsCredential::new_with_target(None, "test", "user")?;

    let missing = matches!(
      ss.map_matching_items(|_item| Ok(()), false),
      Err(keyring::Error::PlatformFailure(_x))
    );

    Ok(Self {
      secret_service_missing: missing,
    })
  }
}

impl CredentialBuilderApi for LinuxCredentialBuilder {
  fn build(
    &self,
    target: Option<&str>,
    service: &str,
    user: &str,
  ) -> Result<Box<(dyn CredentialApi + Send + Sync + 'static)>, keyring::Error> {
    if !self.secret_service_missing {
      let cred = SsCredential::new_with_target(target, service, user)?;
      return Ok(Box::new(cred));
    }

    let cred = KeyutilsCredential::new_with_target(target, service, user)?;
    Ok(Box::new(cred))
  }

  fn as_any(&self) -> &dyn Any {
    self
  }
}
