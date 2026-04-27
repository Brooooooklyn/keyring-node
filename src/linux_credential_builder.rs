use keyring_core::{Result, CredentialStore};
use linux_keyutils_keyring_store::Store as KeyutilsStore;
use dbus_secret_service_keyring_store::Store as SecretServiceStore;

use std::collections::HashMap;
use std::sync::Arc;

/// A custom builder that falls back to keyutils if secret-service is not available.
pub struct LinuxCredentialBuilder {
  store: Arc<CredentialStore>,
}

impl LinuxCredentialBuilder {
  pub fn new() -> Result<Self> {
    // Try to create secret service store, fallback to keyutils if it fails
    let store: Arc<CredentialStore> = match SecretServiceStore::new_with_configuration(&HashMap::new()) {
      Ok(ss_store) => ss_store,
      Err(_) => KeyutilsStore::new_with_configuration(&HashMap::new())?,
    };

    Ok(Self { store })
  }

  pub fn get_store(&self) -> Arc<CredentialStore> {
    self.store.clone()
  }
}
