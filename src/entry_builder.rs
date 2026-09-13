use std::collections::HashMap;

use anyhow::Result;

use crate::options::EntryOptions;

/// Create a `keyring_core::Entry` from the given specifiers, honoring the
/// optional platform-specific `options`.
///
/// On Linux, `options.linux.store` pins the entry to one specific credential
/// store: the named store is constructed directly and any failure to do so is
/// propagated, so requiring an unavailable store throws instead of falling
/// back. Without the option, the default auto-fallback selection is used.
/// On all other platforms the options are accepted and ignored.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(crate) fn create_entry(
  service: &str,
  user: &str,
  target: Option<&str>,
  options: Option<&EntryOptions>,
) -> Result<keyring_core::Entry> {
  #[cfg(target_os = "linux")]
  if let Some(store) = options
    .and_then(|o| o.linux.as_ref())
    .and_then(|l| l.store.as_ref())
  {
    return create_entry_with_linux_store(service, user, target, store);
  }

  #[cfg(target_os = "linux")]
  setup_linux_store()?;
  #[cfg(target_os = "macos")]
  setup_macos_store()?;
  #[cfg(target_os = "windows")]
  setup_windows_store()?;
  #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
  setup_bsd_store()?;

  let entry = match target {
    Some(target) => keyring_core::Entry::new_with_modifiers(service, user, &{
      let mut mods = HashMap::new();
      #[cfg(target_os = "macos")]
      mods.insert("keychain", target);
      #[cfg(not(target_os = "macos"))]
      mods.insert("target", target);
      mods
    })
    .map_err(anyhow::Error::from)?,
    None => keyring_core::Entry::new(service, user).map_err(anyhow::Error::from)?,
  };

  // On Windows, when using the target modifier, the username needs to be preserved
  // by creating a placeholder credential and setting the username attribute explicitly.
  // This is because credentials with explicit targets don't have specifiers in keyring v4.
  // When the actual password is set later, set_secret will read and preserve these attributes.
  #[cfg(target_os = "windows")]
  if target.is_some() {
    // Create a temporary credential with empty password
    if entry.set_secret(&[]).is_ok() {
      // Set the username attribute so it's preserved when the real password is set
      let mut attrs = HashMap::new();
      attrs.insert("username", user);
      entry.update_attributes(&attrs).ok();
    }
  }

  Ok(entry)
}

/// Build an entry directly from the store pinned in the options, failing
/// loudly if that store cannot be constructed.
///
/// The kernel keyring store has no `target` modifier; its equivalent identity
/// knob is the `description` modifier, so a given target is mapped to it to
/// keep distinct targets addressing distinct kernel credentials.
#[cfg(target_os = "linux")]
fn create_entry_with_linux_store(
  service: &str,
  user: &str,
  target: Option<&str>,
  store: &crate::options::LinuxStore,
) -> Result<keyring_core::Entry> {
  use keyring_core::api::CredentialStoreApi;

  use crate::options::LinuxStore;

  match store {
    LinuxStore::SecretService => {
      let store = dbus_secret_service_keyring_store::Store::new_with_configuration(&HashMap::new())
        .map_err(anyhow::Error::from)?;
      let modifiers = target.map(|t| HashMap::from([("target", t)]));
      store
        .build(service, user, modifiers.as_ref())
        .map_err(anyhow::Error::from)
    }
    LinuxStore::Keyutils => {
      let store = linux_keyutils_keyring_store::Store::new_with_configuration(&HashMap::new())
        .map_err(anyhow::Error::from)?;
      let modifiers = target.map(|t| HashMap::from([("description", t)]));
      store
        .build(service, user, modifiers.as_ref())
        .map_err(anyhow::Error::from)
    }
  }
}

#[cfg(target_os = "linux")]
fn setup_linux_store() -> anyhow::Result<()> {
  let builder = crate::linux_credential_builder::LinuxCredentialBuilder::new()?;
  keyring_core::set_default_store(builder.get_store());
  Ok(())
}

#[cfg(target_os = "macos")]
fn setup_macos_store() -> anyhow::Result<()> {
  use apple_native_keyring_store::keychain::Store;

  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(store);
  Ok(())
}

#[cfg(target_os = "windows")]
fn setup_windows_store() -> anyhow::Result<()> {
  use windows_native_keyring_store::Store;

  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(store);
  Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn setup_bsd_store() -> anyhow::Result<()> {
  use dbus_secret_service_keyring_store::Store;

  let store = Store::new_with_configuration(&HashMap::new())?;
  keyring_core::set_default_store(store);
  Ok(())
}
