use napi_derive::napi;

#[napi(object)]
/// Options for creating an `Entry` or `AsyncEntry`.
///
/// All options are platform-specific: they are accepted on every platform but
/// only take effect where documented. Leaving an option absent keeps the
/// current default behavior.
pub struct EntryOptions {
  /// Linux-only options; ignored on other platforms.
  pub linux: Option<LinuxEntryOptions>,
}

#[napi(object)]
/// Linux-only entry options; ignored on other platforms.
pub struct LinuxEntryOptions {
  /// Require a specific Linux credential store. When absent, the default
  /// auto-fallback selection is used (Secret Service, falling back to the
  /// kernel keyring). Requiring a store that is unavailable throws instead of
  /// falling back.
  pub store: Option<LinuxStore>,
}

#[napi(string_enum)]
/// A Linux credential store that entries can be pinned to.
///
/// Linux only; ignored on other platforms. Requiring a store that is
/// unavailable on this machine throws instead of falling back.
pub enum LinuxStore {
  /// The freedesktop Secret Service (D-Bus) as provided by gnome-keyring or
  /// KWallet. Persistent daemon-backed storage.
  #[napi(value = "secret-service")]
  SecretService,
  /// The Linux kernel keyring via keyutils. In-memory only: credentials
  /// vanish on reboot.
  #[napi(value = "keyutils")]
  Keyutils,
}
