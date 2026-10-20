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
  /// macOS-only options; ignored on other platforms.
  pub macos: Option<MacosEntryOptions>,
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

#[napi(object)]
/// macOS-only entry options; ignored on other platforms.
pub struct MacosEntryOptions {
  /// Require a specific macOS credential store. When absent, the default
  /// file-based keychain is used. There is no fallback between stores.
  pub store: Option<MacosStore>,
}

#[napi(string_enum)]
/// A macOS credential store that entries can be pinned to.
///
/// macOS only; ignored on other platforms. There is no fallback between
/// stores. Note that a missing entitlement does not fail construction: when
/// the process lacks the required code-signing entitlement, the `protected`
/// store is still constructed and the error surfaces on the first operation.
/// Construction itself can still throw, e.g. for `withTarget` (not supported
/// with the `protected` store) or an empty service or username.
pub enum MacosStore {
  /// The legacy file-based keychain. This is the default store.
  #[napi(value = "keychain")]
  Keychain,
  /// The data-protection keychain (`kSecUseDataProtectionKeychain`). Items
  /// are protected by the device passcode / Secure Enclave policies. The
  /// calling process must be code-signed with an application identifier;
  /// unsigned processes get an entitlement error. `target` is not supported
  /// with this store.
  #[napi(value = "protected")]
  Protected,
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
