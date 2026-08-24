use napi::bindgen_prelude::*;

/// Convert a lookup result into an optional value.
///
/// [`keyring_core::Error::NoEntry`] means the credential simply is not there,
/// which is not a failure: it becomes `None`. Every other error describes a
/// store that could not answer the question (locked, inaccessible, ambiguous,
/// malformed) and is propagated so the caller can tell "absent" apart from
/// "unavailable".
pub(crate) fn into_optional<T>(result: keyring_core::Result<T>) -> Result<Option<T>> {
  match result {
    Ok(value) => Ok(Some(value)),
    Err(keyring_core::Error::NoEntry) => Ok(None),
    Err(error) => Err(anyhow::Error::from(error).into()),
  }
}

/// Convert a deletion result into "was a credential removed?".
///
/// [`keyring_core::Error::NoEntry`] means there was nothing to delete, so the
/// entry is already in the requested state and `false` is reported. Every
/// other error means the credential may still exist in the store, so it is
/// propagated rather than reported as `false`; otherwise a failed deletion
/// would be indistinguishable from a no-op and the caller would believe a
/// secret had been removed when it had not.
pub(crate) fn into_deleted(result: keyring_core::Result<()>) -> Result<bool> {
  match result {
    Ok(()) => Ok(true),
    Err(keyring_core::Error::NoEntry) => Ok(false),
    Err(error) => Err(anyhow::Error::from(error).into()),
  }
}

#[cfg(test)]
mod tests {
  use super::{into_deleted, into_optional};

  fn platform_error() -> keyring_core::Error {
    keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(
      "credential store is locked",
    )))
  }

  #[test]
  fn into_optional_returns_value_when_found() {
    assert_eq!(
      into_optional(Ok("password".to_string())).unwrap(),
      Some("password".to_string())
    );
  }

  #[test]
  fn into_optional_returns_none_when_entry_is_missing() {
    let result: Result<Option<String>, _> = into_optional(Err(keyring_core::Error::NoEntry));
    assert_eq!(result.unwrap(), None);
  }

  #[test]
  fn into_optional_preserves_non_missing_errors() {
    let result: Result<Option<String>, _> = into_optional(Err(platform_error()));
    assert!(result.is_err());
  }

  #[test]
  fn into_optional_supports_secret_payloads() {
    assert_eq!(
      into_optional(Ok(vec![1u8, 2, 3])).unwrap(),
      Some(vec![1u8, 2, 3])
    );
  }

  #[test]
  fn into_optional_preserves_ambiguous_errors() {
    let result: Result<Option<Vec<u8>>, _> =
      into_optional(Err(keyring_core::Error::Ambiguous(Vec::new())));
    assert!(result.is_err());
  }

  #[test]
  fn into_deleted_reports_true_when_credential_removed() {
    assert!(into_deleted(Ok(())).unwrap());
  }

  #[test]
  fn into_deleted_reports_false_when_entry_is_missing() {
    assert!(!into_deleted(Err(keyring_core::Error::NoEntry)).unwrap());
  }

  #[test]
  fn into_deleted_preserves_non_missing_errors() {
    assert!(into_deleted(Err(platform_error())).is_err());
  }

  #[test]
  fn into_deleted_preserves_ambiguous_errors() {
    assert!(into_deleted(Err(keyring_core::Error::Ambiguous(Vec::new()))).is_err());
  }
}
