use napi::bindgen_prelude::*;

/// Stable, machine-readable identifier for each kind of keychain failure.
///
/// Every error a `#[napi]` call surfaces carries one of these codes as
/// `error.code` on the JavaScript side. Codes are an API contract: the code
/// for a given error kind never changes, while `error.message` remains
/// human-readable text that may change at any time — consumers should test
/// `code`, never the message.
pub(crate) fn error_code(err: &keyring_core::Error) -> &'static str {
  use keyring_core::Error as E;
  match err {
    E::PlatformFailure(_) => "PlatformFailure",
    E::NoStorageAccess(_) => "NoStorageAccess",
    E::NoEntry => "NoEntry",
    E::BadEncoding(_) => "BadEncoding",
    E::BadDataFormat(..) => "BadDataFormat",
    E::BadStoreFormat(_) => "BadStoreFormat",
    E::TooLong(..) => "TooLong",
    E::Invalid(..) => "Invalid",
    E::Ambiguous(_) => "Ambiguous",
    E::NoDefaultStore => "NoDefaultStore",
    E::NotSupportedByStore(_) => "NotSupportedByStore",
    // keyring_core::Error is non_exhaustive: a variant this crate has not
    // seen degrades to the code every keychain error carried before.
    _ => "GenericFailure",
  }
}

/// Convert a keychain error into a napi error carrying its stable
/// [`error_code`]. The reason stays the error's `Display` text, so
/// `error.message` is exactly what callers saw before.
pub(crate) fn keyring_error(err: keyring_core::Error) -> Error<String> {
  Error::new(error_code(&err).to_string(), err.to_string())
}

/// Convert any fallible result into one whose error is a coded napi error.
///
/// When the anyhow chain contains a [`keyring_core::Error`] the error
/// carries that variant's stable code — the first one found, so an
/// error wrapped in `context` still reports its underlying kind. Every
/// other error reports `GenericFailure`, exactly the status the
/// `error_anyhow` conversion used before. The message and the `cause`
/// chain are constructed the same way that conversion constructed them,
/// so both are unchanged for callers.
pub(crate) fn into_napi<T, E>(result: std::result::Result<T, E>) -> Result<T, String>
where
  E: Into<anyhow::Error>,
{
  result.map_err(|e| {
    let e: anyhow::Error = e.into();
    let code = e
      .chain()
      .find_map(|cause| cause.downcast_ref::<keyring_core::Error>())
      .map(error_code)
      .unwrap_or("GenericFailure")
      .to_string();
    let mut chain = e.chain();
    let mut error = Error::new(code, chain.next().unwrap().to_string());
    // `cause` is typed `Box<Error<Status>>` — the chain is built as
    // `Error<Status>` values, exactly what the error_anyhow conversion
    // produced.
    if let Some(first) = chain.next() {
      let mut head = Error::new(Status::GenericFailure, first.to_string());
      let mut current = &mut head;
      for cause in chain {
        current.cause = Some(Box::new(Error::new(
          Status::GenericFailure,
          cause.to_string(),
        )));
        current = current.cause.as_deref_mut().unwrap();
      }
      error.cause = Some(Box::new(head));
    }
    error
  })
}

/// Throw a coded error into `env`, returning the pending-exception marker
/// the task machinery expects. `Task::compute` cannot return a non-`Status`
/// error, so async work carries the [`Error<String>`] in its `Output` and
/// throws it here from `resolve` — the JS promise rejects with the coded
/// error object.
pub(crate) fn throw_coded<T>(env: &Env, err: Error<String>) -> Result<T> {
  unsafe { JsError::from(err).throw_into(env.raw()) };
  Err(Error::new(Status::PendingException, String::new()))
}

/// Convert a lookup result into an optional value.
///
/// [`keyring_core::Error::NoEntry`] means the credential simply is not there,
/// which is not a failure: it becomes `None`. Every other error describes a
/// store that could not answer the question (locked, inaccessible, ambiguous,
/// malformed) and is propagated so the caller can tell "absent" apart from
/// "unavailable".
pub(crate) fn into_optional<T>(result: keyring_core::Result<T>) -> Result<Option<T>, String> {
  match result {
    Ok(value) => Ok(Some(value)),
    Err(keyring_core::Error::NoEntry) => Ok(None),
    Err(error) => Err(keyring_error(error)),
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
pub(crate) fn into_deleted(result: keyring_core::Result<()>) -> Result<bool, String> {
  match result {
    Ok(()) => Ok(true),
    Err(keyring_core::Error::NoEntry) => Ok(false),
    Err(error) => Err(keyring_error(error)),
  }
}

#[cfg(test)]
mod tests {
  use super::{error_code, into_deleted, into_napi, into_optional, keyring_error};

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

  #[test]
  fn every_keyring_variant_has_a_stable_code() {
    use keyring_core::Error as E;
    let cases: Vec<(E, &str)> = vec![
      (
        E::PlatformFailure(Box::new(std::io::Error::other("x"))),
        "PlatformFailure",
      ),
      (
        E::NoStorageAccess(Box::new(std::io::Error::other("x"))),
        "NoStorageAccess",
      ),
      (E::NoEntry, "NoEntry"),
      (E::BadEncoding(vec![0xff]), "BadEncoding"),
      (
        E::BadDataFormat(vec![], Box::new(std::io::Error::other("x"))),
        "BadDataFormat",
      ),
      (E::BadStoreFormat("x".into()), "BadStoreFormat"),
      (E::TooLong("x".into(), 9), "TooLong"),
      (E::Invalid("a".into(), "b".into()), "Invalid"),
      (E::Ambiguous(Vec::new()), "Ambiguous"),
      (E::NoDefaultStore, "NoDefaultStore"),
      (E::NotSupportedByStore("x".into()), "NotSupportedByStore"),
    ];
    for (err, code) in cases {
      assert_eq!(error_code(&err), code);
    }
  }

  #[test]
  fn keyring_error_keeps_message_and_sets_code() {
    let source = platform_error();
    let message = source.to_string();
    let err = keyring_error(source);
    assert_eq!(err.status, "NoStorageAccess");
    assert_eq!(err.reason, message);
  }

  #[test]
  fn into_napi_codes_keyring_errors() {
    let source = platform_error();
    let message = source.to_string();
    let result: Result<(), _> = into_napi::<(), _>(Err(source));
    let err = result.unwrap_err();
    assert_eq!(err.status, "NoStorageAccess");
    assert_eq!(err.reason, message);
  }

  #[test]
  fn into_napi_marks_other_errors_generic_failure() {
    let result: Result<(), _> = into_napi::<(), _>(Err(anyhow::anyhow!("Not a valid utf16 blob")));
    let err = result.unwrap_err();
    assert_eq!(err.status, "GenericFailure");
    assert_eq!(err.reason, "Not a valid utf16 blob");
  }

  #[test]
  fn into_napi_preserves_the_cause_chain() {
    let source = anyhow::anyhow!("inner detail");
    let wrapped = source.context("outer context");
    let result: Result<(), _> = into_napi::<(), _>(Err(wrapped));
    let err = result.unwrap_err();
    assert_eq!(err.status, "GenericFailure");
    assert_eq!(err.reason, "outer context");
    assert_eq!(err.cause.as_deref().unwrap().reason, "inner detail");
  }

  #[test]
  fn into_napi_finds_the_keyring_error_through_context() {
    let wrapped = anyhow::Error::from(platform_error()).context("keychain read failed");
    let result: Result<(), _> = into_napi::<(), _>(Err(wrapped));
    let err = result.unwrap_err();
    // The outer context is the message; the code comes from the source.
    assert_eq!(err.status, "NoStorageAccess");
    assert_eq!(err.reason, "keychain read failed");
  }
}
