//! Neutral, platform-independent error taxonomy.
//!
//! Phase 1 added an `error.reason` field to the helper wire protocol so a
//! non-macOS backend can drive `_SecKeyBackend`'s dispatch without borrowing
//! macOS `OSStatus` ints. The four reasons mirror
//! `mordred_hermes.keyvault._seckey_backend._OPS_REASONS`; the Python side
//! validates the string and falls back to the numeric status for anything it
//! does not recognise.

/// A recognised, platform-neutral failure reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No key exists for the tag (maps to `errSecItemNotFound`).
    NotFound,
    /// A key already exists for the tag (maps to `errSecDuplicateItem`).
    Exists,
    /// The hardware backend is unavailable on this host.
    Unavailable,
    /// The operation was denied / failed authorization.
    AuthDenied,
}

impl Reason {
    /// The wire string the Python `_normalize_reason` validates against.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::NotFound => "NOT_FOUND",
            Reason::Exists => "EXISTS",
            Reason::Unavailable => "UNAVAILABLE",
            Reason::AuthDenied => "AUTH_DENIED",
        }
    }

    /// A stable, human-facing numeric status for the `tpm` error domain. The
    /// Python side dispatches on `reason`, not this value, but it must still be
    /// a JSON integer for `_run_helper`.
    pub fn status(self) -> i64 {
        match self {
            Reason::NotFound => 1,
            Reason::Exists => 2,
            Reason::Unavailable => 3,
            Reason::AuthDenied => 4,
        }
    }
}

/// An operation failure carrying a neutral [`Reason`] and a human message.
#[derive(Debug, PartialEq, Eq)]
pub struct OpError {
    /// The neutral failure reason.
    pub reason: Reason,
    /// A human-readable detail (never parsed by the caller).
    pub message: String,
}

impl OpError {
    /// Construct an [`OpError`] from a reason and message.
    pub fn new(reason: Reason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// `NOT_FOUND` convenience constructor.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Reason::NotFound, message)
    }

    /// `EXISTS` convenience constructor.
    pub fn exists(message: impl Into<String>) -> Self {
        Self::new(Reason::Exists, message)
    }

    /// `UNAVAILABLE` convenience constructor.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(Reason::Unavailable, message)
    }

    /// `AUTH_DENIED` convenience constructor.
    pub fn auth_denied(message: impl Into<String>) -> Self {
        Self::new(Reason::AuthDenied, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_strings_match_the_neutral_taxonomy() {
        assert_eq!(Reason::NotFound.as_str(), "NOT_FOUND");
        assert_eq!(Reason::Exists.as_str(), "EXISTS");
        assert_eq!(Reason::Unavailable.as_str(), "UNAVAILABLE");
        assert_eq!(Reason::AuthDenied.as_str(), "AUTH_DENIED");
    }

    #[test]
    fn statuses_are_distinct_and_positive() {
        let all = [
            Reason::NotFound,
            Reason::Exists,
            Reason::Unavailable,
            Reason::AuthDenied,
        ];
        let mut seen = std::collections::HashSet::new();
        for r in all {
            assert!(r.status() > 0);
            assert!(seen.insert(r.status()), "duplicate status for {r:?}");
        }
    }

    #[test]
    fn constructors_set_reason() {
        assert_eq!(OpError::not_found("x").reason, Reason::NotFound);
        assert_eq!(OpError::exists("x").reason, Reason::Exists);
        assert_eq!(OpError::unavailable("x").reason, Reason::Unavailable);
        assert_eq!(OpError::auth_denied("x").reason, Reason::AuthDenied);
    }
}
