//! Request / response JSON shapes for the helper wire protocol.

use serde::Deserialize;
use serde_json::Value;

use crate::errmap::OpError;

/// A single request object read from stdin.
///
/// The field set is the union across all commands; each command reads only the
/// fields it needs (mirrors the Swift `Request`).
#[derive(Debug, Deserialize)]
pub struct Request {
    /// The operation: `generate` / `public_key` / `delete` / `ecdh` / `probe`.
    pub cmd: String,
    /// Application tag as hex (the store filename stem). Required by every
    /// command except `probe`.
    pub tag_hex: Option<String>,
    /// Human label (accepted for parity with the SE helper; unused).
    pub label: Option<String>,
    /// Peer public key as uncompressed-SEC1 hex (`ecdh` only).
    pub peer_pub_hex: Option<String>,
    /// `generate` only: machine-bound-but-unprompted when true. In the Tier-2
    /// TPM MVP both modes are machine-bound with no per-use prompt, so this is
    /// accepted but does not change behaviour.
    pub unattended: Option<bool>,
}

/// The structured response, serialized to exactly one JSON object.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// `{"public_key_hex": "04.."}`
    PublicKey(String),
    /// `{"shared_hex": ".."}`
    Shared(String),
    /// `{"ok": true}`
    Ok,
    /// `{"error": { .. }}`
    Error(ErrorBody),
}

/// The body of an error response.
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorBody {
    /// Error domain: `tpm` for backend failures, `helper` for bridge/request
    /// failures.
    pub domain: String,
    /// Numeric status (human-facing; dispatch is by `reason` when present).
    pub status: i64,
    /// Human-readable message.
    pub message: String,
    /// Neutral taxonomy reason, when applicable (absent for `helper` errors).
    pub reason: Option<String>,
}

impl Response {
    /// A `helper`-domain error for a malformed request (no neutral reason, so
    /// the Python side maps it to its conservative `auth_failed` default).
    pub fn request_error(message: impl Into<String>) -> Self {
        Response::Error(ErrorBody {
            domain: "helper".to_string(),
            status: -1,
            message: message.into(),
            reason: None,
        })
    }

    /// A `tpm`-domain error carrying the neutral [`crate::errmap::Reason`].
    pub fn from_op_error(err: OpError) -> Self {
        Response::Error(ErrorBody {
            domain: "tpm".to_string(),
            status: err.reason.status(),
            message: err.message,
            reason: Some(err.reason.as_str().to_string()),
        })
    }

    /// True when this response is an error (the process should exit 1).
    pub fn is_error(&self) -> bool {
        matches!(self, Response::Error(_))
    }

    /// Serialize to a single-line JSON object string.
    pub fn to_json(&self) -> String {
        let value = match self {
            Response::PublicKey(hex) => serde_json::json!({ "public_key_hex": hex }),
            Response::Shared(hex) => serde_json::json!({ "shared_hex": hex }),
            Response::Ok => serde_json::json!({ "ok": true }),
            Response::Error(body) => {
                // Build the error object field-by-field so `reason` is omitted
                // (not null) when absent, matching the Swift helper's shape.
                let mut err = serde_json::Map::new();
                err.insert("domain".to_string(), Value::from(body.domain.clone()));
                err.insert("status".to_string(), Value::from(body.status));
                err.insert("message".to_string(), Value::from(body.message.clone()));
                if let Some(reason) = &body.reason {
                    err.insert("reason".to_string(), Value::from(reason.clone()));
                }
                serde_json::json!({ "error": Value::Object(err) })
            }
        };
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn public_key_serializes() {
        let v = parse(&Response::PublicKey("0401".into()).to_json());
        assert_eq!(v, serde_json::json!({"public_key_hex": "0401"}));
    }

    #[test]
    fn shared_serializes() {
        let v = parse(&Response::Shared("ab".into()).to_json());
        assert_eq!(v, serde_json::json!({"shared_hex": "ab"}));
    }

    #[test]
    fn ok_serializes() {
        let v = parse(&Response::Ok.to_json());
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    #[test]
    fn op_error_carries_reason() {
        let resp = Response::from_op_error(OpError::not_found("no key"));
        assert!(resp.is_error());
        let v = parse(&resp.to_json());
        assert_eq!(v["error"]["domain"], "tpm");
        assert_eq!(v["error"]["reason"], "NOT_FOUND");
        assert_eq!(v["error"]["message"], "no key");
        assert!(v["error"]["status"].is_i64());
    }

    #[test]
    fn request_error_has_no_reason() {
        let resp = Response::request_error("bad");
        assert!(resp.is_error());
        let v = parse(&resp.to_json());
        assert_eq!(v["error"]["domain"], "helper");
        assert_eq!(v["error"]["status"], -1);
        assert!(v["error"].get("reason").is_none_or(|r| r.is_null()));
    }

    #[test]
    fn non_error_variants_are_not_errors() {
        assert!(!Response::Ok.is_error());
        assert!(!Response::PublicKey("x".into()).is_error());
    }
}
