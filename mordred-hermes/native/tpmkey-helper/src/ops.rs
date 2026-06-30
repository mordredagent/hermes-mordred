//! The [`KeyOps`] trait and the request dispatcher.

use zeroize::Zeroize;

use crate::errmap::OpError;
use crate::wire::{Request, Response};

/// The backend operations a helper must provide. One method == one wire
/// command; tags and peer keys arrive already validated.
pub trait KeyOps {
    /// Create a non-extractable keypair for `tag`; return its uncompressed
    /// SEC1 public key.
    fn generate(&self, tag: &str, label: &str, unattended: bool) -> Result<Vec<u8>, OpError>;
    /// Return the uncompressed SEC1 public key for `tag`.
    fn public_key(&self, tag: &str) -> Result<Vec<u8>, OpError>;
    /// Delete the key for `tag` (idempotent).
    fn delete(&self, tag: &str) -> Result<(), OpError>;
    /// ECDH between the key for `tag` and `peer_pub` (uncompressed SEC1);
    /// return the 32-byte shared X coordinate.
    fn ecdh(&self, tag: &str, peer_pub: &[u8]) -> Result<[u8; 32], OpError>;
    /// Prove the hardware path works without persisting anything.
    fn probe(&self) -> Result<(), OpError>;
}

/// True when `s` is non-empty, even-length, all-hex.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Require a present, valid `tag_hex`, else a `helper`-domain request error.
fn require_tag(req: &Request) -> Result<&str, Response> {
    match req.tag_hex.as_deref() {
        Some(t) if is_valid_hex(t) => Ok(t),
        _ => Err(Response::request_error("missing or invalid tag_hex")),
    }
}

/// Route one parsed [`Request`] to `ops` and build its [`Response`].
///
/// Request-shape failures (unknown cmd, missing/invalid `tag_hex` or
/// `peer_pub_hex`) become `helper`-domain errors with no neutral reason,
/// exactly like the Swift helper's `fail(...)`. Backend failures become
/// `tpm`-domain errors carrying the neutral reason.
pub fn dispatch<O: KeyOps>(req: &Request, ops: &O) -> Response {
    match req.cmd.as_str() {
        "generate" => {
            let tag = match require_tag(req) {
                Ok(tag) => tag,
                Err(resp) => return resp,
            };
            let label = req.label.as_deref().unwrap_or("");
            let unattended = req.unattended.unwrap_or(false);
            match ops.generate(tag, label, unattended) {
                Ok(public_key) => Response::PublicKey(hex::encode(public_key)),
                Err(e) => Response::from_op_error(e),
            }
        }
        "public_key" => {
            let tag = match require_tag(req) {
                Ok(tag) => tag,
                Err(resp) => return resp,
            };
            match ops.public_key(tag) {
                Ok(public_key) => Response::PublicKey(hex::encode(public_key)),
                Err(e) => Response::from_op_error(e),
            }
        }
        "delete" => {
            let tag = match require_tag(req) {
                Ok(tag) => tag,
                Err(resp) => return resp,
            };
            match ops.delete(tag) {
                Ok(()) => Response::Ok,
                Err(e) => Response::from_op_error(e),
            }
        }
        "ecdh" => {
            let tag = match require_tag(req) {
                Ok(tag) => tag,
                Err(resp) => return resp,
            };
            let peer = match req.peer_pub_hex.as_deref() {
                Some(h) if is_valid_hex(h) => match hex::decode(h) {
                    Ok(bytes) => bytes,
                    Err(_) => return Response::request_error("missing or invalid peer_pub_hex"),
                },
                _ => return Response::request_error("missing or invalid peer_pub_hex"),
            };
            match ops.ecdh(tag, &peer) {
                Ok(mut shared) => {
                    // M4 (security review 2026-06-11): the Z point is the
                    // key-wrapping secret — wipe our copy as soon as it has
                    // been encoded. Borrowed slice: passing the Copy array by
                    // value would hand encode() a second, unwipeable copy.
                    let resp = Response::Shared(hex::encode(&shared[..]));
                    shared.zeroize();
                    resp
                }
                Err(e) => Response::from_op_error(e),
            }
        }
        "probe" => match ops.probe() {
            Ok(()) => Response::Ok,
            Err(e) => Response::from_op_error(e),
        },
        other => Response::request_error(format!("unknown cmd: {other}")),
    }
}

/// A [`KeyOps`] that answers every command with `UNAVAILABLE`.
///
/// Used until Phase 2b wires the real `tss-esapi` backend (and on any non-Linux
/// host, where a TPM helper has no business running).
pub struct UnavailableOps;

impl UnavailableOps {
    fn unavailable() -> OpError {
        OpError::unavailable("TPM backend not built (Phase 2b); helper is non-functional")
    }
}

impl KeyOps for UnavailableOps {
    fn generate(&self, _tag: &str, _label: &str, _unattended: bool) -> Result<Vec<u8>, OpError> {
        Err(Self::unavailable())
    }
    fn public_key(&self, _tag: &str) -> Result<Vec<u8>, OpError> {
        Err(Self::unavailable())
    }
    fn delete(&self, _tag: &str) -> Result<(), OpError> {
        Err(Self::unavailable())
    }
    fn ecdh(&self, _tag: &str, _peer_pub: &[u8]) -> Result<[u8; 32], OpError> {
        Err(Self::unavailable())
    }
    fn probe(&self) -> Result<(), OpError> {
        Err(Self::unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errmap::Reason;
    use serde_json::Value;

    #[derive(Default)]
    struct FakeOps {
        pubkey: Vec<u8>,
        shared: [u8; 32],
        err: Option<Reason>,
        last_peer: std::cell::RefCell<Option<Vec<u8>>>,
        last_unattended: std::cell::Cell<Option<bool>>,
    }
    impl FakeOps {
        fn failing(reason: Reason) -> Self {
            FakeOps {
                err: Some(reason),
                ..Default::default()
            }
        }
        fn gate(&self) -> Result<(), OpError> {
            match self.err {
                Some(r) => Err(OpError::new(r, "boom")),
                None => Ok(()),
            }
        }
    }
    impl KeyOps for FakeOps {
        fn generate(&self, _t: &str, _l: &str, unattended: bool) -> Result<Vec<u8>, OpError> {
            self.last_unattended.set(Some(unattended));
            self.gate().map(|()| self.pubkey.clone())
        }
        fn public_key(&self, _t: &str) -> Result<Vec<u8>, OpError> {
            self.gate().map(|()| self.pubkey.clone())
        }
        fn delete(&self, _t: &str) -> Result<(), OpError> {
            self.gate()
        }
        fn ecdh(&self, _t: &str, peer: &[u8]) -> Result<[u8; 32], OpError> {
            *self.last_peer.borrow_mut() = Some(peer.to_vec());
            self.gate().map(|()| self.shared)
        }
        fn probe(&self) -> Result<(), OpError> {
            self.gate()
        }
    }

    fn req(s: &str) -> Request {
        serde_json::from_str(s).unwrap()
    }
    fn json(r: Response) -> Value {
        serde_json::from_str(&r.to_json()).unwrap()
    }

    #[test]
    fn generate_returns_public_key_hex() {
        let ops = FakeOps {
            pubkey: vec![0x04, 0xAB],
            ..Default::default()
        };
        let v = json(dispatch(
            &req(r#"{"cmd":"generate","tag_hex":"00","label":"k","unattended":true}"#),
            &ops,
        ));
        assert_eq!(v["public_key_hex"], "04ab");
        assert_eq!(ops.last_unattended.get(), Some(true));
    }

    #[test]
    fn public_key_returns_hex() {
        let ops = FakeOps {
            pubkey: vec![0x04, 0x01, 0x02],
            ..Default::default()
        };
        let v = json(dispatch(
            &req(r#"{"cmd":"public_key","tag_hex":"00"}"#),
            &ops,
        ));
        assert_eq!(v["public_key_hex"], "040102");
    }

    #[test]
    fn delete_returns_ok() {
        let ops = FakeOps::default();
        let v = json(dispatch(&req(r#"{"cmd":"delete","tag_hex":"00"}"#), &ops));
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    #[test]
    fn ecdh_returns_shared_hex_and_passes_peer_bytes() {
        let ops = FakeOps {
            shared: [0x07; 32],
            ..Default::default()
        };
        let v = json(dispatch(
            &req(r#"{"cmd":"ecdh","tag_hex":"00","peer_pub_hex":"04ff"}"#),
            &ops,
        ));
        assert_eq!(v["shared_hex"], hex::encode([0x07u8; 32]));
        assert_eq!(*ops.last_peer.borrow(), Some(vec![0x04, 0xff]));
    }

    #[test]
    fn probe_returns_ok() {
        let ops = FakeOps::default();
        let v = json(dispatch(&req(r#"{"cmd":"probe"}"#), &ops));
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    #[test]
    fn unknown_cmd_is_helper_error() {
        let ops = FakeOps::default();
        let v = json(dispatch(&req(r#"{"cmd":"frobnicate"}"#), &ops));
        assert_eq!(v["error"]["domain"], "helper");
        assert!(v["error"].get("reason").is_none_or(|r| r.is_null()));
    }

    #[test]
    fn missing_tag_hex_is_helper_error() {
        let ops = FakeOps::default();
        let v = json(dispatch(&req(r#"{"cmd":"generate"}"#), &ops));
        assert_eq!(v["error"]["domain"], "helper");
    }

    #[test]
    fn invalid_tag_hex_is_helper_error() {
        let ops = FakeOps::default();
        let v = json(dispatch(
            &req(r#"{"cmd":"public_key","tag_hex":"zz"}"#),
            &ops,
        ));
        assert_eq!(v["error"]["domain"], "helper");
    }

    #[test]
    fn ecdh_missing_peer_is_helper_error() {
        let ops = FakeOps::default();
        let v = json(dispatch(&req(r#"{"cmd":"ecdh","tag_hex":"00"}"#), &ops));
        assert_eq!(v["error"]["domain"], "helper");
    }

    #[test]
    fn backend_error_becomes_tpm_reason() {
        let ops = FakeOps::failing(Reason::NotFound);
        let v = json(dispatch(
            &req(r#"{"cmd":"public_key","tag_hex":"00"}"#),
            &ops,
        ));
        assert_eq!(v["error"]["domain"], "tpm");
        assert_eq!(v["error"]["reason"], "NOT_FOUND");
    }

    #[test]
    fn unavailable_ops_reports_unavailable() {
        let v = json(dispatch(&req(r#"{"cmd":"probe"}"#), &UnavailableOps));
        assert_eq!(v["error"]["reason"], "UNAVAILABLE");
    }
}
