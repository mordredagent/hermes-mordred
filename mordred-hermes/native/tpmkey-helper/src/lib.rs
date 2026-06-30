//! `mordred-hermes-tpmkey` — TPM 2.0 hardware-key helper for the Mordred keyvault.
//!
//! One process invocation == one operation: read a single JSON request object
//! from stdin, perform the operation, write a single JSON response object to
//! stdout, exit (0 success / 1 error). This is byte-for-byte the same
//! JSON-over-stdio protocol the macOS Secure-Enclave helper
//! (`mordred-hermes-sekey`) speaks, so the Python driver
//! (`mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps`) drives either
//! one unchanged.
//!
//! ## Module map (Phase 2a — pure, host-agnostic, `cargo test`-covered)
//! - [`pad`]    — left-pad an ECDH Z X-coordinate to a fixed 32 bytes.
//! - [`sec1`]   — SEC1 / X9.63 uncompressed P-256 point encode/decode.
//! - [`wire`]   — request/response JSON shapes.
//! - [`errmap`] — neutral error taxonomy (`NOT_FOUND`/`EXISTS`/`UNAVAILABLE`/`AUTH_DENIED`).
//! - [`store`]  — opaque key-blob file store under `HERMES_HOME`.
//! - [`ops`]    — the [`ops::KeyOps`] trait + the request dispatcher.
//!
//! The TPM-touching backend (`tss-esapi`, Linux-only) is deferred to Phase 2b;
//! until then [`ops::UnavailableOps`] answers every command with `UNAVAILABLE`.

pub mod errmap;
pub mod ops;
pub mod pad;
pub mod sec1;
pub mod store;
#[cfg(target_os = "linux")]
pub mod tpm;
pub mod wire;

use ops::KeyOps;
use wire::Response;

/// Parse one JSON request from `input`, run it against `ops`, and return the
/// serialized JSON response plus the process exit code (0 ok / 1 error).
///
/// A malformed request (non-JSON / wrong shape) yields a `helper`-domain error
/// with no neutral `reason`, mirroring the Swift helper's `fail(...)` path.
pub fn run_with<O: KeyOps>(input: &[u8], ops: &O) -> (String, i32) {
    let response = match serde_json::from_slice::<wire::Request>(input) {
        Ok(request) => ops::dispatch(&request, ops),
        Err(_) => Response::request_error("invalid JSON request on stdin"),
    };
    let code = if response.is_error() { 1 } else { 0 };
    (response.to_json(), code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ops::UnavailableOps;

    #[test]
    fn malformed_json_is_helper_error_exit_1() {
        let (json, code) = run_with(b"not json", &UnavailableOps);
        assert_eq!(code, 1);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["error"]["domain"], "helper");
    }

    #[test]
    fn routed_command_maps_backend_error_to_exit_1() {
        let (json, code) = run_with(br#"{"cmd":"probe"}"#, &UnavailableOps);
        assert_eq!(code, 1);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["error"]["reason"], "UNAVAILABLE");
    }
}
