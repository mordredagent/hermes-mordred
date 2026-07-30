//! Linux TPM 2.0 backend for the helper's [`KeyOps`] (v2-OS2 Phase 2b).
//!
//! Mirrors the macOS Secure-Enclave path: a non-extractable P-256 key plus
//! on-chip ECDH, so the keyvault's WMK wire format (P-256 ECDH → HKDF → AES-KW)
//! is byte-identical across platforms. The TPM holds the private key; we persist
//! only the opaque key-context blob (`<store>/<tag_hex>.bin`) via [`crate::store`].
//!
//! ## Object model
//! - A deterministic ECC P-256 **storage primary** (`CreatePrimary`, owner
//!   hierarchy, restricted decrypt) — recreated identically on every invocation
//!   because the TPM's hierarchy seed is stable, so a child saved in one process
//!   loads in the next.
//! - A non-restricted **ECDH decrypt child** (`Create`, `fixedTPM | fixedParent`)
//!   whose (public, private) blob is what we store. `ECDH_ZGen` runs the key
//!   agreement on-chip; `FlushContext` releases transient handles per op.
//!
//! `unattended` is accepted for protocol parity but ignored: Tier-2 TPM keys are
//! machine-bound with no per-use presence gate (no PIN/PCR prompt) in this MVP.
//!
//! ## Error mapping
//! Store outcomes carry the precise neutral reason (`EXISTS` / `NOT_FOUND`); any
//! `tss-esapi` failure maps conservatively to `UNAVAILABLE`. Because every key is
//! created with an empty auth value, an `AUTH_DENIED` path does not arise in this
//! MVP (it is reserved for a future per-use-gate follow-up).
//!
//! This module is Linux-only (`tss-esapi` links libtss2); non-Linux hosts use
//! [`crate::ops::UnavailableOps`]. It is exercised against a `swtpm` emulator —
//! tests run only when `MORDRED_TPM_TEST` is set and a TCTI is reachable.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributes, SessionAttributesMask},
    constants::SessionType,
    handles::{KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Private,
        Public, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    tcti_ldr::DeviceConfig,
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf,
};

use crate::errmap::OpError;
use crate::ops::KeyOps;
use crate::sec1;
use crate::{pad, store};

/// A [`KeyOps`] backed by a TPM 2.0 device via `tss-esapi`.
pub struct TpmOps {
    /// Where opaque per-key TPM context blobs live (`<dir>/<tag_hex>.bin`).
    store_dir: PathBuf,
}

impl TpmOps {
    /// Construct using the process-resolved key-blob store directory
    /// (`MORDRED_TPMKEY_STORE` → `$HERMES_HOME/...` → `~/.hermes/...`).
    pub fn new() -> Self {
        Self {
            store_dir: store::store_dir(),
        }
    }

    /// Construct against an explicit store directory (tests).
    #[cfg(test)]
    fn with_store_dir(store_dir: PathBuf) -> Self {
        Self { store_dir }
    }
}

impl Default for TpmOps {
    fn default() -> Self {
        Self::new()
    }
}

// --- error glue ---------------------------------------------------------------

/// Any `tss-esapi` failure is, from the keyvault's point of view, the hardware
/// path being unable to complete — surfaced as the neutral `UNAVAILABLE`.
impl From<tss_esapi::Error> for OpError {
    fn from(e: tss_esapi::Error) -> Self {
        OpError::unavailable(format!("TPM error: {e}"))
    }
}

/// Map a key-blob store outcome onto the neutral taxonomy.
fn store_err(e: store::StoreError) -> OpError {
    match e {
        store::StoreError::Exists => OpError::exists("a key already exists for this tag"),
        store::StoreError::NotFound => OpError::not_found("no key for this tag"),
        store::StoreError::Io(msg) => OpError::unavailable(format!("key store: {msg}")),
    }
}

// --- TPM bus parameter encryption (security review H4) ------------------------

/// Session attributes for an HMAC session that parameter-encrypts the first
/// command AND response parameter. On the ECDH path the encrypted response is
/// what matters: `ECDH_ZGen`'s output is the shared Z point, and without this
/// it would travel the TPM bus (LPC/SPI) in cleartext where a bus analyser, a
/// malicious hypervisor, or a co-process with `/dev/tpm0` access could lift the
/// key-wrapping secret.
fn encrypting_session_attrs() -> (SessionAttributes, SessionAttributesMask) {
    SessionAttributes::builder()
        .with_decrypt(true)
        .with_encrypt(true)
        .with_continue_session(true)
        .build()
}

/// Start an HMAC session **salted** to `salt_key` (a restricted decryption key,
/// here the storage primary) with AES-128-CFB parameter encryption, and apply
/// the encrypt/decrypt attributes.
///
/// Salting is what makes the encryption meaningful against a *passive* bus
/// observer: the session key is seeded from a salt encrypted to `salt_key`'s
/// public area, so only the TPM (which holds the private half) can recover it.
/// An unsalted/unbound session derives its key from the cleartext nonces alone
/// and would give a sniffer everything needed to decrypt the parameters.
fn start_encrypted_session(ctx: &mut Context, salt_key: KeyHandle) -> Result<AuthSession, OpError> {
    let session = ctx
        .start_auth_session(
            Some(salt_key),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| OpError::unavailable("TPM returned no auth session"))?;
    let (attrs, mask) = encrypting_session_attrs();
    ctx.tr_sess_set_attributes(session, attrs, mask)?;
    Ok(session)
}

// --- TPM key templates --------------------------------------------------------

/// Deterministic ECC P-256 storage primary (restricted decrypt) — the parent
/// that wraps the ECDH child. Recreated identically each invocation from the
/// stable hierarchy seed.
fn primary_template() -> Result<Public, OpError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

/// Non-restricted ECDH decrypt child (`fixedTPM | fixedParent`), empty auth.
fn child_template() -> Result<Public, OpError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(false)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

// --- blob (de)serialization ---------------------------------------------------

/// Pack the child's (public, private) as `u32-BE len(public) ‖ public ‖ private`.
///
/// The public area is a full TPM structure (`Marshall`); the private area is an
/// opaque `TPM2B_PRIVATE` buffer, so its raw bytes are stored directly.
fn encode_blob(public: &Public, private: &Private) -> Result<Vec<u8>, OpError> {
    let pub_bytes = public.marshall()?;
    let priv_bytes = private.value();
    let pub_len = u32::try_from(pub_bytes.len())
        .map_err(|_| OpError::unavailable("public area too large to encode"))?;
    let mut out = Vec::with_capacity(4 + pub_bytes.len() + priv_bytes.len());
    out.extend_from_slice(&pub_len.to_be_bytes());
    out.extend_from_slice(&pub_bytes);
    out.extend_from_slice(priv_bytes);
    Ok(out)
}

/// Inverse of [`encode_blob`].
fn decode_blob(blob: &[u8]) -> Result<(Public, Private), OpError> {
    let header: [u8; 4] = blob
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| OpError::unavailable("key blob truncated (header)"))?;
    let pub_len = u32::from_be_bytes(header) as usize;
    let pub_end = 4usize
        .checked_add(pub_len)
        .filter(|&end| end <= blob.len())
        .ok_or_else(|| OpError::unavailable("key blob truncated (public area)"))?;
    let public = Public::unmarshall(&blob[4..pub_end])?;
    let private = Private::try_from(blob[pub_end..].to_vec())?;
    Ok((public, private))
}

/// Extract the uncompressed SEC1 public key from a TPM ECC public area.
fn public_to_sec1(public: &Public) -> Result<[u8; sec1::UNCOMPRESSED_LEN], OpError> {
    match public {
        Public::Ecc { unique, .. } => {
            let x = pad::left_pad_32(unique.x().value())
                .map_err(|_| OpError::unavailable("public key X coordinate too long"))?;
            let y = pad::left_pad_32(unique.y().value())
                .map_err(|_| OpError::unavailable("public key Y coordinate too long"))?;
            Ok(sec1::encode_point(&x, &y))
        }
        _ => Err(OpError::unavailable("stored key is not an ECC key")),
    }
}

// --- context ------------------------------------------------------------------

/// M3 (security review 2026-06-11): may an env-provided TCTI be honoured?
///
/// Kernel device nodes (`device:...`) are OS-managed and always allowed — that
/// keeps real operator overrides working. Everything else (swtpm/mssim socket
/// transports, loadable TCTI modules) is reachable by any unprivileged local
/// process that can bind a socket, so an attacker-controlled environment could
/// redirect generate/ecdh to a spoofed TPM and observe or substitute the
/// wrapped key material. Those transports need the explicit `MORDRED_TPM_TEST`
/// opt-in (the CI/dev swtpm loop sets both variables).
fn env_tcti_allowed(tcti: &TctiNameConf, test_gate: bool) -> bool {
    matches!(tcti, TctiNameConf::Device(_)) || test_gate
}

/// Resolve which TPM to talk to.
///
/// An explicit `TCTI` env wins when [`env_tcti_allowed`] admits it (a device
/// path, or anything under the `MORDRED_TPM_TEST` gate for swtpm in CI/dev);
/// otherwise fall back to the system TPM, preferring the in-kernel resource
/// manager (`/dev/tpmrm0`) over the raw device (`/dev/tpm0`). The fallback
/// matters because `hermes mordred keyvault enable-tpm` probes with no `TCTI`
/// set — without it a perfectly good hardware TPM would report `UNAVAILABLE`.
fn resolve_tcti() -> Result<TctiNameConf, OpError> {
    if let Ok(tcti) = TctiNameConf::from_environment_variable() {
        if env_tcti_allowed(&tcti, std::env::var("MORDRED_TPM_TEST").is_ok()) {
            return Ok(tcti);
        }
        eprintln!(
            "mordred-hermes-tpmkey: ignoring non-device TCTI from environment \
             (socket TCTIs need MORDRED_TPM_TEST=1); falling back to the system TPM"
        );
    }
    for path in ["/dev/tpmrm0", "/dev/tpm0"] {
        if Path::new(path).exists() {
            let config = DeviceConfig::from_str(path)
                .map_err(|e| OpError::unavailable(format!("bad TPM device path {path}: {e}")))?;
            return Ok(TctiNameConf::Device(config));
        }
    }
    Err(OpError::unavailable(
        "no TCTI env and no /dev/tpmrm0 or /dev/tpm0 device found",
    ))
}

/// Open a TPM context against the resolved [`TctiNameConf`].
fn open_context() -> Result<Context, OpError> {
    let tcti = resolve_tcti()?;
    Context::new(tcti).map_err(|e| OpError::unavailable(format!("cannot open TPM: {e}")))
}

impl TpmOps {
    fn blob_dir(&self) -> &Path {
        &self.store_dir
    }
}

impl KeyOps for TpmOps {
    fn generate(&self, tag: &str, _label: &str, _unattended: bool) -> Result<Vec<u8>, OpError> {
        let mut ctx = open_context()?;

        // Create the storage primary first; it is both the child's parent and
        // the salt key for the encrypted session.
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(OpError::from)
        })?;
        let primary_handle = primary.key_handle;

        // Create the child under a salted + encrypted session so its sensitive
        // create parameters are parameter-encrypted on the bus (H4). The
        // resulting out_private is additionally parent-wrapped by the TPM.
        let session = match start_encrypted_session(&mut ctx, primary_handle) {
            Ok(s) => s,
            Err(e) => {
                let _ = ctx.flush_context(primary_handle.into());
                return Err(e);
            }
        };

        let created = ctx.execute_with_session(
            Some(session),
            |ctx| -> Result<([u8; sec1::UNCOMPRESSED_LEN], Vec<u8>), OpError> {
                let created =
                    ctx.create(primary_handle, child_template()?, None, None, None, None)?;
                let sec1_pub = public_to_sec1(&created.out_public)?;
                let blob = encode_blob(&created.out_public, &created.out_private)?;
                Ok((sec1_pub, blob))
            },
        );

        // Release the transient session + primary regardless of how create went.
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        let _ = ctx.flush_context(primary_handle.into());

        let (sec1_pub, blob) = created?;

        // Persist last: atomic no-replace publication turns a pre-existing tag
        // into a race-free EXISTS, and the just-created TPM child was never
        // made persistent, so a refusal here leaks nothing.
        store::write_blob_excl(self.blob_dir(), tag, &blob).map_err(store_err)?;
        Ok(sec1_pub.to_vec())
    }

    fn public_key(&self, tag: &str) -> Result<Vec<u8>, OpError> {
        let blob = store::read_blob(self.blob_dir(), tag).map_err(store_err)?;
        let (public, private) = decode_blob(&blob)?;

        // Never trust the cleartext public area from the filesystem on its own.
        // The TPM-wrapped private blob contains an integrity value bound to the
        // public area's Name and to this deterministic storage parent. Loading
        // both halves makes the live TPM authenticate that binding, defeating
        // an offline substitution of an attacker's software public key.
        let mut ctx = open_context()?;
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(OpError::from)
        })?;
        let primary_handle = primary.key_handle;

        let live_public = ctx.execute_with_nullauth_session(|ctx| -> Result<Public, OpError> {
            let child = ctx.load(primary_handle, private, public)?;
            // Return what the TPM reports for the successfully loaded
            // object, rather than echoing any filesystem-supplied bytes.
            let read_result = ctx.read_public(child);
            let _ = ctx.flush_context(child.into());
            let (live_public, _name, _qualified_name) = read_result?;
            Ok(live_public)
        });

        let _ = ctx.flush_context(primary_handle.into());
        Ok(public_to_sec1(&live_public?)?.to_vec())
    }

    fn delete(&self, tag: &str) -> Result<(), OpError> {
        store::delete_blob(self.blob_dir(), tag).map_err(store_err)
    }

    fn ecdh(&self, tag: &str, peer_pub: &[u8]) -> Result<[u8; 32], OpError> {
        let blob = store::read_blob(self.blob_dir(), tag).map_err(store_err)?;
        let (public, private) = decode_blob(&blob)?;

        let (x, y) = sec1::decode_point(peer_pub)
            .map_err(|_| OpError::unavailable("malformed peer point"))?;
        let in_point = EccPoint::new(
            EccParameter::try_from(x.to_vec())?,
            EccParameter::try_from(y.to_vec())?,
        );

        let mut ctx = open_context()?;

        // The storage primary doubles as the salt key for the encrypted
        // session, so it must be loaded before the session starts. Create it
        // under a null (password) session first.
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(OpError::from)
        })?;
        let primary_handle = primary.key_handle;

        // Salted + AES-128-CFB-encrypted HMAC session so ECDH_ZGen's response
        // (the shared Z point) is parameter-encrypted on the TPM bus (H4).
        let session = match start_encrypted_session(&mut ctx, primary_handle) {
            Ok(s) => s,
            Err(e) => {
                let _ = ctx.flush_context(primary_handle.into());
                return Err(e);
            }
        };

        let z = ctx.execute_with_session(Some(session), |ctx| -> Result<[u8; 32], OpError> {
            let child = ctx.load(primary_handle, private.clone(), public.clone())?;
            let shared = ctx.ecdh_z_gen(child, in_point);
            let _ = ctx.flush_context(child.into());
            let shared = shared?;
            pad::left_pad_32(shared.x().value())
                .map_err(|_| OpError::unavailable("shared secret X coordinate too long"))
        });

        let _ = ctx.flush_context(SessionHandle::from(session).into());
        let _ = ctx.flush_context(primary_handle.into());
        z
    }

    fn probe(&self) -> Result<(), OpError> {
        let mut ctx = open_context()?;
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(OpError::from)
        })?;
        let primary_handle = primary.key_handle;

        // Probe the full path under the same encrypted session the real ECDH
        // uses, so a TPM that cannot establish a salted/encrypted session fails
        // the probe instead of passing and breaking on the first real ECDH (H4).
        let session = match start_encrypted_session(&mut ctx, primary_handle) {
            Ok(s) => s,
            Err(e) => {
                let _ = ctx.flush_context(primary_handle.into());
                return Err(e);
            }
        };

        // Exercise the *full* path the keyvault depends on — create the ECDH
        // child, load it, and run ECDH_ZGen — so a TPM that supports the storage
        // primary but not the non-restricted ECDH child / Load / ECDH_ZGen fails
        // the probe instead of breaking on the first real generate. Nothing is
        // persisted (no blob is written).
        let result =
            ctx.execute_with_session(Some(session), |ctx| probe_ecdh_path(ctx, primary_handle));

        let _ = ctx.flush_context(SessionHandle::from(session).into());
        let _ = ctx.flush_context(primary_handle.into());
        result
    }
}

/// Create a throwaway ECDH child under `primary`, load it, and run `ECDH_ZGen`
/// against its own public point. Flushes the child; leaves `primary` to the
/// caller. Used only by [`TpmOps::probe`] to verify the live ECDH path.
fn probe_ecdh_path(
    ctx: &mut Context,
    primary: tss_esapi::handles::KeyHandle,
) -> Result<(), OpError> {
    let created = ctx.create(primary, child_template()?, None, None, None, None)?;
    let peer_point = match &created.out_public {
        Public::Ecc { unique, .. } => unique.clone(),
        _ => return Err(OpError::unavailable("probe: TPM returned a non-ECC child")),
    };
    let child = ctx.load(primary, created.out_private, created.out_public)?;
    let ecdh = ctx.ecdh_z_gen(child, peer_point);
    let _ = ctx.flush_context(child.into());
    ecdh?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errmap::Reason;
    use crate::sec1;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// TPM tests run only when explicitly enabled against a reachable TCTI
    /// (`MORDRED_TPM_TEST=1`), mirroring the Python `MORDRED_*_LIVE` gates. The
    /// no-swtpm CI leg compiles this module but skips the live assertions.
    fn tpm_enabled() -> bool {
        std::env::var("MORDRED_TPM_TEST").is_ok()
    }

    /// A unique throwaway store directory, removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let mut p = std::env::temp_dir();
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            p.push(format!("tpmkey-tpm-test-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ops_in(dir: &TempDir) -> TpmOps {
        TpmOps::with_store_dir(dir.0.clone())
    }

    /// A unique hex tag per logical key (the store filename stem).
    fn tag(s: &str) -> String {
        hex::encode(s.as_bytes())
    }

    #[test]
    fn ecdh_session_requests_parameter_encryption() {
        // Security review H4: the ECDH path must run under a session that
        // parameter-encrypts BOTH directions so the shared Z point never
        // crosses the TPM bus in cleartext. This asserts the session-attribute
        // policy directly — no TPM required, so it runs on every CI leg.
        let (attrs, _mask) = encrypting_session_attrs();
        assert!(
            attrs.encrypt(),
            "session must encrypt response params (the ECDH Z point)"
        );
        assert!(attrs.decrypt(), "session must encrypt command params too");
        assert!(
            attrs.continue_session(),
            "session must persist across Load + ECDH_ZGen"
        );
    }

    #[test]
    fn env_socket_tcti_requires_test_gate() {
        // Security review M3: an attacker-controlled TCTI env var must not be
        // able to redirect generate/ecdh to a spoofed socket TPM — swtpm/mssim
        // transports are plain TCP sockets any unprivileged local process can
        // bind. They are honoured only under the explicit MORDRED_TPM_TEST
        // gate (the CI/dev swtpm loop sets both). Kernel device nodes remain
        // honoured ungated so real operator overrides keep working. This
        // asserts the policy directly — no TPM required.
        let device = TctiNameConf::from_str("device:/dev/tpmrm0").expect("device tcti parses");
        let swtpm =
            TctiNameConf::from_str("swtpm:host=127.0.0.1,port=2321").expect("swtpm tcti parses");
        let mssim =
            TctiNameConf::from_str("mssim:host=127.0.0.1,port=2321").expect("mssim tcti parses");

        assert!(
            env_tcti_allowed(&device, false),
            "a device TCTI needs no gate"
        );
        assert!(
            !env_tcti_allowed(&swtpm, false),
            "an ungated swtpm TCTI must be ignored"
        );
        assert!(
            !env_tcti_allowed(&mssim, false),
            "an ungated mssim TCTI must be ignored"
        );
        assert!(
            env_tcti_allowed(&swtpm, true),
            "the CI/dev gate re-enables socket TCTIs"
        );
    }

    #[test]
    fn probe_succeeds_against_swtpm() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        ops_in(&dir)
            .probe()
            .expect("probe should succeed against a reachable TPM");
    }

    #[test]
    fn generate_then_public_key_matches() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        let ops = ops_in(&dir);
        let t = tag("gen-pk");

        let pk1 = ops.generate(&t, "label", false).expect("generate");
        assert_eq!(pk1.len(), sec1::UNCOMPRESSED_LEN);
        assert_eq!(pk1[0], sec1::PREFIX_UNCOMPRESSED);

        let pk2 = ops.public_key(&t).expect("public_key");
        assert_eq!(pk1, pk2, "public_key must echo the generate output");
    }

    #[test]
    fn public_key_rejects_public_private_blob_substitution() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        let ops = ops_in(&dir);
        let victim_tag = tag("victim");
        let substitute_tag = tag("substitute");

        ops.generate(&victim_tag, "", false)
            .expect("generate victim");
        ops.generate(&substitute_tag, "", false)
            .expect("generate substitute");

        let victim_blob = store::read_blob(ops.blob_dir(), &victim_tag).expect("read victim blob");
        let substitute_blob =
            store::read_blob(ops.blob_dir(), &substitute_tag).expect("read substitute blob");
        let (_victim_public, victim_private) =
            decode_blob(&victim_blob).expect("decode victim blob");
        let (substitute_public, _substitute_private) =
            decode_blob(&substitute_blob).expect("decode substitute blob");

        // Simulate an offline attacker replacing only the cleartext public
        // area while retaining the victim's opaque TPM private area. Merely
        // decoding this blob would expose the substitute public key; TPM Load
        // must reject the mismatched Name/integrity binding.
        let forged_blob =
            encode_blob(&substitute_public, &victim_private).expect("encode forged blob");
        std::fs::write(store::blob_path(ops.blob_dir(), &victim_tag), forged_blob)
            .expect("replace stored blob");

        let err = ops
            .public_key(&victim_tag)
            .expect_err("TPM must reject a substituted public area");
        assert_eq!(err.reason, Reason::Unavailable);
    }

    #[test]
    fn generate_twice_is_exists() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        let ops = ops_in(&dir);
        let t = tag("dup");
        ops.generate(&t, "", false).expect("first generate");
        let err = ops
            .generate(&t, "", false)
            .expect_err("second generate must fail");
        assert_eq!(err.reason, Reason::Exists);
    }

    #[test]
    fn public_key_missing_is_not_found() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        let err = ops_in(&dir)
            .public_key(&tag("nope"))
            .expect_err("missing key");
        assert_eq!(err.reason, Reason::NotFound);
    }

    #[test]
    fn delete_is_idempotent_then_not_found() {
        if !tpm_enabled() {
            return;
        }
        let dir = TempDir::new();
        let ops = ops_in(&dir);
        let t = tag("del");
        ops.delete(&t).expect("delete of a missing key is ok");
        ops.generate(&t, "", false).expect("generate");
        ops.delete(&t).expect("delete of an existing key");
        let err = ops.public_key(&t).expect_err("deleted key is gone");
        assert_eq!(err.reason, Reason::NotFound);
    }

    /// The contract that makes the whole helper interchangeable with the SE
    /// helper and the software fallback: the TPM's ECDH shared X coordinate must
    /// equal a software P-256 ECDH over the same key pair, so `wrap.py`'s HKDF
    /// input is identical across backends.
    #[test]
    fn ecdh_matches_software_p256() {
        if !tpm_enabled() {
            return;
        }
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};

        let dir = TempDir::new();
        let ops = ops_in(&dir);
        let t = tag("ecdh");

        // TPM child public key (uncompressed SEC1).
        let tpm_pub_sec1 = ops.generate(&t, "", false).expect("generate");
        let tpm_pub = PublicKey::from_sec1_bytes(&tpm_pub_sec1).expect("parse TPM public key");

        // A software peer keypair.
        let peer_secret = SecretKey::random(&mut rand_core::OsRng);
        let peer_pub_sec1 = peer_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        // TPM side: ECDH(child_priv, peer_pub) → shared X (32 bytes).
        let z_tpm = ops.ecdh(&t, &peer_pub_sec1).expect("tpm ecdh");

        // Software side: ECDH(peer_priv, child_pub) → shared X (32 bytes).
        let z_sw = diffie_hellman(peer_secret.to_nonzero_scalar(), tpm_pub.as_affine());

        assert_eq!(
            z_tpm.to_vec(),
            z_sw.raw_secret_bytes().to_vec(),
            "TPM and software ECDH must agree (wrap.py HKDF parity)"
        );
    }
}
