use std::io::{Read, Write};
use std::process::exit;

use mordred_hermes_tpmkey::run_with;
use zeroize::Zeroize;

#[cfg(not(target_os = "linux"))]
use mordred_hermes_tpmkey::ops::UnavailableOps;
#[cfg(target_os = "linux")]
use mordred_hermes_tpmkey::tpm::TpmOps;

fn main() {
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        let _ = std::io::stdout().write_all(
            br#"{"error":{"domain":"helper","status":-1,"message":"failed to read stdin"}}"#,
        );
        exit(1);
    }

    // On Linux the real TPM backend handles every command; if no TPM/TCTI is
    // reachable each op surfaces the neutral `UNAVAILABLE` reason itself. On
    // every other host a TPM helper has no business running, so the static
    // `UnavailableOps` answers `UNAVAILABLE` without touching any hardware.
    #[cfg(target_os = "linux")]
    let (mut json, code) = run_with(&input, &TpmOps::new());
    #[cfg(not(target_os = "linux"))]
    let (mut json, code) = run_with(&input, &UnavailableOps);

    let _ = std::io::stdout().write_all(json.as_bytes());
    // M4 (security review 2026-06-11): an ecdh response embeds the shared Z
    // secret in hex — wipe the buffer once written instead of leaving it to
    // the allocator. (`exit` follows immediately, so this bounds the window
    // during which a core dump / swap could capture it.)
    json.zeroize();
    exit(code);
}
