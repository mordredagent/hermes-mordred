use std::io::{Read, Write};
use std::process::exit;

use mordred_hermes_tpmkey::run_with;

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
    let (json, code) = run_with(&input, &TpmOps::new());
    #[cfg(not(target_os = "linux"))]
    let (json, code) = run_with(&input, &UnavailableOps);

    let _ = std::io::stdout().write_all(json.as_bytes());
    exit(code);
}
