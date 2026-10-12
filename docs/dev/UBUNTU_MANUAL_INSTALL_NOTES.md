# Ubuntu manual installation notes

Manual session: 2026-10-07. Fresh Ubuntu 24.04.5 x86_64 on EC2
(`t3.medium`, NitroTPM), with Xfce, TigerVNC, and noVNC over an SSH tunnel.
This records observed installation failures and their remedies, not a claim
that the full Mordred or Telegram workflow has been validated.

## Hermes installation and Desktop launch

| Symptom | Observed cause | Action and result |
| --- | --- | --- |
| Installer requested `[sudo] password for ubuntu` while checking Node dependencies. | `libatomic.so.1` was missing. The installer used `sudo -v`; this EC2 account had no login password, although the required package command worked with passwordless sudo. | Installed `libatomic1` with `sudo -n apt-get install -y libatomic1`, then resumed the official installer. Installation progressed. No password was created. |
| Setup waited for Nous Portal login approval. | Provider onboarding had started; this was not an installation failure. | Cancelled onboarding with Ctrl+C and declined gateway startup. Later chose “I'll choose a provider later” in Desktop. Desktop can open before model setup. |
| `hermes desktop` failed in `node-gyp`, reporting missing `make`. | The fresh Ubuntu image lacked native build tools. | Installed `build-essential` and `pkg-config`, then ran `hermes desktop --build-only`. |
| Desktop build was slow and memory usage approached the 4 GiB instance limit. | The build used most available memory; high CPU steal was also observed. | Added a temporary 4 GiB swap file and temporarily changed EC2 CPU credits to unlimited. The build completed. CPU credits were restored to standard. Swap was not added to `/etc/fstab`. These were build aids, not verified product requirements. |
| Packaged Desktop had a missing shared library. | `ldd` reported `libasound.so.2 => not found`. | Installed Ubuntu 24.04 package `libasound2t64`. Dependency inspection then showed no missing libraries. |
| First packaged launch needed the Electron sandbox helper configured. | The freshly built helper had not yet been configured. | The Hermes launcher configured its Linux sandbox helper automatically. No `--no-sandbox` workaround was used. |

Verification: the packaged Desktop main screen was visibly displayed. A later
launch through **Applications → Accessories → Hermes** displayed the Mordred
setup screen and **Backend ready**.

## Venice provider setup

Configured the endpoint `https://api.venice.ai/api/v1` and model
`e2ee-deepseek-v4-flash` from the user's local credential file. The API key was
stored through Hermes's provider configuration helpers in its `.env`, with a
`key_env` reference in configuration and mode `0600` on `.env`. Existing config
and environment files were backed up under `~/.hermes/backups/before-venice-*`.
No credential values are included in these notes.

Verification: the models endpoint returned HTTP 200 and included the selected
model; Desktop showed Venice as **Active**. This did not test inference or
prove end-to-end encryption for a chat request. Telegram credentials were not
configured as part of this step.

## TPM helper setup failure

The **Set up TPM 2.0** button displayed:

> Building or probing the TPM helper failed. Install Rust, pkg-config and
> libtss2-dev; ensure this user can access /dev/tpmrm0.

Read-only checks established three concrete prerequisites:

- `cargo` and `rustc` were absent. Running
  `hermes-mordred keyvault enable-tpm` reproduced
  `missing build tool(s): cargo`.
- `pkg-config` was installed, but `libtss2-dev` was absent and
  `pkg-config --modversion tss2-esys` could not resolve the library.
- `/dev/tpmrm0` existed with owner/group `tss:tss` and mode `0660`, but
  `id ubuntu` did not include the `tss` group. Read/write access checks failed.

The packaged helper declares Rust >= 1.85. Ubuntu's unversioned `rustc`/`cargo`
package candidate was 1.75, so simply installing those packages would not meet
the helper's declared minimum.

Remediation performed:

1. Install `libtss2-dev`, `clang`, `libclang-dev`, and `pkg-config` from Ubuntu.
2. Install the stable Rust toolchain using the official rustup installer with
   the minimal profile.
3. Add `ubuntu` to `tss`, preserving existing groups.
4. Build the packaged helper in a new SSH session with the updated groups.
5. Load `$HOME/.cargo/env` from this test machine's `~/.vnc/xstartup`, then
   restart `manual-desktop.service` to refresh the GUI session's groups and
   reopen Hermes through its Applications menu. The startup script was backed
   up as `~/.vnc/xstartup.before-rust`.

Verified results:

- Rust/Cargo 1.99.0 installed; `pkg-config --modversion tss2-esys` returned 4.0.1.
- The new session included `tss`; `/dev/tpmrm0` read/write checks passed.
- `hermes-mordred keyvault enable-tpm` exited 0 after a 2m 48s release build,
  reporting “TPM 2.0 helper installed and hardware probe succeeded.”
- A separate `{"cmd":"probe"}` request to `~/.local/bin/mordred-hermes-tpmkey`
  returned `{"ok":true}`.
- After the session restart, Desktop displayed **✓ TPM 2.0** and **Backend
  ready**. The running Hermes processes included group 104 (`tss`). Memory
  encryption, question-model setup, and Telegram login remain separate steps;
  they were not activated during this repair.

No TPM reset, key deletion, software-key fallback, or world-write device
permission change has been performed. Logs remain on the test host as
`~/tpm-prerequisites-install.log`, `~/tpm-rust-install.log`, and
`~/tpm-helper-build.log`.

## Landing page troubleshooting draft

Intended for a future Linux troubleshooting section; not yet published to the
landing page. The recovery above was verified on the test machine. These
commands target Ubuntu 24.04; package names can differ on other Linux
distributions.

### “Building or probing the TPM helper failed”

Mordred needs a Rust compiler, TPM development libraries, and permission to
access a real TPM 2.0 device. This error can mean a build dependency is missing
or the current desktop session cannot access the device.

1. Install the native build dependencies:

   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential pkg-config libtss2-dev clang libclang-dev
   ```

2. Install Rust using the official installer, then load its environment:

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/mordred-rustup-init.sh
   sh /tmp/mordred-rustup-init.sh -y --profile minimal
   . "$HOME/.cargo/env"
   rustc --version
   cargo --version
   ```

   This helper requires Rust 1.85 or newer. Ubuntu 24.04's unversioned Rust
   packages may be too old; check the version rather than assuming any Cargo
   installation is sufficient.

3. Inspect the TPM device and current group membership:

   ```sh
   ls -l /dev/tpmrm0
   id
   ```

   If the device is owned by group `tss` and your user is not a member:

   ```sh
   sudo usermod -aG tss "$(id -un)"
   ```

   **Sign out of the Linux desktop session and sign back in.** Disconnecting
   and reconnecting a VNC viewer alone does not refresh the remote session's
   groups. Existing terminals and Desktop processes keep their old groups.

4. In a new terminal, check access, then build and probe the helper:

   ```sh
   . "$HOME/.cargo/env"
   test -r /dev/tpmrm0 && test -w /dev/tpmrm0 && echo 'TPM device access OK'
   hermes-mordred keyvault enable-tpm
   ```

   The success message must say the hardware probe succeeded. Reopen Hermes
   Desktop and check the Mordred setup status.

If `/dev/tpmrm0` is absent, this procedure does not create a TPM. Check the
machine or VM's TPM support and configuration. Linux KeyVault requires a
working TPM; it does not fall back to a software key. Do not solve access
errors by making the TPM device world-writable.

### Desktop installation reports missing `make` or `libasound.so.2`

For `node-gyp` reporting missing `make`:

```sh
sudo apt-get install -y build-essential pkg-config
hermes desktop --build-only
```

For `libasound.so.2 => not found` on Ubuntu 24.04:

```sh
sudo apt-get install -y libasound2t64
hermes desktop --skip-build
```

Successful compilation alone is not the final check: confirm the Desktop
window opens and reaches its main screen.
