# Mordred.pkg — the one-step Mac installer

How the package is put together, how to build and check it, and how to try the
installer without touching a real install. For what the person installing sees,
see [`docs/user/QUICKSTART.md`](../../docs/user/QUICKSTART.md).

## How it works

```
Mordred.pkg
├── Distribution            distribution.xml: one choice, Apple silicon, macOS 14+,
│                           no destination step (rootVolumeOnly)
├── Resources/<lang>.lproj  welcome.html and conclusion.html in 25 languages
└── Mordred-core.pkg
    ├── Payload             this checkout → /Library/Application Support/Mordred/installer/source
    └── Scripts/postinstall
```

1. Installer.app copies the payload, a copy of this checkout without `tests/`
   and `docs/`, to `/Library/Application Support/Mordred/installer/source`.
   macOS asks for the administrator's approval here; that is the only prompt
   that is not Touch ID.
2. `postinstall` runs as root. It finds the user logged in at the screen,
   copies the source to a temporary folder that user owns, and runs
   `scripts/install-standalone.sh --from-source <copy> --dialogs` **as that user,
   inside their login session** (`launchctl asuser`). That is why the Touch ID
   prompts and the installer's own dialogs show up on their screen.
3. `install-standalone.sh` does the actual install into `~/.mordred-hermes`:
   - Hermes Agent at a pinned commit;
   - hermes-mordred from the copied source;
   - the Secure Enclave helper, built on this Mac with Swift;
   - the two commands in `~/.local/bin`;
   - the Bonsai runtime and models;
   - the setup (keys and encryption);
   - the login agents;
   - the browsers' native messaging host.

   Its log is `~/Library/Logs/Mordred/install.log`. The installer's exit status
   is the package's: if the installer fails, Installer.app reports the failure.

Running the package again is the way to recover from an interrupted or failed
install: what is already installed is reused, not installed twice. Half-made keys (the keyvault's `meta.json` with neither a vault
nor a backup file) are started over. Leftover processes of the home can be
stopped from a dialog. Every error dialog has **Show Log**.

### What the Mac needs at install time

- Apple silicon and macOS 14 or later (`distribution.xml`, `check_host`).
- Apple's Command Line Tools, for `git` and for building the Secure Enclave
  helper. Without them, the installer opens Apple's own install window and asks
  the user to open Mordred.pkg again afterwards.
- A network connection to:
  - GitHub (the Hermes Agent installer at `HERMES_AGENT_COMMIT`);
  - the Python package index (Hermes's and Bonsai's packages, through `uv`);
  - Hugging Face (the models, unless `~/models/bonsai/models` already holds
    the pinned revisions).

### Pinned versions

These are at the top of `scripts/install-standalone.sh`. Change them only
together with a run of the installer:

| What | Where |
| --- | --- |
| Hermes Agent commit | `HERMES_AGENT_COMMIT` |
| Small / large Bonsai model and revision | `SMALL_MODEL_*`, `LARGE_MODEL_*` |
| Bonsai server's Python packages | `scripts/bonsai-runtime-macos.txt` |
| Ports (extension 47711, small model 47712, large model 47713) | `EXTENSION_PORT`, `SMALL_PORT`, `LARGE_PORT` |

A default port that another program already uses is replaced by a free one in
47714–47799. The extension finds the server's port through the native host
(`mordred/extension-endpoint.json`), so nobody types it.

## Build

```bash
packaging/macos/build-pkg.sh              # → dist/Mordred.pkg
packaging/macos/build-pkg.sh /path/out.pkg
```

- The version is `__version__` in `src/mordred_hermes/__about__.py`.
- **The payload is the working tree, not a commit.** It is every tracked file
  plus every untracked file that `.gitignore` does not exclude
  (`git ls-files -co --exclude-standard`). Edits that are not committed go into
  the package as they are. Build from a clean checkout (`git status` empty) for
  anything you hand to someone.
- It uses `pkgbuild` and `productbuild` (in `/usr/bin`) and `rsync`.
- The package is unsigned unless `MORDRED_PKG_SIGN` names a signing identity
  (see [Signing](#signing-and-notarization)).

## Check a built package

```bash
pkgutil --check-signature dist/Mordred.pkg    # "no signature" until it is signed
spctl -a -vv -t install dist/Mordred.pkg      # Gatekeeper: "rejected" while unsigned
pkgutil --expand dist/Mordred.pkg /tmp/mordred-pkg-expanded
ls /tmp/mordred-pkg-expanded/Resources        # one <lang>.lproj per language
(cd /tmp/mordred-pkg-expanded/Mordred-core.pkg && gunzip -dc < Payload | cpio -it | grep -v '/\._' | less)
```

The payload listing also shows a `._name` entry next to most files. These are
the files' extended attributes (`com.apple.provenance`), which `pkgbuild`
stores that way. Installer.app turns them back into attributes, so none of them
are left in the installed `source` folder.

## Try the installer without touching a real install

Run the installer script straight from the checkout, into a scratch folder:

```bash
scratch="$(mktemp -d)"
scripts/install-standalone.sh --from-source . \
  --home "$scratch/home" --bin-dir "$scratch/bin" \
  --backup-file "$scratch/backup.mrkv" \
  --no-services
```

- **`--no-services` matters.** The login agents are named per home, but the
  browsers' native messaging host (`com.mordred.hermes`) is one file per
  browser. Without `--no-services`, a scratch run would point Brave and Chrome
  at the scratch home instead of the real one.
- Add `--unattended-keys` for keys that never ask for Touch ID (automated
  runs). Without it, the setup asks for Touch ID twice, as the package does.
- Add `--dialogs` to see the same macOS dialogs as the package.
- Add `--model-dir DIR` to reuse models that were downloaded earlier.
- `--help` lists every option. `--home ~/.hermes` is refused.

The installer's own tests run without any of this:

```bash
.venv/bin/python -m pytest -q tests/test_install_standalone.py tests/test_i18n_mac.py
```

## Development builds of the extension

The native host answers only the extension IDs in `mordred/extension-ids`.
The Chrome Web Store ID is always included; an unpacked development build has
another ID. Add it at install time with `--extension-id ID` (repeatable), or
afterwards:

```bash
HERMES_HOME=~/.mordred-hermes hermes-mordred extension browsers install --extension-id ID
```

This keeps the IDs already accepted, adds the new one, and rewrites the native
host for each installed browser (Brave, Chrome). An unpacked build's ID is shown
on the browser's extensions page.

## Languages

The installer's dialogs, its welcome and conclusion pages, and the Touch ID
reasons follow the Mac's preferred language (`defaults read -g
AppleLanguages`). They use the extension's 25 languages, and anything else
shows English.

| Text | Files |
| --- | --- |
| Dialogs and notifications (`msg KEY "English"` in `install-standalone.sh`), Touch ID reasons | `src/mordred_hermes/i18n/strings/<lang>.json` |
| Welcome and conclusion pages | `resources/<lang>.lproj/{welcome,conclusion}.html` |

- The English text lives in the code that shows it, so a missing file or key
  still shows English.
- To add a text:
  - write the English text in the code;
  - add the key, with that same text, to `en.json`;
  - add the key to the other 24 files.
- `tests/test_i18n_mac.py` checks two things:
  - every language has the same keys and the same `{placeholders}`;
  - the English in the code matches `en.json`.

## Signing and notarization

> Not exercised yet: the package has only been built unsigned.

An unsigned package is rejected by Gatekeeper. The person installing has to
allow it once in **System Settings → Privacy & Security → Open Anyway**. To hand
the package to people, Apple's usual path is:

1. A **Developer ID Installer** certificate (Apple Developer Program) in the
   login keychain.
2. `MORDRED_PKG_SIGN="Developer ID Installer: NAME (TEAMID)" packaging/macos/build-pkg.sh`
3. `xcrun notarytool submit dist/Mordred.pkg --keychain-profile PROFILE --wait`
4. `xcrun stapler staple dist/Mordred.pkg`
5. `spctl -a -vv -t install dist/Mordred.pkg` should then say `accepted`.

The Secure Enclave helper is built on the user's Mac, which is why the Command
Line Tools are needed. A helper built and signed ahead of time, shipped in the
payload, would remove that need.

The keychain records of an existing vault trust only the helper that wrote
them. That is why `install_helper` keeps an existing helper when a vault
exists: a different helper would make macOS ask for the login password.
