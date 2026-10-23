// Mordred setup for Hermes Desktop.
//
// Secrets typed here (Telegram api_hash, login code, 2FA password, a Venice
// key) go from these masked inputs straight to Mordred's local API through
// ctx.rest(): never into the chat, the model, the agent's tools, plugin
// storage, notifications or logs. Inputs are cleared after each submit.
//
// The macOS and Linux page is one column: an overview card, then four groups
// (Protect, Connect, Ask Hermes, Maintenance) of steps whose state comes only
// from status fields (stepStates / overviewRows). The layout is chosen from
// `platform` and `hardware_kind`, never from English text; Windows keeps
// WindowsSetup. Only the names below may be imported from the SDK: a named
// export the installed Desktop lacks fails the module link and the whole page.
import {
  host,
  Button,
  Checkbox,
  Input,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  PALETTE_AREA,
} from '@hermes/plugin-sdk'
import { jsx, jsxs, Fragment } from 'react/jsx-runtime'
import { useCallback, useEffect, useRef, useState } from 'react'

let rest = null
// The SDK checkbox's default border is a pale theme colour that disappears on
// a white card; draw it in the text colour (CanvasText follows light/dark).
const CHECKBOX_STYLE = { borderColor: 'CanvasText', borderWidth: 1.5, borderStyle: 'solid' }
// Colours come only from currentColor, CanvasText and the Desktop theme
// variables, so light and dark both work; a hex value is only a var() fallback.
const DESTRUCTIVE = 'var(--destructive, #b91c1c)'
const ACCENT = 'var(--ui-accent, currentColor)'
const STROKE = 'var(--ui-stroke-secondary, var(--border, #333))'
const MUTED_TEXT = 'var(--ui-text-secondary, currentColor)'
// Pages listening for background-job events (Enclave build, import).
const jobListeners = new Set()
// The page reads the version 4 status (databases, imports, mail). The start-up
// notice only needs installed / missing / unreachable, so it keeps the lighter
// version 3 answer and opens no store at every Desktop start. The backend
// compares versions with >=, so an older Mordred answers 4 like 3.
const STATUS_PATH = '/status?client_version=4'
const STARTUP_STATUS_PATH = '/status?client_version=3'

const MESSAGES = {
  telegram_session_revoked:
    'Telegram ended this login (for example it was terminated in Telegram → Settings → Devices, or Telegram signed it out). Log in again in the Telegram step — your imported messages are kept.',
  telegram_platform_unsupported: 'Private Telegram requires macOS Secure Enclave or Linux TPM 2.0, with memory encryption enabled. Update both Mordred and its Desktop assets if platform metadata is missing.',
  memory_encryption_required: 'Turn on memory encryption first (the memory encryption step).',
  memory_encryption_failed: 'Memory encryption could not be turned on. Check hardware access and the Hermes runtime, then try again.',
  telegram_already_logged_in: 'Telegram is already connected.',
  invalid_api_credentials: 'api_id must be a number and api_hash 32 hex characters (my.telegram.org → API development tools).',
  invalid_phone: 'Enter the phone number in international format, e.g. +819012345678.',
  login_code_invalid: 'That login code is not correct.',
  login_code_expired: 'The login code expired. Start again.',
  uninstall_confirm_mismatch: 'Type delete my data exactly to also delete your data.',
  uninstall_failed: 'Uninstall stopped before removing anything it could not restore. See the report below.',
  login_password_invalid: 'That Telegram two-step verification password is not correct.',
  login_flow_expired: 'This login attempt expired. Start again.',
  telegram_rate_limited: 'Telegram asked to wait before trying again.',
  hermes_venice_key_missing: 'No Venice key is set in Hermes. Enter one below.',
  local_endpoint_invalid: 'Use http://127.0.0.1:<port>/… (this host only).',
  tee_unavailable: 'The hardware key helper is unavailable (the helper step).',
  tee_auth_cancelled: 'Touch ID was cancelled.',
  tpm_build_failed: 'Building or probing the TPM helper failed. Install Rust, pkg-config and libtss2-dev; ensure this user can access /dev/tpmrm0.',
  enclave_build_failed: 'Building the Secure Enclave helper failed. Install the Xcode command-line tools and retry.',
  sync_in_progress: 'A Telegram import or a mail fetch is already running.',
  telegram_not_configured: 'Set the question model first.',
  hermes_model_not_private: 'Hermes itself must use a Venice private model or a local model first (the Hermes chat model step).',
  // Package updates (`hermes-mordred update` behind the Update Mordred button).
  update_check_failed: 'PyPI could not be asked for Mordred releases right now. Check the network path and try again.',
  update_failed: 'The update stopped and the previous version was kept or reinstalled. See the step output below; fix the cause and try again.',
  update_rollback_failed: 'The update stopped AND reinstalling the previous version failed. Mordred may not load until you reinstall it from a terminal with the installer.',
  update_hermes_too_old: 'That Mordred release needs a newer Hermes than the one installed (the previous Mordred was restored). Update Hermes first.',
  update_unsupported_windows: 'In-place updates are not supported on Windows. Rerun the Windows installer, keeping the existing Hermes home and custody keys, then restart Hermes.',
  update_source_install: 'Mordred was installed from a local checkout. Update it with scripts/install.sh --from-source <checkout>.',
  update_no_uv: 'uv was not found on PATH or under the Hermes home. Install uv, then try again.',
  update_not_a_venv: 'Hermes is not running inside a virtual environment, so Mordred refuses to modify it.',
  update_foreign_source: 'The running Mordred was not loaded from the installed package, so updating the package would not change what runs. Remove that copy, restart Hermes, then update.',
  update_bad_version: 'That is not a valid release version.',
  update_refused: 'Mordred cannot update itself here. Rerun the installer from a terminal.',
  update_not_newer: 'That release is not newer than the one installed.',
  update_busy: 'An uninstall is running. Wait for it to finish.',
  uninstall_busy: 'A Mordred update is running. Wait for it to finish, then restart Hermes.',
  update_job_lost: 'The backend no longer reports the update job (it probably restarted). Press Check for updates to see what is installed now; do not start a second update until then.',
  update_job_timeout: 'The update is taking longer than expected. Leave it running and press Check for updates later; do not start a second update until then.',
  job_not_found: 'The backend no longer reports that job (it probably restarted). Check the current state before retrying.',
  // Windows (machine-bound CNG custody, no per-use presence).
  telegram_not_enrolled: 'Telegram custody is not enrolled on this Windows profile. Follow the custody step or recovery remedy below.',
  telegram_custody_unavailable: 'Telegram custody could not be checked on this Windows profile.',
  presence_acknowledgement_required: 'First confirm that Windows asks for no per-use approval (Telegram custody step).',
  presence_unsupported: 'Windows has no per-use presence prompt. Confirm the machine-bound key first.',
  custody_unsafe: 'A Mordred custody file or folder is not private to this Windows account. Mordred never repairs it: fix its ownership or ACL by hand.',
  custody_uncertain: 'Custody is busy or has an unresolved journal. Let other Hermes/Mordred processes finish, then retry.',
  custody_broken: 'Custody evidence does not match this profile and Windows account (a copied or restored profile). It is preserved, never adopted.',
  memory_encryption_refused: 'Memory encryption was not turned on. Nothing was sealed.',
  memory_disable_refused: 'Memory encryption was not turned off.',
  memory_operation_in_progress: 'Another vault or memory encryption change is running. Try again when it finishes.',
  custody_busy: 'Memory custody is busy (another Hermes or Mordred process is using it). Try again in a moment.',
  forget_confirm_mismatch: 'Type delete my data exactly to delete the Telegram data.',
  secrets_corrupt: 'The sealed Telegram credentials cannot be opened with this profile’s key.',
  store_path_unsafe: 'A Telegram archive file or folder is not private to this account. Nothing was changed.',
  store_unavailable: 'The Telegram archive is unavailable right now.',
  store_write_uncertain: 'A Telegram archive write may not have completed. Check the archive before retrying.',
  store_missing: 'A Telegram archive file is missing.',
  store_io: 'The Telegram archive could not be read or written.',
  store_busy: 'The Telegram archive is busy. Try again shortly.',
  store_undecryptable: 'The Telegram archive cannot be decrypted with the current credentials.',
  forget_unsupported: 'Deleting Telegram data this way is not supported on this platform.',
  // Extension pairing and local storage (shared wire codes).
  storage_unavailable: 'Mordred’s local storage is unsafe or locked; nothing was changed.',
  storage_uncertain: 'A Mordred storage write may not have completed; check the pairing before retrying.',
  storage_error: 'Mordred’s local storage refused the operation.',
  attestation_key_missing: 'The pairing identity key is missing; remove the pairing, then pair again.',
  // The page needs a newer Mordred (its status lacks the version 4 keys).
  mordred_update_required: 'Update Mordred to use this. The running Mordred does not report this step yet; the update is under Maintenance.',
  // Database encryption, the import store and mail (closed sets of the version 4 API).
  databases_unsupported: 'Database encryption needs macOS with SQLCipher. Nothing was changed.',
  databases_key_missing: 'The database key is not available yet. Finish the memory step and restart Hermes Desktop first.',
  databases_failed: 'Scheduling the database encryption failed. The step shows the current state again; try again, or run hermes-mordred databases status in Terminal.',
  databases_busy: 'A database conversion is already running. Try again when it finishes.',
  // Step 1.3 attention states (the second design revision's table).
  plaintext_in_armed_home: 'A plaintext database is in a Hermes home whose databases are already encrypted (a new or restored file). Quit Hermes Desktop, then run hermes-mordred databases encrypt in Terminal.',
  stale_pending: 'The databases are already encrypted, but an older conversion request is still pending. Run hermes-mordred databases status in Terminal.',
  decrypt_pending: 'Database decryption is pending: the databases become plain files again at the next start. Run hermes-mordred databases status in Terminal.',
  journal: 'A database conversion was interrupted and left its journal. Run hermes-mordred databases status in Terminal.',
  vault_anchor_stale: 'A Mordred vault was removed from this Mac earlier, but its Keychain anchor remains, so a new vault cannot be created.',
  mail_already_configured: 'A mailbox is already set up. Remove it below first.',
  mail_setup_flow_expired: 'This mail setup expired. Start again; nothing was stored.',
  mail_setup_busy: 'Another mail setup is waiting for its folder choice (in another Hermes Desktop window). Finish or cancel it there, or wait up to 10 minutes. Nothing was stored.',
  mail_setup_stale: 'A mailbox was set up or removed elsewhere while this setup waited. Start again; this setup stored nothing.',
  mail_setup_cancelled: 'This mailbox setup was cancelled before anything was stored.',
  touch_id_policy_mismatch: 'The mailbox key’s Touch ID setting differs from your choice and could not be replaced. Remove the mailbox, then set it up again. Nothing was stored.',
  invalid_selection: 'Choose one of the listed folders.',
  account_mismatch: 'The sealed mailbox has a different account label. Leave the label empty, or enter the mailbox’s own label.',
  mail_fetch_timeout: 'The fetch is taking longer than expected. It continues in the background; check this step again later.',
  mail_fetch_busy: 'A mail fetch is already running. Wait for it to finish.',
  mail_not_configured: 'No mailbox is set up yet.',
  invalid_address: 'Enter a mail address such as name@example.com.',
  invalid_host: 'Enter the IMAP server name, for example imap.gmail.com.',
  invalid_account: 'The account label must start with a lowercase letter and use only lowercase letters, digits and underscores (at most 32 characters).',
  invalid_password: 'The app password must be 1 to 256 printable characters.',
  too_many_addresses: 'List at most 20 other addresses.',
  imap_auth_failed: 'The login was refused. Nothing was stored.',
  imap_unreachable: 'The server could not be reached (network, Tor or VPN path). Nothing was stored.',
  imap_protocol: 'The mail server answered in a way Mordred does not accept. Try again later.',
  imap_command_refused: 'The mail server refused a read-only command. Try again later.',
  routing_unavailable: 'Mordred’s network route (Tor or VPN) is not ready, so the mail server was not contacted.',
  egress_unsupported: 'Mordred’s network policy cannot reach the mail server safely from here, so it was not contacted.',
  import_store_unavailable: 'Mordred’s encrypted store is not available right now.',
  not_armed: 'Mordred’s store opens only after the Hermes databases are encrypted (step 1.3).',
  conversion_pending: 'The Hermes databases are converted at the next start. Restart Hermes Desktop to finish step 1.3.',
  unprotected_process: 'Hermes started before its databases were encrypted. Restart Hermes Desktop.',
  no_key: 'The database key is not available. Finish the memory step and restart Hermes Desktop.',
  plaintext_store: 'Mordred’s store can be read without the database key, so Mordred does not use it.',
  busy: 'Mordred’s store is busy. Try again shortly.',
  store_uninitialised: 'Mordred’s store is created by the first Telegram import or mail fetch.',
  profile_mismatch: 'Mordred’s store belongs to another Hermes profile, so Mordred does not open it here.',
  schema_newer: 'Mordred’s store was written by a newer Mordred. Update Mordred (Maintenance).',
  unkeyed_connection: 'Mordred’s store was not opened with the database key. Restart Hermes Desktop; if this stays, run hermes-mordred databases status in Terminal.',
  disk_full: 'The disk is full. Free some space, then try again.',
  run_not_open: 'Mordred’s store refused the write because no import run was open. Try again.',
  conflict: 'Mordred’s store refused the write: the conversation is already stored for another account. Run hermes-mordred status in Terminal.',
  credentials_changed: 'The mailbox was set up again while it was being removed, so nothing was deleted. Try again.',
  credentials_left: 'Sealed mailbox credentials are still on this Mac. Remove the mailbox to delete them.',
  key_left: 'The mailbox key in the Secure Enclave could not be deleted. Remove the mailbox again to finish.',
  account_unknown: 'The label of the removed mailbox could not be read, so its fetched mail and cursors were kept. Remove them in Terminal with hermes-mordred mail forget --account LABEL.',
  fetch_failed: 'The mail fetch failed. Try again later.',
  run_failed: 'The fetch stopped because Mordred’s store refused a write; nothing incomplete was kept. Try again.',
  unsupported_platform: 'This is available only on macOS.',
  invalid_request: 'The request was not valid.',
  // Transport failures (call() never shows the response itself).
  transport_error: 'Mordred’s local API could not be reached. Check that Hermes is running, then try again.',
  backend_unreachable: 'Mordred’s local API did not answer: Mordred may be turned off or Hermes may be restarting. Check the Mordred page again.',
  invalid_response: 'Mordred’s local API gave an answer this page does not understand. Check the Mordred page again or run hermes-mordred status in Terminal.',
  invalid_body: 'The request was not valid.',
  // The vault (step 1.2a) and memory (step 1.2b) ceremonies of the version 4 API.
  vault_required: 'Create the vault first (step 1.2a).',
  vault_exists: 'The vault already exists, so no new recovery passphrase was made: the one shown when it was created stays the only one.',
  vault_flow_expired: 'This recovery passphrase expired before the vault was created (or Hermes restarted). Nothing was created. Start again for a new passphrase.',
  passphrase_reused: '.env was moved into the vault that already existed on this Mac. Its recovery passphrase is the one shown when it was created; the words shown here were not used.',
  env_optout: '.env encryption was turned off on purpose earlier (a plaintext .env was restored), so this page does not turn it back on. Run hermes-mordred encryption enable env in Terminal to turn it on again.',
  env_required: 'Hermes does not read .env from the vault yet. Create the vault (step 1.2a) and restart Hermes Desktop first.',
  // Mail wording for codes whose shared text names Telegram (see explainMail).
  mail_sync_in_progress: 'A mail fetch or import is running (from Hermes or Terminal). Try again when it finishes.',
  mail_forget_confirm_mismatch: 'Type delete my data exactly to also delete the fetched mail.',
  mail_secrets_corrupt: 'The sealed mailbox credentials cannot be opened with this Mac’s key. Remove the mailbox and set it up again.',
  mail_store_path_unsafe: 'A Mordred mail file or folder is not private to this account. Nothing was changed.',
  // A fetch that stopped (the setup wording says "Nothing was stored"; see fetchError).
  fetch_imap_auth_failed: 'The fetch stopped: the mail server refused the login. If you changed or revoked the app password, remove the mailbox and set it up again with a new one.',
  fetch_imap_unreachable: 'The fetch stopped: the mail server could not be reached (network, Tor or VPN path). Fetch again later.',
}

// `imap_auth_failed` refined by the server's response code (never its text).
const IMAP_HINTS = {
  authentication_failed: 'The server rejected the address or the app password. Check that the app password was created while signed in to the same Google account as this address, that the address is the account’s primary sign-in address (not an alias or a “send as” address), and that 2-Step Verification is on. A Workspace administrator can turn off IMAP or app passwords for the organisation, and Advanced Protection disables app passwords. Nothing was stored.',
  server_alert: 'The server refused the login with an alert. For Gmail this usually means an app password is required (not the account password) or that Google wants a sign-in in the browser first. Open https://myaccount.google.com/apppasswords, create a new app password and try again. Nothing was stored.',
  login_disabled: 'This server does not allow password login over IMAP. Nothing was stored.',
  gmail_app_password_length: 'A Gmail app password is exactly 16 letters. What you pasted has a different length, so it is probably the account password or incomplete. Nothing was sent to the server.',
}

// The stale vault anchor when the API sends no command to run (by `anchor_store`). The
// command comes only as `remedy`, when deleting a legacy Keychain anchor is known to be safe.
const VAULT_ANCHOR_NOTES = {
  helper: 'The anchor from an earlier installation is held by the hardware helper. It needs the Mordred release with the keyvault anchor reset; until then the vault cannot be created here.',
  other: 'An anchor remains; the keyvault reset of a later Mordred release handles it.',
}

// Why a step cannot run yet: a code computed by stepStates from status fields
// (never free text from the API) and the step that lifts it.
const BLOCKERS = {
  needs_hermes_model: { step: 'hermes_model', text: 'Hermes must chat with a Venice private model or a local model first.' },
  needs_enclave: { step: 'enclave', text: 'Set up the hardware key helper first.' },
  needs_vault: { step: 'vault', text: 'Create the vault and restart Hermes Desktop first, so Hermes reads .env from the vault.' },
  needs_memory: { step: 'memory', text: 'Turn on memory encryption first.' },
  needs_databases: { step: 'databases', text: 'Encrypt the Hermes databases first.' },
  needs_restart: { step: 'databases', text: 'Restart Hermes Desktop to finish step 1.3.' },
  needs_login: { step: 'telegram', text: 'Connect Telegram first.' },
  needs_question_model: { step: 'question_model', text: 'Set the question model first.' },
}

// macOS/Linux steps in reading order. Linux has no 1.2a, 1.3 and 2.5, and its memory
// step is 1.2 (see stepNumbers).
const STEP_NUMBERS = {
  enclave: '1.1',
  vault: '1.2a',
  memory: '1.2b',
  databases: '1.3',
  hermes_model: '2.1',
  question_model: '2.2',
  telegram: '2.3',
  telegram_import: '2.4',
  mail: '2.5',
}
// Step states: a decorative glyph and the state as text after the title (the
// text of `todo` is read by screen readers only).
const STATE_BADGES = {
  done: { glyph: '✓', text: 'Done' },
  next: { glyph: '→', text: 'Next' },
  todo: { glyph: '', text: 'To do' },
  blocked: { glyph: '⏸', text: 'Blocked' },
  running: { glyph: '⟳', text: 'Running' },
  attention: { glyph: '!', text: 'Needs attention' },
}
const VISUALLY_HIDDEN = { position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap' }
// Overview dots.
const DOTS = {
  done: { glyph: '●', color: 'currentColor', label: 'done' },
  partial: { glyph: '◐', color: ACCENT, label: 'partly done' },
  not_started: { glyph: '○', color: 'currentColor', label: 'not started' },
  attention: { glyph: '!', color: DESTRUCTIVE, label: 'needs attention' },
}
const GROUPS = {
  protect: { n: 1, title: 'Protect this Mac', linux: 'Protect this host' },
  connect: { n: 2, title: 'Connect' },
  ask: { n: 3, title: 'Ask Hermes' },
  maintenance: { n: 4, title: 'Maintenance' },
}
// Import-store gate codes (`status.imports.code`) for the Telegram overview row.
const STORE_GATES = {
  not_armed: 'counts after step 1.3',
  conversion_pending: 'counts after a restart',
  unprotected_process: 'counts after a restart',
  no_key: 'store key unavailable',
  plaintext_store: 'store not encrypted',
  store_unavailable: 'store unavailable',
  busy: 'store busy',
  store_uninitialised: 'nothing in Mordred’s store yet',
  profile_mismatch: 'store of another profile',
  schema_newer: 'store from a newer Mordred',
  unkeyed_connection: 'store key not applied',
  unsupported_platform: 'store not available here',
  disk_full: 'disk full',
}
// `databases.databases[].state` (discovery without the key) as the step 1.3 table says it.
const DATABASE_STATES = {
  plaintext: 'will encrypt',
  unreadable: 'encrypted or unreadable',
}
const DATABASES_RESTART = {
  scheduled: 'Scheduled. Hermes Desktop keeps its databases open, so they are encrypted the next time Hermes starts, before it opens them. Restart now:',
  armed: 'Database encryption is on, but this Hermes Desktop started before it. Restart Hermes Desktop to finish:',
}
// `/mail/fetch` results: the keys of FetchResult.as_dict() in display order, with labels.
// The result block shows only these, and only the non-zero, true or non-null ones.
const RESULT_FIELDS = [
  ['inserted', 'inserted'],
  ['duplicates', 'duplicates'],
  ['revised', 'revised'],
  ['conflicts', 'conflicts'],
  ['fetched', 'fetched'],
  ['skipped', 'skipped'],
  ['skipped_oversize', 'skipped (too large)'],
  ['excluded_history', 'older, not fetched'],
  ['merge_skipped', 'not merged into a thread'],
  ['mailboxes', 'mailboxes'],
  ['batches', 'batches'],
  ['gmail', 'Gmail'],
  ['cursor_reset', 'cursor reset'],
  ['dry_run', 'dry run'],
  ['partial', 'partial'],
  ['partial_reason', 'stopped by'],
  ['abandoned', 'abandoned'],
  ['lock_retained', 'lock kept by the stopped fetch'],
  ['error', 'error'],
]
const PARTIAL_REASON_LABELS = {
  time_budget: 'the time limit',
  max_messages: 'the message limit',
  max_bytes: 'the size limit',
  cancelled: 'a cancel',
  error: 'an error',
}
const DEFAULT_MAIL_ACCOUNT = 'mail'
const GMAIL_HOST = 'imap.gmail.com'
const MAX_FETCH = 2000
// The "No sent folder" choice (an IMAP folder id is never empty).
const NO_SENT_FOLDER = ''
// Finish answers after which the server's flow may still wait (any other answer ends it).
const KEEP_FLOW = new Set(['invalid_selection', 'sync_in_progress', 'tee_auth_cancelled'])
const TAGLINES = {
  macos: 'Private Telegram and mail for Hermes, encrypted on this Mac.',
  linux: 'Private, read-only Telegram for Hermes, encrypted on this host.',
  other: 'Private, read-only Telegram for Hermes.',
}
// "Why this step?" copy.
const WHY = {
  enclave: 'Mordred seals your Telegram login, your mail app password and the encryption keys with a key that never leaves this Mac’s Secure Enclave. The helper is a small signed program that talks to it.',
  enclave_linux: 'Mordred seals your Telegram login and the memory key with a key bound to this host’s TPM 2.0. The helper is a small program that talks to it.',
  vault: 'Hermes keeps its API keys in .env. The vault holds it encrypted with a key that never leaves this Mac’s Secure Enclave, and Hermes Desktop reads it from there when it starts. The recovery passphrase is the only way back in if this Mac or its key is lost.',
  memory: 'Telegram and mail history can be connected only when everything Hermes remembers is encrypted: what Hermes learns from your history ends up in its memory files, so they must not stay readable on disk.',
  databases: 'Hermes stores your chats (state.db), projects and cron history in SQLite files. Mordred’s own store for imported Telegram and mail history (mordred.db) only opens when these files are encrypted too, with the same key as the memory files. Encryption happens on disk; Hermes keeps working as before.',
  hermes_model: 'Everything Hermes reads goes to its chat model. Telegram and mail history are offered to Hermes only when that model is a Venice private model (no retention) or a model running on this Mac.',
  hermes_model_linux: 'Everything Hermes reads goes to its chat model. Telegram history is offered to Hermes only when that model is a Venice private model (no retention) or a model running on this host.',
  question_model: 'When Hermes asks Mordred about your Telegram history, Mordred prepares the answer with this model, and the imported text is sent nowhere else. Only two kinds are accepted: a Venice private model (no retention) or a model on this computer, reached directly and never redirected.',
  telegram: 'Telegram requires every third-party client to register an app. The app is yours; its api_id and api_hash identify it, not you. They are sealed with your login.',
  telegram_import: 'Mordred copies your messages into its encrypted store on this computer, so Hermes can search them without asking Telegram each time. Pinned chats come first; large groups and archived chats are skipped; nothing is downloaded twice.',
  mail: 'Your address and the app password are sealed by the Secure Enclave on this Mac. Each fetch unseals them, logs in with TLS, reads new mail and logs out: nothing is marked read, moved, deleted or sent. Gmail: Mordred reads All Mail with its labels, so mail you sent is recognised as yours. Other servers: the inbox and the sent folder.',
}

// Windows labels, selected from explicit metadata (codes and names), never by matching text.
const CAPABILITY_LABELS = {
  memory_custody: 'Memory custody',
  native_audit: 'Audit custody',
  telegram_hardware: 'Telegram custody',
  file_vault: 'File vault',
  env_config_workspace_seals: '.env / config / workspace seals',
  recovery: 'Key recovery',
  presence: 'Per-use presence',
  secret_store: 'Secret store',
}
const REASONS = {
  enrolled: 'enrolled',
  'not-enrolled': 'not enrolled yet',
  'custody-unsafe': 'not private to this Windows account (never repaired)',
  'custody-uncertain': 'busy or an unresolved journal',
  'custody-broken': 'does not match this profile and account (preserved, never adopted)',
  'helper-missing': 'CNG helper not installed',
  'helper-uncertain': 'CNG helper location could not be checked',
  'runtime-not-admitted': 'this interpreter is not an installed Hermes environment (the installed runtime is proven when memory encryption is turned on)',
  'runtime-uncertain': 'this interpreter could not be checked (the installed runtime is proven when memory encryption is turned on)',
  'excluded-on-windows': 'not available on Windows',
  'not-ported-on-windows': 'not yet available on Windows',
  unsupported: 'only on native Windows',
  'gateways-unknown': 'the Hermes gateway inventory is unknown (never treated as empty)',
  'gateways-running': 'a Hermes gateway is running',
  gateways: 'a Hermes gateway started or could not be checked',
  'ceremony-refused': 'the custody ceremony refused',
  'lifecycle-partial': 'stopped part-way; every memory file is plaintext or an authenticated seal',
  'interpreter-invalid': 'no validated installed Hermes interpreter',
  'module-outside-environment': 'Hermes imports Mordred from outside its environment',
  'helper-mismatch': 'Hermes used a different CNG helper',
  'proof-stale': 'custody changed while proving the runtime',
  'proof-expired': 'the runtime proof expired',
  'proof-not-issued': 'the runtime proof was not issued',
  'locks-held': 'another Mordred operation holds a lock',
  'custody-not-enrolled': 'memory custody is not enrolled',
  'custody-pending': 'an unresolved custody journal',
  'memory-write-approval-plaintext': 'memory.write_approval is on: writes awaiting approval stay plaintext until applied',
}
const STEP_LABELS = {
  capabilities: 'capabilities',
  gate: 'gateway check',
  ceremony: 'custody ceremony',
  proof: 'installed-runtime proof',
  lifecycle: 'encryption',
}
const HELPER_STATES = {
  present: 'installed',
  unchecked: 'not checked while custody is unavailable',
  validated: 'installed (installer-owned)',
  installed: 'installed (not installer-owned)',
  missing: 'not installed',
  uncertain: 'could not be checked',
}
const MEMORY_STATES = {
  off: 'off',
  enrolled: 'custody key enrolled, memory not encrypted yet',
  on: 'on',
  exposed: 'on, but a plaintext memory file is on disk',
  degraded: 'on, with a problem',
  paused: 'turned off (custody key kept)',
  'disabled-incomplete': 'turned off, but seals or interrupted staging remain (turn it off again to finish)',
  unavailable: 'unavailable',
}

// Every failure the page shows is a fixed sentence chosen by code: never response
// text (a validation error can echo what was typed) and never an unknown code.
const GENERIC_FAILURE = 'The request failed. Check the Mordred page again or run hermes-mordred status in Terminal.'
const CODE_RE = /^[a-z][a-z0-9_]{1,63}$/
const safeCode = (value) => (typeof value === 'string' && CODE_RE.test(value) ? value : null)
const own = (table, key) => typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key)

function explain(code, hint = null) {
  if (code === 'imap_auth_failed' && own(IMAP_HINTS, hint)) return IMAP_HINTS[hint]
  if (own(MESSAGES, code)) return MESSAGES[code]
  if (own(BLOCKERS, code)) return BLOCKERS[code].text
  return GENERIC_FAILURE
}

// Mail routes share some codes with Telegram; prefer the mail wording when one exists.
function explainMail(code, hint = null) {
  return own(MESSAGES, `mail_${code}`) ? MESSAGES[`mail_${code}`] : explain(code, hint)
}

function reason(code) {
  return REASONS[code] || code || 'unknown'
}

class MordredError extends Error {
  constructor(code, info) {
    super(explain(code, info && info.hint))
    this.code = code
    this.info = info || {}
  }
}

// Anything thrown inside a handler becomes a MordredError, so toasts and notes only
// ever carry explain() text.
const asMordredError = (e) => (e instanceof MordredError ? e : new MordredError(null, {}))

// A rejected request keeps only a code: the Mordred code when the answer carries a
// well-formed one, else a fixed transport code. Nothing of the body survives.
function transportCode(err) {
  const body = err ? err.body : undefined
  const fromBody = body && typeof body === 'object' ? safeCode(body.error) : null
  const match = !fromBody && err && typeof err.message === 'string' ? err.message.match(/"error"\s*:\s*"([a-z][a-z0-9_]{1,63})"/) : null
  if (fromBody || match) return fromBody || match[1]
  const status = Number(err && (err.status || err.statusCode || (err.response && err.response.status)))
  if ([404, 502, 503, 504].includes(status)) return 'backend_unreachable'
  if (status || (body !== undefined && body !== null)) return 'invalid_response'
  return 'transport_error'
}

async function call(path, body) {
  let res
  try {
    res = await rest(path, body === undefined ? {} : { method: 'POST', body })
  } catch (err) {
    throw new MordredError(transportCode(err), {})
  }
  if (!res || typeof res !== 'object') throw new MordredError('invalid_response', {})
  if (res.ok === false) {
    const code = safeCode(res.error)
    throw new MordredError(code || 'invalid_response', code ? res : {})
  }
  return res
}

// A command the owner runs in Terminal (the stale vault anchor's remedy), with a copy button.
function CommandLine({ command }) {
  return jsxs(Row, {
    children: [
      jsx('code', { key: 'command', style: { userSelect: 'all', whiteSpace: 'pre-wrap' }, children: command }),
      jsx(Button, {
        key: 'copy',
        variant: 'outline',
        onClick: () => navigator.clipboard && navigator.clipboard.writeText(command),
        children: 'Copy command',
      }),
    ],
  })
}

const asText = (value) => (typeof value === 'string' ? value : null)

// The stale vault anchor under StepFailure: the validated command when the API sends it
// as `remedy` (a legacy Keychain anchor and no vault left), otherwise a note by `anchor_store`.
function AnchorRemedy({ remedy, store }) {
  if (remedy) {
    return jsxs(Fragment, {
      children: [
        jsx('p', { key: 'run', children: 'Run this command in Terminal, then try again:' }),
        jsx(CommandLine, { key: 'command', command: remedy }),
      ],
    })
  }
  return jsx('p', { children: own(VAULT_ANCHOR_NOTES, store) ? VAULT_ANCHOR_NOTES[store] : VAULT_ANCHOR_NOTES.other })
}

// The Windows refusal note. The Windows API composes the refusing step, reason,
// remedy, custody notice and ceremony output from its fixed tables (C11) and the
// Windows page shows them. Only Mordred's own `ok: false` answers carry them: call()
// gives a failed request no info at all, so no response text can arrive here.
function FailureNote({ error }) {
  const info = (error && error.info) || {}
  return jsxs('div', {
    role: 'alert',
    style: { border: `1px solid ${DESTRUCTIVE}`, borderRadius: 8, padding: 10, marginTop: 10 },
    children: [
      jsx('p', { style: { margin: 0 }, children: explain(error && error.code, info.hint) }),
      info.storage_error ? jsx('p', { children: explain(info.storage_error) }) : null,
      info.step ? jsx('p', { children: `Stopped at the ${STEP_LABELS[info.step] || info.step} step: ${reason(info.reason)}.` }) : null,
      asText(info.remedy) ? jsx('p', { children: info.remedy }) : null,
      asText(info.custody_notice) ? jsx('p', { children: `A memory custody key was created and is kept for a retry. ${info.custody_notice}` }) : null,
      asText(info.detail) ? jsx('pre', { style: { whiteSpace: 'pre-wrap', fontSize: 12 }, children: info.detail }) : null,
    ],
  })
}

// The only remedy text the grouped page renders, and only in exactly this form.
const STALE_ANCHOR_REMEDY = /^security delete-generic-password -s mordred-hermes\.vault\.anchor -a mordred-hermes\.vault\.[0-9a-f]{16}$/

// The grouped page's failure note: the code's fixed sentence (an IMAP hint refines
// imap_auth_failed) and, for a stale vault anchor, the validated remedy command.
// Nothing else from a response is shown.
function StepFailure({ error, noteRef = null }) {
  const code = error && error.code
  const info = (error && error.info) || {}
  const remedy = code === 'vault_anchor_stale' && STALE_ANCHOR_REMEDY.test(asText(info.remedy) || '') ? info.remedy : null
  return jsxs('div', {
    role: 'alert',
    ref: noteRef,
    tabIndex: -1,
    style: { border: `1px solid ${DESTRUCTIVE}`, borderRadius: 8, padding: 10, marginTop: 10 },
    children: [
      jsx('p', { style: { margin: 0 }, children: explain(code, info.hint) }),
      code === 'vault_anchor_stale' ? jsx(AnchorRemedy, { remedy, store: info.anchor_store }) : null,
    ],
  })
}

// -- page framework: steps, groups, overview -------------------------------------------

const stepAnchor = (key) => `mordred-step-${key}`
const groupAnchor = (key) => `mordred-group-${key}`

// Scroll to a step or group heading and give it keyboard focus (headings carry tabIndex -1).
function focusTarget(id) {
  const target = typeof document !== 'undefined' && document.getElementById(id)
  if (!target) return
  if (typeof target.scrollIntoView === 'function') target.scrollIntoView({ behavior: 'smooth', block: 'start' })
  if (typeof target.focus === 'function') target.focus({ preventScroll: true })
}

// Move keyboard focus to a result or failure container once it appears.
function useFocusOn(value) {
  const ref = useRef(null)
  useEffect(() => {
    if (value && ref.current && typeof ref.current.focus === 'function') ref.current.focus()
  }, [value])
  return ref
}

// Native disclosure: keyboard-operable and announced without extra code.
function Why({ children }) {
  return jsxs('details', {
    style: { marginTop: 10 },
    children: [
      jsx('summary', { style: { cursor: 'pointer' }, children: 'Why this step?' }),
      jsx('p', { style: { margin: '6px 0 0' }, children }),
    ],
  })
}

// Before the state model: a numbered card whose body disappears when `done`.
// Every Windows step still renders this way (no `state`), unchanged.
function legacyStep({ n, title, done, children }) {
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: `${done ? '✓' : n}  ${title}` }),
      done ? null : children,
    ],
  })
}

function StateBadge({ state, color }) {
  const badge = STATE_BADGES[state] || STATE_BADGES.todo
  return jsxs('span', {
    style: { marginLeft: 10, fontSize: 12, fontWeight: 'normal', color },
    children: [
      badge.glyph ? jsx('span', { 'aria-hidden': true, children: `${badge.glyph} ` }) : null,
      jsx('span', { style: badge.glyph ? undefined : VISUALLY_HIDDEN, children: badge.text }),
    ],
  })
}

function stepBody({ state, id, open, setOpen, onCollapse, summary, toggle, keepOpen, blocker, goto, progress, whyBlock, children }) {
  if (state === 'done' && keepOpen) {
    return [jsx('p', { key: 'summary', style: { margin: 0, color: MUTED_TEXT }, children: summary || 'Done.' }), children, whyBlock]
  }
  if (state === 'done') {
    const detailsId = id ? `${stepAnchor(id)}-details` : undefined
    return [
      jsx('p', { key: 'summary', style: { margin: 0, color: MUTED_TEXT }, children: summary || 'Done.' }),
      children
        ? jsx(Button, {
            key: 'toggle',
            variant: 'ghost',
            'aria-expanded': open,
            'aria-controls': detailsId,
            onClick: () => {
              // Closing the disclosure is the owner's cue to drop anything typed in it.
              if (open && onCollapse) onCollapse()
              setOpen(!open)
            },
            children: open ? 'Hide' : toggle,
          })
        : null,
      open ? jsxs('div', { key: 'details', id: detailsId, children: [children, whyBlock] }) : null,
    ]
  }
  if (state === 'blocked') {
    const reasonFor = BLOCKERS[blocker] || null
    return [
      jsx('p', { key: 'reason', children: reasonFor ? reasonFor.text : 'Finish the earlier steps first.' }),
      reasonFor
        ? jsx(Button, {
            key: 'go',
            variant: 'outline',
            onClick: () => focusTarget(stepAnchor(reasonFor.step)),
            children: `Go to step ${goto || STEP_NUMBERS[reasonFor.step]}`,
          })
        : null,
      whyBlock,
    ]
  }
  if (state === 'running') {
    return [
      jsx('p', { key: 'progress', role: 'status', 'aria-live': 'polite', children: `⟳ ${progress || 'Working…'}` }),
      jsx('fieldset', { key: 'controls', disabled: true, style: { border: 0, margin: 0, padding: 0, minWidth: 0 }, children }),
      whyBlock,
    ]
  }
  return [children, whyBlock]
}

// A setup step. `state` is one of done | next | todo | blocked | running | attention:
// done collapses the body into `summary` behind a toggle (`onCollapse` runs when it
// closes), blocked replaces it by the BLOCKERS reason and a "Go to step" button,
// running disables its controls under a polite progress line. `failure` is an alert
// under the title in every state but blocked, so a failed change of a done step shows
// too. Without `state` (the Windows steps pass `done`) the step renders as it always did.
// `goto` is the number of the step that lifts `blocker` on this page (stepNumbers);
// `keepOpen` keeps a done step's body visible (the mail card: fetching is its daily use).
function Step({
  id = null,
  n,
  title,
  state = null,
  done = false,
  summary = null,
  toggle = 'Details',
  keepOpen = false,
  blocker = null,
  goto = null,
  failure = null,
  noteRef = null,
  progress = null,
  notice = null,
  why = null,
  onCollapse = null,
  children = null,
}) {
  // The same hooks in every mode, so a step keeps its identity whatever it renders.
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (state !== 'done') setOpen(false)
  }, [state])
  if (state == null) return legacyStep({ n, title, done, children })
  const headingId = id ? stepAnchor(id) : undefined
  const edge = state === 'next' ? ACCENT : state === 'attention' ? DESTRUCTIVE : null
  const whyBlock = why ? jsx(Why, { key: 'why', children: why }) : null
  const body = stepBody({ state, id, open, setOpen, onCollapse, summary, toggle, keepOpen, blocker, goto, progress, whyBlock, children })
  const failureNote = failure && state !== 'blocked' ? jsx(StepFailure, { key: 'failure', error: failure, noteRef }) : null
  return jsxs('section', {
    'aria-labelledby': headingId,
    style: {
      border: `1px solid ${STROKE}`,
      borderLeft: edge ? `4px solid ${edge}` : `1px solid ${STROKE}`,
      borderRadius: 10,
      padding: 16,
      marginBottom: 12,
    },
    children: [
      jsxs('h3', {
        id: headingId,
        tabIndex: headingId ? -1 : undefined,
        style: { margin: '0 0 8px', color: state === 'done' ? MUTED_TEXT : undefined },
        children: [`${n}  ${title}`, jsx(StateBadge, { state, color: edge || MUTED_TEXT })],
      }),
      failureNote,
      ...body,
      state === 'blocked' ? null : notice,
    ],
  })
}

function Row({ children }) {
  return jsx('div', { style: { display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }, children })
}

// A labelled radio group (fieldset + legend), e.g. the mail sent-folder choice.
// options: [{value, label, detail?}].
function RadioGroup({ legend, name, options, value, onChange, disabled = false }) {
  return jsxs('fieldset', {
    disabled,
    style: { border: 0, margin: '8px 0 0', padding: 0, minWidth: 0 },
    children: [
      jsx('legend', { style: { padding: 0, marginBottom: 4 }, children: legend }),
      ...options.map((option) =>
        jsxs('label', {
          key: option.value,
          style: { display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 6, cursor: 'pointer' },
          children: [
            jsx('input', {
              type: 'radio',
              name,
              value: option.value,
              checked: value === option.value,
              onChange: () => onChange(option.value),
              style: { accentColor: 'CanvasText', width: 16, height: 16, marginTop: 3, flexShrink: 0 },
            }),
            jsxs('span', {
              children: [option.label, option.detail ? jsx('span', { style: { display: 'block', fontSize: 12, color: MUTED_TEXT }, children: option.detail }) : null],
            }),
          ],
        }),
      ),
    ],
  })
}

const groupTitle = (key, layout) => (layout === 'linux' && GROUPS[key].linux) || GROUPS[key].title

// One of the four page groups: a section labelled by its focusable h2.
function Group({ id, layout, children }) {
  const headingId = groupAnchor(id)
  return jsxs('section', {
    'aria-labelledby': headingId,
    style: { marginTop: 28 },
    children: [
      jsx('h2', { id: headingId, tabIndex: -1, style: { margin: '0 0 12px', fontSize: 18 }, children: `${GROUPS[id].n}  ${groupTitle(id, layout)}` }),
      ...[].concat(children),
    ],
  })
}

function StatusRow({ dot, label, detail, target, layout }) {
  const look = DOTS[dot] || DOTS.not_started
  return jsxs('div', {
    role: 'listitem',
    style: { display: 'flex', gap: 10, alignItems: 'baseline', padding: '3px 0' },
    children: [
      jsx('span', { role: 'img', 'aria-label': look.label, style: { color: look.color, width: 16, flexShrink: 0 }, children: look.glyph }),
      jsx('strong', { style: { width: 150, flexShrink: 0 }, children: label }),
      jsx('span', { style: { flex: 1 }, children: detail }),
      GROUPS[target]
        ? jsx(Button, {
            variant: 'ghost',
            'aria-label': `Go to ${groupTitle(target, layout)}`,
            onClick: () => focusTarget(groupAnchor(target)),
            children: 'Go',
          })
        : null,
    ],
  })
}

function Overview({ rows, layout }) {
  return jsxs('section', {
    'aria-labelledby': 'mordred-overview',
    style: { border: `1px solid ${STROKE}`, borderRadius: 10, padding: '12px 16px', margin: '16px 0' },
    children: [
      jsx('h2', { id: 'mordred-overview', style: { margin: '0 0 6px', fontSize: 16 }, children: 'Overview' }),
      jsx('div', { role: 'list', children: rows.map((row) => jsx(StatusRow, { key: row.key, ...row, layout })) }),
    ],
  })
}

// -- state from status fields -------------------------------------------------------------

// The page layout from explicit metadata only (never from English text).
function pageLayout(status) {
  if (!status) return null
  if (status.hardware_kind === 'cng') return 'windows'
  if (!status.telegram_supported) return 'unsupported'
  if (status.platform === 'darwin' && status.hardware_kind === 'secure_enclave') return 'macos'
  if (status.hardware_kind === 'tpm') return 'linux'
  return 'unsupported'
}

// A version 4 answer carries all three keys; without them Mordred is older than this page.
function reportsV4(status) {
  return Boolean(status) && ['databases', 'imports', 'mail'].every((key) => status[key] != null)
}

// The vault ceremony is its own step (1.2a) when the macOS API reports `vault`; elsewhere
// (Linux, an older Mordred) memory is one ceremony that also creates the vault.
function splitVault(status) {
  return pageLayout(status) === 'macos' && Boolean(status.vault) && typeof status.vault === 'object'
}

// Step numbers for this status: memory is 1.2 wherever there is no separate vault step.
function stepNumbers(status) {
  return splitVault(status) ? STEP_NUMBERS : { ...STEP_NUMBERS, memory: '1.2' }
}

const plural = (count, noun) => `${count} ${noun}${count === 1 ? '' : 's'}`

function relativeTime(at, now = Date.now()) {
  if (typeof at !== 'number') return 'at an unknown time'
  const minutes = Math.max(0, Math.round((now / 1000 - at) / 60))
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${plural(minutes, 'minute')} ago`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${plural(hours, 'hour')} ago`
  return `${plural(Math.round(hours / 24), 'day')} ago`
}

// Per-source counts of Mordred's store (totals across accounts): `{}` while the store is
// not created yet, null when unknown (Linux, an older API, a gate refusal).
function storeSources(status) {
  if (!(pageLayout(status) === 'macos' && reportsV4(status))) return null
  const imports = status.imports
  if (imports.available) return imports.sources || {}
  return imports.code === 'store_uninitialised' ? {} : null
}

// The mailbox label (ACCOUNT_RE): never anything that could be an address.
const mailLabel = (mail) => (typeof mail.account === 'string' && /^[a-z][a-z0-9_]{0,31}$/.test(mail.account) ? mail.account : null)
const timed = (entry) => (entry && typeof entry === 'object' && typeof entry.at === 'number' ? entry : null)
// A recorded error: its code, or 'failed' when it is not a well-formed code.
// A code the page names: one of its own MESSAGES keys (never an unknown backend code).
const knownCode = (value) => (own(MESSAGES, value) ? value : null)
// A recorded error: its code when the page knows it, else 'failed'.
const attemptError = (value) => (value == null ? null : knownCode(value) || 'failed')
// The latest fetch: `last_attempt`, else `last_success` (a complete one).
function lastFetch(mail) {
  const attempt = timed(mail.last_attempt)
  if (attempt) return { at: attempt.at, error: attemptError(attempt.error), partial: attempt.partial === true }
  const success = timed(mail.last_success)
  return success ? { at: success.at, error: null, partial: false } : null
}
const fetchOutcome = (last) => last.error || (last.partial ? 'partial' : 'complete')

// Telegram counts: Mordred's store (version 4 `imports`) or, from an older API and on
// Linux, the import service's in-process counts (`GET /sync`). null when unknown.
function telegramCounts(status, sync) {
  if (pageLayout(status) === 'macos' && reportsV4(status)) {
    const sources = storeSources(status)
    if (!sources) return null
    const telegram = sources.telegram || {}
    return { chats: Number(telegram.conversations) || 0, messages: Number(telegram.messages) || 0, store: true }
  }
  if (!sync) return null
  return { chats: Number(sync.dialog_count) || 0, messages: Number(sync.message_count) || 0, store: false }
}

const countsText = (counts) => `${plural(counts.chats, 'chat')} · ${plural(counts.messages, 'message')}`
// Store counts are totals across accounts; the in-process counts (older API, Linux) are this login's.
const countsWhere = (counts) => (counts.store ? ' in Mordred’s store (all accounts)' : ' imported')

const databaseRows = (db) => (Array.isArray(db && db.databases) ? db.databases.filter((row) => row && typeof row.relative === 'string') : [])

// Step 1.3 from the databases facts (the second design revision): an attention code; done
// (armed, this process protected, no plaintext file); or a restart that finishes it (armed
// but this process started before, or a conversion scheduled for the next start).
function databaseState(db) {
  const plaintext = databaseRows(db).some((row) => row.state === 'plaintext')
  if (db.decrypt_pending) return { code: 'decrypt_pending' }
  if (db.journal) return { code: 'journal' }
  if (db.armed && db.encrypt_pending) return { code: 'stale_pending' }
  if (db.armed && plaintext) return { code: 'plaintext_in_armed_home' }
  if (db.armed) return db.runtime_protected ? { done: true } : { restart: true }
  return db.encrypt_pending ? { restart: true } : {}
}

// The first unmet prerequisite, in reading order: rules are [met, blocker] pairs.
function firstBlocker(...rules) {
  const unmet = rules.find(([met]) => !met)
  return unmet ? unmet[1] : null
}

// Steps 2.4 and 2.5 write to mordred.db, which opens only once the databases are
// armed (step 1.3) and Hermes restarted. null on Linux and from an older API.
function storeBlocker(status) {
  if (!(pageLayout(status) === 'macos' && reportsV4(status))) return null
  const db = status.databases
  if (!db.armed) return db.encrypt_pending ? 'needs_restart' : 'needs_databases'
  if (!db.runtime_protected) return 'needs_restart'
  const code = status.imports.available === false ? status.imports.code : null
  if (code === 'conversion_pending' || code === 'unprotected_process') return 'needs_restart'
  return code === 'not_armed' ? 'needs_databases' : null
}

// The state of every step of the macOS/Linux page: {key: {state, blocker?, code?, job?}}.
// Facts from the status decide first (helper installed, memory on, databases armed,
// logged in, model private, mailbox configured, a failure the status reports), then
// unmet prerequisites (`blocked`), then `status.jobs[].kind` (`running`), then page
// state: `sync`, the polled `GET /sync` answer. The vault and memory ceremonies and the
// Telegram import are not registry jobs, so their `running` lives only in the page. A reopened page
// with no job shows the fact-derived state. The first `todo` in reading order is `next`.
function stepStates(status, sync = null) {
  const layout = pageLayout(status)
  const checks = status.checks || {}
  const ok = (name) => Boolean(checks[name] && checks[name].ok)
  const jobs = Array.isArray(status.jobs) ? status.jobs : []
  const runningJob = (...kinds) => jobs.find((job) => job && kinds.includes(job.kind) && (!job.state || job.state === 'running')) || null
  const hardware = ok('hardware')
  const memory = ok('memory_encryption')
  const model = Boolean(status.hermes_model && status.hermes_model.ok)
  const llm = ok('privacy_llm')
  const login = ok('login')
  const macos = layout === 'macos'
  const v4 = macos && reportsV4(status)
  const store = storeBlocker(status)
  const states = {}
  const decide = (key, { done = false, fact = null, blocker = null, job = null, page = null }) => {
    states[key] = done
      ? { state: 'done' }
      : fact
        ? { state: 'attention', code: fact }
        : blocker
          ? { state: 'blocked', blocker }
          : job
            ? { state: 'running', job: job.job_id }
            : page || { state: 'todo' }
  }
  decide('enclave', { done: hardware, job: runningJob('enclave', 'hardware') })
  // macOS with a version 4 API: the vault (1.2a) comes first, and memory (1.2b) needs
  // Hermes to read .env from it (enrolled, and injected into this process at start).
  const vault = splitVault(status) ? status.vault : null
  if (vault) {
    decide('vault', {
      done: Boolean(vault.exists && vault.env_enrolled),
      fact: vault.optout ? 'env_optout' : null,
      blocker: firstBlocker([hardware, 'needs_enclave']),
    })
  }
  const vaultReady = !vault || Boolean(vault.env_enrolled && vault.env_injecting)
  decide('memory', { done: memory, blocker: firstBlocker([hardware, 'needs_enclave'], [vaultReady, 'needs_vault']) })
  if (macos && !v4) states.databases = { state: 'attention', code: 'mordred_update_required' }
  else if (v4) {
    const db = databaseState(status.databases)
    decide('databases', {
      done: Boolean(db.done),
      fact: status.databases.supported === false ? 'databases_unsupported' : db.code || null,
      blocker: firstBlocker([hardware, 'needs_enclave'], [memory, 'needs_memory']),
      page: db.restart ? { state: 'todo', restart: true } : null,
    })
  }
  decide('hermes_model', { done: model })
  decide('question_model', { done: llm, blocker: firstBlocker([hardware, 'needs_enclave'], [model, 'needs_hermes_model']) })
  decide('telegram', {
    done: login,
    blocker: firstBlocker([hardware, 'needs_enclave'], [memory, 'needs_memory'], [model, 'needs_hermes_model'], [llm, 'needs_question_model']),
  })
  const counts = telegramCounts(status, sync)
  // A store not created yet is no failure: the first import creates it.
  const gate = v4 && !store && status.imports.available === false ? status.imports.code || 'import_store_unavailable' : null
  const storeCode = gate === 'store_uninitialised' ? null : gate
  decide('telegram_import', {
    done: login && Boolean(counts && counts.messages > 0),
    fact: storeCode,
    blocker: firstBlocker(
      [hardware, 'needs_enclave'],
      [memory, 'needs_memory'],
      [!store, store],
      [model, 'needs_hermes_model'],
      [llm, 'needs_question_model'],
      [login, 'needs_login'],
    ),
    page: sync && sync.syncing ? { state: 'running' } : sync && sync.last_error ? { state: 'attention', code: sync.last_error } : null,
  })
  if (macos && !v4) states.mail = { state: 'attention', code: 'mordred_update_required' }
  else if (v4) {
    const mail = status.mail
    const last = mail.configured ? lastFetch(mail) : null
    const lastError = (last && last.error) || null
    // Sealed credentials without their settings: the step offers Remove.
    const residue = mail.residue === 'credentials_left' ? 'credentials_left' : null
    decide('mail', {
      done: Boolean(mail.configured) && !lastError && !residue,
      fact: residue || lastError,
      blocker: firstBlocker([hardware, 'needs_enclave'], [memory, 'needs_memory'], [!store, store]),
      job: runningJob('mail_fetch'),
    })
  }
  const next = Object.keys(STEP_NUMBERS).find((key) => states[key] && states[key].state === 'todo')
  if (next) states[next] = { ...states[next], state: 'next' }
  return states
}

function modelRow(check) {
  const c = check || {}
  const row = { key: 'model', label: 'Hermes chat model', target: 'connect' }
  if (c.ok) return { ...row, dot: 'done', detail: `${c.model} (${c.kind === 'local' ? 'local, this host only' : 'Venice private'})` }
  if (c.model && c.kind === 'venice' && c.private === null) return { ...row, dot: 'partial', detail: `${c.model} (not verified with Venice yet)` }
  if (c.model) return { ...row, dot: 'attention', detail: `${c.model} · not private` }
  return { ...row, dot: 'not_started', detail: 'not set' }
}

function vaultFact(vault) {
  if (!vault.exists) return 'no vault'
  return vault.env_enrolled ? 'vault' : 'vault without .env'
}

function protectionRow(status, layout, hardware, memory) {
  const row = { key: 'protection', label: 'Protection', target: 'protect' }
  const vault = splitVault(status) ? status.vault : null
  const facts = [
    hardware ? (layout === 'macos' ? 'Secure Enclave' : 'TPM 2.0') : 'helper missing',
    ...(vault ? [vaultFact(vault)] : []),
    memory ? 'memory encrypted' : 'memory not encrypted',
  ]
  if (layout === 'linux') {
    const dot = hardware && memory ? 'done' : hardware || memory ? 'partial' : 'not_started'
    return { ...row, dot, detail: [...facts, 'Databases: not available on Linux'].join(' · ') }
  }
  if (!reportsV4(status)) return { ...row, dot: 'attention', detail: [...facts, 'databases: Update Mordred to use this'].join(' · ') }
  const db = status.databases
  const state = databaseState(db)
  const parts = [hardware, memory, Boolean(state.done), ...(vault ? [Boolean(vault.exists && vault.env_enrolled)] : [])]
  const on = parts.filter(Boolean).length
  const attention = db.supported === false || Boolean(state.code) || Boolean(vault && vault.optout && !vault.env_enrolled)
  const dot = attention ? 'attention' : on === parts.length ? 'done' : on === 0 && !state.restart ? 'not_started' : 'partial'
  return { ...row, dot, detail: [...facts, databasesFact(db, state)].join(' · ') }
}

function databasesFact(db, state) {
  if (db.supported === false) return 'databases: not available'
  if (state.done) return 'databases on'
  if (state.code) return 'databases: needs attention'
  if (state.restart) return db.armed ? 'databases: restart Hermes Desktop' : 'databases: converting at next restart'
  return 'databases off'
}

function telegramRow(status, sync, login) {
  const row = { key: 'telegram', label: 'Telegram', target: 'connect' }
  if (!login) return { ...row, dot: 'not_started', detail: 'not connected' }
  if (sync && sync.last_error) return { ...row, dot: 'attention', detail: 'connected · the last import stopped' }
  const counts = telegramCounts(status, sync)
  if (counts && counts.messages > 0) {
    return { ...row, dot: 'done', detail: `connected · ${countsText(counts)}${counts.store ? ' in Mordred’s store (all accounts)' : ''}` }
  }
  if (pageLayout(status) === 'macos' && reportsV4(status)) {
    // Zero in the store is not "nothing imported": the history may be in the older archive.
    if (!counts) return { ...row, dot: 'partial', detail: `connected · ${STORE_GATES[status.imports.code] || 'store unavailable'}` }
    return { ...row, dot: 'partial', detail: 'connected · nothing in Mordred’s store yet' }
  }
  // The in-process counts restart at 0 with the backend: say nothing rather than "nothing imported".
  return { ...row, dot: 'done', detail: 'connected' }
}

function mailRow(status, layout, now) {
  const row = { key: 'mail', label: 'Mail', target: 'connect' }
  if (layout === 'linux') return { ...row, dot: 'not_started', detail: 'not available on Linux' }
  if (!reportsV4(status)) return { ...row, dot: 'attention', detail: 'Update Mordred to use this' }
  const mail = status.mail
  if (mail.residue === 'credentials_left') return { ...row, dot: 'attention', detail: 'leftover credentials · remove them in step 2.5' }
  if (!mail.configured) return { ...row, dot: 'not_started', detail: 'not set up' }
  const parts = [`account ${mailLabel(mail) || 'with an unreadable label'}`]
  const sources = storeSources(status)
  if (sources) parts.push(plural(Number(sources.mail && sources.mail.messages) || 0, 'message'))
  const last = lastFetch(mail)
  parts.push(last ? `last fetch ${relativeTime(last.at, now)} (${fetchOutcome(last)})` : 'never fetched')
  return { ...row, dot: last && last.error ? 'attention' : 'done', detail: parts.join(' · ') }
}

// The overview card's four rows, built only from status fields (and the `/sync` counts).
function overviewRows(status, sync = null, now = Date.now()) {
  const layout = pageLayout(status)
  const checks = status.checks || {}
  const ok = (name) => Boolean(checks[name] && checks[name].ok)
  return [
    modelRow(status.hermes_model),
    protectionRow(status, layout, ok('hardware'), ok('memory_encryption')),
    telegramRow(status, sync, ok('login')),
    mailRow(status, layout, now),
  ]
}

// A step's own failure first, else the attention code stepStates computed from status.
const stepFailure = (failure, code) => failure || (code ? new MordredError(code) : null)

// Masked inputs are cleared after every submit (success, failure, cancel) and
// whenever their fields leave the page: the step becomes done or blocked, its
// disclosure closes (Step's onCollapse) or the component unmounts.
function useClearSecrets(clear, shown) {
  useEffect(() => {
    if (shown === 'done' || shown === 'blocked') clear()
  }, [shown])
  useEffect(() => clear, [])
}

// A failure note belongs to the attempt that failed: drop it once the step becomes done.
function useDropOnDone(state, drop) {
  useEffect(() => {
    if (state === 'done') drop()
  }, [state])
}

// Accessible names on the grouped page only: the Windows fields render as before.
const named = (legacy, label) => (legacy ? {} : { 'aria-label': label })

function HermesModelInstructions({ check, refresh, ok, verifying }) {
  return jsxs(Fragment, {
    children: [
      ok
        ? null
        : jsx('p', {
            children: verifying
              ? `Could not verify ${check.model} with Venice right now (offline?).`
              : `Everything Hermes reads goes to its chat model${check && check.model ? ` (now: ${check.model})` : ''}. For Telegram it must be a Venice private model or a model on this host.`,
          }),
      verifying
        ? null
        : jsx('ol', {
            children: [
              jsx('li', { key: 1, children: 'Open Settings → Providers → “Local / custom endpoint”.' }),
              jsx('li', { key: 2, children: 'Venice: base URL https://api.venice.ai/api/v1, your Venice API key, and a private model such as e2ee-deepseek-v4-flash or deepseek-v4-flash.' }),
              jsx('li', { key: 3, children: 'Or a local server (Ollama / LM Studio) at http://127.0.0.1:<port>/v1.' }),
              jsx('li', { key: 4, children: 'Select that model for chats, then press Check again.' }),
            ],
          }),
      jsx(Button, { onClick: refresh, children: 'Check again' }),
    ],
  })
}

function HermesModelStep({ id = null, n = 0, state = null, check, refresh, why = null }) {
  const ok = Boolean(check && check.ok)
  const verifying = check && check.kind === 'venice' && check.private === null
  const line = ok ? `${check.model} (${check.kind === 'local' ? 'local, this host only' : 'Venice private, no retention'})` : null
  if (state == null) {
    // Windows: the card as it always was.
    return jsxs('section', {
      style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
      children: [
        jsx('h3', { style: { margin: '0 0 8px' }, children: `${ok ? '✓' : '0'}  Hermes chat model` }),
        ok ? jsx('p', { children: line }) : jsx(HermesModelInstructions, { check, refresh, ok, verifying }),
      ],
    })
  }
  return jsx(Step, {
    id,
    n,
    title: 'Hermes chat model',
    state,
    summary: line,
    toggle: 'Change',
    why,
    children: jsx(HermesModelInstructions, { check, refresh, ok, verifying }),
  })
}

function EnclaveStep({ id = null, n, state, job = null, refresh, hardwareKind }) {
  const linux = hardwareKind === 'tpm'
  const label = linux ? 'TPM 2.0' : 'Secure Enclave'
  const [starting, setStarting] = useState(false)
  const [failure, setFailure] = useState(null)
  const [watched, setWatched] = useState(null)
  const alive = useRef(true)
  const noteRef = useFocusOn(failure)
  useDropOnDone(state, () => setFailure(null))
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])
  // Latch the build job seen in status.jobs (also after a page re-open) and wait
  // for its end: a failure, or a job the backend no longer reports, becomes a note.
  useEffect(() => {
    if (job) setWatched(job)
  }, [job])
  useEffect(() => {
    if (!watched) return undefined
    let current = true
    pollJob(watched, { alive: () => current && alive.current }).then((end) => {
      if (!current || !alive.current) return
      if (end.state === 'failed') setFailure(new MordredError(safeCode(end.error) || (linux ? 'tpm_build_failed' : 'enclave_build_failed')))
      else if (end.state === 'lost') setFailure(new MordredError('job_not_found'))
      setWatched(null)
      refresh()
    })
    return () => {
      current = false
    }
  }, [watched])
  const build = async () => {
    setStarting(true)
    setFailure(null)
    try {
      const started = await call('/hardware/build', {})
      host.notify({ kind: 'info', message: `Building the ${label} helper… this takes a few minutes.` })
      if (started && started.job_id) setWatched(started.job_id)
      await refresh()
    } catch (e) {
      setFailure(asMordredError(e))
    } finally {
      if (alive.current) setStarting(false)
    }
  }
  // Facts first (installed), then the registry job, then this page's request and failure.
  const shown = state === 'done' ? 'done' : state === 'running' || starting ? 'running' : failure ? 'attention' : state
  return jsx(Step, {
    id,
    n,
    title: `${label} helper`,
    state: shown,
    summary: 'Installed.',
    progress: `Building the ${label} helper… this takes a few minutes.`,
    failure,
    noteRef,
    why: linux ? WHY.enclave_linux : WHY.enclave,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: linux ? 'Telegram keys are bound to this TPM. There is no per-use user-presence prompt or portable recovery. Losing TPM state loses access.' : 'Your Telegram keys are sealed by a key that never leaves this device’s Secure Enclave.' }),
        jsx(Button, { disabled: shown === 'running', onClick: build, children: shown === 'running' ? 'Building…' : `Set up ${label}` }),
      ],
    }),
  })
}

const MEMORY_BODY = 'Hermes keeps what it learns about you in memory files and its API keys in .env. This step moves .env into Mordred’s encrypted vault and encrypts the memory files. You get a recovery passphrase once: it is the only way to read these files if this Mac is lost or the Secure Enclave key is gone.'
const ASK_EVERY_TIME_NOTE = 'Off by default: Hermes Desktop starts its backend in the background, and an unlock it cannot answer would start Hermes without its secrets. With this off, the key opens silently while you are logged in. Your Telegram and mail keys are separate and keep their own Touch ID setting.'
// Memory alone (step 1.2b): the vault and .env are step 1.2a.
const MEMORY_ONLY_BODY = 'Hermes keeps what it learns about you in memory files. This step encrypts them with the vault’s key, so they are never readable on disk. Restart Hermes Desktop afterwards.'

function AskEveryTime({ checked, onChange }) {
  return jsx(Checked, {
    checked,
    onChange,
    children: [
      jsx('span', { key: 'label', children: 'Ask for Touch ID every time Hermes unlocks the vault' }),
      jsx('span', { key: 'note', style: { display: 'block', fontSize: 12, color: MUTED_TEXT }, children: ASK_EVERY_TIME_NOTE }),
    ],
  })
}

function PassphraseCard({ phrase, resultRef, saved, setSaved, onContinue }) {
  return jsxs('div', {
    ref: resultRef,
    tabIndex: -1,
    children: [
      jsx('p', { children: 'Write this down and keep it safe. It is shown only once and is the only way to recover your encrypted data if this Mac is lost.' }),
      jsx('pre', { style: { fontSize: 18, padding: 12, userSelect: 'all', whiteSpace: 'pre-wrap' }, children: phrase }),
      jsxs('label', {
        style: { display: 'flex', gap: 8, alignItems: 'center' },
        children: [jsx(Checkbox, { checked: saved, onCheckedChange: (v) => setSaved(v === true), style: CHECKBOX_STYLE }), 'I have written it down'],
      }),
      jsx(Row, { children: jsx(Button, { disabled: !saved, onClick: onContinue, children: 'Continue' }) }),
    ],
  })
}

// `split`: the macOS version 4 page, where the vault is step 1.2a and this step
// encrypts memory only. Otherwise (Linux, an older Mordred) one ceremony does both and
// may answer the recovery passphrase.
function MemoryStep({ id = null, n, state, blocker = null, goto = null, refresh, hardwareKind, split = false }) {
  const linux = hardwareKind === 'tpm'
  const [busy, setBusy] = useState(false)
  const [phrase, setPhrase] = useState(null)
  const [saved, setSaved] = useState(false)
  const [askEveryTime, setAskEveryTime] = useState(false)
  const [failure, setFailure] = useState(null)
  const [restart, setRestart] = useState(false)
  const noteRef = useFocusOn(failure)
  const resultRef = useFocusOn(phrase || restart)
  useDropOnDone(state, () => setFailure(null))
  const enable = async () => {
    setBusy(true)
    setFailure(null)
    try {
      // macOS: the vault key opens silently unless the owner asks for Touch ID every time
      // (asked by the vault step when it is separate).
      const body = linux ? { acknowledge_tpm_no_recovery: true } : split ? {} : { unattended: !askEveryTime }
      const r = await call('/memory/enable', body)
      if (r.recovery_passphrase && !split) setPhrase(r.recovery_passphrase)
      else {
        if (!r.already) setRestart(true)
        refresh()
      }
    } catch (e) {
      setFailure(asMordredError(e))
    } finally {
      setBusy(false)
    }
  }
  const finish = () => {
    setPhrase(null)
    setSaved(false)
    setRestart(true)
    host.notify({ kind: 'success', message: 'Memory encryption is on. Restart Hermes to finish.' })
    refresh()
  }
  // The passphrase is the request's one-time answer: shown before any status fact.
  if (phrase) {
    return jsx(Step, {
      id,
      n,
      title: 'Save your recovery passphrase',
      state: 'next',
      children: jsx(PassphraseCard, { phrase, resultRef, saved, setSaved, onContinue: finish }),
    })
  }
  const restartNotice = restart
    ? jsxs('div', {
        ref: resultRef,
        tabIndex: -1,
        style: { marginTop: 10 },
        children: [
          jsx('p', { role: 'status', children: 'Memory encryption is on. Restart Hermes Desktop to finish: Hermes reads the encrypted files only after a restart.' }),
          jsx(RestartHermesControl, {}),
        ],
      })
    : null
  // Not a registry job: `running` only while this page's request is in flight.
  const shown = state === 'done' || state === 'blocked' ? state : busy ? 'running' : failure ? 'attention' : state
  const linuxBody = 'Memory is encrypted with a TPM-bound key, without per-use user presence or a recovery passphrase. Disable encryption before moving hosts to restore plaintext while the original TPM works. Restart Hermes after setup.'
  return jsx(Step, {
    id,
    n,
    title: linux || split ? 'Encrypt Hermes memory' : 'Encrypt Hermes memory and secrets',
    state: shown,
    blocker,
    goto,
    summary: 'On.',
    progress: linux ? 'Encrypting Hermes memory…' : 'Encrypting… approve a Touch ID prompt if one appears.',
    failure,
    noteRef,
    notice: restartNotice,
    why: WHY.memory,
    children: jsxs(Fragment, {
      children: [
        // The vault exists (this step is open only then): a retry runs the memory half alone.
        split && failure
          ? jsx('p', {
              key: 'retry',
              // Only a code of the page's own table is named; an unknown one is left out.
              children: `Vault created, memory encryption failed${knownCode(failure.code) ? ` (${failure.code})` : ''}; retry.`,
            })
          : null,
        jsx('p', { key: 'body', children: linux ? linuxBody : split ? MEMORY_ONLY_BODY : MEMORY_BODY }),
        linux || split ? null : jsx(AskEveryTime, { key: 'ask', checked: askEveryTime, onChange: setAskEveryTime }),
        jsx(Row, {
          key: 'enable',
          children: [
            jsx(Button, { key: 'enable', disabled: busy, onClick: enable, children: busy ? 'Encrypting…' : 'Turn on memory encryption' }),
            linux ? null : jsx('span', { key: 'hint', style: { fontSize: 12, color: MUTED_TEXT }, children: 'May show a Touch ID prompt.' }),
          ],
        }),
      ],
    }),
  })
}

const VAULT_BODY = 'Hermes keeps its API keys in .env. This step creates Mordred’s encrypted vault on this Mac and moves .env into it. First you get a recovery passphrase of eight words: it is the only way to open the vault if this Mac is lost or the Secure Enclave key is gone. Nothing is created until you confirm that you wrote it down.'
const VAULT_EXISTS_BODY = 'This Mac already has a vault, but Hermes’s .env is not in it yet. This step moves .env into the vault; the recovery passphrase shown when the vault was created stays the only one.'
// `/vault/prepare` on an existing vault without .env: no passphrase exists to show.
const VAULT_REUSE = 'The vault already exists; its recovery passphrase is the one shown when it was created. .env will be moved into it.'
const VAULT_DONE = 'Hermes reads .env from the vault when it starts. The recovery passphrase was shown once, when the vault was created.'
const VAULT_RESTART = 'Restart Hermes Desktop so Hermes reads .env from the vault, then turn on memory encryption (step 1.2b).'

// The eight words of `/vault/prepare` (an array; a string is split defensively).
function passphraseWords(passphrase) {
  const words = Array.isArray(passphrase) ? passphrase : typeof passphrase === 'string' ? passphrase.split(/\s+/) : []
  return words.map((word) => String(word).trim()).filter(Boolean)
}

// The prepared flow before its commit. With words: the recovery passphrase, shown once
// and gated by "I have written it down" (selectable text only: no copy button, since a
// clipboard manager would keep it). Without (`reuse`, an existing vault): one sentence
// and the commit straight away.
function VaultCommitCard({ flow, saved, setSaved, askEveryTime, setAskEveryTime, onCommit, onCancel, cardRef }) {
  const reuse = flow.reuse
  return jsxs('div', {
    ref: cardRef,
    tabIndex: -1,
    children: [
      reuse
        ? jsx('p', { key: 'reuse', children: VAULT_REUSE })
        : jsx('p', {
            key: 'intro',
            children: 'Your recovery passphrase. Write these eight words down in this order and keep them somewhere safe. They are shown only now; nothing is created until you continue.',
          }),
      reuse
        ? null
        : jsx('ol', {
            key: 'words',
            'aria-label': 'Recovery passphrase',
            style: { fontSize: 18, columns: 2, margin: '8px 0', userSelect: 'text' },
            children: flow.words.map((word, index) => jsx('li', { key: index, children: word })),
          }),
      reuse ? null : jsx(Checked, { key: 'saved', checked: saved, onChange: setSaved, children: 'I have written it down' }),
      jsx(AskEveryTime, { key: 'ask', checked: askEveryTime, onChange: setAskEveryTime }),
      jsx(Row, {
        key: 'commit',
        children: [
          jsx(Button, { key: 'create', disabled: !reuse && !saved, onClick: onCommit, children: reuse ? 'Move .env into the vault' : 'Create the vault' }),
          jsx(Button, { key: 'cancel', variant: 'ghost', onClick: onCancel, children: 'Cancel' }),
          jsx('span', { key: 'hint', style: { fontSize: 12, color: MUTED_TEXT }, children: 'May show a Touch ID prompt.' }),
        ],
      }),
    ],
  })
}

// Step 1.2a (macOS, version 4 API): prepare → acknowledge → commit. `/vault/prepare`
// returns the passphrase and changes nothing; `/vault/{flow}/commit` creates the vault
// with that passphrase and moves .env into it. For an existing vault without .env the
// prepare answer has no passphrase (`passphrase_reused`) and the commit only moves .env.
// The passphrase lives only in this component's state: dropped after the commit, on
// Cancel, on a failure that ends the flow, when the step is done or blocked and when the
// page goes away. Never notified, logged or copied.
function VaultStep({ id, n, state, blocker = null, goto = null, code = null, vault, refresh }) {
  const [flow, setFlow] = useState(null)
  const [saved, setSaved] = useState(false)
  const [askEveryTime, setAskEveryTime] = useState(false)
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  const [outcome, setOutcome] = useState(null)
  const noteRef = useFocusOn(failure)
  const cardRef = useFocusOn(flow)
  const resultRef = useFocusOn(outcome)
  const exists = Boolean(vault && vault.exists)
  const drop = () => {
    setFlow(null)
    setSaved(false)
    setAskEveryTime(false)
  }
  // Blocked first; then this page's request, the prepared passphrase, facts and failures.
  const shown = state === 'blocked' ? state : busy ? 'running' : flow ? (failure ? 'attention' : 'next') : state === 'done' ? state : failure ? 'attention' : state
  useClearSecrets(drop, shown)
  useDropOnDone(state, () => setFailure(null))
  const prepare = async () => {
    setBusy(true)
    setFailure(null)
    setOutcome(null)
    try {
      const r = await call('/vault/prepare', {})
      const reuse = r.passphrase == null && r.passphrase_reused === true
      const words = reuse ? [] : passphraseWords(r.passphrase)
      if (!r.flow_id || (!reuse && words.length === 0)) throw new MordredError('invalid_response')
      setSaved(false)
      setFlow({ id: String(r.flow_id), words, reuse })
    } catch (e) {
      setFailure(asMordredError(e))
    } finally {
      setBusy(false)
    }
  }
  const commit = async () => {
    if (!flow || (!flow.reuse && !saved)) return
    setBusy(true)
    setFailure(null)
    try {
      const r = await call(`/vault/${encodeURIComponent(flow.id)}/commit`, { unattended: !askEveryTime })
      // Words shown but an existing vault kept: say they were not used.
      setOutcome(flow.reuse ? 'moved' : r.passphrase_reused ? 'reused' : 'created')
      drop()
      host.notify({ kind: 'success', message: r.passphrase_reused ? '.env moved into the existing vault.' : 'Vault created.' })
    } catch (e) {
      // A busy ceremony leaves the prepared flow valid for a retry; any other answer ends it.
      if (!(e && e.code === 'memory_operation_in_progress')) drop()
      setFailure(asMordredError(e))
    } finally {
      setBusy(false)
      refresh()
    }
  }
  const cancel = () => {
    drop()
    setFailure(null)
  }
  const restartNotice = (text) =>
    jsxs('div', {
      ref: resultRef,
      tabIndex: -1,
      style: { marginTop: 10 },
      children: [jsx('p', { key: 'text', role: 'status', children: text }), jsx(RestartHermesControl, { key: 'restart' })],
    })
  const outcomes = {
    created: 'Vault created and .env moved into it.',
    reused: MESSAGES.passphrase_reused,
    moved: '.env was moved into the existing vault; its recovery passphrase is the one shown when it was created.',
  }
  const notice = outcome
    ? restartNotice(`${outcomes[outcome]} ${VAULT_RESTART}`)
    : state === 'done' && vault && !vault.env_injecting
      ? restartNotice(VAULT_RESTART)
      : null
  // The key's effective policy as the API reads it, never the one requested here.
  const policy = vault && vault.unattended === true ? ' · opens without Touch ID while you are logged in' : vault && vault.unattended === false ? ' · Touch ID on every unlock' : ''
  const children = flow
    ? jsx(VaultCommitCard, {
        flow,
        saved,
        setSaved,
        askEveryTime,
        setAskEveryTime,
        onCommit: commit,
        onCancel: cancel,
        cardRef,
      })
    : shown === 'done'
      ? jsx('p', { children: VAULT_DONE })
      : jsxs(Fragment, {
          children: [
            jsx('p', { key: 'body', children: exists ? VAULT_EXISTS_BODY : VAULT_BODY }),
            code === 'env_optout'
              ? null
              : jsx(Row, {
                  key: 'prepare',
                  children: [
                    jsx(Button, { key: 'go', disabled: busy, onClick: prepare, children: exists ? 'Move .env into the vault' : 'Create the vault' }),
                    jsx('span', {
                      key: 'hint',
                      style: { fontSize: 12, color: MUTED_TEXT },
                      children: exists ? 'Nothing changes until you confirm.' : 'Shows a recovery passphrase first; nothing is created yet.',
                    }),
                  ],
                }),
          ],
        })
  return jsx(Step, {
    id,
    n,
    title: 'Create the vault',
    state: shown,
    blocker,
    goto,
    summary: `On · .env is in the vault${policy}.`,
    progress: flow ? 'Creating the vault… approve a Touch ID prompt if one appears.' : 'Preparing…',
    failure: stepFailure(failure, code),
    noteRef,
    notice,
    why: WHY.vault,
    children,
  })
}

const TELEGRAM_DONE = 'Connected (read-only). To disconnect, end the session in Telegram → Settings → Devices on your phone, or run hermes-mordred telegram logout in Terminal.'

function TelegramStep({ id = null, state = null, blocker = null, goto = null, done = false, needsApi, refresh, n = 4, extra = null, summary = null, why = null }) {
  const legacy = state == null
  const [apiId, setApiId] = useState('')
  const [apiHash, setApiHash] = useState('')
  const [phone, setPhone] = useState('')
  const [secret, setSecret] = useState('')
  const [flow, setFlow] = useState(null)
  const [step, setStep] = useState('phone')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  const [result, setResult] = useState(null)
  const noteRef = useFocusOn(failure)
  const resultRef = useFocusOn(result)
  // Each submit is an attempt; cancel and reset start a new one, so a late answer
  // to an abandoned attempt changes nothing (a late new flow is cancelled).
  const attempt = useRef(0)
  const shown = legacy ? null : state === 'done' || state === 'blocked' ? state : failure ? 'attention' : state
  const clearSecrets = () => {
    setApiHash('')
    setSecret('')
  }
  useClearSecrets(clearSecrets, legacy ? (done ? 'done' : 'todo') : shown)
  useDropOnDone(state, () => setFailure(null))
  const reset = () => {
    attempt.current += 1
    setFlow(null)
    setStep('phone')
    clearSecrets()
  }
  const submit = async () => {
    const mine = ++attempt.current
    const current = () => attempt.current === mine
    setBusy(true)
    setFailure(null)
    setResult(null)
    try {
      if (step === 'phone') {
        const body = { phone, ...(extra || {}) }
        if (needsApi) Object.assign(body, { api_id: apiId, api_hash: apiHash })
        const r = await call('/telegram/login/start', body)
        if (!current()) {
          if (typeof r.flow_id === 'string') call(`/telegram/login/${encodeURIComponent(r.flow_id)}/cancel`, {}).catch(() => {})
          return
        }
        setFlow(r.flow_id)
        setStep(r.step)
      } else {
        const path = `/telegram/login/${flow}/${step === 'code' ? 'code' : 'password'}`
        const r = await call(path, step === 'code' ? { code: secret } : { password: secret })
        if (!current()) return
        if (r.step === 'done') {
          host.notify({ kind: 'success', message: 'Telegram connected (read-only).' })
          setResult('Telegram connected (read-only).')
          reset()
          refresh()
        } else setStep(r.step)
      }
    } catch (e) {
      if (!current()) return
      if (legacy) host.notifyError(asMordredError(e), 'Telegram login failed')
      else setFailure(asMordredError(e))
      if (e && (e.code === 'login_flow_expired' || e.code === 'login_code_expired')) reset()
    } finally {
      clearSecrets()
      setBusy(false)
    }
  }
  const cancel = () => {
    call(`/telegram/login/${flow}/cancel`, {}).catch(() => {})
    reset()
  }
  // Hiding a done step's details drops what was typed there and abandons any login
  // attempt (an open flow is cancelled; a late answer to a request is ignored).
  const collapse = () => (flow ? cancel() : reset())
  const field = (label, props) => jsx(Input, { autoComplete: 'off', ...props, ...named(legacy, label) })
  return jsx(Step, {
    id,
    n,
    title: 'Connect Telegram (read-only)',
    state: shown,
    done,
    blocker,
    goto,
    summary: summary || 'Connected (read-only).',
    failure,
    noteRef,
    notice: result ? jsx('p', { ref: resultRef, tabIndex: -1, role: 'status', children: result }) : null,
    why,
    onCollapse: collapse,
    children: jsxs(Fragment, {
      children: [
        step === 'phone' && needsApi
          ? jsxs(Fragment, {
              children: [
                jsxs('p', {
                  children: [
                    'Create an app at ',
                    jsx('code', { style: { userSelect: 'all' }, children: 'https://my.telegram.org/apps' }),
                    ' (API development tools) and paste its api_id and api_hash.',
                  ],
                }),
                jsx(Row, { children: field('api_id', { placeholder: 'api_id', value: apiId, onChange: (e) => setApiId(e.target.value) }) }),
                jsx(Row, { children: field('api_hash', { type: 'password', placeholder: 'api_hash', value: apiHash, onChange: (e) => setApiHash(e.target.value) }) }),
              ],
            })
          : null,
        step === 'phone'
          ? jsx(Row, {
              children: field('Phone number', { placeholder: 'Phone number, e.g. +819012345678', value: phone, onChange: (e) => setPhone(e.target.value) }),
            })
          : jsxs(Fragment, {
              children: [
                jsx('p', {
                  children:
                    step === 'code'
                      ? 'Enter the login code Telegram just sent to your Telegram app.'
                      : 'Enter your Telegram two-step verification password (the "Cloud Password" you set in Telegram → Settings → Privacy and Security). This is not your computer password or a Mordred passphrase. It is not stored.',
                }),
                jsx(Row, {
                  children: field(step === 'code' ? 'Telegram login code' : 'Telegram password', {
                    type: 'password',
                    placeholder: step === 'code' ? 'Telegram login code' : 'Telegram password',
                    value: secret,
                    onChange: (e) => setSecret(e.target.value),
                  }),
                }),
              ],
            }),
        jsxs(Row, {
          children: [
            jsx(Button, { disabled: busy, onClick: submit, children: busy ? 'Working…' : step === 'phone' ? 'Send login code' : 'Continue' }),
            flow ? jsx(Button, { variant: 'ghost', onClick: cancel, children: 'Cancel' }) : null,
          ],
        }),
      ],
    }),
  })
}

function LlmStep({ id = null, state = null, blocker = null, goto = null, done = false, hermesKey, refresh, n = 3, extra = null, why = null }) {
  const legacy = state == null
  const [key, setKey] = useState('')
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:11434/v1')
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  const [result, setResult] = useState(null)
  const noteRef = useFocusOn(failure)
  const resultRef = useFocusOn(result)
  const shown = legacy ? null : state === 'done' || state === 'blocked' ? state : failure ? 'attention' : state
  useClearSecrets(() => setKey(''), legacy ? (done ? 'done' : 'todo') : shown)
  useDropOnDone(state, () => setFailure(null))
  const run = async (path, body) => {
    setBusy(true)
    setFailure(null)
    setResult(null)
    try {
      await call(path, { ...body, ...(extra || {}) })
      host.notify({ kind: 'success', message: 'Question model set.' })
      setResult('Question model set.')
      refresh()
    } catch (e) {
      if (legacy) host.notifyError(asMordredError(e), 'Could not set the model')
      else setFailure(asMordredError(e))
    } finally {
      setKey('')
      setBusy(false)
    }
  }
  return jsx(Step, {
    id,
    n,
    title: 'Question model (Venice private or local)',
    state: shown,
    done,
    blocker,
    goto,
    summary: 'Set.',
    toggle: 'Change',
    failure,
    noteRef,
    notice: result ? jsx('p', { ref: resultRef, tabIndex: -1, role: 'status', children: result }) : null,
    why,
    onCollapse: () => setKey(''),
    children: jsxs(Fragment, {
      children: [
        hermesKey
          ? jsx(Row, { children: jsx(Button, { disabled: busy, onClick: () => run('/llm/venice', { use_hermes_key: true }), children: 'Use the Venice key Hermes already has' }) })
          : null,
        jsx(Row, {
          children: [
            jsx(Input, { key: 'k', type: 'password', autoComplete: 'off', placeholder: 'Or paste a Venice API key', ...named(legacy, 'Venice API key'), value: key, onChange: (e) => setKey(e.target.value) }),
            jsx(Button, { key: 'b', disabled: busy || !key, onClick: () => run('/llm/venice', { api_key: key }), children: 'Use this key' }),
          ],
        }),
        jsx(Row, {
          children: [
            jsx(Input, { key: 'e', placeholder: 'Local endpoint', ...named(legacy, 'Local endpoint'), value: endpoint, onChange: (e) => setEndpoint(e.target.value) }),
            jsx(Input, { key: 'm', placeholder: 'Local model name', ...named(legacy, 'Local model name'), value: model, onChange: (e) => setModel(e.target.value) }),
            jsx(Button, { key: 'l', disabled: busy || !model, onClick: () => run('/llm/local', { endpoint, model }), children: 'Use local model' }),
          ],
        }),
      ],
    }),
  })
}

// Every GET /sync poll gets a number, increasing for the page's life (across remounts of the
// import step), so an answer can be told apart from one to a poll issued before an import
// was started (see SetupPage's onSync).
let syncPollSeq = 0

const importProgress = (progress) =>
  progress ? `Chats ${progress.dialogs_done}/${progress.dialogs_total}, ${progress.messages_imported} new messages` : 'Starting the import…'

function ImportSummary({ counts, sync }) {
  const text = sync && sync.syncing ? importProgress(sync.progress) : counts ? `${countsText(counts)}${countsWhere(counts)}.` : 'Imported.'
  return jsxs(Fragment, { children: [text, sync && sync.last_error ? ` Last import: ${explain(sync.last_error)}` : null] })
}

// `legacyHint`: logged in, and Mordred's store holds no Telegram message, so the history
// may still be in the older archive (the status cannot tell without the sealed key).
// `onStarted(fromSeq)` tells the page an import was started here: only answers to polls
// numbered `fromSeq` or later can show its end (see SetupPage's onSync).
function ImportStep({ ready, refresh, n = 5, id = null, state = null, blocker = null, goto = null, code = null, title = 'Import messages', counts = null, onSync = null, onStarted = null, why = null, legacyHint = false }) {
  const legacy = state == null
  const usable = legacy ? ready : state !== 'blocked'
  const [days, setDays] = useState(3)
  const [sync, setSync] = useState(null)
  const [starting, setStarting] = useState(false)
  const [failure, setFailure] = useState(null)
  const noteRef = useFocusOn(failure)
  const mounted = useRef(true)
  // The newest poll number this step applied: an older answer arriving late is ignored.
  const newestPoll = useRef(0)
  useDropOnDone(state, () => setFailure(null))
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const poll = useCallback(async () => {
    const seq = ++syncPollSeq
    try {
      const answer = await call('/sync')
      if (seq < newestPoll.current) return
      newestPoll.current = seq
      setSync(answer)
      if (onSync) onSync(answer, seq)
    } catch (_) {
      /* ignore */
    }
  }, [onSync])
  // A revoked login flips the Telegram step back to "log in": re-read the setup status.
  const lastError = sync && sync.last_error
  useEffect(() => {
    if (lastError === 'telegram_session_revoked') refresh()
  }, [lastError, refresh])
  useEffect(() => {
    if (!usable) return undefined
    poll()
    const t = setInterval(poll, 3000)
    return () => clearInterval(t)
  }, [usable, poll])
  const start = async () => {
    setStarting(true)
    setFailure(null)
    try {
      await call('/sync', { days: Number(days) || 3, include_archived: false })
      host.notify({ kind: 'info', message: 'Import started. Approve a hardware prompt if asked.' })
      // Gone meanwhile: no mark and no poll (a later page reads the status itself).
      if (!mounted.current) return
      // A poll already in flight may answer "idle" from before the start: only polls
      // issued from now on can show this import's end.
      if (onStarted) onStarted(syncPollSeq + 1)
      poll()
    } catch (e) {
      if (legacy) host.notifyError(asMordredError(e), 'Import failed')
      else setFailure(asMordredError(e))
    } finally {
      setStarting(false)
    }
  }
  const progress = sync && sync.progress
  const syncing = Boolean(sync && sync.syncing)
  const daysRow = jsxs(Row, {
    children: [
      'Last',
      jsx(Input, { style: { width: 70 }, type: 'number', min: 1, ...named(legacy, 'Days of history to import'), value: days, onChange: (e) => setDays(e.target.value) }),
      'days',
      // Windows keeps its old expression (null or a boolean); the grouped page also waits for its own request.
      jsx(Button, { disabled: legacy ? sync && sync.syncing : syncing || starting, onClick: start, children: syncing ? 'Importing…' : 'Import' }),
    ],
  })
  if (legacy) {
    return jsx(Step, {
      n,
      title,
      done: false,
      children: ready
        ? jsxs(Fragment, {
            children: [
              jsx('p', { children: 'Pinned chats first. Large groups and archived chats are skipped. Nothing is downloaded twice.' }),
              daysRow,
              sync
                ? jsx('p', {
                    children: sync.syncing && progress
                      ? `Chats ${progress.dialogs_done}/${progress.dialogs_total}, ${progress.messages_imported} new messages`
                      : sync.last_error
                        ? explain(sync.last_error)
                        : 'Ready. Ask Hermes about your Telegram messages in any chat.',
                  })
                : null,
            ],
          })
        : jsx('p', { children: 'Finish the steps above first.' }),
    })
  }
  // Status first (imported, blocked, a refusal it reports): a stale poll or this page's
  // request never hides them; then this page's request, the polled import, failures.
  const shown = state === 'done' || state === 'blocked' || state === 'attention' ? state : starting || syncing ? 'running' : failure ? 'attention' : state
  return jsx(Step, {
    id,
    n,
    title,
    state: shown,
    blocker,
    goto,
    summary: jsx(ImportSummary, { counts, sync }),
    toggle: 'Import more',
    progress: importProgress(progress),
    failure: stepFailure(failure, code),
    noteRef,
    why,
    children: jsxs(Fragment, {
      children: [
        daysRow,
        jsx('p', { style: { fontSize: 12, color: MUTED_TEXT }, children: '30 for a useful first import; 0 is not accepted here, use the terminal for all history.' }),
        counts && counts.messages > 0 ? jsx('p', { children: `${countsText(counts)}${countsWhere(counts)}.` }) : null,
        legacyHint
          ? jsxs('p', {
              children: [
                'Your Telegram history may still be in the older archive; run ',
                jsx('code', { key: 'command', style: { userSelect: 'all' }, children: 'hermes-mordred telegram migrate-store --commit' }),
                ' in Terminal to move it into Mordred’s store.',
              ],
            })
          : null,
      ],
    }),
  })
}

// Shown instead of a step the running Mordred cannot report (no version 4 status keys).
function UpdateRequiredStep({ id, n, title, why }) {
  return jsx(Step, {
    id,
    n,
    title,
    state: 'attention',
    failure: new MordredError('mordred_update_required'),
    why,
    children: jsx(Row, {
      children: jsx(Button, { variant: 'outline', onClick: () => focusTarget(groupAnchor('maintenance')), children: 'Go to Maintenance' }),
    }),
  })
}

// -- version 4 sections: databases (1.3) and mail (2.5) ----------------------------------------

function DatabaseTable({ rows }) {
  if (!rows.length) return jsx('p', { children: 'No Hermes database files were found yet.' })
  const cell = { textAlign: 'left', padding: '2px 16px 2px 0' }
  return jsxs('table', {
    style: { borderCollapse: 'collapse', margin: '8px 0' },
    children: [
      jsx('thead', {
        key: 'head',
        children: jsxs('tr', {
          children: [jsx('th', { key: 'file', scope: 'col', style: cell, children: 'Database' }), jsx('th', { key: 'state', scope: 'col', style: cell, children: 'State' })],
        }),
      }),
      jsx('tbody', {
        key: 'body',
        children: rows.map((row) =>
          jsxs('tr', {
            key: row.relative,
            children: [
              jsx('td', { key: 'file', style: cell, children: jsx('code', { children: row.relative }) }),
              jsx('td', { key: 'state', style: cell, children: DATABASE_STATES[row.state] || 'unknown' }),
            ],
          }),
        ),
      }),
    ],
  })
}

// Step 1.3 (macOS, version 4 API). The table is the preview: discovery runs on every
// status read without a key or Touch ID. "Encrypt databases" never converts from the
// backend: Hermes Desktop holds the files open, so it schedules the conversion for the
// next start, and the step then offers the restart. Attention states point to Terminal.
function DatabasesStep({ id, n, state, blocker = null, goto = null, code = null, restart = false, status, refresh }) {
  const db = status.databases || {}
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  // The answer that asks for a restart: `scheduled` (converted at the next start) or
  // `needs_restart` (armed, but this Hermes Desktop opened the databases before).
  const [restartFor, setRestartFor] = useState(null)
  const noteRef = useFocusOn(failure)
  const resultRef = useFocusOn(restartFor)
  useDropOnDone(state, () => setFailure(null))
  const encrypt = async () => {
    setBusy(true)
    setFailure(null)
    try {
      const r = await call('/databases/encrypt', {})
      // An attention answer carries its code; only a well-formed one is shown.
      if (r.action === 'attention') throw new MordredError(safeCode(r.code) || 'databases_failed', {})
      if (r.action === 'scheduled' || r.action === 'needs_restart') {
        setRestartFor(r.action)
        if (r.action === 'scheduled') host.notify({ kind: 'info', message: 'Database encryption is scheduled for the next start of Hermes Desktop.' })
      } else if (r.action !== 'done') throw new MordredError('invalid_response', {})
      // `done`: already on; the status read below makes the step done.
    } catch (e) {
      setFailure(asMordredError(e))
    } finally {
      setBusy(false)
      // An answer may not say what changed (databases_failed): read the facts again.
      refresh()
    }
  }
  const rows = databaseRows(db)
  const unreadable = rows.filter((row) => row.state === 'unreadable').length
  const backups = Number(db.plaintext_backups) || 0
  const waiting = Boolean(restartFor) || restart
  const shown = state === 'done' || state === 'blocked' ? state : busy ? 'running' : failure ? 'attention' : state
  const scheduledText = restartFor ? restartFor === 'scheduled' : !db.armed
  const notice =
    waiting && shown !== 'done'
      ? jsxs('div', {
          ref: resultRef,
          tabIndex: -1,
          style: { marginTop: 10 },
          children: [
            jsx('p', { key: 'text', role: 'status', children: scheduledText ? DATABASES_RESTART.scheduled : DATABASES_RESTART.armed }),
            jsx(RestartHermesControl, { key: 'restart' }),
          ],
        })
      : null
  return jsx(Step, {
    id,
    n,
    title: 'Encrypt Hermes databases',
    state: shown,
    blocker,
    goto,
    summary: `Database encryption: on (${plural(unreadable, 'file')} encrypted or unreadable).`,
    progress: 'Scheduling the database encryption…',
    failure: stepFailure(failure, code),
    noteRef,
    notice,
    why: WHY.databases,
    children: jsxs(Fragment, {
      children: [
        jsx(DatabaseTable, { key: 'table', rows }),
        backups > 0
          ? jsx('p', { key: 'backups', children: `${plural(backups, 'backup archive')} in your Hermes home may contain plaintext copies; delete them when you no longer need them.` })
          : null,
        waiting || code
          ? null
          : jsx(Row, {
              key: 'encrypt',
              children: [
                jsx(Button, { key: 'go', disabled: busy, onClick: encrypt, children: busy ? 'Scheduling…' : 'Encrypt databases' }),
                jsx('span', { key: 'hint', style: { fontSize: 12, color: MUTED_TEXT }, children: 'Takes effect the next time Hermes Desktop starts.' }),
              ],
            }),
      ],
    }),
  })
}

const MAIL_INTRO = 'Mordred can fetch your mail read-only over IMAP and add it to the same encrypted store as Telegram, so Hermes can answer questions about it.'
const MAIL_PRIVACY = 'The address and app password you type here never reach the chat, the model, the tools, plugin or browser storage, or logs: the Secure Enclave on this Mac seals them. A mail fetch gives Hermes counts only. When you ask Hermes about your mail, it reads the matching messages through mordred_history_search, and that chat then runs in reader mode.'
const APP_PASSWORD_GUIDE = 'Create an app password: turn on 2-Step Verification for your Google account, then open https://myaccount.google.com/apppasswords and create one for “Mordred”. Google shows it as four groups of four letters; paste it with or without the spaces. Mordred never needs your Google account password, and you can revoke the app password at any time in the same place. Other providers call this an app-specific password.'
const FETCH_PROGRESS = 'Fetching new mail… this may take up to about 10 minutes and continues where it stopped if interrupted. Approve the Touch ID prompt if it appears.'
const MAIL_PROGRESS = {
  setup: 'Connecting to the mail server… it logs in once, read-only. Approve a Touch ID prompt if one appears.',
  finish: 'Saving the mailbox…',
  remove: 'Removing the mailbox…',
}
const FOLDER_QUESTIONS = {
  all_mail: 'Which folder holds all your mail (Gmail’s “All Mail”)?',
  sent: 'Which folder holds your sent mail? (optional)',
}

// What the page says about the chat sync: not advertised as the reliable path.
const syncHint = (where) => [
  `Fetch new mail ${where} (reliable). You can also say “sync my mail” in a Hermes chat; if Hermes fails to reach the tool, see the note on `,
  jsx('code', { key: 'tool', children: 'tools.tool_search' }),
  ' in Mordred’s USAGE guide. A mail sync or fetch gives Hermes counts only.',
]

const gmailAddress = (address) => /@(gmail|googlemail)\.com$/i.test(address.trim())
// "Other addresses": commas, semicolons, spaces or new lines between them.
const splitAddresses = (text) => text.split(/[\s,;]+/).filter(Boolean)
// The "Fetch at most" field: a whole number from 1 to MAX_FETCH.
const validMax = (text) => {
  const digits = `${text}`.trim()
  return /^\d{1,4}$/.test(digits) && Number(digits) >= 1 && Number(digits) <= MAX_FETCH
}
const validDate = (text) => /^\d{4}-\d{2}-\d{2}$/.test(text)
const countOf = (value) => (Number.isFinite(Number(value)) ? Number(value) : 0)
const codesOf = (list) => (Array.isArray(list) ? list.map(safeCode).filter(Boolean) : [])
const folderOptions = (folders) =>
  (Array.isArray(folders) ? folders : [])
    .filter((folder) => folder && typeof folder.id === 'string' && folder.id && typeof folder.display === 'string')
    .map((folder) => ({ value: folder.id, label: folder.display }))

function mailScope(mail) {
  if (mail.gmail === true) return 'Gmail (All Mail with labels)'
  return Array.isArray(mail.scope) && mail.scope.includes('sent') ? 'inbox and sent folder' : 'inbox'
}

// Last success and last attempt; the attempt only when it says something the success does not.
function mailHistory(mail, now = Date.now()) {
  const success = timed(mail.last_success)
  const attempt = timed(mail.last_attempt)
  const lines = []
  if (success) lines.push(`Last successful fetch: ${relativeTime(success.at, now)}.`)
  if (attempt && (!success || attempt.at !== success.at || attemptError(attempt.error) || attempt.partial === true)) {
    lines.push(`Last attempt: ${relativeTime(attempt.at, now)} (${fetchOutcome(lastFetch({ last_attempt: attempt }))}).`)
  }
  return lines.length ? lines : ['Not fetched yet.']
}

// A mail failure under the page's `mail_<code>` wording when there is one (StepFailure
// shows only explain(code)); the IMAP hint is kept, nothing else of the answer.
function mailError(error) {
  const e = asMordredError(error)
  const code = own(MESSAGES, `mail_${e.code}`) ? `mail_${e.code}` : e.code
  return new MordredError(code, e.info && e.info.hint ? { hint: e.info.hint } : {})
}

// A fetch that stopped (a failed job, or the last attempt the status reports), under the
// page's `fetch_<code>` wording where the setup wording ("Nothing was stored") would mislead.
function fetchError(code) {
  const safe = safeCode(code) || 'fetch_failed'
  return own(MESSAGES, `fetch_${safe}`) ? new MordredError(`fetch_${safe}`, {}) : mailError(new MordredError(safe, {}))
}

// The result as counts, flags and closed codes only, in RESULT_FIELDS order: zero, false
// and null are left out, and a value that is not a count, a flag or a code is ignored.
function resultParts(result) {
  return RESULT_FIELDS.flatMap(([key, label]) => {
    const value = result[key]
    if (typeof value === 'number' && Number.isFinite(value) && value !== 0) return [`${label} ${value}`]
    if (value === true) return [`${label}: yes`]
    if (key === 'partial_reason') return own(PARTIAL_REASON_LABELS, value) ? [`${label}: ${PARTIAL_REASON_LABELS[value]}`] : []
    const code = knownCode(value)
    return code ? [`${label}: ${code}`] : []
  })
}

function FetchResultBlock({ result, resultRef }) {
  const parts = resultParts(result)
  return jsxs('div', {
    ref: resultRef,
    tabIndex: -1,
    role: 'status',
    style: { marginTop: 10 },
    children: [
      jsx('p', { key: 'counts', style: { margin: 0 }, children: `Result (counts only): ${parts.length ? parts.join(' · ') : 'nothing new'}.` }),
      result.partial === true ? jsx('p', { key: 'partial', style: { margin: '4px 0 0' }, children: 'Fetch again to continue.' }) : null,
    ],
  })
}

function ForgetOutcome({ outcome, noticeRef }) {
  return jsxs('div', {
    ref: noticeRef,
    tabIndex: -1,
    role: 'status',
    style: { marginTop: 10 },
    children: [
      jsx('p', {
        key: 'done',
        children: `${outcome.had ? 'Mailbox removed.' : 'No sealed mailbox credentials were found.'} ${plural(outcome.messages, 'message')} and ${plural(outcome.cursors, 'cursor')} deleted.`,
      }),
      outcome.warnings.length ? jsx('ul', { key: 'warnings', children: outcome.warnings.map((code) => jsx('li', { key: code, children: explainMail(code) })) }) : null,
    ],
  })
}

const hint = (text) => jsx('span', { key: 'hint', style: { fontSize: 12, color: MUTED_TEXT }, children: text })

// Step 2.5 (macOS, version 4 API) in four sub-states: not set up (the form), setup in
// progress (the folder question of a pending flow), set up (fetch and remove) and
// removing. Every input is cleared after each submit (success, failure, cancel) and when
// the step is blocked or unmounts; a pending flow is cancelled on unmount (its password
// waits in the backend's memory). Only counts, codes and the owner's label are shown,
// and folder names only in the folder question.
function MailStep({ id, n, state, blocker = null, goto = null, code = null, status, refresh }) {
  const mail = status.mail || {}
  const [address, setAddress] = useState('')
  const [others, setOthers] = useState('')
  const [server, setServer] = useState('')
  const [serverEdited, setServerEdited] = useState(false)
  const [account, setAccount] = useState(DEFAULT_MAIL_ACCOUNT)
  const [password, setPassword] = useState('')
  const [unattended, setUnattended] = useState(false)
  const [flow, setFlow] = useState(null)
  const [selection, setSelection] = useState(null)
  const [maxText, setMaxText] = useState(String(MAX_FETCH))
  const [older, setOlder] = useState(false)
  const [since, setSince] = useState('')
  const [fetchJob, setFetchJob] = useState(null)
  const [result, setResult] = useState(null)
  const [purge, setPurge] = useState(false)
  const [phrase, setPhrase] = useState('')
  const [retryAccount, setRetryAccount] = useState('')
  const [forgotten, setForgotten] = useState(null)
  const [busy, setBusy] = useState(null)
  const [failure, setFailure] = useState(null)
  const [note, setNote] = useState(null)
  const mounted = useRef(true)
  const flowRef = useRef(null)
  const polling = useRef(null)
  // Each setup start is an attempt; leaving the step (done, blocked, unmount) starts a new
  // one, so a late answer to an abandoned start is cancelled instead of applied.
  const attempt = useRef(0)
  const latestState = useRef(state)
  latestState.current = state
  const noteRef = useFocusOn(failure)
  const resultRef = useFocusOn(result)
  const noticeRef = useFocusOn(forgotten || note)
  const statusJob = (Array.isArray(status.jobs) ? status.jobs : []).find(
    (job) => job && job.kind === 'mail_fetch' && (!job.state || job.state === 'running'),
  )
  const fetching = Boolean(fetchJob) || busy === 'fetch' || Boolean(statusJob)
  const shown = state === 'blocked' ? state : busy || fetching ? 'running' : failure ? 'attention' : state
  const clearForm = () => {
    setAddress('')
    setOthers('')
    setServer('')
    setServerEdited(false)
    setAccount(DEFAULT_MAIL_ACCOUNT)
    setPassword('')
    setUnattended(false)
  }
  const clearFetch = () => {
    setMaxText(String(MAX_FETCH))
    setOlder(false)
    setSince('')
  }
  const clearRemove = () => {
    setPurge(false)
    setPhrase('')
    setRetryAccount('')
  }
  // Leaving the page or the step (done, blocked) also ends a flow waiting for its folder
  // choice and abandons a start still in flight.
  useClearSecrets(() => {
    attempt.current += 1
    clearForm()
    clearFetch()
    clearRemove()
    dropFlow()
  }, shown)
  useDropOnDone(state, () => setFailure(null))
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      // A flow waiting for its folder choice holds the password in the backend: cancel it.
      const pending = flowRef.current
      flowRef.current = null
      setFlow(null)
      setSelection(null)
      if (pending) call(`/mail/setup/${encodeURIComponent(pending)}/cancel`, {}).catch(() => {})
    }
  }, [])
  // Poll a fetch job until it ends: one this page started, or one in status.jobs (a
  // re-opened page, another window, `already_running`). Each job is polled once.
  const follow = async (jobId) => {
    if (!jobId || polling.current === jobId) return
    polling.current = jobId
    setFetchJob(jobId)
    const end = await pollJob(jobId, { alive: () => mounted.current && polling.current === jobId })
    if (!mounted.current || polling.current !== jobId) return
    polling.current = null
    setFetchJob(null)
    const counts = end.progress && end.progress.result
    if (counts && typeof counts === 'object') setResult(counts)
    if (end.state === 'failed') setFailure(fetchError(end.error || 'fetch_failed'))
    else if (end.state === 'lost') setFailure(new MordredError('job_not_found'))
    else if (end.state === 'timeout') setFailure(new MordredError('mail_fetch_timeout'))
    refresh()
  }
  const statusJobId = statusJob ? String(statusJob.job_id) : null
  useEffect(() => {
    if (statusJobId) follow(statusJobId)
  }, [statusJobId])
  // A flow ends here: cancelled on the server too (idempotent), its folder names dropped.
  const dropFlow = () => {
    const pending = flowRef.current
    flowRef.current = null
    setFlow(null)
    setSelection(null)
    if (pending) call(`/mail/setup/${encodeURIComponent(pending)}/cancel`, {}).catch(() => {})
  }
  const finished = () => {
    flowRef.current = null
    setFlow(null)
    setSelection(null)
    setNote('Mailbox connected (read-only).')
    host.notify({ kind: 'success', message: 'Mailbox connected (read-only).' })
    refresh()
  }
  const onAddress = (value) => {
    setAddress(value)
    if (!serverEdited) setServer(gmailAddress(value) ? GMAIL_HOST : '')
  }
  const connect = async () => {
    const mine = ++attempt.current
    // Still this page's attempt: mounted, not superseded, and the step neither done nor blocked.
    const current = () => mounted.current && attempt.current === mine && latestState.current !== 'done' && latestState.current !== 'blocked'
    setBusy('setup')
    setFailure(null)
    setNote(null)
    setForgotten(null)
    try {
      const body = {
        address: address.trim(),
        account: account.trim() || DEFAULT_MAIL_ACCOUNT,
        extra_addresses: splitAddresses(others),
        app_password: password,
        touch_id: !unattended,
      }
      if (server.trim()) body.imap_host = server.trim()
      const r = await call('/mail/setup/start', body)
      if (!current()) {
        // A late answer: release the backend's single pending flow (and the password it
        // holds) at once, show nothing; a sealed setup appears with the next status read.
        if (typeof r.flow_id === 'string' && r.flow_id) call(`/mail/setup/${encodeURIComponent(r.flow_id)}/cancel`, {}).catch(() => {})
        if (mounted.current && r.step === 'done') refresh()
        return
      }
      if (r.step === 'folders') {
        if (!r.flow_id) throw new MordredError('invalid_request')
        flowRef.current = String(r.flow_id)
        setSelection(null)
        setFlow({ id: String(r.flow_id), question: r.question === 'all_mail' ? 'all_mail' : 'sent', folders: folderOptions(r.folders) })
      } else finished()
    } catch (e) {
      if (current()) setFailure(mailError(e))
    } finally {
      clearForm()
      setBusy(null)
    }
  }
  const finish = async () => {
    if (!flow || selection === null) return
    setBusy('finish')
    setFailure(null)
    try {
      await call(`/mail/setup/${encodeURIComponent(flow.id)}/finish`, { selection: selection === NO_SENT_FOLDER ? null : selection })
      finished()
    } catch (e) {
      if (!(e && KEEP_FLOW.has(e.code))) dropFlow()
      setFailure(mailError(e))
    } finally {
      setBusy(null)
    }
  }
  const cancelSetup = () => {
    dropFlow()
    clearForm()
    setFailure(null)
  }
  const fetchMail = async () => {
    if (!validMax(maxText) || (older && !validDate(since))) return
    setBusy('fetch')
    setFailure(null)
    setResult(null)
    setNote(null)
    setForgotten(null)
    const body = { max: Number(maxText) }
    if (older) body.since = since
    let jobId = null
    try {
      const r = await call('/mail/fetch', body)
      jobId = r.job_id ? String(r.job_id) : null
      if (!jobId) throw new MordredError('fetch_failed')
      if (r.already_running) setNote('A fetch was already running; its result appears here when it ends.')
    } catch (e) {
      setFailure(mailError(e))
    } finally {
      clearFetch()
      setBusy(null)
    }
    if (jobId) await follow(jobId)
  }
  const residue = mail.residue === 'credentials_left'
  const accountUnknown = Boolean(forgotten && forgotten.warnings.includes('account_unknown')) || Boolean(failure && failure.code === 'account_unknown')
  const askAccount = residue || accountUnknown
  const remove = async () => {
    setFailure(null)
    setForgotten(null)
    setNote(null)
    if (purge && phrase.trim() !== PURGE_PHRASE) {
      // Checked before anything is sent, as the API checks it before anything is read.
      setFailure(mailError(new MordredError('forget_confirm_mismatch')))
      clearRemove()
      return
    }
    setBusy('remove')
    try {
      const body = { rows: purge }
      if (purge) body.confirm = PURGE_PHRASE
      if (askAccount && retryAccount.trim()) body.account = retryAccount.trim()
      const r = await call('/mail/forget', body)
      // The route cancels pending setup flows.
      flowRef.current = null
      setFlow(null)
      setForgotten({ had: r.had_credentials === true, messages: countOf(r.deleted_messages), cursors: countOf(r.cursors_deleted), warnings: codesOf(r.warnings) })
      host.notify({ kind: 'success', message: 'Mailbox removed.' })
    } catch (e) {
      setFailure(mailError(e))
    } finally {
      clearRemove()
      setBusy(null)
      refresh()
    }
  }
  const configured = Boolean(mail.configured)
  const label = mailLabel(mail)
  const touch = mail.touch_id === false ? 'syncs without Touch ID' : mail.touch_id === true ? 'Touch ID on each fetch' : null
  const accountLine = `Account ${label || '(label unreadable)'} · ${mailScope(mail)}${touch ? ` · ${touch}` : ''}`
  const sources = storeSources(status)
  const field = (props) => jsx(Input, { autoComplete: 'off', ...props })
  const removeSection = jsxs('details', {
    key: 'remove',
    open: askAccount || undefined,
    style: { marginTop: 12 },
    children: [
      jsx('summary', { key: 'summary', style: { cursor: 'pointer' }, children: 'Remove this mailbox…' }),
      jsx('p', {
        key: 'what',
        children: 'Removes the sealed address, the app password and the mailbox key from this Mac. Revoke the app password with your mail provider too if you no longer need it.',
      }),
      jsx(Checked, {
        key: 'rows',
        checked: purge,
        onChange: setPurge,
        children: `Also delete every message imported under account ${label || 'of this mailbox'} (including Takeout imports)`,
      }),
      purge
        ? jsx('p', { key: 'warn', children: `This deletes data and cannot be undone. Type “${PURGE_PHRASE}” to confirm.` })
        : null,
      purge
        ? jsx(Row, { key: 'phrase', children: field({ placeholder: PURGE_PHRASE, 'aria-label': 'Type delete my data to confirm', value: phrase, onChange: (e) => setPhrase(e.target.value) }) })
        : null,
      askAccount
        ? jsx('p', { key: 'why-label', children: 'The mailbox settings could not be read, so Mordred needs the account label to find its mail and cursors.' })
        : null,
      askAccount
        ? jsx(Row, { key: 'label', children: field({ placeholder: DEFAULT_MAIL_ACCOUNT, 'aria-label': 'Account label to remove', value: retryAccount, onChange: (e) => setRetryAccount(e.target.value) }) })
        : null,
      jsx(Row, {
        key: 'go',
        children: jsx(Button, { variant: 'outline', disabled: Boolean(busy), onClick: remove, children: purge ? 'Remove mailbox and delete its mail' : 'Remove mailbox' }),
      }),
    ],
  })
  const fetchReady = validMax(maxText) && (!older || validDate(since))
  const setUpCard = [
    shown === 'done' ? null : jsx('p', { key: 'account', children: accountLine }),
    ...mailHistory(mail).map((line, index) => jsx('p', { key: `history-${index}`, style: { margin: '4px 0' }, children: line })),
    sources ? jsx('p', { key: 'count', style: { margin: '4px 0' }, children: `${plural(Number(sources.mail && sources.mail.messages) || 0, 'message')} in Mordred’s store (all accounts).` }) : null,
    jsx(Row, {
      key: 'max',
      children: [
        'Fetch at most',
        jsx(Input, { key: 'n', style: { width: 90 }, type: 'number', min: 1, max: MAX_FETCH, 'aria-label': 'Fetch at most N messages', value: maxText, onChange: (e) => setMaxText(e.target.value) }),
        'messages',
      ],
    }),
    jsx(Checked, { key: 'older', checked: older, onChange: setOlder, children: 'Also fetch older mail since a date' }),
    older ? jsx(Row, { key: 'since', children: jsx(Input, { type: 'date', 'aria-label': 'Fetch older mail since', value: since, onChange: (e) => setSince(e.target.value) }) }) : null,
    jsx(Row, {
      key: 'fetch',
      children: [
        jsx(Button, { key: 'go', disabled: fetching || !fetchReady, onClick: fetchMail, children: fetching ? 'Fetching…' : 'Fetch new mail' }),
        mail.touch_id === false ? null : hint('May show a Touch ID prompt.'),
      ],
    }),
    result ? jsx(FetchResultBlock, { key: 'result', result, resultRef }) : null,
    jsx('p', { key: 'chat', children: syncHint('here') }),
    removeSection,
  ]
  const folderChoice = flow
    ? [
        jsx('p', { key: 'intro', children: 'Logged in (read-only). One question before the mailbox is saved; folder names are shown only here.' }),
        jsx(RadioGroup, {
          key: 'folders',
          legend: FOLDER_QUESTIONS[flow.question],
          name: 'mordred-mail-folder',
          options: flow.question === 'sent' ? [...flow.folders, { value: NO_SENT_FOLDER, label: 'No sent folder' }] : flow.folders,
          value: selection,
          onChange: setSelection,
        }),
        jsx(Row, {
          key: 'finish',
          children: [
            jsx(Button, { key: 'finish', disabled: Boolean(busy) || selection === null, onClick: finish, children: 'Finish' }),
            jsx(Button, { key: 'cancel', variant: 'ghost', disabled: Boolean(busy), onClick: cancelSetup, children: 'Cancel' }),
          ],
        }),
      ]
    : null
  const form = [
    jsx('p', { key: 'intro', children: MAIL_INTRO }),
    jsx('p', { key: 'privacy', style: { fontSize: 12, color: MUTED_TEXT }, children: MAIL_PRIVACY }),
    jsxs('p', { key: 'guide', children: [jsx('strong', { key: 'lead', children: 'Before you start (Gmail). ' }), APP_PASSWORD_GUIDE] }),
    jsx(Row, { key: 'address', children: field({ placeholder: 'Mail address', 'aria-label': 'Mail address', value: address, onChange: (e) => onAddress(e.target.value) }) }),
    jsx(Row, {
      key: 'others',
      children: field({ placeholder: 'Other addresses that are yours (comma-separated, optional)', 'aria-label': 'Other addresses that are yours', value: others, onChange: (e) => setOthers(e.target.value) }),
    }),
    jsx(Row, {
      key: 'server',
      children: [
        field({
          key: 'input',
          placeholder: 'IMAP server',
          'aria-label': 'IMAP server',
          value: server,
          onChange: (e) => {
            setServerEdited(true)
            setServer(e.target.value)
          },
        }),
        hint('Filled in for Gmail addresses.'),
      ],
    }),
    jsx(Row, {
      key: 'account',
      children: [
        field({ key: 'input', placeholder: DEFAULT_MAIL_ACCOUNT, 'aria-label': 'Account label', value: account, onChange: (e) => setAccount(e.target.value) }),
        hint('A short name for this mailbox in Mordred, not an address.'),
      ],
    }),
    jsx(Row, { key: 'password', children: field({ type: 'password', placeholder: 'App password', 'aria-label': 'App password', value: password, onChange: (e) => setPassword(e.target.value) }) }),
    jsx(Checked, {
      key: 'unattended',
      checked: unattended,
      onChange: setUnattended,
      children: [
        jsx('span', { key: 'label', children: 'Allow syncing without Touch ID' }),
        jsx('span', { key: 'note', style: { display: 'block', fontSize: 12, color: MUTED_TEXT }, children: 'For scheduled syncs; otherwise each fetch asks for Touch ID.' }),
      ],
    }),
    jsx(Row, {
      key: 'connect',
      children: [
        jsx(Button, { key: 'go', disabled: Boolean(busy) || !address.trim() || !password, onClick: connect, children: 'Connect mailbox' }),
        hint('Logs in once, read-only; may show a Touch ID prompt.'),
      ],
    }),
    accountUnknown ? removeSection : null,
  ]
  const children = flow ? folderChoice : configured ? setUpCard : residue ? [removeSection] : form
  const notice = forgotten ? jsx(ForgetOutcome, { outcome: forgotten, noticeRef }) : note ? jsx('p', { ref: noticeRef, tabIndex: -1, role: 'status', children: note }) : null
  const statusFailure = code ? (code === 'credentials_left' ? mailError(new MordredError(code)) : fetchError(code)) : null
  return jsx(Step, {
    id,
    n,
    title: 'Mail over IMAP',
    state: shown,
    blocker,
    goto,
    summary: accountLine,
    keepOpen: true,
    progress: fetching ? FETCH_PROGRESS : MAIL_PROGRESS[busy] || null,
    failure: failure || statusFailure,
    noteRef,
    notice,
    why: WHY.mail,
    children: jsxs(Fragment, { children }),
  })
}

// Group 3: what to say in a chat and what Hermes sees (copy only).
function AskHermes({ macos }) {
  const strong = (text) => jsx('strong', { children: text })
  const code = (text) => jsx('code', { children: text })
  const paragraph = (children) => jsxs('p', { children })
  return jsxs('div', {
    style: { border: `1px solid ${STROKE}`, borderRadius: 10, padding: '4px 16px' },
    children: [
      paragraph([
        strong('In any Hermes chat. '),
        `Ask about your ${macos ? 'Telegram or mail' : 'Telegram'} history the way you would ask a colleague: “What did Tanaka say about the invoice last week?” Hermes reads the matching messages through Mordred’s `,
        code('mordred_history_search'),
        ' tool, each with its head line (who wrote it, when), and quotes its evidence. After a history question the chat is in reader mode: Hermes cannot write files, run commands, send messages, schedule or delegate in that chat until you start a new chat.',
      ]),
      macos ? paragraph([strong('Fetching mail. '), ...syncHint('in step 2.5')]) : null,
      paragraph([
        strong('What Hermes sees. '),
        macos
          ? 'Secrets you type on this page (the app password, Telegram codes, keys) never reach the chat, the model, the tools, storage or logs. A Telegram import or a mail fetch gives Hermes counts only. '
          : 'Secrets you type on this page (Telegram codes, keys) never reach the chat, the model, the tools, storage or logs. A Telegram import gives Hermes counts only. ',
        'When you ask about your history, Hermes reads the matching messages (head line and text). The chat model must be a Venice private model or a local model, or these tools are not offered.',
      ]),
      paragraph([
        strong('Terminal only. '),
        ...(macos ? [code('hermes-mordred mail import'), ' (Takeout files), '] : []),
        code('hermes-mordred telegram sync --days 0'),
        ' (all history), ',
        code('hermes-mordred telegram logout'),
        ', and ',
        code('hermes-mordred status'),
        ' for the full report.',
      ]),
    ],
  })
}

function Checked({ checked, onChange, children }) {
  return jsxs('label', {
    style: { display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 8 },
    children: [jsx(Checkbox, { checked, onCheckedChange: (v) => onChange(v === true), style: CHECKBOX_STYLE }), jsx('span', { children })],
  })
}

function CapabilityList({ rows, error }) {
  if (error) return jsx('p', { role: 'status', children: `Windows capabilities could not be read (${reason(error)}).` })
  return jsx('ul', {
    style: { margin: '4px 0 12px', paddingLeft: 20 },
    children: (rows || []).map((row) =>
      jsx('li', {
        key: row.name,
        children: `${CAPABILITY_LABELS[row.name] || row.name}: ${
          row.supported ? (row.available ? 'available' : 'not available yet') : 'not supported on Windows'
        } (${reason(row.reason)})`,
      }),
    ),
  })
}

function HelperStep({ helper, done, refresh }) {
  const [busy, setBusy] = useState(false)
  const [checked, setChecked] = useState(null)
  const shown = checked || helper || {}
  const check = async () => {
    setBusy(true)
    try {
      const r = await call('/hardware/build', {})
      setChecked(r.helper)
      refresh()
    } catch (e) {
      host.notifyError(e, 'Could not check the helper')
    } finally {
      setBusy(false)
    }
  }
  return jsx(Step, {
    n: 1,
    title: 'Windows TPM helper (CNG)',
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: `Helper: ${HELPER_STATES[shown.state] || shown.state || 'unknown'}.` }),
        jsxs('p', {
          children: [
            'Install it with the Mordred Windows installer, or run ',
            jsx('code', { style: { userSelect: 'all' }, children: shown.install_command || 'hermes-mordred keyvault enable-winkey' }),
            ' in a terminal, then check again. This page never builds or installs it.',
          ],
        }),
        jsx(Button, { disabled: busy, onClick: check, children: busy ? 'Checking…' : 'Check again' }),
      ],
    }),
  })
}

function WindowsMemoryStep({ status, refresh }) {
  const memory = status.memory || {}
  const [noRecovery, setNoRecovery] = useState(false)
  const [noPresence, setNoPresence] = useState(false)
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  const enable = async () => {
    setBusy(true)
    setFailure(null)
    try {
      const r = await call('/memory/enable', { acknowledge_cng_no_recovery: noRecovery, acknowledge_no_presence: noPresence })
      host.notify({ kind: 'success', message: 'Memory encryption is on. Restart Hermes and its gateways to finish.' })
      ;(r.warnings || []).forEach((code) =>
        host.notify({ kind: 'info', message: `${reason(code)}${code === 'memory-write-approval-plaintext' && r.pending_approvals ? ` (${r.pending_approvals})` : ''}.` }),
      )
      refresh()
    } catch (e) {
      setFailure(e)
    } finally {
      setBusy(false)
    }
  }
  const state = `${MEMORY_STATES[memory.state] || memory.state || 'unknown'}${memory.reason ? ` (${reason(memory.reason)})` : ''}`
  return jsx(Step, {
    n: 2,
    title: 'Encrypt Hermes memory',
    done: memory.active === true,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: `Memory encryption: ${state}.` }),
        memory.detail ? jsx('p', { style: { fontSize: 12, opacity: 0.8 }, children: memory.detail }) : null,
        jsx('p', { children: status.custody_notice }),
        jsx('p', {
          children: `Per-use presence is not supported on Windows (${reason(status.presence_reason)}). Stop every Hermes gateway before turning this on, and restart Hermes afterwards.`,
        }),
        jsx(Checked, {
          checked: noRecovery,
          onChange: setNoRecovery,
          children: 'I understand there is no portable recovery: losing the TPM, this Windows account or this profile folder loses the encrypted memory.',
        }),
        jsx(Checked, {
          checked: noPresence,
          onChange: setNoPresence,
          children: 'I understand Windows asks for no per-use approval: programs running as this account can use the key.',
        }),
        jsx(Row, {
          children: jsx(Button, {
            disabled: busy || !noRecovery || !noPresence,
            onClick: enable,
            children: busy ? 'Encrypting…' : 'Turn on memory encryption',
          }),
        }),
        failure ? jsx(FailureNote, { error: failure }) : null,
      ],
    }),
  })
}

function TelegramCustodyStep({ custody, ack, setAck }) {
  if (!custody.enrolled) {
    return jsx(Step, {
      n: 3,
      title: 'Telegram custody',
      done: false,
      children: jsx('p', {
        children: custody.ceremony_command
          ? `Telegram custody is not enrolled (${reason(custody.reason)}). Run ${custody.ceremony_command} in a terminal, then reload.`
          : `Telegram custody is not enrolled (${reason(custody.reason)}). Its Windows enrollment ceremony is not available in this Mordred build yet, so Telegram setup stops here. Nothing was created.`,
      }),
    })
  }
  return jsx(Step, {
    n: 3,
    title: 'Telegram custody',
    done: false,
    children: jsx(Checked, {
      checked: ack,
      onChange: setAck,
      children: 'Telegram credentials are sealed by this PC’s TPM. I understand Windows asks for no per-use approval and there is no portable recovery.',
    }),
  })
}

function WindowsLogout({ refresh, loggedIn }) {
  const [forget, setForget] = useState(false)
  const [phrase, setPhrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [failure, setFailure] = useState(null)
  const run = async () => {
    setBusy(true)
    setResult(null)
    setFailure(null)
    try {
      const r = await call('/telegram/logout', forget ? { forget, confirm: phrase } : { forget })
      setResult(r)
      host.notify({
        kind: 'success',
        message: forget ? 'Telegram deletion finished. See the checked outcome below.' : 'Logged out of Telegram; the encrypted archive is kept.',
      })
      if (r.manual_revoke) host.notify({ kind: 'info', message: r.remedy })
      refresh()
    } catch (e) {
      setFailure(e)
      host.notifyError(e, 'Logout failed')
      refresh()
    } finally {
      setBusy(false)
      setPhrase('')
    }
  }
  if (!loggedIn && !result && !failure) return null
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: 'Disconnect Telegram' }),
      jsx(Checked, {
        checked: forget,
        onChange: setForget,
        children: 'Also delete the archive, the sealed credentials and the Telegram custody key (memory and audit keys stay).',
      }),
      forget
        ? jsx(Row, { children: jsx(Input, { value: phrase, autoComplete: 'off', placeholder: PURGE_PHRASE, onChange: (e) => setPhrase(e.target.value) }) })
        : null,
      jsx(Row, {
        children: jsx(Button, {
          variant: 'outline',
          disabled: busy || !loggedIn || (forget && phrase.trim() !== PURGE_PHRASE),
          onClick: run,
          children: busy ? 'Working…' : forget ? 'Log out and delete Telegram data' : 'Log out',
        }),
      }),
      result && result.outcome ? jsx('pre', { style: { whiteSpace: 'pre-wrap' }, children: result.outcome.join('\n') }) : null,
      result && result.remedy ? jsx('p', { children: result.remedy }) : null,
      failure && failure.info.outcome ? jsx('pre', { style: { whiteSpace: 'pre-wrap' }, children: failure.info.outcome.join('\n') }) : null,
      failure ? jsx(FailureNote, { error: failure }) : null,
    ],
  })
}

function WindowsSetup({ status, refresh }) {
  const [presenceAck, setPresenceAck] = useState(false)
  const c = status.checks || {}
  const ok = (name) => Boolean(c[name] && c[name].ok)
  const custody = status.telegram_custody || {}
  const modelOk = Boolean(status.hermes_model && status.hermes_model.ok)
  const extra = presenceAck ? { acknowledge_no_presence: true } : null
  const telegramOpen = Boolean(status.telegram_supported && custody.enrolled && presenceAck)
  const loggedIn = ok('login')
  return jsxs(Fragment, {
    children: [
      jsx('p', { children: 'Windows: keys are machine-bound CNG keys in this PC’s TPM, without per-use presence or portable recovery.' }),
      jsx('h3', { children: 'Windows capabilities' }),
      jsx(CapabilityList, { rows: status.capabilities, error: status.capabilities_error }),
      jsx(HermesModelStep, { check: status.hermes_model, refresh }),
      jsx(HelperStep, { helper: status.helper, done: ok('hardware'), refresh }),
      jsx(WindowsMemoryStep, { status, refresh }),
      status.telegram_supported
        ? jsxs(Fragment, {
            children: [
              jsx(TelegramCustodyStep, { custody, ack: presenceAck, setAck: setPresenceAck }),
              telegramOpen && modelOk && ok('memory_encryption')
                ? jsxs(Fragment, {
                    children: [
                      jsx(LlmStep, { n: 4, done: ok('privacy_llm'), hermesKey: status.hermes_venice_key, refresh, extra }),
                      ok('privacy_llm')
                        ? jsx(TelegramStep, { n: 5, done: loggedIn, needsApi: !status.telegram_api, refresh, extra })
                        : jsx(Step, { n: 5, title: 'Connect Telegram (read-only)', done: false, children: jsx('p', { children: 'Set the question model first (step 4).' }) }),
                      jsx(ImportStep, { n: 6, ready: loggedIn && ok('privacy_llm') && ok('memory_encryption'), refresh }),
                    ],
                  })
                : jsx('p', { children: 'The Telegram steps unlock once Hermes uses a private or local model, memory encryption is on and Telegram custody is confirmed.' }),
              // Keep results mounted after logout changes the login status; controls then disable.
              jsx(WindowsLogout, { refresh, loggedIn }),
            ],
          })
        : jsx('p', { role: 'status', children: 'Private Telegram is not available on this Windows profile.' }),
    ],
  })
}

const PURGE_PHRASE = 'delete my data'

function UninstallSection({ platform = null }) {
  const [open, setOpen] = useState(false)
  const [plan, setPlan] = useState(null)
  // decrypt: back to normal files (data kept unless `purge`); erase: delete encrypted data without decrypting.
  const [mode, setMode] = useState('decrypt')
  const [purge, setPurge] = useState(false)
  const [phrase, setPhrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState(null)
  // Explicit server metadata (Windows: no erase-without-decrypting; purge deletes only the memory key).
  const eraseSupported = !(platform && platform.erase_supported === false)
  const windowsUninstall = Boolean(platform && platform.purge_scope === 'memory_custody_key')
  const deleting = mode === 'erase' || purge
  const show = async () => {
    setOpen(true)
    try {
      setPlan(await call('/uninstall/plan'))
    } catch (e) {
      host.notifyError(e, 'Could not read the uninstall plan')
    }
  }
  const reset = () => {
    setOpen(false)
    setMode('decrypt')
    setPurge(false)
    setPhrase('')
  }
  const run = async () => {
    setBusy(true)
    try {
      const body = { mode, purge_data: mode === 'decrypt' && purge }
      if (deleting) body.confirm = phrase
      const job = await call('/uninstall', body)
      // Poll the job: the report is on it, and the page may go away after Mordred is removed.
      for (;;) {
        await new Promise((r) => setTimeout(r, 2000))
        const j = await call(`/jobs/${job.job_id}`)
        if (j.state !== 'running') {
          setReport({ ok: j.state === 'done', text: (j.progress && j.progress.summary) || '' })
          break
        }
      }
    } catch (e) {
      host.notifyError(e, 'Uninstall failed')
    } finally {
      setBusy(false)
      setPhrase('')
    }
  }
  const box = { border: `1px solid ${DESTRUCTIVE}`, borderRadius: 10, padding: 16, margin: '32px 0 12px' }
  const pre = { whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 280, overflow: 'auto', background: 'rgba(127,127,127,0.08)', padding: 8, borderRadius: 6 }
  const radio = { accentColor: 'CanvasText', width: 16, height: 16, marginTop: 3, flexShrink: 0 }
  const choice = (value, title, detail) =>
    jsxs('label', {
      key: value,
      style: { display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 10, cursor: 'pointer' },
      children: [
        jsx('input', { type: 'radio', name: 'mordred-uninstall-mode', checked: mode === value, onChange: () => setMode(value), style: radio }),
        jsxs('span', { children: [jsx('strong', { children: title }), jsx('br', {}), detail] }),
      ],
    })
  if (report) {
    return jsxs('section', {
      style: box,
      children: [
        jsx('h3', { style: { margin: '0 0 8px' }, children: report.ok ? 'Mordred was uninstalled' : 'Uninstall stopped' }),
        jsx('p', {
          children: report.ok
            ? windowsUninstall
              ? 'Quit Hermes Desktop and open it again to finish.'
              : 'Quit Hermes Desktop (⌘Q) and open it again to finish.'
            : 'Nothing that could not be restored was removed.',
        }),
        jsx('pre', { style: pre, children: report.text }),
      ],
    })
  }
  const shownPlan = plan && (mode === 'erase' ? plan.plan_erase : purge ? plan.plan_purge : plan.plan)
  return jsxs('section', {
    style: box,
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: 'Uninstall Mordred' }),
      jsx('p', { children: 'Removes Mordred from Hermes and restores Hermes to how it was before. Choose what happens to your encrypted data.' }),
      open
        ? jsxs(Fragment, {
            children: [
              choice(
                'decrypt',
                'Decrypt, then uninstall',
                windowsUninstall
                  ? 'Encrypted Hermes memory becomes normal files again, so Hermes keeps everything. Every Hermes gateway must be stopped.'
                  : 'Encrypted files (Hermes memory, .env, config) become normal files again, so Hermes keeps everything. Hardware approval may be requested.',
              ),
              mode === 'decrypt'
                ? jsxs('label', {
                    style: { display: 'flex', gap: 8, alignItems: 'center', margin: '8px 0 0 24px' },
                    children: [
                      jsx(Checkbox, { checked: purge, onCheckedChange: (v) => setPurge(v === true), style: CHECKBOX_STYLE }),
                      windowsUninstall
                        ? 'Also delete the Windows memory custody key. Telegram and audit custody, their history and the Mordred folders are kept and listed in the plan.'
                        : 'Also delete Mordred’s own data and keys (Telegram archive and login, vault, keyvault).',
                    ],
                  })
                : null,
              eraseSupported
                ? choice('erase', 'Erase encrypted data without decrypting, then uninstall', 'Nothing is decrypted. Encrypted Hermes memory, the vault copies of .env / config and all Mordred data and keys are deleted. Anything that exists only in encrypted form is lost for good.')
                : null,
              shownPlan ? jsx('pre', { style: { ...pre, marginTop: 12 }, children: shownPlan }) : jsx('p', { children: 'Loading…' }),
              deleting
                ? jsxs(Fragment, {
                    children: [
                      jsx('p', { children: `This deletes data and cannot be undone. Type “${PURGE_PHRASE}” to confirm.` }),
                      jsx(Row, { children: jsx(Input, { value: phrase, autoComplete: 'off', placeholder: PURGE_PHRASE, onChange: (e) => setPhrase(e.target.value) }) }),
                    ],
                  })
                : null,
              jsx(Row, {
                children: [
                  jsx(Button, {
                    key: 'go',
                    variant: 'destructive',
                    disabled: busy || !plan || (deleting && phrase.trim() !== PURGE_PHRASE),
                    onClick: run,
                    children: busy
                      ? 'Uninstalling… (approve a hardware prompt if asked)'
                      : mode === 'erase'
                        ? 'Erase and uninstall'
                        : purge
                          ? 'Decrypt, uninstall and delete Mordred data'
                          : 'Decrypt and uninstall',
                  }),
                  jsx(Button, { key: 'cancel', variant: 'outline', disabled: busy, onClick: reset, children: 'Cancel' }),
                ],
              }),
            ],
          })
        : jsx(Row, { children: jsx(Button, { variant: 'outline', onClick: show, children: 'Uninstall Mordred…' }) }),
    ],
  })
}

const INSTALL_COMMAND = 'curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash'
const WINDOWS_REINSTALL = 'Automatic repair after Hermes updates is not supported on Windows. Rerun the original Windows installer, keeping the existing Hermes home and custody keys, then restart Hermes and check again.'

// Ask Mordred's local API whether the Python side is present. Three answers:
// installed (the real API), missing (the shim in plugins/mordred/dashboard
// loaded but the package is not in Hermes's current environment) and
// unreachable (no API mounted at all: Mordred is disabled, or an older shim
// failed to import).
async function probe(path = STATUS_PATH) {
  let res
  try {
    res = await rest(path)
  } catch (err) {
    return { kind: 'unreachable', detail: String((err && err.message) || err || '') }
  }
  if (res && res.ok === false && res.error === 'mordred_not_installed') return { kind: 'missing', info: res }
  if (res && res.ok) {
    let health = null
    try {
      health = await rest('/health')
    } catch (_) {
      health = null
    }
    return { kind: 'installed', status: res, health }
  }
  return { kind: 'unreachable', detail: (res && res.error) || 'unknown' }
}

function describeMember(member) {
  if (member && member.supported === false) return 'not supported on this platform'
  if (!member || !member.present) return 'not registered'
  if (!member.valid) return 'registration damaged'
  const extras = (member.extras || []).join(', ') || 'none'
  const from = member.source === 'path' ? `local source ${member.path}` : 'PyPI'
  return `hermes-mordred ${member.version} from ${from} (extras: ${extras})`
}

function windowsEnvironment(env) {
  if (env && env.platform) return env.platform === 'win32'
  // An unreachable API has no server metadata. Hermes Desktop's local client
  // can still refuse the POSIX repair workflow on Windows.
  return typeof navigator !== 'undefined' && (
    navigator.userAgentData?.platform === 'Windows' || String(navigator.platform || '').startsWith('Win')
  )
}

async function cliExec(argv) {
  const res = await host.request('cli.exec', { argv, timeout: 600 }, 610_000)
  if (res && res.blocked) throw new Error(res.hint || 'blocked')
  return res || { code: -1, output: '' }
}

// host.restartGateway() targets messaging, not the Desktop backend importing
// Mordred. Relaunch the whole local app through its optional Electron bridge.
const DESKTOP_RESTART_DEADLINE_MS = 30_000
const MANUAL_DESKTOP_RESTART = 'Quit Hermes Desktop completely and open it again. For a remote or unknown connection, restart Hermes on the machine serving that connection.'

function RestartHermesControl() {
  const [state, setState] = useState({ kind: 'idle' })
  const mounted = useRef(true)
  const attempt = useRef(null)
  const timer = useRef(null)
  const sent = useRef(false)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      attempt.current = null
      clearTimeout(timer.current)
    }
  }, [])

  const restart = async () => {
    // The ref closes the gap before React renders the disabled state, and
    // latches a sent IPC even if it later rejects or times out.
    if (attempt.current || sent.current || !mounted.current) return
    const request = {}
    attempt.current = request
    const active = () => mounted.current && attempt.current === request
    const finish = (kind, message) => {
      if (!active()) return
      attempt.current = null
      clearTimeout(timer.current)
      timer.current = null
      setState({ kind, message })
    }
    setState({ kind: 'restarting' })
    timer.current = setTimeout(() => {
      finish('manual', `The restart could not be confirmed. ${MANUAL_DESKTOP_RESTART}`)
    }, DESKTOP_RESTART_DEADLINE_MS)
    try {
      const bridge = typeof window !== 'undefined' && window.hermesDesktop
      const connection = host.state && host.state.connectionId
      if (!bridge || typeof bridge.relaunchApp !== 'function' ||
          !connection || typeof connection.get !== 'function' || typeof host.connections !== 'function') {
        finish('manual', MANUAL_DESKTOP_RESTART)
        return
      }
      const connectionId = connection.get()
      if (!connectionId) {
        finish('manual', MANUAL_DESKTOP_RESTART)
        return
      }
      const rows = await host.connections()
      // A late registry result must not relaunch after timeout, disposal, or
      // switching to a different connection. Unknown ownership stays manual.
      if (!active()) return
      const matches = Array.isArray(rows) ? rows.filter(row => row && row.id === connectionId) : []
      if (matches.length !== 1 || matches[0].kind !== 'local' ||
          host.state?.connectionId?.get?.() !== connectionId) {
        finish('manual', MANUAL_DESKTOP_RESTART)
        return
      }
      sent.current = true
      const result = await bridge.relaunchApp()
      if (result === false || (result && result.ok === false)) {
        finish('failed', `Hermes Desktop could not be restarted. ${MANUAL_DESKTOP_RESTART}`)
      }
      // An accepted IPC is not proof of restart. Keep progress visible until
      // this window exits, or the deadline offers manual recovery.
    } catch (_) {
      finish('failed', `Hermes Desktop could not be restarted. ${MANUAL_DESKTOP_RESTART}`)
    }
  }
  return jsxs('div', {
    children: [
      state.kind === 'idle'
        ? jsx(Button, { onClick: () => setState({ kind: 'confirm' }), children: 'Restart Hermes Desktop' })
        : null,
      state.kind === 'confirm'
        ? jsxs(Fragment, {
            children: [
              jsx('p', { children: 'Restart all Hermes Desktop windows? Work in progress may be interrupted.' }),
              jsx(Button, { onClick: restart, children: 'Restart now' }),
              jsx(Button, { variant: 'outline', onClick: () => setState({ kind: 'idle' }), children: 'Cancel' }),
            ],
          })
        : null,
      state.kind === 'restarting'
        ? jsxs(Fragment, {
            children: [
              jsx('p', { role: 'status', 'aria-live': 'polite', children: 'Restarting Hermes Desktop…' }),
              jsx(Button, { disabled: true, children: 'Restarting…' }),
            ],
          })
        : null,
      state.message ? jsx('p', { role: state.kind === 'failed' ? 'alert' : 'status', children: state.message }) : null,
    ],
  })
}

function RepairPanel({ probeResult, recheck }) {
  const [busy, setBusy] = useState(false)
  const [log, setLog] = useState('')
  const [repaired, setRepaired] = useState(false)
  const missing = probeResult.kind === 'missing'
  const info = probeResult.info || {}
  const member = info.member || null
  const memberOk = Boolean(member && member.valid)
  const env = info.environment || null
  const windows = windowsEnvironment(env)
  const pre = { whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 240, overflow: 'auto', background: 'var(--muted, rgba(127,127,127,.12))', padding: 8, borderRadius: 6 }

  const repairViaShim = async () => {
    const started = await rest('/repair', { method: 'POST', body: {} })
    if (started && started.ok === false) throw new Error(started.error === 'member_missing' ? 'member_missing' : started.error)
    for (;;) {
      await new Promise((r) => setTimeout(r, 3000))
      const res = await rest('/repair')
      const r = (res && res.repair) || {}
      setLog(r.output || 'Rebuilding Hermes’s Python environment with Mordred…')
      if (r.state === 'done') return
      if (r.state === 'failed') throw new Error(`hermes pm install venv failed (exit ${r.code})`)
    }
  }
  const repairViaGateway = async () => {
    // No Mordred API at all: go through Hermes's own CLI over the gateway.
    // `plugins enable` puts mordred back into plugins.enabled if an update
    // turned it off; `pm install venv` rebuilds the environment from its
    // inputs, including Mordred's package-manager member.
    setLog('hermes plugins enable mordred …')
    const enabled = await cliExec(['plugins', 'enable', 'mordred'])
    let out = `$ hermes plugins enable mordred\n${enabled.output || ''}\n`
    setLog(out + '$ hermes pm install venv …')
    const synced = await cliExec(['pm', 'install', 'venv'])
    out += `$ hermes pm install venv\n${synced.output || ''}`
    setLog(out)
    if (synced.code !== 0) throw new Error(`hermes pm install venv failed (exit ${synced.code})`)
  }
  const repair = async () => {
    setBusy(true)
    setLog('')
    try {
      if (missing) await repairViaShim()
      else await repairViaGateway()
      setRepaired(true)
      host.notify({ kind: 'success', message: 'Mordred was rebuilt into Hermes’s environment. Restart Hermes to load it.' })
    } catch (e) {
      if (String(e && e.message) === 'member_missing') {
        setLog(`This Mordred install predates automatic repair. Reinstall it once from a terminal:\n\n${INSTALL_COMMAND}\n\n(or scripts/install.sh --from-source <checkout> for a local checkout), then restart Hermes.`)
      } else {
        host.notifyError(e, 'Repair failed')
      }
    } finally {
      setBusy(false)
    }
  }
  return jsxs('section', {
    style: { border: '1px solid var(--destructive, #c33)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: missing ? 'Mordred is not installed in Hermes’s current environment' : 'Mordred is not running in Hermes' }),
      jsx('p', {
        children: missing
          ? 'Hermes was probably updated: each update builds a new Python environment, and this one does not contain Mordred. Mordred’s protections are not active until it is repaired.'
          : 'Mordred’s local API is not loaded. Either Hermes was updated into an environment without Mordred, or Mordred was turned off in plugins.enabled. Mordred’s protections are not active.',
      }),
      env ? jsx('p', { style: { fontSize: 12, opacity: 0.8 }, children: `Environment: ${env.environment} (Python ${env.python})` }) : null,
      missing ? jsx('p', { style: { fontSize: 12, opacity: 0.8 }, children: `Package-manager registration: ${windows ? 'not supported on Windows' : describeMember(member)}` }) : null,
      windows ? jsx('p', { children: WINDOWS_REINSTALL }) : null,
      missing && !memberOk && !windows
        ? jsx('p', { children: 'Mordred never registered itself with Hermes’s package manager (installed by an older version), so the one-click repair cannot rebuild it. Reinstall once from a terminal; later updates keep it automatically.' })
        : null,
      jsx(Row, {
        children: [
          windows ? null : missing && !memberOk
            ? jsx(Button, { key: 'copy', onClick: () => navigator.clipboard && navigator.clipboard.writeText(INSTALL_COMMAND), children: 'Copy reinstall command' })
            : jsx(Button, { key: 'repair', disabled: busy || repaired, onClick: repair, children: busy ? 'Repairing… (a few minutes)' : 'Repair / reinstall Mordred' }),
          repaired ? jsx(RestartHermesControl, { key: 'restart' }) : null,
          jsx(Button, { key: 'check', variant: 'outline', disabled: busy, onClick: recheck, children: 'Check again' }),
        ],
      }),
      repaired ? jsx('p', { children: 'Done. Restart Hermes (button above, or quit and reopen the app) so it starts on the rebuilt environment, then press Check again.' }) : null,
      log ? jsx('pre', { style: pre, children: log }) : null,
    ],
  })
}

// Package updates. `/update/check` reuses Hermes's own daily plugin check or a
// day-old answer and asks PyPI at most once a day; `refresh=1` is the user's
// explicit "Check now". The decision whether an update can run here comes from
// the API (`supported` / `refusal.code`), never from text or the platform guess.
// Poll a job until it ends. Stops when the server no longer knows the job
// (ok:false: the backend restarted mid-job), after `deadlineMs`, or when
// `alive()` says the panel went away; a few transport errors in a row are
// tolerated (the backend may be busy) before giving up.
const UPDATE_JOB_DEADLINE_MS = 30 * 60 * 1000
async function pollJob(jobId, { alive = () => true, deadlineMs = UPDATE_JOB_DEADLINE_MS } = {}) {
  const until = Date.now() + deadlineMs
  let errors = 0
  for (;;) {
    await new Promise((r) => setTimeout(r, 3000))
    if (!alive()) return { state: 'abandoned' }
    if (Date.now() > until) return { state: 'timeout' }
    let res
    try {
      res = await rest(`/jobs/${jobId}`)
      errors = 0
    } catch (e) {
      if (++errors >= 5) return { state: 'lost', error: 'update_job_lost' }
      continue
    }
    if (!res || res.ok === false) return { state: 'lost', error: (res && res.error) || 'update_job_lost' }
    if (res.state !== 'running') return res
  }
}

function describeCheck(check) {
  if (!check) return 'Not checked yet.'
  const when = check.checked_at ? new Date(check.checked_at * 1000).toLocaleString() : ''
  const via = check.source === 'hermes-receipt' ? 'Hermes’s plugin check' : check.source === 'cache' ? 'cached' : 'PyPI'
  if (check.latest == null) return `Could not determine the newest release (${check.reason || 'unknown'}; ${via}${when ? ', ' + when : ''}).`
  if (check.available === true) return `Mordred ${check.latest} is available (installed: ${check.installed}).`
  return `Mordred ${check.installed} is up to date (newest: ${check.latest}; ${via}${when ? ', ' + when : ''}).`
}

function UpdatePanel({ health, onInfo = null }) {
  const [info, setInfo] = useState(null)
  const [busy, setBusy] = useState(false)
  const [checking, setChecking] = useState(false)
  const [report, setReport] = useState(null)
  const [failure, setFailure] = useState(null)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const load = useCallback(async (refresh) => {
    setChecking(true)
    setFailure(null)
    try {
      const res = await rest(`/update/check${refresh ? '?refresh=1' : ''}`)
      if (!mounted.current) return
      if (res && res.ok) {
        setInfo(res)
        if (onInfo) onInfo(res)
        if (res.check_error) setFailure({ error: 'update_check_failed', output: res.check_error })
      } else {
        setFailure({ error: (res && res.error) || 'update_check_failed' })
      }
    } catch (e) {
      if (mounted.current) setFailure({ error: 'update_check_failed' })
    } finally {
      if (mounted.current) setChecking(false)
    }
  }, [onInfo])
  useEffect(() => {
    load(false)
  }, [load])
  const check = (info && info.check) || null
  // The server compares the version on disk with the one this process runs:
  // true after an update until the gateway restarts, whatever this panel
  // remembers (it may have been remounted since).
  const restartRequired = Boolean(info && info.restart_required)
  // The running package was imported from outside the installed distribution
  // (a checkout added to Hermes's base interpreter, for instance): the server
  // names the place, offers no restart (it would change nothing) and refuses
  // the update until that copy is gone.
  const foreign = (info && info.foreign_source) || null
  const available = !restartRequired && Boolean(check && check.available === true && check.latest)
  const supported = Boolean(info && info.supported)
  const refusal = (info && info.refusal) || null
  const update = async () => {
    setBusy(true)
    setFailure(null)
    try {
      const started = await rest('/update/apply', { method: 'POST', body: { version: check.latest } })
      if (!started || started.ok === false) {
        setFailure({ error: (started && started.error) || 'update_refused' })
        return
      }
      const job = await pollJob(started.job_id, { alive: () => mounted.current })
      if (!mounted.current) return
      if (job.state === 'done') {
        setReport((job.progress && job.progress.report) || { target: check.latest })
      } else if (job.state === 'failed') {
        const p = job.progress || {}
        const rollback = p.rolled_back === false && p.rollback_output ? `\n\nrollback: ${p.rollback_output}` : ''
        setFailure({ error: job.error || 'update_failed', step: p.step, output: (p.output || p.refusal || '') + rollback })
      } else if (job.state === 'lost') {
        setFailure({ error: job.error })
      } else if (job.state === 'timeout') {
        setFailure({ error: 'update_job_timeout' })
      }
      // The job event handler in register() shows the toast; the server says
      // whether a restart is now required.
      await load(false)
    } catch (e) {
      if (mounted.current) setFailure({ error: 'update_failed', output: String((e && e.message) || e) })
    } finally {
      if (mounted.current) setBusy(false)
    }
  }
  const windows = windowsEnvironment(health && health.environment)
  const pre = { whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 240, overflow: 'auto', background: 'var(--muted, rgba(127,127,127,.12))', padding: 8, borderRadius: 6 }
  const warnings = (report && report.warnings) || []
  return jsxs('section', {
    style: available ? { border: '1px solid var(--primary, #36c)', borderRadius: 10, padding: 16, marginBottom: 12 } : { marginBottom: 12 },
    children: [
      available ? jsx('h3', { style: { margin: '0 0 8px' }, children: `Mordred ${check.latest} is available` }) : null,
      jsx('p', {
        style: { fontSize: 12, opacity: 0.8 },
        children: foreign
          ? `Running Mordred ${info.running} was loaded from ${foreign}, not from the installed package (${info.installed}). Restarting Hermes does not change that: remove that copy (for an editable install: uv pip uninstall hermes-mordred --python <its interpreter>), restart Hermes, then update.`
          : restartRequired
            ? `Running Mordred: ${info.running}. Installed package metadata: ${info.installed}. These differ; restarting Hermes reloads its installed environment.`
            : describeCheck(check),
      }),
      available && !supported && refusal && !foreign ? jsx('p', { children: explain(refusal.code) }) : null,
      warnings.length ? jsx('pre', { style: pre, children: warnings.join('\n') }) : null,
      jsx(Row, {
        children: [
          available && supported && !windows
            ? jsx(Button, { key: 'update', disabled: busy, onClick: update, children: busy ? 'Updating… (a few minutes)' : `Update Mordred to ${check.latest}` })
            : null,
          restartRequired ? jsx(RestartHermesControl, { key: 'restart' }) : null,
          jsx(Button, { key: 'check', variant: 'outline', disabled: busy || checking, onClick: () => load(true), children: checking ? 'Checking…' : 'Check for updates' }),
        ],
      }),
      failure
        ? jsxs('div', {
            role: 'alert',
            style: { border: `1px solid ${DESTRUCTIVE}`, borderRadius: 8, padding: 10, marginTop: 10 },
            children: [
              jsx('p', { style: { margin: 0 }, children: explain(failure.error) }),
              failure.step || failure.output ? jsx('pre', { style: pre, children: `${failure.step ? 'step: ' + failure.step + '\n' : ''}${failure.output || ''}` }) : null,
            ],
          })
        : null,
    ],
  })
}

function HealthLine({ health }) {
  if (!health || !health.ok) return null
  const env = health.environment || {}
  if (windowsEnvironment(env)) return jsx('p', {
    style: { fontSize: 12, opacity: 0.8 },
    children: `Mordred ${health.version} in Hermes environment ${env.environment} (Python ${env.python}). ${WINDOWS_REINSTALL}`,
  })
  const memberText = health.pm_managed === false ? 'not needed (Hermes is not pm-managed)' : describeMember(health.member)
  return jsx('p', {
    style: { fontSize: 12, opacity: 0.8 },
    children: `Mordred ${health.version} in Hermes environment ${env.environment} (Python ${env.python}). Survives Hermes updates: ${memberText}.`,
  })
}

// The update panel's state in one line near the page title; the panel itself is under Maintenance.
function UpdateLine({ info }) {
  if (!info) return null
  const check = info.check || null
  const text = info.foreign_source
    ? 'Mordred is loaded from outside its installed package.'
    : info.restart_required
      ? `Restart Hermes to load Mordred ${info.installed}.`
      : check && check.available === true && check.latest
        ? `Mordred ${check.latest} is available.`
        : describeCheck(check)
  return jsxs('div', {
    style: { display: 'flex', gap: 8, alignItems: 'center', fontSize: 12, color: MUTED_TEXT },
    children: [
      jsx('span', { key: 'text', children: text }),
      jsx(Button, { key: 'go', variant: 'ghost', 'aria-label': 'Go to Maintenance', onClick: () => focusTarget(groupAnchor('maintenance')), children: 'Maintenance' }),
    ],
  })
}

// macOS and Linux: overview card, then the four groups in a fixed order. Every
// component keeps its place on each status refresh, so typed values and focus survive.
function GroupedSetup({ status, health, sync = null, onSync = null, onImportStarted = null, updateInfo = null, onUpdateInfo = null, refresh }) {
  const layout = pageLayout(status)
  const macos = layout === 'macos'
  const v4 = macos && reportsV4(status)
  const states = stepStates(status, sync)
  const numbers = stepNumbers(status)
  // A step's props: its number, its state entry and the number of the step that lifts its blocker.
  const step = (key) => {
    const entry = states[key] || {}
    const target = entry.blocker ? BLOCKERS[entry.blocker] : null
    return { key, id: key, n: numbers[key], ...entry, goto: target ? numbers[target.step] : null }
  }
  const split = splitVault(status)
  const kind = status.hardware_kind
  const sources = storeSources(status)
  const loggedIn = Boolean(status.checks && status.checks.login && status.checks.login.ok)
  const legacyHint = loggedIn && Boolean(sources) && !(Number(sources.telegram && sources.telegram.messages) > 0)
  return jsxs(Fragment, {
    children: [
      jsx(HealthLine, { health }),
      jsx(UpdateLine, { info: updateInfo }),
      jsx(Overview, { rows: overviewRows(status, sync), layout }),
      jsx('p', { children: 'Secrets entered here go only to Mordred on this host and are sealed by its hardware key.' }),
      jsx(Group, {
        id: 'protect',
        layout,
        children: [
          jsx(EnclaveStep, { ...step('enclave'), refresh, hardwareKind: kind }),
          split ? jsx(VaultStep, { ...step('vault'), vault: status.vault, refresh }) : null,
          jsx(MemoryStep, { ...step('memory'), refresh, hardwareKind: kind, split }),
          macos
            ? v4
              ? jsx(DatabasesStep, { ...step('databases'), status, refresh })
              : jsx(UpdateRequiredStep, { key: 'databases', id: 'databases', n: STEP_NUMBERS.databases, title: 'Encrypt Hermes databases', why: WHY.databases })
            : null,
        ],
      }),
      jsx(Group, {
        id: 'connect',
        layout,
        children: [
          jsx(HermesModelStep, { ...step('hermes_model'), check: status.hermes_model, refresh, why: macos ? WHY.hermes_model : WHY.hermes_model_linux }),
          jsx(LlmStep, { ...step('question_model'), hermesKey: status.hermes_venice_key, refresh, why: WHY.question_model }),
          jsx(TelegramStep, { ...step('telegram'), needsApi: !status.telegram_api, refresh, summary: TELEGRAM_DONE, why: WHY.telegram }),
          jsx(ImportStep, {
            ...step('telegram_import'),
            title: 'Import Telegram messages',
            counts: telegramCounts(status, sync),
            onSync,
            onStarted: onImportStarted,
            refresh,
            why: WHY.telegram_import,
            legacyHint,
          }),
          macos
            ? v4
              ? jsx(MailStep, { ...step('mail'), status, refresh })
              : jsx(UpdateRequiredStep, { key: 'mail', id: 'mail', n: STEP_NUMBERS.mail, title: 'Mail over IMAP', why: WHY.mail })
            : null,
        ],
      }),
      jsx(Group, { id: 'ask', layout, children: jsx(AskHermes, { macos }) }),
      jsx(Group, {
        id: 'maintenance',
        layout,
        children: [
          jsx(UpdatePanel, { key: 'update', health, onInfo: onUpdateInfo }),
          jsx(UninstallSection, { key: 'uninstall', platform: status.uninstall || null }),
        ],
      }),
    ],
  })
}

// Everything below the title once the API answered: the grouped page on macOS and
// Linux; Windows and unsupported platforms keep the page they had.
function PageBody({ status, health, sync = null, onSync = null, onImportStarted = null, updateInfo = null, onUpdateInfo = null, refresh }) {
  const layout = pageLayout(status)
  if (layout === 'macos' || layout === 'linux') {
    return jsx(GroupedSetup, { status, health, sync, onSync, onImportStarted, updateInfo, onUpdateInfo, refresh })
  }
  return jsxs(Fragment, {
    children: [
      jsx(HealthLine, { health }),
      jsx(UpdatePanel, { health }),
      layout === 'windows'
        ? jsx(WindowsSetup, { status, refresh })
        : jsxs('section', {
            role: 'status',
            children: [
              jsx('h3', { children: 'Private Telegram setup unavailable' }),
              jsx('p', { children: MESSAGES.telegram_platform_unsupported }),
            ],
          }),
      jsx(UninstallSection, { platform: status.uninstall || null }),
    ],
  })
}

// While a job runs the whole status (store counts included) is read at most this often;
// the job itself is polled through GET /jobs/{id} every 3 s.
const STATUS_POLL_MS = 10_000

function SetupPage() {
  const [status, setStatus] = useState(null)
  const [health, setHealth] = useState(null)
  const [broken, setBroken] = useState(null)
  const [sync, setSync] = useState(null)
  const [updateInfo, setUpdateInfo] = useState(null)
  const lastSync = useRef('')
  // The last /sync answer's activity, to see a Telegram import end.
  const syncWas = useRef({ syncing: false, error: null })
  // An import this page started that no /sync answer has shown running yet: it may end
  // between two polls, so the first idle answer to a poll issued after the start (number
  // `importPending.current` or later) is its completion. null: none pending.
  const importPending = useRef(null)
  // The newest /sync poll number answered so far (polls can answer out of order).
  const newestPoll = useRef(0)
  const reading = useRef(null)
  const again = useRef(false)
  // One status read at a time: refreshes asked for meanwhile run once, after it.
  const refresh = useCallback(() => {
    if (reading.current) {
      again.current = true
      return reading.current
    }
    const read = async () => {
      try {
        do {
          again.current = false
          const result = await probe()
          if (result.kind === 'installed') {
            setBroken(null)
            setStatus(result.status)
            setHealth(result.health)
          } else {
            setStatus(null)
            setBroken(result)
          }
        } while (again.current)
      } finally {
        reading.current = null
      }
    }
    reading.current = read()
    return reading.current
  }, [])
  // The import step polls GET /sync (numbered polls; out-of-order answers are dropped);
  // keep the answer only when it changed. An import that
  // ended (syncing → idle, a new error, or an idle answer after this page started one
  // that was never seen running) changed the store counts and the step states, so the
  // status is read once more (coalesced with a read in flight).
  const onSync = useCallback(
    (answer, seq = null) => {
      // An answer older than the newest one seen is out of date: ignored entirely, before
      // it can touch the busy → idle state, the pending mark or the shown answer.
      if (typeof seq === 'number') {
        if (seq < newestPoll.current) return
        newestPoll.current = seq
      }
      const syncing = Boolean(answer && answer.syncing)
      // An answer to a poll issued after the start: seen running, the busy → idle rule
      // takes over; seen idle, the import already ended. Older answers change nothing here.
      const afterStart = importPending.current !== null && typeof seq === 'number' && seq >= importPending.current
      const startedAndEnded = afterStart && !syncing
      if (afterStart) importPending.current = null
      const key = JSON.stringify(answer)
      if (key === lastSync.current) {
        if (startedAndEnded) refresh()
        return
      }
      lastSync.current = key
      setSync(answer)
      const error = (answer && safeCode(answer.last_error)) || null
      const ended = startedAndEnded || (syncWas.current.syncing && !syncing) || (error !== null && error !== syncWas.current.error)
      syncWas.current = { syncing, error }
      if (ended) refresh()
    },
    [refresh],
  )
  const onImportStarted = useCallback((fromSeq) => {
    importPending.current = typeof fromSeq === 'number' ? fromSeq : syncPollSeq + 1
  }, [])
  useEffect(() => () => {
    importPending.current = null
  }, [])
  useEffect(() => {
    refresh()
  }, [refresh])
  // Re-read the status when a background job ends, and poll while one runs in
  // case the event was missed (e.g. the page was reopened mid-job).
  useEffect(() => {
    jobListeners.add(refresh)
    return () => jobListeners.delete(refresh)
  }, [refresh])
  // A registry job or a Telegram import (not a registry job) is running: re-read the status,
  // store counts included, at most every STATUS_POLL_MS.
  const running = Boolean(status && status.jobs && status.jobs.length) || Boolean(sync && sync.syncing)
  useEffect(() => {
    if (!running) return undefined
    const t = setInterval(refresh, STATUS_POLL_MS)
    return () => clearInterval(t)
  }, [running, refresh])
  const layout = pageLayout(status)
  // The grouped page titles its h2 groups with an h1; Windows keeps its old header.
  const grouped = layout === 'macos' || layout === 'linux'
  return jsxs('div', {
    style: { maxWidth: grouped ? 760 : 720, margin: '24px auto', padding: '0 16px' },
    children: [
      grouped ? jsx('h1', { style: { fontSize: 24, margin: '0 0 4px' }, children: 'Mordred' }) : jsx('h2', { children: 'Mordred setup' }),
      jsx('p', { style: grouped ? { marginTop: 0 } : undefined, children: TAGLINES[layout] || TAGLINES.other }),
      broken ? jsx(RepairPanel, { probeResult: broken, recheck: refresh }) : null,
      status
        ? jsx(PageBody, { status, health, sync, onSync, onImportStarted, updateInfo, onUpdateInfo: setUpdateInfo, refresh })
        : broken
          ? null
          : jsx('p', { children: 'Loading…' }),
    ],
  })
}

export default {
  id: 'mordred',
  name: 'Mordred',
  register(ctx) {
    rest = ctx.rest
    ctx.register({ id: 'setup-route', area: ROUTES_AREA, data: { path: '/mordred' }, render: () => jsx(SetupPage, {}) })
    ctx.register({ id: 'setup-nav', area: SIDEBAR_NAV_AREA, data: { path: '/mordred', label: 'Mordred', codicon: 'shield' } })
    ctx.register({
      id: 'setup-palette',
      area: PALETTE_AREA,
      data: { id: 'mordred.setup', label: 'Mordred: Set up private Telegram', keywords: ['telegram', 'privacy', 'mordred'], run: () => host.navigate('/mordred') },
    })
    // Notice at Desktop start when a Hermes update left Mordred out of the
    // environment (the Python side cannot report it: it is not there).
    ctx.setTimeout(async () => {
      const result = await probe(STARTUP_STATUS_PATH)
      if (result.kind === 'installed') {
        // Newer release known (Hermes's daily plugin check or our day-old
        // answer; at most one PyPI request a day, none when the user turned
        // Hermes's check off): say so once, the page has the button.
        try {
          const res = await rest('/update/check')
          const check = res && res.ok && res.supported && !res.restart_required && res.check
          if (check && check.available === true && check.latest) {
            host.notify({ kind: 'info', message: `Mordred ${check.latest} is available (installed: ${check.installed}). Open Mordred in the sidebar to update.` })
          }
        } catch (_) {
          // nothing to say
        }
        return
      }
      host.notify({
        kind: 'warning',
        message: result.kind === 'missing'
          ? 'Mordred is not installed in Hermes’s current environment (Hermes was probably updated). Open Mordred in the sidebar to repair it.'
          : 'Mordred is not running in Hermes. Open Mordred in the sidebar to repair it.',
      })
    }, 5000)
    ctx.onEvent('plugin.mordred.job', (e) => {
      const p = e && e.payload
      if (!p) return
      if (p.state === 'done') host.notify({ kind: 'success', message: `Mordred: ${p.kind} finished.` })
      if (p.state === 'failed') host.notify({ kind: 'error', message: `Mordred: ${explain(p.error)}` })
      if (p.state === 'done' || p.state === 'failed') jobListeners.forEach((fn) => fn())
    })
  },
}
