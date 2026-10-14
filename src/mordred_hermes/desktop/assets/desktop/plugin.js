// Mordred setup for Hermes Desktop.
//
// Secrets typed here (Telegram api_hash, login code, 2FA password, a Venice
// key) go from these masked inputs straight to Mordred's local API through
// ctx.rest(): never into the chat, the model, the agent's tools, plugin
// storage, notifications or logs. Inputs are cleared after each submit.
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
import { useCallback, useEffect, useState } from 'react'

let rest = null
// The SDK checkbox's default border is a pale theme colour that disappears on
// a white card; draw it in the text colour (CanvasText follows light/dark).
const CHECKBOX_STYLE = { borderColor: 'CanvasText', borderWidth: 1.5, borderStyle: 'solid' }
// Pages listening for background-job events (Enclave build, import).
const jobListeners = new Set()

const MESSAGES = {
  telegram_session_revoked:
    'Telegram ended this login (for example it was terminated in Telegram → Settings → Devices, or Telegram signed it out). Log in again in step 4 — your imported messages are kept.',
  telegram_platform_unsupported: 'Private Telegram requires macOS Secure Enclave or Linux TPM 2.0, with memory encryption enabled. Update both Mordred and its Desktop assets if platform metadata is missing.',
  memory_encryption_required: 'Turn on memory encryption first (step 2).',
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
  tee_unavailable: 'The hardware key helper is unavailable (step 1).',
  tee_auth_cancelled: 'Touch ID was cancelled.',
  tpm_build_failed: 'Building or probing the TPM helper failed. Install Rust, pkg-config and libtss2-dev; ensure this user can access /dev/tpmrm0.',
  enclave_build_failed: 'Building the Secure Enclave helper failed. Install the Xcode command-line tools and retry.',
  sync_in_progress: 'An import is already running.',
  telegram_not_configured: 'Set the question model first (step 3).',
  hermes_model_not_private: 'Hermes itself must use a Venice private model or a local model first (step 0).',
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
  memory_operation_in_progress: 'Another memory encryption change is running. Try again when it finishes.',
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

function explain(code) {
  return MESSAGES[code] || `Failed (${code || 'unknown'})`
}

function reason(code) {
  return REASONS[code] || code || 'unknown'
}

class MordredError extends Error {
  constructor(code, info) {
    super(explain(code))
    this.code = code
    this.info = info || {}
  }
}

async function call(path, body) {
  let res
  try {
    res = await rest(path, body === undefined ? {} : { method: 'POST', body })
  } catch (err) {
    const code = (err && (err.body && err.body.error)) || (err && err.message) || 'unknown'
    throw new MordredError(String(code).replace(/^.*"error":"([^"]+)".*$/, '$1'), (err && err.body) || {})
  }
  if (res && res.ok === false) throw new MordredError(res.error, res)
  return res
}

function FailureNote({ error }) {
  const info = (error && error.info) || {}
  return jsxs('div', {
    role: 'alert',
    style: { border: '1px solid #b91c1c', borderRadius: 8, padding: 10, marginTop: 10 },
    children: [
      jsx('p', { style: { margin: 0 }, children: error && error.message }),
      info.storage_error ? jsx('p', { children: explain(info.storage_error) }) : null,
      info.step ? jsx('p', { children: `Stopped at the ${STEP_LABELS[info.step] || info.step} step: ${reason(info.reason)}.` }) : null,
      info.remedy ? jsx('p', { children: info.remedy }) : null,
      info.custody_notice ? jsx('p', { children: `A memory custody key was created and is kept for a retry. ${info.custody_notice}` }) : null,
      info.detail ? jsx('pre', { style: { whiteSpace: 'pre-wrap', fontSize: 12 }, children: info.detail }) : null,
    ],
  })
}

function Step({ n, title, done, children }) {
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: `${done ? '✓' : n}  ${title}` }),
      done ? null : children,
    ],
  })
}

function Row({ children }) {
  return jsx('div', { style: { display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }, children })
}

function HermesModelStep({ check, refresh }) {
  const ok = Boolean(check && check.ok)
  const verifying = check && check.kind === 'venice' && check.private === null
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: `${ok ? '✓' : '0'}  Hermes chat model` }),
      ok
        ? jsx('p', { children: `${check.model} (${check.kind === 'local' ? 'local, this host only' : 'Venice private, no retention'})` })
        : jsxs(Fragment, {
            children: [
              jsx('p', {
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
          }),
    ],
  })
}

function EnclaveStep({ done, refresh, hardwareKind }) {
  const linux = hardwareKind === "tpm"
  const label = linux ? "TPM 2.0" : "Secure Enclave"
  const [busy, setBusy] = useState(false)
  const build = async () => {
    setBusy(true)
    try {
      await call('/hardware/build', {})
      host.notify({ kind: 'info', message: `Building the ${label} helper… this takes a few minutes.` })
      refresh()
    } catch (e) {
      host.notifyError(e, 'Build failed')
      setBusy(false)
    }
  }
  useEffect(() => {
    if (done) setBusy(false)
  }, [done])
  useEffect(() => {
    // A failed build ends the job without `done`; let the user retry.
    const reset = () => setBusy(false)
    jobListeners.add(reset)
    return () => jobListeners.delete(reset)
  }, [])
  return jsx(Step, {
    n: 1,
    title: label,
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: linux ? 'Telegram keys are bound to this TPM. There is no per-use user-presence prompt or portable recovery. Losing TPM state loses access.' : 'Your Telegram keys are sealed by a key that never leaves this device’s Secure Enclave.' }),
        jsx(Button, { disabled: busy, onClick: build, children: busy ? 'Building…' : `Set up ${label}` }),
      ],
    }),
  })
}

function MemoryStep({ done, refresh, hardwareKind }) {
  const [busy, setBusy] = useState(false)
  const [phrase, setPhrase] = useState(null)
  const [saved, setSaved] = useState(false)
  const enable = async () => {
    setBusy(true)
    try {
      const r = await call('/memory/enable', { acknowledge_tpm_no_recovery: hardwareKind === 'tpm' })
      if (r.recovery_passphrase) setPhrase(r.recovery_passphrase)
      else refresh()
    } catch (e) {
      host.notifyError(e, 'Memory encryption failed')
    } finally {
      setBusy(false)
    }
  }
  if (phrase) {
    return jsx(Step, {
      n: 2,
      title: 'Save your recovery passphrase',
      done: false,
      children: jsxs(Fragment, {
        children: [
          jsx('p', { children: 'Write this down and keep it safe. It is shown only once and is the only way to recover your encrypted data if this Mac is lost.' }),
          jsx('pre', { style: { fontSize: 18, padding: 12, userSelect: 'all', whiteSpace: 'pre-wrap' }, children: phrase }),
          jsxs('label', {
            style: { display: 'flex', gap: 8, alignItems: 'center' },
            children: [jsx(Checkbox, { checked: saved, onCheckedChange: (v) => setSaved(v === true), style: CHECKBOX_STYLE }), 'I have written it down'],
          }),
          jsx(Row, {
            children: jsx(Button, {
              disabled: !saved,
              onClick: () => {
                setPhrase(null)
                host.notify({ kind: 'success', message: 'Memory encryption is on. Restart Hermes to finish.' })
                refresh()
              },
              children: 'Continue',
            }),
          }),
        ],
      }),
    })
  }
  return jsx(Step, {
    n: 2,
    title: 'Encrypt Hermes memory',
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: hardwareKind === 'tpm' ? 'Memory is encrypted with a TPM-bound key, without per-use user presence or a recovery passphrase. Disable encryption before moving hosts to restore plaintext while the original TPM works. Restart Hermes after setup.' : 'Telegram requires everything Hermes remembers to be encrypted. Hardware approval may be requested.' }),
        jsx(Button, { disabled: busy, onClick: enable, children: busy ? 'Encrypting…' : 'Turn on memory encryption' }),
      ],
    }),
  })
}

function TelegramStep({ done, needsApi, refresh, n = 4, extra = null }) {
  const [apiId, setApiId] = useState('')
  const [apiHash, setApiHash] = useState('')
  const [phone, setPhone] = useState('')
  const [secret, setSecret] = useState('')
  const [flow, setFlow] = useState(null)
  const [step, setStep] = useState('phone')
  const [busy, setBusy] = useState(false)
  const reset = () => {
    setFlow(null)
    setStep('phone')
    setSecret('')
  }
  const submit = async () => {
    setBusy(true)
    try {
      if (step === 'phone') {
        const body = { phone, ...(extra || {}) }
        if (needsApi) Object.assign(body, { api_id: apiId, api_hash: apiHash })
        const r = await call('/telegram/login/start', body)
        setApiHash('')
        setFlow(r.flow_id)
        setStep(r.step)
      } else {
        const path = `/telegram/login/${flow}/${step === 'code' ? 'code' : 'password'}`
        const r = await call(path, step === 'code' ? { code: secret } : { password: secret })
        setSecret('')
        if (r.step === 'done') {
          host.notify({ kind: 'success', message: 'Telegram connected (read-only).' })
          reset()
          refresh()
        } else setStep(r.step)
      }
    } catch (e) {
      setSecret('')
      host.notifyError(e, 'Telegram login failed')
      if (e && (e.code === 'login_flow_expired' || e.code === 'login_code_expired')) reset()
    } finally {
      setBusy(false)
    }
  }
  const field = (props) => jsx(Input, { autoComplete: 'off', ...props })
  return jsx(Step, {
    n,
    title: 'Connect Telegram (read-only)',
    done,
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
                jsx(Row, { children: field({ placeholder: 'api_id', value: apiId, onChange: (e) => setApiId(e.target.value) }) }),
                jsx(Row, { children: field({ type: 'password', placeholder: 'api_hash', value: apiHash, onChange: (e) => setApiHash(e.target.value) }) }),
              ],
            })
          : null,
        step === 'phone'
          ? jsx(Row, { children: field({ placeholder: 'Phone number, e.g. +819012345678', value: phone, onChange: (e) => setPhone(e.target.value) }) })
          : jsxs(Fragment, {
              children: [
                jsx('p', {
                  children:
                    step === 'code'
                      ? 'Enter the login code Telegram just sent to your Telegram app.'
                      : 'Enter your Telegram two-step verification password (the "Cloud Password" you set in Telegram → Settings → Privacy and Security). This is not your computer password or a Mordred passphrase. It is not stored.',
                }),
                jsx(Row, { children: field({ type: 'password', placeholder: step === 'code' ? 'Telegram login code' : 'Telegram password', value: secret, onChange: (e) => setSecret(e.target.value) }) }),
              ],
            }),
        jsxs(Row, {
          children: [
            jsx(Button, { disabled: busy, onClick: submit, children: busy ? 'Working…' : step === 'phone' ? 'Send login code' : 'Continue' }),
            flow ? jsx(Button, { variant: 'ghost', onClick: () => { call(`/telegram/login/${flow}/cancel`, {}).catch(() => {}); reset() }, children: 'Cancel' }) : null,
          ],
        }),
      ],
    }),
  })
}

function LlmStep({ done, hermesKey, refresh, n = 3, extra = null }) {
  const [key, setKey] = useState('')
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:11434/v1')
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (path, body) => {
    setBusy(true)
    try {
      await call(path, { ...body, ...(extra || {}) })
      setKey('')
      host.notify({ kind: 'success', message: 'Question model set.' })
      refresh()
    } catch (e) {
      host.notifyError(e, 'Could not set the model')
    } finally {
      setBusy(false)
    }
  }
  return jsx(Step, {
    n,
    title: 'Question model (Venice private or local)',
    done,
    children: jsxs(Fragment, {
      children: [
        hermesKey
          ? jsx(Row, { children: jsx(Button, { disabled: busy, onClick: () => run('/llm/venice', { use_hermes_key: true }), children: 'Use the Venice key Hermes already has' }) })
          : null,
        jsx(Row, {
          children: [
            jsx(Input, { key: 'k', type: 'password', autoComplete: 'off', placeholder: 'Or paste a Venice API key', value: key, onChange: (e) => setKey(e.target.value) }),
            jsx(Button, { key: 'b', disabled: busy || !key, onClick: () => run('/llm/venice', { api_key: key }), children: 'Use this key' }),
          ],
        }),
        jsx(Row, {
          children: [
            jsx(Input, { key: 'e', placeholder: 'Local endpoint', value: endpoint, onChange: (e) => setEndpoint(e.target.value) }),
            jsx(Input, { key: 'm', placeholder: 'Local model name', value: model, onChange: (e) => setModel(e.target.value) }),
            jsx(Button, { key: 'l', disabled: busy || !model, onClick: () => run('/llm/local', { endpoint, model }), children: 'Use local model' }),
          ],
        }),
      ],
    }),
  })
}

function ImportStep({ ready, refresh, n = 5 }) {
  const [days, setDays] = useState(3)
  const [sync, setSync] = useState(null)
  const poll = useCallback(async () => {
    try {
      setSync(await call('/sync'))
    } catch (_) {
      /* ignore */
    }
  }, [])
  // A revoked login flips step 4 back to "log in": re-read the setup status.
  const lastError = sync && sync.last_error
  useEffect(() => {
    if (lastError === 'telegram_session_revoked') refresh()
  }, [lastError, refresh])
  useEffect(() => {
    if (!ready) return undefined
    poll()
    const t = setInterval(poll, 3000)
    return () => clearInterval(t)
  }, [ready, poll])
  const start = async () => {
    try {
      await call('/sync', { days: Number(days) || 3, include_archived: false })
      host.notify({ kind: 'info', message: 'Import started. Approve a hardware prompt if asked.' })
      poll()
    } catch (e) {
      host.notifyError(e, 'Import failed')
    }
  }
  const progress = sync && sync.progress
  return jsx(Step, {
    n,
    title: 'Import messages',
    done: false,
    children: ready
      ? jsxs(Fragment, {
          children: [
            jsx('p', { children: 'Pinned chats first. Large groups and archived chats are skipped. Nothing is downloaded twice.' }),
            jsxs(Row, {
              children: [
                'Last',
                jsx(Input, { style: { width: 70 }, type: 'number', min: 1, value: days, onChange: (e) => setDays(e.target.value) }),
                'days',
                jsx(Button, { disabled: sync && sync.syncing, onClick: start, children: sync && sync.syncing ? 'Importing…' : 'Import' }),
              ],
            }),
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
  const box = { border: '1px solid #b91c1c', borderRadius: 10, padding: 16, margin: '32px 0 12px' }
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
async function probe() {
  let res
  try {
    res = await rest('/status?client_version=3')
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
  const restart = async () => {
    try {
      await host.restartGateway()
      host.notify({ kind: 'info', message: 'Restarting the Hermes backend… If Mordred is still missing, quit and reopen Hermes.' })
    } catch (e) {
      host.notifyError(e, 'Quit and reopen Hermes to finish')
    }
    setTimeout(recheck, 8000)
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
          repaired ? jsx(Button, { key: 'restart', onClick: restart, children: 'Restart Hermes backend' }) : null,
          jsx(Button, { key: 'check', variant: 'outline', disabled: busy, onClick: recheck, children: 'Check again' }),
        ],
      }),
      repaired ? jsx('p', { children: 'Done. Restart Hermes (button above, or quit and reopen the app) so it starts on the rebuilt environment, then press Check again.' }) : null,
      log ? jsx('pre', { style: pre, children: log }) : null,
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

function SetupPage() {
  const [status, setStatus] = useState(null)
  const [health, setHealth] = useState(null)
  const [broken, setBroken] = useState(null)
  const refresh = useCallback(async () => {
    const result = await probe()
    if (result.kind === 'installed') {
      setBroken(null)
      setStatus(result.status)
      setHealth(result.health)
    } else {
      setStatus(null)
      setBroken(result)
    }
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
  const running = Boolean(status && status.jobs && status.jobs.length)
  useEffect(() => {
    if (!running) return undefined
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [running, refresh])
  const c = (status && status.checks) || {}
  const ok = (name) => Boolean(c[name] && c[name].ok)
  const loggedIn = ok('login')
  const modelOk = Boolean(status && status.hermes_model && status.hermes_model.ok)
  return jsxs('div', {
    style: { maxWidth: 720, margin: '24px auto', padding: '0 16px' },
    children: [
      jsx('h2', { children: 'Mordred setup' }),
      jsx('p', { children: 'Private, read-only Telegram for Hermes.' }),
      broken ? jsx(RepairPanel, { probeResult: broken, recheck: refresh }) : null,
      status ? jsx(HealthLine, { health }) : null,
      status && status.hardware_kind === 'cng'
        ? jsx(WindowsSetup, { status, refresh })
        : status
        ? status.telegram_supported && ["secure_enclave", "tpm"].includes(status.hardware_kind)
          ? jsxs(Fragment, {
              children: [
                jsx('p', { children: 'Secrets entered here go only to Mordred on this host and are sealed by its hardware key.' }),
                jsx(HermesModelStep, { check: status.hermes_model, refresh }),
                modelOk
                  ? jsxs(Fragment, {
                      children: [
                        jsx(EnclaveStep, { done: c.hardware?.ok === true, refresh, hardwareKind: status.hardware_kind }),
                        jsx(MemoryStep, { done: ok('memory_encryption'), refresh, hardwareKind: status.hardware_kind }),
                        jsx(LlmStep, { done: ok('privacy_llm'), hermesKey: status.hermes_venice_key, refresh }),
                        ok('privacy_llm')
                          ? jsx(TelegramStep, { done: loggedIn, needsApi: !status.telegram_api, refresh })
                          : jsx(Step, { n: 4, title: 'Connect Telegram (read-only)', done: false, children: jsx('p', { children: 'Set the question model first (step 3).' }) }),
                        jsx(ImportStep, { ready: loggedIn && ok('privacy_llm') && ok('memory_encryption'), refresh }),
                      ],
                    })
                  : jsx('p', { children: 'The remaining steps unlock once Hermes uses a private or local model.' }),
              ],
            })
          : jsxs('section', {
              role: 'status',
              children: [
                jsx('h3', { children: 'Private Telegram setup unavailable' }),
                jsx('p', { children: MESSAGES.telegram_platform_unsupported }),
              ],
            })
        : broken ? null : jsx('p', { children: 'Loading…' }),
      status ? jsx(UninstallSection, { platform: status.uninstall || null }) : null,
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
      const result = await probe()
      if (result.kind === 'installed') return
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
