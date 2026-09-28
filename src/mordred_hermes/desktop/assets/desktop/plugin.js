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

const MESSAGES = {
  memory_encryption_required: 'Turn on memory encryption first (step 2).',
  memory_encryption_failed: 'Memory encryption could not be turned on. Check Touch ID and try again.',
  telegram_already_logged_in: 'Telegram is already connected.',
  invalid_api_credentials: 'api_id must be a number and api_hash 32 hex characters (my.telegram.org → API development tools).',
  invalid_phone: 'Enter the phone number in international format, e.g. +819012345678.',
  login_code_invalid: 'That login code is not correct.',
  login_code_expired: 'The login code expired. Start again.',
  login_password_invalid: 'That two-step verification password is not correct.',
  login_flow_expired: 'This login attempt expired. Start again.',
  telegram_rate_limited: 'Telegram asked to wait before trying again.',
  hermes_venice_key_missing: 'No Venice key is set in Hermes. Enter one below.',
  local_endpoint_invalid: 'Use http://127.0.0.1:<port>/… (this Mac only).',
  tee_unavailable: 'The Secure Enclave helper is missing (step 1).',
  tee_auth_cancelled: 'Touch ID was cancelled.',
  enclave_build_failed: 'Building the Secure Enclave helper failed. Install the Xcode command-line tools and retry.',
  sync_in_progress: 'An import is already running.',
  telegram_not_configured: 'Set the question model first (step 3).',
  hermes_model_not_private: 'Hermes itself must use a Venice private model or a local model first (step 0).',
}

function explain(code) {
  return MESSAGES[code] || `Failed (${code || 'unknown'})`
}

async function call(path, body) {
  try {
    const res = await rest(path, body === undefined ? {} : { method: 'POST', body })
    if (res && res.ok === false) throw new Error(res.error)
    return res
  } catch (err) {
    const code = (err && (err.body && err.body.error)) || (err && err.message) || 'unknown'
    throw new Error(explain(String(code).replace(/^.*"error":"([^"]+)".*$/, '$1')))
  }
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
        ? jsx('p', { children: `${check.model} (${check.kind === 'local' ? 'local, this Mac only' : 'Venice private, no retention'})` })
        : jsxs(Fragment, {
            children: [
              jsx('p', {
                children: verifying
                  ? `Could not verify ${check.model} with Venice right now (offline?).`
                  : `Everything Hermes reads goes to its chat model${check && check.model ? ` (now: ${check.model})` : ''}. For Telegram it must be a Venice private model or a model on this Mac.`,
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

function EnclaveStep({ done, refresh }) {
  const [busy, setBusy] = useState(false)
  const build = async () => {
    setBusy(true)
    try {
      await call('/enclave/build', {})
      host.notify({ kind: 'info', message: 'Building the Secure Enclave helper… this takes a few minutes.' })
    } catch (e) {
      host.notifyError(e, 'Build failed')
      setBusy(false)
    }
  }
  useEffect(() => {
    if (done) setBusy(false)
  }, [done])
  return jsx(Step, {
    n: 1,
    title: 'Secure Enclave',
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: 'Your Telegram keys are sealed by a key that never leaves this Mac’s Secure Enclave.' }),
        jsx(Button, { disabled: busy, onClick: build, children: busy ? 'Building…' : 'Set up the Secure Enclave' }),
      ],
    }),
  })
}

function MemoryStep({ done, refresh }) {
  const [busy, setBusy] = useState(false)
  const [phrase, setPhrase] = useState(null)
  const [saved, setSaved] = useState(false)
  const enable = async () => {
    setBusy(true)
    try {
      const r = await call('/memory/enable', {})
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
            children: [jsx(Checkbox, { checked: saved, onCheckedChange: (v) => setSaved(v === true) }), 'I have written it down'],
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
        jsx('p', { children: 'Telegram requires everything Hermes remembers to be encrypted. Touch ID may be requested.' }),
        jsx(Button, { disabled: busy, onClick: enable, children: busy ? 'Encrypting…' : 'Turn on memory encryption' }),
      ],
    }),
  })
}

function TelegramStep({ done, needsApi, refresh }) {
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
        const body = { phone }
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
      if (/expired/.test(String(e && e.message))) reset()
    } finally {
      setBusy(false)
    }
  }
  const field = (props) => jsx(Input, { autoComplete: 'off', ...props })
  return jsx(Step, {
    n: 4,
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
                jsx('p', { children: step === 'code' ? 'Enter the login code Telegram just sent to your Telegram app.' : 'Enter your two-step verification password (not stored).' }),
                jsx(Row, { children: field({ type: 'password', placeholder: step === 'code' ? 'Login code' : 'Password', value: secret, onChange: (e) => setSecret(e.target.value) }) }),
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

function LlmStep({ done, hermesKey, refresh }) {
  const [key, setKey] = useState('')
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:11434/v1')
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (path, body) => {
    setBusy(true)
    try {
      await call(path, body)
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
    n: 3,
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

function ImportStep({ ready, refresh }) {
  const [days, setDays] = useState(3)
  const [sync, setSync] = useState(null)
  const poll = useCallback(async () => {
    try {
      setSync(await call('/sync'))
    } catch (_) {
      /* ignore */
    }
  }, [])
  useEffect(() => {
    if (!ready) return undefined
    poll()
    const t = setInterval(poll, 3000)
    return () => clearInterval(t)
  }, [ready, poll])
  const start = async () => {
    try {
      await call('/sync', { days: Number(days) || 3, include_archived: false })
      host.notify({ kind: 'info', message: 'Import started. Approve Touch ID if asked.' })
      poll()
    } catch (e) {
      host.notifyError(e, 'Import failed')
    }
  }
  const progress = sync && sync.progress
  return jsx(Step, {
    n: 5,
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

function SetupPage() {
  const [status, setStatus] = useState(null)
  const refresh = useCallback(async () => {
    try {
      setStatus(await call('/status'))
    } catch (e) {
      host.notifyError(e, 'Mordred is not reachable. Restart Hermes after installing Mordred.')
    }
  }, [])
  useEffect(() => {
    refresh()
  }, [refresh])
  const c = (status && status.checks) || {}
  const ok = (name) => Boolean(c[name] && c[name].ok)
  const loggedIn = ok('login')
  const modelOk = Boolean(status && status.hermes_model && status.hermes_model.ok)
  return jsxs('div', {
    style: { maxWidth: 720, margin: '24px auto', padding: '0 16px' },
    children: [
      jsx('h2', { children: 'Mordred setup' }),
      jsx('p', { children: 'Private, read-only Telegram for Hermes. Secrets entered here go only to Mordred on this Mac and are sealed by the Secure Enclave.' }),
      status
        ? jsxs(Fragment, {
            children: [
              jsx(HermesModelStep, { check: status.hermes_model, refresh }),
              modelOk
                ? jsxs(Fragment, {
                    children: [
                      jsx(EnclaveStep, { done: c.secure_enclave && /helper ready/.test(c.secure_enclave.detail || ''), refresh }),
                      jsx(MemoryStep, { done: ok('memory_encryption'), refresh }),
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
    ctx.onEvent('plugin.mordred.job', (e) => {
      const p = e && e.payload
      if (!p) return
      if (p.state === 'done') host.notify({ kind: 'success', message: `Mordred: ${p.kind} finished.` })
      if (p.state === 'failed') host.notify({ kind: 'error', message: `Mordred: ${explain(p.error)}` })
    })
  },
}
