// Windows (and shared legacy-mode) renderings for tests/test_desktop_page.py's
// snapshot test. Fragments are flattened (React adds no element for them); the
// snapshot next to this file (windows_page.json) was produced from the page
// at f782f9cff, before the step framework.
const normal = node => {
  if (Array.isArray(node)) return node.flatMap(child => {
    const n = normal(child)
    return n && n.type === 'fragment' ? [].concat(n.props.children) : [n]
  })
  if (!node || typeof node !== 'object' || !node.props) return node
  const props = {}
  for (const [key, value] of Object.entries(node.props)) {
    if (key !== 'children') { props[key] = value; continue }
    const n = normal(value)
    props.children = n && !Array.isArray(n) && n.type === 'fragment' ? n.props.children : n
  }
  return {type: node.type, props}
}
const refresh = () => {}
const health = {ok: true, version: '0.3.0a4', pm_managed: true,
  environment: {platform: 'win32', environment: 'hermes', python: '3.11'},
  member: {present: true, valid: true, version: '0.3.0a4', source: 'pypi', extras: []}}
const checks = on => Object.fromEntries(['telethon', 'hardware', 'memory_encryption', 'login', 'privacy_llm', 'archive']
  .map(name => [name, {ok: on.includes(name), detail: name}]))
const windows = {ok: true, platform: 'win32', hardware_kind: 'cng',
  capabilities: [{name: 'memory_custody', supported: true, available: true, reason: 'enrolled'},
    {name: 'file_vault', supported: false, available: false, reason: 'excluded-on-windows'}],
  helper: {state: 'validated'}, memory: {active: true, state: 'on'}, custody_notice: 'The custody key stays.',
  presence_reason: 'unsupported', uninstall: {erase_supported: false, purge_scope: 'memory_custody_key'},
  hermes_model: {model: 'qwen', kind: 'local', private: true, ok: true}, hermes_venice_key: true, jobs: []}
const telegram = {...windows, telegram_supported: true, telegram_custody: {enrolled: true}}
const out = {}
const page = status => { states = [status, health, null]; cursor = 0; return normal(SetupPage()) }
out.unsupported = page({...windows, telegram_supported: false, checks: checks(['hardware'])})
out.not_enrolled = page({...windows, telegram_supported: true, checks: checks(['hardware', 'memory_encryption']),
  telegram_custody: {enrolled: false, reason: 'not-enrolled', ceremony_command: 'hermes-mordred keyvault native init --role telegram'}})
out.no_acknowledgement = page({...telegram, checks: checks(['hardware', 'memory_encryption'])})
const setup = status => { states = [true]; cursor = 0; return normal(WindowsSetup({status, refresh})) }
out.question_model = setup({...telegram, telegram_api: false, checks: checks(['hardware', 'memory_encryption'])})
out.login = setup({...telegram, telegram_api: false, checks: checks(['hardware', 'memory_encryption', 'privacy_llm'])})
out.connected = setup({...telegram, telegram_api: true, checks: checks(['hardware', 'memory_encryption', 'privacy_llm', 'login'])})
const fresh = (preset, view) => { states = preset; cursor = 0; return normal(view()) }
out.code = fresh(['', '', '+819012345678', '', 'f1', 'code'], () => TelegramStep({n: 5, done: false, needsApi: false, refresh}))
out.password = fresh(['', '', '+819012345678', '', 'f1', 'password'], () => TelegramStep({n: 5, done: false, needsApi: true, refresh}))
out.question_model_step = fresh([], () => LlmStep({n: 4, done: false, hermesKey: true, refresh}))
out.question_model_done = fresh([], () => LlmStep({n: 4, done: true, hermesKey: true, refresh}))
out.import_running = fresh([3, {syncing: true, progress: {dialogs_done: 1, dialogs_total: 4, messages_imported: 9}}],
  () => ImportStep({n: 6, ready: true, refresh}))
out.import_stopped = fresh([3, {syncing: false, last_error: 'telegram_rate_limited'}], () => ImportStep({n: 6, ready: true, refresh}))
out.import_ready = fresh([3, {syncing: false, last_error: null}], () => ImportStep({n: 6, ready: true, refresh}))
out.import_waiting = fresh([], () => ImportStep({n: 6, ready: false, refresh}))
out.model_local = fresh([], () => HermesModelStep({check: {model: 'qwen', kind: 'local', private: true, ok: true}, refresh}))
out.model_venice = fresh([], () => HermesModelStep({check: {model: 'e2ee-x', kind: 'venice', private: true, ok: true}, refresh}))
out.model_public = fresh([], () => HermesModelStep({check: {model: 'gpt-x', kind: 'other', private: null, ok: false}, refresh}))
out.model_unverified = fresh([], () => HermesModelStep({check: {model: 'e2ee-x', kind: 'venice', private: null, ok: false}, refresh}))
out.refusal = normal(FailureNote({error: new MordredError('memory_encryption_refused', {step: 'gate', reason: 'gateways-running',
  remedy: 'Stop every Hermes gateway, then retry.', detail: 'ceremony output', custody_notice: 'Kept for a retry.'})}))
out.forget_failed = normal(FailureNote({error: new MordredError('custody_uncertain', {remedy: 'Also end the session in Telegram → Settings → Devices.'})}))
console.log(JSON.stringify(out))
