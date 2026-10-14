"""The Hermes Desktop page's Windows contract (C11): syntax and explicit-metadata selection.

``plugin.js`` runs only inside Hermes Desktop, so this checks what can be
checked without it: the module parses (``node --input-type=module --check``
when Node is installed), the page asks for ``client_version=3``, the Windows
branch is chosen by ``hardware_kind`` and every capability name, reason code
and step the Windows API can return has an explicit label. Readiness is never
derived from matching English text.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from importlib import resources

import pytest

from mordred_hermes.wizard import _windows_gates

PAGE = resources.files("mordred_hermes.desktop").joinpath("assets", "desktop", "plugin.js")
CAPABILITIES = (
    "memory_custody",
    "native_audit",
    "telegram_hardware",
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
    "secret_store",
)
DESKTOP_REASONS = ("gateways-unknown", "gateways-running", "gateways", "ceremony-refused", "lifecycle-partial")
STEPS = ("capabilities", "gate", "ceremony", "proof", "lifecycle")
CODES = (
    "storage_unavailable",
    "storage_uncertain",
    "storage_error",
    "telegram_not_enrolled",
    "presence_acknowledgement_required",
    "presence_unsupported",
    "custody_unsafe",
    "custody_uncertain",
    "custody_broken",
    "memory_encryption_refused",
    "memory_disable_refused",
    "memory_operation_in_progress",
    "forget_confirm_mismatch",
    "custody_busy",
)


def source() -> str:
    return PAGE.read_text(encoding="utf-8")


def block(name: str) -> str:
    match = re.search(rf"const {name} = \{{(.*?)\n\}}", source(), re.S)
    assert match, f"{name} table missing"
    return match.group(1)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_page_is_a_valid_es_module():
    completed = subprocess.run(
        ["node", "--input-type=module", "--check"],
        input=source(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_page_requests_the_windows_capable_status_and_selects_by_hardware_kind():
    text = source()
    assert "/status?client_version=3" in text
    assert "hardware_kind === 'cng'" in text
    assert "acknowledge_cng_no_recovery: noRecovery, acknowledge_no_presence: noPresence" in text
    assert "acknowledge_no_presence: true" in text


def test_every_windows_label_comes_from_an_explicit_table():
    labels, reasons, steps, messages = (
        block("CAPABILITY_LABELS"),
        block("REASONS"),
        block("STEP_LABELS"),
        block("MESSAGES"),
    )
    for name in CAPABILITIES:
        assert re.search(rf"\b{name}:", labels), name
    every_reason = set(_windows_gates._REMEDIES) | set(_windows_gates._PROOF_REMEDIES) | set(DESKTOP_REASONS)
    for code in sorted(every_reason):
        assert f"'{code}':" in reasons or re.search(rf"\b{re.escape(code)}:", reasons), code
    for step in STEPS:
        assert re.search(rf"\b{step}:", steps), step
    for code in CODES:
        assert re.search(rf"\b{code}:", messages), code


def test_no_readiness_is_derived_from_english_text():
    text = source()
    assert ".test(String(" not in text, "error handling selects by code, not by matching the message"
    assert "/expired/" not in text
    assert "e.code === 'login_flow_expired'" in text


def render_page(script):
    """Run the page components and button handlers with a tiny SDK/React boundary."""
    if shutil.which("node") is None:
        pytest.skip("Node.js is not installed")
    page = re.sub(r"^import[\s\S]*?from '[^']+'\n", "", source(), flags=re.M)
    page = page.replace("export default {", "globalThis.plugin = {")
    harness = """
const notifications = []
let states = [], cursor = 0
const host = {notify: n => notifications.push(n), notifyError: e => notifications.push({error: e.message})}
const Button = 'button', Checkbox = 'checkbox', Input = 'input', Fragment = 'fragment'
const ROUTES_AREA = '', SIDEBAR_NAV_AREA = '', PALETTE_AREA = ''
const useCallback = f => f, useEffect = () => {}
const useState = initial => {
  const index = cursor++
  if (!(index in states)) states[index] = initial
  return [states[index], value => {states[index] = value}]
}
let jsx = (type, props) => typeof type === 'function' ? type(props) : {type, props}
let jsxs = jsx
const find = (node, predicate) => {
  if (!node || typeof node !== 'object') return null
  if (predicate(node)) return node
  const children = node.props && node.props.children
  for (const child of Array.isArray(children) ? children : [children]) {
    const found = find(child, predicate)
    if (found) return found
  }
  return null
}
"""
    result = subprocess.run(
        ["node", "--input-type=module"],
        input=harness + page + "\n" + script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_custody_step_renders_the_status_ceremony_command():
    result = render_page("""
const tree = TelegramCustodyStep({custody: {enrolled: false, reason: 'not-enrolled',
  ceremony_command: 'hermes-mordred keyvault native init --role telegram'}})
console.log(JSON.stringify(tree))
""")
    assert "Run hermes-mordred keyvault native init --role telegram in a terminal" in json.dumps(result)


@pytest.mark.parametrize("ok", [False, True])
def test_logout_renders_outcome_and_manual_remedy_after_success_or_error(ok):
    response = {
        "ok": ok,
        "forgot": True,
        "error": "custody_uncertain",
        "revoked": False,
        "manual_revoke": True,
        "remedy": "End the session in Telegram → Settings → Devices.",
        "outcome": ["Deleted:", "the sealed credentials", "Still present:", "the custody deletion journal"],
    }
    result = render_page(
        """
states = [true, 'delete my data', false]
const requests = []
rest = async (...args) => {requests.push(args); return RESPONSE}
let refreshes = 0
const refresh = () => {refreshes++}
const first = WindowsLogout({refresh, loggedIn: true})
await find(first, n => n.type === 'button').props.onClick()
cursor = 0
const tree = WindowsLogout({refresh, loggedIn: false})
console.log(JSON.stringify({tree, notifications, refreshes, requests}))
""".replace("RESPONSE", json.dumps(response))
    )
    text = json.dumps(result["tree"], ensure_ascii=False)
    assert "the sealed credentials" in text and "the custody deletion journal" in text
    assert "Settings" in text and "Devices" in text
    assert result["refreshes"] == 1, "refresh even after partial local deletion"
    assert result["requests"] == [
        ["/telegram/logout", {"method": "POST", "body": {"forget": True, "confirm": "delete my data"}}]
    ]


def test_setup_keeps_logout_component_mounted_after_status_refresh():
    result = render_page("""
jsx = jsxs = (type, props) => ({type: typeof type === 'function' ? type.name : type, props})
const tree = WindowsSetup({status: {telegram_supported: true, checks: {login: {ok: false}}}, refresh: () => {}})
console.log(JSON.stringify(find(tree, n => n.type === 'WindowsLogout')))
""")
    assert result is not None, "logout outcome must survive the status refresh after local deletion"
    assert result["props"]["loggedIn"] is False


def test_ordinary_logout_disables_controls_after_logged_out_refresh():
    result = render_page("""
rest = async () => ({ok: true, forgot: false, revoked: true})
const first = WindowsLogout({refresh: () => {}, loggedIn: true})
await find(first, n => n.type === 'button').props.onClick()
cursor = 0
const tree = WindowsLogout({refresh: () => {}, loggedIn: false})
console.log(JSON.stringify(find(tree, n => n.type === 'button').props.disabled))
""")
    assert result is True


def test_roleless_credentials_show_cli_recovery_without_new_key_instruction():
    result = render_page("""
const error = new MordredError('telegram_not_enrolled', {
  remedy: 'Run hermes-mordred telegram logout --forget in a terminal for checked recovery.'})
console.log(JSON.stringify(FailureNote({error})))
""")
    text = json.dumps(result)
    assert "hermes-mordred telegram logout --forget" in text
    assert "native init" not in text, "a new key cannot open the retained credentials"


@pytest.mark.parametrize("valid_member", [False, True])
def test_windows_missing_package_offers_manual_reinstall_without_pm_repair_or_bash(valid_member):
    result = render_page(
        """
let calls = []
rest = async (...args) => {calls.push(args); return {ok: true}}
const tree = RepairPanel({probeResult: {kind: 'missing', info: {
  environment: {platform: 'win32', environment: 'test', python: '3.12'},
  member: {present: true, valid: VALID_MEMBER}}}, recheck: () => {}})
const buttons = []
const visit = node => {
  if (!node || typeof node !== 'object') return
  if (node.type === 'button') buttons.push(node.props.children)
  const children = node.props && node.props.children
  for (const child of Array.isArray(children) ? children : [children]) visit(child)
}
visit(tree)
console.log(JSON.stringify({tree, buttons, calls}))
""".replace("VALID_MEMBER", json.dumps(valid_member))
    )
    text = json.dumps(result["tree"])
    assert "original Windows installer" in text and "existing Hermes home" in text
    assert "later updates keep it automatically" not in text
    assert "Copy reinstall command" not in result["buttons"]
    assert "Repair / reinstall Mordred" not in result["buttons"]
    assert result["calls"] == []


def test_windows_health_does_not_claim_automatic_update_survival():
    result = render_page("""
console.log(JSON.stringify(HealthLine({health: {ok: true, version: '0.2.0a0', pm_managed: true,
  environment: {platform: 'win32', environment: 'test', python: '3.12'},
  member: {present: true, valid: true, version: '0.2.0a0'}}})))
""")
    text = json.dumps(result)
    assert "original Windows installer" in text
    assert "Survives Hermes updates:" not in text


def test_posix_valid_member_keeps_automatic_repair():
    result = render_page("""
const tree = RepairPanel({probeResult: {kind: 'missing', info: {
  environment: {platform: 'darwin'}, member: {present: true, valid: true}}}, recheck: () => {}})
console.log(JSON.stringify(find(tree, n => n.type === 'button').props.children))
""")
    assert result == "Repair / reinstall Mordred"


def test_unreachable_windows_backend_does_not_offer_generic_gateway_pm_repair():
    result = render_page("""
Object.defineProperty(globalThis, 'navigator', {value: {platform: 'Win32'}, configurable: true})
const tree = RepairPanel({probeResult: {kind: 'unreachable'}, recheck: () => {}})
console.log(JSON.stringify({tree, firstButton: find(tree, n => n.type === 'button').props.children}))
""")
    assert "original Windows installer" in json.dumps(result["tree"])
    assert result["firstButton"] == "Check again"


def test_windows_client_does_not_infer_survival_from_older_health_metadata():
    result = render_page("""
Object.defineProperty(globalThis, 'navigator', {value: {platform: 'Win32'}, configurable: true})
console.log(JSON.stringify(HealthLine({health: {ok: true, version: '0.2.0a0', pm_managed: true,
  environment: {environment: 'test', python: '3.12'}, member: {present: false}}})))
""")
    text = json.dumps(result)
    assert "original Windows installer" in text
    assert "Survives Hermes updates:" not in text


# -- package updates (the Update Mordred button) ---------------------------------------------


def test_update_button_is_gated_by_the_api_not_by_text():
    page = source()
    panel = page[page.index("function UpdatePanel(") : page.index("function HealthLine(")]
    # The page asks the API and keys the button on its structured answer.
    assert "rest(`/update/check${refresh ? '?refresh=1' : ''}`)" in panel
    assert "check.available === true" in panel and "info.supported" in panel
    assert "'/update/apply'" in panel and "{ version: check.latest }" in panel
    # Whether a restart is pending comes from the server (on-disk vs running
    # version), so a remounted panel cannot claim "up to date" with old code running.
    assert "info.restart_required" in panel and "host.restartGateway()" in panel
    assert "const available = !restartRequired &&" in panel
    # Refusals are explained from the code table, never by matching English.
    assert "explain(refusal.code)" in panel
    for code in (
        "update_unsupported_windows",
        "update_source_install",
        "update_no_uv",
        "update_failed",
        "update_check_failed",
        "update_not_newer",
        "update_busy",
        "uninstall_busy",
        "update_job_lost",
        "update_job_timeout",
    ):
        assert f"  {code}:" in page, code


def test_update_polling_is_bounded_and_stops_when_the_job_is_lost():
    page = source()
    poll = page[page.index("async function pollJob(") : page.index("function describeCheck(")]
    assert "if (!alive()) return { state: 'abandoned' }" in poll
    assert "if (Date.now() > until) return { state: 'timeout' }" in poll
    assert "if (!res || res.ok === false) return { state: 'lost'" in poll
    assert "if (++errors >= 5) return { state: 'lost', error: 'update_job_lost' }" in poll
    panel = page[page.index("function UpdatePanel(") : page.index("function HealthLine(")]
    assert "pollJob(started.job_id, { alive: () => mounted.current })" in panel
    # One toast per job: the register() handler shows it, the panel does not.
    assert "host.notify({ kind: 'success'" not in panel


def test_startup_notice_mentions_a_known_newer_release_without_forcing_a_request():
    page = source()
    start = page[page.index("ctx.setTimeout(async () => {") : page.index("ctx.onEvent('plugin.mordred.job'")]
    assert "rest('/update/check')" in start and "refresh=1" not in start
    assert "check.available === true" in start
