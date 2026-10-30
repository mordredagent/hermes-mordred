"""Auth v2: browsers approved by a vault-key signature instead of pairing codes."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp
import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import pairing, trust
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, key_id
from mordred_hermes.wizard import extension_devices_cli
from tests.extension._trust_helpers import Browser, MemoryVault, receive, with_test_root


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _echo(content: str, _context: dict[str, Any]) -> Any:
    yield f"echo:{content}"


def _run(scenario: Callable[[aiohttp.ClientSession, str], Awaitable[Any]]) -> Any:
    async def main() -> Any:
        port = _free_port()
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_echo)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                return await scenario(session, f"http://127.0.0.1:{port}/ext")
        finally:
            await server.stop()

    return asyncio.run(main())


def _origin(browser: Browser) -> dict[str, str]:
    return {"Origin": browser.origin}


def _ledger() -> dict[str, Any]:
    return json.loads(trust._default_ledger().read_bytes())


def _write_ledger(doc: dict[str, Any]) -> None:
    pairing._write_private(trust._default_ledger(), json.dumps(doc).encode())


async def _approved(browser: Browser, session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    async with session.ws_connect(url, headers=_origin(browser)) as ws:
        reply: dict[str, Any] = await browser.connect(ws)
        return reply


def _flip_s(signature: str) -> str:
    """The same ECDSA signature rewritten as (r, n - s), which also verifies."""
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    raw = trust.unb64u(signature)
    s = int.from_bytes(raw[32:], "big")
    return trust.b64u(raw[:32] + (order - s).to_bytes(32, "big"))


def test_first_contact_asks_for_approval_then_admits_with_a_shared_session_key(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            challenge = await receive(ws)
            hello, eph, body = browser.hello(challenge)
            await ws.send_str(json.dumps(hello))
            unendorsed = await receive(ws)
            await ws.send_str(json.dumps({"type": "device_enroll"}))
            ok = await receive(ws)
            browser.finish(ok, eph, body)
            sealed = encrypt_message_v2(browser.session_key, "hello", key_id(browser.session_key))
            await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": sealed}))
            chunk = await receive(ws)
            return challenge, unendorsed, ok, chunk

    challenge, unendorsed, ok, chunk = _run(scenario)
    assert challenge["auth_versions"] == [2]
    assert unendorsed["type"] == "auth2_unendorsed" and unendorsed["endorsements"] == []
    fields = json.loads(unendorsed["body"])
    state = store.load(fresh=True)
    assert ok["type"] == "auth2_ok"
    # Both endorsements verify against the pinned V and name this browser.
    hermes_id, device_add = ok["endorsements"]
    v_spki = trust.unb64u(json.loads(ok["body"])["v_spki"])
    assert trust.check_endorsement(
        hermes_id, v_spki, action="hermes-id", vault_id=state.vault_id, hermes_spki=state.hermes_spki
    )
    added = trust.check_endorsement(
        device_add, v_spki, action="device-add", vault_id=state.vault_id, hermes_spki=state.hermes_spki
    )
    assert trust.unb64u(added["subject"]["device_spki"]) == browser.spki
    assert added["subject"]["sas"] == fields["sas"]
    # The reply was sealed with the key the browser derived on its own.
    assert decrypt_message(browser.session_key, chunk["content"]) == "echo:hello"
    assert list(state.devices) == [trust.device_id_of(browser.spki)]
    # The master key exists for Hermes' own uses, and never left Hermes.
    assert pairing.load_pairing() is not None


def test_the_check_code_binds_both_nonces_and_all_three_keys(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            challenge = await receive(ws)
            hello, _eph, body = browser.hello(challenge)
            await ws.send_str(json.dumps(hello))
            return challenge, body, await receive(ws)

    challenge, body, unendorsed = _run(scenario)
    state = store.load(fresh=True)
    nonce_c = trust.unb64u(json.loads(body)["nonce_c"])
    expected = trust.sas(state.v_spki, state.hermes_spki, browser.spki, trust.unb64u(challenge["nonce"]), nonce_c)
    fields = json.loads(unendorsed["body"])
    assert fields["sas"] == expected
    assert trust.verify(
        state.hermes_spki, trust.SERVER_CONTEXT + unendorsed["body"].encode(), trust.unb64u(unendorsed["sig"])
    )


def test_an_approved_browser_reconnects_without_approval(monkeypatch):
    with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            first = await browser.connect(ws)
        first_key = browser.session_key
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            second = await browser.connect(ws, enroll=False)
        return first, second, first_key

    first, second, first_key = _run(scenario)
    assert first["type"] == "auth2_ok" and second["type"] == "auth2_ok"
    # Each socket gets its own session key.
    assert first_key != browser.session_key


def test_an_unknown_browser_is_not_authenticated_until_approved(monkeypatch):
    with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            reply = await browser.connect(ws, enroll=False)
            await ws.send_str(json.dumps({"id": "h", "type": "history_get"}))
            return reply, await receive(ws)

    reply, refused = _run(scenario)
    assert reply["type"] == "auth2_unendorsed"
    assert refused == {"type": "auth_fail", "reason": "not_authenticated"}


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda hello, body: {**hello, "sig": trust.b64u(b"\x00" * 64)}, "bad_signature"),
        (lambda hello, body: {**hello, "body": body.replace('"v":2', '"v":1')}, "bad_hello"),
    ],
)
def test_a_bad_hello_is_refused(monkeypatch, mutate, reason):
    with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            hello, _eph, body = browser.hello(await receive(ws))
            await ws.send_str(json.dumps(mutate(hello, body)))
            return await receive(ws)

    assert _run(scenario) == {"type": "auth_fail", "reason": reason}


def test_a_hello_for_another_socket_or_origin_is_refused(monkeypatch):
    with_test_root(monkeypatch)
    browser = Browser(origin="chrome-extension://other")

    async def scenario(session, url):
        async with session.ws_connect(url, headers={"Origin": "chrome-extension://abc"}) as ws:
            hello, _eph, _body = browser.hello(await receive(ws))
            await ws.send_str(json.dumps(hello))
            wrong_origin = await receive(ws)
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            await receive(ws)
            hello, _eph, _body = browser.hello({"nonce": trust.b64u(b"\x01" * 32)})
            await ws.send_str(json.dumps(hello))
            wrong_nonce = await receive(ws)
        return wrong_origin, wrong_nonce

    assert _run(scenario) == ({"type": "auth_fail", "reason": "bad_hello"},) * 2


def test_approval_needs_an_extension_origin(monkeypatch):
    with_test_root(monkeypatch)
    browser = Browser(origin="")

    async def scenario(session, url):
        async with session.ws_connect(url) as ws:
            return await browser.connect(ws)

    assert _run(scenario) == {"type": "auth_fail", "reason": "extension_origin_required"}


def test_a_denied_approval_admits_nothing(monkeypatch):
    store, _vault = with_test_root(monkeypatch)

    def deny(*_args: Any, **_kwargs: Any) -> Any:
        raise trust.TrustError("approval_denied")

    monkeypatch.setattr(store, "approve", deny)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            return await browser.connect(ws)

    assert _run(scenario) == {"type": "auth_fail", "reason": "approval_denied"}
    assert store.load(fresh=True).devices == {}


def test_removing_a_browser_revokes_its_open_socket(monkeypatch):
    clock = [0.0]
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    vault = MemoryVault()
    store = vault.store(clock=lambda: clock[0])
    trust.set_store(store)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            await browser.connect(ws)
            assert await asyncio.to_thread(store.remove, trust.device_id_of(browser.spki))
            clock[0] += 10
            await ws.send_str(json.dumps({"id": "h", "type": "history_get"}))
            return await receive(ws)

    assert _run(scenario) == {"type": "auth_fail", "reason": "pairing_changed"}


def test_a_device_entry_without_v_signature_is_ignored(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser()

    async def scenario(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            await browser.connect(ws)

    _run(scenario)
    intruder = Browser()
    doc = _ledger()
    [entry] = doc["devices"].values()
    forged_body = entry["body"].replace(trust.b64u(browser.spki), trust.b64u(intruder.spki))
    doc["devices"][trust.device_id_of(intruder.spki)] = {"body": forged_body, "sig": entry["sig"]}
    _write_ledger(doc)
    devices = store.load(fresh=True).devices
    assert list(devices) == [trust.device_id_of(browser.spki)]


def test_an_endorsement_copied_back_after_removal_stays_revoked(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser()
    _run(lambda session, url: _approved(browser, session, url))
    saved = _ledger()
    device_id = trust.device_id_of(browser.spki)
    assert store.remove(device_id)

    _write_ledger(saved)
    assert store.load(fresh=True).devices == {}
    # Nor with the signature rewritten into its other valid form.
    entry = saved["devices"][device_id]
    saved["devices"][device_id] = {"body": entry["body"], "sig": _flip_s(entry["sig"])}
    _write_ledger(saved)
    assert store.load(fresh=True).devices == {}

    # Approving the same browser again issues a new endorsement, which counts.
    assert _run(lambda session, url: _approved(browser, session, url))["type"] == "auth2_ok"
    assert list(store.load(fresh=True).devices) == [device_id]


def test_an_unreadable_ledger_trusts_no_browser(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser()
    _run(lambda session, url: _approved(browser, session, url))
    pairing._write_private(trust._default_ledger(), b"{not json")
    assert store.load(fresh=True).devices == {}
    # The next approval starts the file over.
    assert _run(lambda session, url: _approved(browser, session, url))["type"] == "auth2_ok"


def test_an_approval_stored_in_the_vault_by_an_earlier_version_still_counts(monkeypatch):
    store, vault = with_test_root(monkeypatch)
    browser = Browser()
    _run(lambda session, url: _approved(browser, session, url))
    # Earlier versions kept the endorsements in the vault file itself.
    doc = json.loads(vault.files[trust.VAULT_FILE])
    doc.update(_ledger())
    doc["v"] = 1
    vault.files[trust.VAULT_FILE] = json.dumps(doc).encode()
    trust._default_ledger().unlink()
    device_id = trust.device_id_of(browser.spki)
    assert list(store.load(fresh=True).devices) == [device_id]

    assert store.remove(device_id)
    assert store.load(fresh=True).devices == {}


def test_a_test_root_is_refused_without_its_variable(monkeypatch):
    store, _vault = with_test_root(monkeypatch)
    store.ensure_root()
    monkeypatch.delenv(trust.TEST_ROOT_ENV)
    with pytest.raises(trust.TrustError) as caught:
        store.load(fresh=True)
    assert caught.value.reason == "test_root_refused"


def test_a_test_root_is_never_created_under_the_default_home(monkeypatch, tmp_path):
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    assert not trust.test_root_allowed()


def test_the_enclave_signer_reports_a_cancelled_sheet_as_denied(monkeypatch):
    from mordred_hermes.keyvault._seckey_errors import _OpsError

    class Ops:
        def sign(self, tag: bytes, messages: list[bytes], reason: str) -> list[bytes]:
            raise _OpsError(-2, "com.apple.LocalAuthentication", "Canceled by user.")

    monkeypatch.setattr(trust, "_helper", lambda: Ops())
    signer = trust._EnclaveSigner(b"t" * 16, b"spki")
    with pytest.raises(trust.TrustError) as caught:
        signer.sign([b"m"], "reason")
    assert caught.value.reason == "approval_denied"


def test_the_devices_command_lists_and_removes(monkeypatch, capsys):
    store, _vault = with_test_root(monkeypatch)
    browser = Browser(label="Brave on Mac")
    store.approve(browser.spki, browser.label, browser.origin, "ABC-DEF")
    assert extension_devices_cli.extension_devices() == 0
    listed = capsys.readouterr().out
    device_id = trust.device_id_of(browser.spki)
    assert device_id in listed and "Brave on Mac" in listed and "[test root]" in listed
    assert extension_devices_cli.extension_devices(remove=device_id) == 0
    assert extension_devices_cli.extension_devices(remove=device_id) == 1
    assert store.load(fresh=True).devices == {}


def test_the_vault_is_opened_only_when_another_writer_changed_it(monkeypatch):
    # Each open unwraps the vault master, which can be a Touch ID prompt.
    clock = [0.0]
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    vault = MemoryVault()
    store = vault.store(clock=lambda: clock[0])
    trust.set_store(store)
    browser = Browser()

    async def frames(ws: Any, count: int) -> None:
        for n in range(count):
            clock[0] += 10  # well past the freshness window each time
            await ws.send_str(json.dumps({"id": f"h{n}", "type": "history_get"}))
            assert (await receive(ws))["type"] != "auth_fail"

    async def first(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            assert (await browser.connect(ws))["type"] == "auth2_ok"
            await frames(ws, 5)

    _run(first)
    # Read the empty vault, create the root. The approval itself opens nothing.
    assert vault.opens == 2

    async def again(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            clock[0] += 10
            assert (await browser.connect(ws, enroll=False))["type"] == "auth2_ok"
            await frames(ws, 5)

    _run(again)
    assert vault.opens == 2

    # Another process (``extension devices --remove``) commits a new generation.
    vault.store().remove(trust.device_id_of(browser.spki))
    opens = vault.opens

    async def revoked(session, url):
        async with session.ws_connect(url, headers=_origin(browser)) as ws:
            clock[0] += 10
            return await browser.connect(ws, enroll=False)

    assert _run(revoked)["type"] == "auth2_unendorsed"  # back to asking for approval
    assert vault.opens == opens + 1


def test_a_store_primed_at_start_up_reads_without_opening_the_vault(monkeypatch):
    clock = [0.0]
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    vault = MemoryVault()
    vault.store().ensure_root()
    store = vault.store(clock=lambda: clock[0])
    opens = vault.opens

    store.prime(vault, "mordred-hermes.vault.test")
    clock[0] += 10
    assert store.load() is not None
    assert vault.opens == opens


def test_a_store_primed_at_start_up_approves_a_browser_without_opening_the_vault(monkeypatch):
    # Opening the vault is a Touch ID prompt of its own; the approval is one already.
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    vault = MemoryVault()
    store = vault.store()
    trust.set_store(store)
    store.prime(vault, "mordred-hermes.vault.test")  # an empty vault gets its roots here
    assert trust.VAULT_FILE in vault.files

    browser = Browser()
    assert _run(lambda session, url: _approved(browser, session, url))["type"] == "auth2_ok"
    assert vault.opens == 0
