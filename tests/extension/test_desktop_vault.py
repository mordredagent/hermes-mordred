"""The macOS vault ceremony (prepare → acknowledge → commit), memory-only enable, the lock and the anchor diagnosis."""

from __future__ import annotations

import asyncio
import functools
import json
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import _seams, _vault, api
from mordred_hermes.keyvault import _identity
from mordred_hermes.keyvault import vault as kv_vault
from mordred_hermes.keyvault._memory_hook import memory_marker_path
from mordred_hermes.wizard import env_decrypt_cli, memory_cli, vault_cli


def _tree(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


@pytest.fixture
def ceremony(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Fake env/memory ceremonies that record what they were given."""
    root = desktop.home / "mordred" / "vault"
    state: dict[str, Any] = {"env": [], "memory": [], "active": False, "enrolled": False, "env_rc": 0, "memory_rc": 0}

    def env_enable(**kwargs: Any) -> int:
        flow = kwargs["flow_session"]
        state["env"].append(
            {
                "passphrase": flow.passphrase,  # what init would take
                "unattended": flow.unattended,
                "prompt_password": kwargs["prompt_io"].ask_password("Choose a vault recovery passphrase"),
                "env_mode": stat.S_IMODE((kwargs["home"] / ".env").stat().st_mode),
            }
        )
        if state["env_rc"] == 0:
            root.mkdir(parents=True, exist_ok=True)
            (root / "manifest.1.mvmf").write_bytes(b"m")
            state["enrolled"] = True
        print("Vault initialised at", root)  # captured and discarded
        return int(state["env_rc"])

    def memory_enable(**kwargs: Any) -> int:
        state["memory"].append({"prompt_password": kwargs["prompt_io"].ask_password("x")})
        state["active"] = state["memory_rc"] == 0
        return int(state["memory_rc"])

    monkeypatch.setattr(env_decrypt_cli, "enable", env_enable)
    monkeypatch.setattr(memory_cli, "enable", memory_enable)
    monkeypatch.setattr(
        "mordred_hermes.wizard.encryption_cli._enrolled_names",
        lambda r: {".env"} if state["enrolled"] else set(),
    )
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active",
        lambda home=None: state["active"],
    )
    return SimpleNamespace(desktop=desktop, root=root, state=state, home=desktop.home)


def _prepare(c: Any) -> dict[str, Any]:
    return dict(c.desktop.post("/vault/prepare", {}))


def test_prepare_shows_a_passphrase_and_changes_nothing_on_disk(ceremony: Any, capsys: Any) -> None:
    before = _tree(ceremony.home)
    prepared = _prepare(ceremony)
    assert prepared["ok"] is True and prepared["passphrase_reused"] is False
    words = prepared["passphrase"]
    assert isinstance(words, list) and len(words) == 8 and len(set(words)) >= 6
    assert _tree(ceremony.home) == before
    phrase = " ".join(words)
    elsewhere = json.dumps([ceremony.desktop.events, ceremony.desktop.get("/status?client_version=4")])
    assert phrase not in elsewhere and phrase not in "\n".join(ceremony.desktop.logs.lines)
    assert phrase not in capsys.readouterr().out
    assert phrase not in repr(_seams.vault_flows()) + repr(_seams.vault_flows().get(prepared["flow_id"]))


def test_commit_creates_the_vault_with_the_prepared_passphrase(ceremony: Any, capsys: Any) -> None:
    prepared = _prepare(ceremony)
    committed = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {"unattended": False})
    assert committed == {"ok": True, "passphrase_reused": False}
    (seen,) = ceremony.state["env"]
    assert seen["passphrase"] == " ".join(prepared["passphrase"])  # THAT phrase, through the flow session
    assert seen["prompt_password"] == ""  # no prompt can obtain it
    assert seen["unattended"] is False and seen["env_mode"] == 0o600  # an empty private .env was created
    assert (ceremony.home / ".env").read_bytes() == b""
    phrase = " ".join(prepared["passphrase"])
    assert phrase not in json.dumps(ceremony.desktop.events) + capsys.readouterr().out
    # The flow is spent: a retry or a lost answer cannot create anything else.
    again = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {})
    assert again == {"ok": False, "error": "vault_flow_expired"}


def test_commit_keeps_an_existing_env_file(ceremony: Any) -> None:
    (ceremony.home / ".env").write_text("A=1\n", encoding="utf-8")
    prepared = _prepare(ceremony)
    assert ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {"unattended": True})["ok"] is True
    assert (ceremony.home / ".env").read_text(encoding="utf-8") == "A=1\n"
    assert ceremony.state["env"][0]["unattended"] is True


def test_commit_without_unattended_uses_the_backend_default(ceremony: Any) -> None:
    prepared = _prepare(ceremony)
    assert ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {})["ok"] is True
    assert ceremony.state["env"][0]["unattended"] is None
    assert ceremony.desktop.post("/vault/x/commit", {"unattended": "no"}) == {"ok": False, "error": "invalid_body"}


def test_an_unknown_or_expired_flow_creates_nothing(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    before = _tree(ceremony.home)
    assert ceremony.desktop.post("/vault/unknown_flow_id/commit", {}) == {"ok": False, "error": "vault_flow_expired"}
    now = [1000.0]
    flows = _vault.VaultFlows(api.generate_recovery_passphrase, clock=lambda: now[0])
    monkeypatch.setattr(_seams, "VAULT_FLOWS", flows)
    prepared = _prepare(ceremony)
    now[0] += 601
    assert ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {}) == {
        "ok": False,
        "error": "vault_flow_expired",
    }
    assert ceremony.state["env"] == [] and _tree(ceremony.home) == before


def test_a_second_prepare_replaces_the_first(ceremony: Any) -> None:
    first, second = _prepare(ceremony), _prepare(ceremony)
    assert first["passphrase"] != second["passphrase"]
    assert ceremony.desktop.post(f"/vault/{first['flow_id']}/commit", {})["error"] == "vault_flow_expired"
    assert ceremony.desktop.post(f"/vault/{second['flow_id']}/commit", {})["ok"] is True


def test_an_existing_vault_without_env_is_enrolled_without_a_new_phrase(ceremony: Any) -> None:
    ceremony.root.mkdir(parents=True)
    (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    prepared = _prepare(ceremony)
    assert prepared["passphrase"] is None and prepared["passphrase_reused"] is True
    committed = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {"unattended": True})
    assert committed == {"ok": True, "passphrase_reused": True}
    assert ceremony.state["env"][0]["passphrase"] is None


def test_a_vault_created_elsewhere_meanwhile_is_reported_as_reused(
    ceremony: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare(ceremony)

    def env_enable(**kwargs: Any) -> int:  # the vault already existed: init never asked for the phrase
        ceremony.root.mkdir(parents=True, exist_ok=True)
        (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
        return 0

    monkeypatch.setattr(env_decrypt_cli, "enable", env_enable)
    committed = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {})
    assert committed == {"ok": True, "passphrase_reused": True}


def test_nothing_to_do_and_optout(ceremony: Any) -> None:
    ceremony.root.mkdir(parents=True)
    (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    ceremony.state["enrolled"] = True
    assert _prepare(ceremony) == {"ok": False, "error": "vault_exists"}
    flow = _seams.vault_flows().prepare(reuse=True)
    assert ceremony.desktop.post(f"/vault/{flow.flow_id}/commit", {}) == {"ok": False, "error": "vault_exists"}
    (ceremony.home / "mordred" / "env-vault.optout").write_text("opt-out\n", encoding="utf-8")
    assert _prepare(ceremony) == {"ok": False, "error": "env_optout"}
    flow = _seams.vault_flows().prepare(reuse=True)
    assert ceremony.desktop.post(f"/vault/{flow.flow_id}/commit", {}) == {"ok": False, "error": "env_optout"}
    assert ceremony.state["env"] == []


def test_vault_routes_are_macos_only(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    assert _prepare(ceremony) == {"ok": False, "error": "unsupported_platform"}
    assert ceremony.desktop.post("/vault/x/commit", {}) == {"ok": False, "error": "unsupported_platform"}


def test_a_failed_commit_keeps_the_flow_until_a_vault_exists(ceremony: Any) -> None:
    ceremony.state["env_rc"] = 1
    prepared = _prepare(ceremony)
    failed = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {})
    assert failed == {"ok": False, "error": "memory_encryption_failed"}  # no anchor anywhere (fakes below: none)
    ceremony.state["env_rc"] = 0
    retried = ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {})
    assert retried == {"ok": True, "passphrase_reused": False}
    assert ceremony.state["env"][1]["passphrase"] == " ".join(prepared["passphrase"])


# -- stale anchor -------------------------------------------------------------------------------


class _Anchors:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.reads: list[str] = []

    def read(self, label: str) -> bytes | None:
        self.reads.append(label)
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


@pytest.fixture
def anchors(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A commit that fails without creating anything (ensure_initialised trusted an anchor)."""
    ceremony.state["env_rc"] = 1

    def env_enable(**kwargs: Any) -> int:
        return 1  # the passphrase is never read: an anchor made the vault look present

    def forbidden(*a: Any, **k: Any) -> Any:
        pytest.fail("default_anchor_store().read() can migrate and prompt")

    monkeypatch.setattr(env_decrypt_cli, "enable", env_enable)
    monkeypatch.setattr("mordred_hermes.keyvault._anchor_keychain.default_anchor_store", forbidden)
    found = SimpleNamespace(helper=None, legacy=_Anchors(None))
    monkeypatch.setattr(_vault, "_helper_anchor_store", lambda: found.helper)
    monkeypatch.setattr(_vault, "_legacy_anchor_store", lambda: found.legacy)
    return found


def _commit_failure(ceremony: Any) -> dict[str, Any]:
    prepared = _prepare(ceremony)
    return dict(ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {}))


def test_a_legacy_anchor_over_an_empty_directory_gets_the_remedy(ceremony: Any, anchors: Any) -> None:
    anchors.legacy = _Anchors(b"pin")
    identity = _identity.vault_identity(ceremony.root)
    assert _commit_failure(ceremony) == {
        "ok": False,
        "error": "vault_anchor_stale",
        "anchor_store": "legacy",
        "anchor_identity": identity,
        "remedy": f"security delete-generic-password -s mordred-hermes.vault.anchor -a {identity}",
    }


@pytest.mark.parametrize("leftover", ["recovery.mrkv", "blobs/ab"])
def test_no_remedy_while_recoverable_state_remains(ceremony: Any, anchors: Any, leftover: str) -> None:
    anchors.legacy = _Anchors(b"pin")
    path = ceremony.root / leftover
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
    answer = _commit_failure(ceremony)
    assert answer["anchor_store"] == "legacy" and "remedy" not in answer


def test_an_empty_blobs_directory_still_gets_the_remedy(ceremony: Any, anchors: Any) -> None:
    anchors.legacy = _Anchors(b"pin")
    (ceremony.root / "blobs").mkdir(parents=True)
    assert "remedy" in _commit_failure(ceremony)


def test_a_helper_anchor_is_read_without_legacy_fallback(ceremony: Any, anchors: Any) -> None:
    anchors.helper = _Anchors(b"pin")
    answer = _commit_failure(ceremony)
    assert answer["anchor_store"] == "helper" and "remedy" not in answer
    assert anchors.legacy.reads == []  # the helper answered: the legacy item is not even read


@pytest.mark.parametrize("legacy", [None, RuntimeError("keychain"), b"pin"])
def test_an_unreadable_helper_is_unknown(ceremony: Any, anchors: Any, legacy: Any) -> None:
    """Finding 4: with a legacy item next to an unreadable helper, the helper may hold one too: no remedy."""
    anchors.helper = _Anchors(RuntimeError("unknown cmd"))
    anchors.legacy = _Anchors(legacy)
    answer = _commit_failure(ceremony)
    assert answer["anchor_store"] == "unknown" and "remedy" not in answer


def test_no_anchor_anywhere_is_a_plain_failure(ceremony: Any, anchors: Any) -> None:
    anchors.helper = _Anchors(None)
    assert _commit_failure(ceremony) == {"ok": False, "error": "memory_encryption_failed"}


# -- a vault created by the CLI while the commit diagnoses (no false vault_anchor_stale) -------------


def _cli_creates_the_vault(root: Path, anchors: Any) -> None:
    """``encryption enable env`` in another process: init_vault's critical section under the vault locks."""
    from mordred_hermes.keyvault._storage import keyvault_lock

    kv_vault._ensure_dir(root)
    kv_vault._ensure_lock(root)
    with keyvault_lock(root):
        (root / "recovery.mrkv").write_bytes(b"r")
        (root / "manifest.0.mvmf").write_bytes(b"m")
        anchors.legacy = _Anchors(b"live-pin")  # the anchor of the vault just created


@pytest.fixture
def racing(ceremony: Any, anchors: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A commit whose wizard succeeds once it runs (the live vault is reused)."""
    monkeypatch.setattr(env_decrypt_cli, "enable", lambda **kwargs: 0)
    return SimpleNamespace(ceremony=ceremony, anchors=anchors)


def test_a_vault_created_after_the_first_snapshot_is_seen_under_the_lock(
    racing: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = _vault.vault_dir_clean
    calls: list[bool] = []

    def snapshot_then_cli(root: Path) -> bool:
        clean = real(root)
        if not calls:  # the unlocked first look: the CLI creates the vault right after it
            creator = threading.Thread(target=_cli_creates_the_vault, args=(root, racing.anchors))
            creator.start()
            creator.join(5)
        calls.append(clean)
        return clean

    monkeypatch.setattr(_vault, "vault_dir_clean", snapshot_then_cli)
    answer = _commit_failure(racing.ceremony)
    assert answer == {"ok": True, "passphrase_reused": True}  # no vault_anchor_stale: the live vault is used
    assert calls[:2] == [True, False]  # the locked snapshot saw the new vault
    assert racing.anchors.legacy.reads == []  # and nothing was diagnosed


def test_a_vault_appearing_during_the_reads_is_rechecked(racing: Any) -> None:
    root = racing.ceremony.root

    class _CreatesWhileRead(_Anchors):
        def read(self, label: str) -> bytes | None:
            # A creator that does not take the lifecycle lock: the vault appears during the read.
            root.mkdir(parents=True, exist_ok=True)
            (root / "manifest.0.mvmf").write_bytes(b"m")
            return super().read(label)

    racing.anchors.legacy = _CreatesWhileRead(b"live-pin")
    assert _commit_failure(racing.ceremony) == {"ok": True, "passphrase_reused": True}


def test_a_cli_init_waits_for_the_diagnosis_lock(racing: Any) -> None:
    root = racing.ceremony.root
    started, blocked = threading.Event(), []
    creator = threading.Thread(target=_cli_creates_the_vault, args=(root, racing.anchors))

    class _StartsTheCli(_Anchors):
        def read(self, label: str) -> bytes | None:
            if not started.is_set():
                started.set()
                creator.start()
                time.sleep(0.1)
                blocked.append(creator.is_alive())  # init_vault waits on the lifecycle lock we hold
            return super().read(label)

    racing.anchors.legacy = _StartsTheCli(None)
    answer = _commit_failure(racing.ceremony)
    creator.join(5)
    assert answer["ok"] is True and blocked == [True]
    assert kv_vault.artifacts_present(root)  # the CLI then finished: nothing of its vault was refused


def test_the_helper_store_has_no_legacy_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper.find_sekey_helper", lambda: None)
    assert _vault._helper_anchor_store() is None
    monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper.find_sekey_helper", lambda: "/bin/helper")
    store = _vault._helper_anchor_store()
    assert store is not None and store._legacy is None
    assert type(_vault._legacy_anchor_store()).__name__ == "KeychainAnchorStore"


def test_vault_dir_clean(tmp_path: Path) -> None:
    root = tmp_path / "v"
    assert _vault.vault_dir_clean(root)
    root.mkdir()
    assert _vault.vault_dir_clean(root)
    (root / "manifest.3.mvmf").write_bytes(b"m")
    assert not _vault.vault_dir_clean(root)
    (root / "manifest.3.mvmf").unlink()
    (root / "blobs").write_bytes(b"not a dir")
    assert not _vault.vault_dir_clean(root)


# -- memory only ----------------------------------------------------------------------------------


def test_memory_enable_needs_the_vault_then_the_env_target(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "generate_recovery_passphrase", lambda: pytest.fail("memory never makes a phrase"))
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "vault_required"}
    ceremony.root.mkdir(parents=True)
    (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "env_required"}
    ceremony.state["enrolled"] = True
    (ceremony.home / "mordred" / "env-vault.optout").write_text("opt-out\n", encoding="utf-8")
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "env_required"}
    (ceremony.home / "mordred" / "env-vault.optout").unlink()
    assert ceremony.desktop.post("/memory/enable", {"unattended": True}) == {"ok": True, "restart_required": True}
    assert ceremony.state["env"] == []  # memory only: .env and the vault are not touched
    assert ceremony.state["memory"] == [{"prompt_password": ""}]
    assert ceremony.desktop.post("/memory/enable") == {"ok": True, "already": True}


@pytest.mark.parametrize("state", ["no_vault", "not_enrolled", "optout"])
def test_memory_on_never_hides_a_missing_prerequisite(ceremony: Any, state: str) -> None:
    """Finding 5: ``already`` only after the vault and the env target are in place."""
    ceremony.state["active"] = True  # memory encryption reports on
    expected = "vault_required" if state == "no_vault" else "env_required"
    if state != "no_vault":
        ceremony.root.mkdir(parents=True)
        (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    if state == "optout":
        ceremony.state["enrolled"] = True
        (ceremony.home / "mordred" / "env-vault.optout").write_text("opt-out\n", encoding="utf-8")
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": expected}
    assert ceremony.state["memory"] == []


def test_memory_enable_failure(ceremony: Any) -> None:
    ceremony.root.mkdir(parents=True)
    (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    ceremony.state["enrolled"] = True
    ceremony.state["memory_rc"] = 1
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "memory_encryption_failed"}


def test_a_crashing_ceremony_is_a_code(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    ceremony.root.mkdir(parents=True)
    (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
    ceremony.state["enrolled"] = True

    def boom(**kwargs: Any) -> int:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(memory_cli, "enable", boom)
    monkeypatch.setattr(env_decrypt_cli, "enable", boom)
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "memory_encryption_failed"}
    flow = _seams.vault_flows().prepare(reuse=True)
    ceremony.state["enrolled"] = False
    assert ceremony.desktop.post(f"/vault/{flow.flow_id}/commit", {})["error"] == "memory_encryption_failed"
    assert "secret detail" not in "\n".join(ceremony.desktop.logs.lines)


# -- one ceremony at a time, never cut short by the request ---------------------------------------


def test_ceremonies_are_serialised(ceremony: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    entered, release = threading.Event(), threading.Event()

    def slow_env(**kwargs: Any) -> int:
        assert kwargs["flow_session"].passphrase  # init takes the prepared phrase
        entered.set()
        release.wait(5)
        ceremony.root.mkdir(parents=True, exist_ok=True)
        (ceremony.root / "manifest.1.mvmf").write_bytes(b"m")
        return 0

    monkeypatch.setattr(env_decrypt_cli, "enable", slow_env)
    prepared = _prepare(ceremony)
    results: list[Any] = []
    worker = threading.Thread(
        target=lambda: results.append(ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {}))
    )
    worker.start()
    assert entered.wait(5)
    assert ceremony.desktop.post("/memory/enable") == {"ok": False, "error": "memory_operation_in_progress"}
    assert ceremony.desktop.post(f"/vault/{prepared['flow_id']}/commit", {}) == {
        "ok": False,
        "error": "memory_operation_in_progress",
    }
    release.set()
    worker.join(5)
    assert results == [{"ok": True, "passphrase_reused": False}]


def test_a_cancelled_request_does_not_cancel_the_ceremony(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seams, "CEREMONY_LOCK", threading.Lock())
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def work() -> dict[str, Any]:
        entered.set()
        release.wait(5)
        finished.set()
        return {"ok": True}

    async def scenario() -> None:
        task = asyncio.ensure_future(_seams.run_ceremony(work))
        await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert _seams.CEREMONY_LOCK.locked()  # still held: the ceremony runs on
        busy = await _seams.run_ceremony(lambda: {"ok": True})
        assert json.loads(busy.body) == {"ok": False, "error": "memory_operation_in_progress"}
        release.set()
        await asyncio.to_thread(finished.wait, 5)
        for _ in range(100):
            if not _seams.CEREMONY_LOCK.locked():
                break
            await asyncio.sleep(0.01)
        assert not _seams.CEREMONY_LOCK.locked()

    asyncio.run(scenario())


def test_linux_memory_enable_runs_under_the_lock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    monkeypatch.setattr(_seams, "vault_root", lambda: tmp_path / "v")
    lock = threading.Lock()
    monkeypatch.setattr(_seams, "CEREMONY_LOCK", lock)
    armed: list[bool] = []
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: bool(armed)
    )

    def enable(**kwargs: Any) -> int:
        assert lock.locked()
        armed.append(True)
        return 0

    monkeypatch.setattr(memory_cli, "enable", enable)
    body = {"acknowledge_tpm_no_recovery": True}
    assert asyncio.run(api.memory_enable(body)) == {"ok": True, "restart_required": True}
    armed.clear()
    monkeypatch.setattr(memory_cli, "enable", lambda **kwargs: 1)
    response = asyncio.run(api.memory_enable(body))
    assert json.loads(response.body) == {"ok": False, "error": "memory_encryption_failed"}


# -- flow lifetime: the reaper and shutdown -------------------------------------------------------


def test_the_reaper_drops_expired_flows_without_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]
    vault_flows = _vault.VaultFlows(lambda: "a b c d e f g h", clock=lambda: now[0])
    mail_flows = SimpleNamespace(reaped=0)
    mail_flows.reap = lambda: setattr(mail_flows, "reaped", mail_flows.reaped + 1)
    mail_flows.cancel_all = lambda: None
    monkeypatch.setattr(_seams, "VAULT_FLOWS", vault_flows)
    monkeypatch.setattr(_seams, "MAIL_FLOWS", mail_flows)
    monkeypatch.setattr(_seams, "REAP_INTERVAL_S", 0.01)
    flow = vault_flows.prepare(reuse=False)

    async def scenario() -> None:
        task = asyncio.ensure_future(_seams.reaper())
        try:
            await asyncio.sleep(0.05)
            assert vault_flows.get(flow.flow_id) is flow  # within the TTL
            now[0] += 601.0
            for _ in range(100):
                if vault_flows._flow is None:
                    break
                await asyncio.sleep(0.01)
        finally:
            task.cancel()

    asyncio.run(scenario())
    assert vault_flows._flow is None and mail_flows.reaped > 0


def test_reap_and_cancel_failures_are_logged_not_raised(monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    def boom() -> None:
        raise RuntimeError("x")

    monkeypatch.setattr(_seams, "MAIL_FLOWS", SimpleNamespace(reap=boom, cancel_all=boom))
    monkeypatch.setattr(_seams, "VAULT_FLOWS", None)
    _seams.reap_once()
    _seams.cancel_all_flows()
    assert "RuntimeError" in caplog.text


def test_shutdown_cancels_every_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    vault_flows = _vault.VaultFlows(lambda: "a b c d e f g h")
    calls: list[str] = []
    mail_flows = SimpleNamespace(reap=lambda: None, cancel_all=lambda: calls.append("mail"))
    monkeypatch.setattr(_seams, "VAULT_FLOWS", vault_flows)
    monkeypatch.setattr(_seams, "MAIL_FLOWS", mail_flows)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/mordred")
    with TestClient(app):
        vault_flows.prepare(reuse=False)
    assert calls == ["mail"] and vault_flows._flow is None


def test_vault_flows_repr_and_discard() -> None:
    flows = _vault.VaultFlows(lambda: "alpha beta gamma delta epsilon zeta eta theta")
    flow = flows.prepare(reuse=False)
    assert "alpha" not in repr(flow) + repr(flows)
    assert flows.get("other") is None and flows.get(flow.flow_id) is flow
    assert flows.get("\u00e9t\u00e9-\ud800") is None  # non-ASCII (even unpaired surrogates) is simply unknown
    flows.discard("other")
    assert flows.get(flow.flow_id) is flow
    flows.discard(flow.flow_id)
    assert flows.get(flow.flow_id) is None and flows.reap() == 0


# -- the real wizard path with software fakes (no Enclave, no Keychain) ----------------------------


def test_the_real_ceremony_creates_a_vault_that_the_prepared_phrase_recovers(
    desktop: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tests._keyvault_fakes import FakeAnchorStore
    from tests.test_wizard_flow_session import _plaintext_home, _RecordingBackend, _stub_runtime_probes, _unlocks

    monkeypatch.setattr("sys.platform", "darwin")
    _stub_runtime_probes(monkeypatch)
    home, root = desktop.home, tmp_path / "vault"
    _plaintext_home(home)
    backend, store = _RecordingBackend(), FakeAnchorStore()
    monkeypatch.setattr(_seams, "vault_root", lambda: root)
    monkeypatch.setattr(vault_cli, "_resolve_root", lambda _r: root)
    for module in (env_decrypt_cli, memory_cli):
        monkeypatch.setattr(module, "enable", functools.partial(module.enable, backend=backend, store=store))
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active",
        lambda home=None: memory_marker_path(desktop.home).is_file(),
    )

    prepared = desktop.post("/vault/prepare", {})
    phrase = " ".join(prepared["passphrase"])
    assert not kv_vault.artifacts_present(root)
    committed = desktop.post(f"/vault/{prepared['flow_id']}/commit", {"unattended": False})
    assert committed == {"ok": True, "passphrase_reused": False}
    assert _unlocks(backend) == 0  # the new vault stays open in the flow: enrolling .env needs no unwrap
    assert backend.unattended[_identity.vault_identity(root)] is False
    with kv_vault.recover_vault(root, phrase) as opened:  # the phrase shown before commit IS the recovery phrase
        assert ".env" in opened.list_files()
    status = desktop.get("/status?client_version=4")["vault"]
    assert status == {"exists": True, "env_enrolled": True, "env_injecting": True, "optout": False, "unattended": None}

    assert desktop.post("/memory/enable") == {"ok": True, "restart_required": True}
    assert _unlocks(backend) == 1  # memory is a separate ceremony: one hot-path open
    assert desktop.post("/memory/enable") == {"ok": True, "already": True}
    assert phrase not in json.dumps(desktop.events) + "\n".join(desktop.logs.lines)


def test_reaper_interval_is_thirty_seconds() -> None:
    assert _seams.REAP_INTERVAL_S == 30.0 and _vault.VAULT_TTL_S == 600.0
    assert time.monotonic() > 0


# -- the stale anchor through the REAL wizard path (simulated Keychain and helper only) -----------


@pytest.fixture
def keychain(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Only the native boundaries are simulated: the Keychain (SimKeychain), the SE helper and the SE key."""
    from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper
    from tests._keychain_sim import SimHelperRunner, SimKeychain, SimPyobjcOps
    from tests._keyvault_fakes import FakeBackend
    from tests.test_wizard_flow_session import _stub_runtime_probes

    monkeypatch.setattr("sys.platform", "darwin")
    _stub_runtime_probes(monkeypatch)
    kc = SimKeychain()
    runner = SimHelperRunner(kc)
    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "mordred-hermes-sekey")
    monkeypatch.setattr(_seckey_helper, "_run_helper", runner)
    monkeypatch.setattr(_anchor_keychain, "_PyobjcKeychainOps", lambda: SimPyobjcOps(kc, "python-hermes"))
    backend = FakeBackend()
    monkeypatch.setattr(env_decrypt_cli, "enable", functools.partial(env_decrypt_cli.enable, backend=backend))
    root = desktop.home / "mordred" / "vault"
    (desktop.home / ".env").write_text("A=1\n", encoding="utf-8")
    return SimpleNamespace(
        desktop=desktop, kc=kc, runner=runner, backend=backend, root=root, identity=_identity.vault_identity(root)
    )


def _real_commit(k: Any) -> dict[str, Any]:
    prepared = k.desktop.post("/vault/prepare", {})
    assert prepared["ok"] is True
    return dict(k.desktop.post(f"/vault/{prepared['flow_id']}/commit", {"unattended": True}))


def _no_migration(k: Any) -> None:
    from mordred_hermes.keyvault._anchor_keychain import HELPER_SERVICE

    assert not any(cmd in ("anchor_add", "anchor_set") for cmd in k.runner.calls)  # no helper.add / put
    assert not any(op == "SecItemDelete" for _binary, op, _service in k.kc.ops)  # no legacy.discard
    assert (HELPER_SERVICE, k.identity) not in k.kc.items


def test_real_path_legacy_anchor_is_diagnosed_before_the_wizard_migrates_it(keychain: Any) -> None:
    """Finding 2: the wizard's default_anchor_store().read() would move the item into the helper store."""
    from mordred_hermes.keyvault._anchor_keychain import DEFAULT_SERVICE

    keychain.kc.seed(DEFAULT_SERVICE, keychain.identity, b"pin", creator="python-dev")
    answer = _real_commit(keychain)
    assert answer == {
        "ok": False,
        "error": "vault_anchor_stale",
        "anchor_store": "legacy",
        "anchor_identity": keychain.identity,
        "remedy": f"security delete-generic-password -s {DEFAULT_SERVICE} -a {keychain.identity}",
    }
    _no_migration(keychain)
    assert (DEFAULT_SERVICE, keychain.identity) in keychain.kc.items  # the remedy still has its target
    assert not keychain.root.exists() and keychain.backend.calls == []  # the wizard never ran
    assert (keychain.desktop.home / ".env").read_text(encoding="utf-8") == "A=1\n"


def test_real_path_helper_anchor_is_reported_without_a_remedy(keychain: Any) -> None:
    from mordred_hermes.keyvault._anchor_keychain import HELPER_SERVICE

    keychain.kc.seed(HELPER_SERVICE, keychain.identity, b"pin", creator="mordred-hermes-sekey")
    answer = _real_commit(keychain)
    assert answer["error"] == "vault_anchor_stale" and answer["anchor_store"] == "helper" and "remedy" not in answer
    assert keychain.kc.ops == [("mordred-hermes-sekey", "SecItemCopyMatching", HELPER_SERVICE)]  # one read only


def test_real_path_old_helper_with_a_legacy_item_is_unknown(keychain: Any) -> None:
    """Finding 4 through the real path: an old helper cannot say, so no deletion command is offered."""
    from mordred_hermes.keyvault._anchor_keychain import DEFAULT_SERVICE

    keychain.runner.supports_anchor = False
    keychain.kc.seed(DEFAULT_SERVICE, keychain.identity, b"pin", creator="python-dev")
    answer = _real_commit(keychain)
    assert answer["anchor_store"] == "unknown" and "remedy" not in answer
    _no_migration(keychain)


def test_real_path_without_any_anchor_creates_the_vault(keychain: Any) -> None:
    from mordred_hermes.keyvault._anchor_keychain import DEFAULT_SERVICE, HELPER_SERVICE

    answer = _real_commit(keychain)
    assert answer == {"ok": True, "passphrase_reused": False}
    assert kv_vault.artifacts_present(keychain.root)
    assert (HELPER_SERVICE, keychain.identity) in keychain.kc.items  # the new anchor lives in the helper item
    assert (DEFAULT_SERVICE, keychain.identity) not in keychain.kc.items
    assert keychain.kc.dialog_count == 0
