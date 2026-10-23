"""Shared fakes and the HTTP fixture for the Desktop API tests (macOS sections, D4).

Fakes replace the module seams of :mod:`mordred_hermes.desktop.api` only
(``_mail_flows``, ``_forget``, ``_open_store_readonly``, ``_mail_secret_store``,
``_imap_status``, ``_run_fetch``, ``_fetch_env``, ``_store_refusal``): no IMAP,
no Secure Enclave, no SQLCipher. Not a ``test_*`` module.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.desktop import api

PREFIX = "/api/plugins/mordred"

# Canaries: none of these may leave the request that carried them (or, for the
# passphrase, the /vault/prepare answer; for folder names, the folders step).
ADDRESS = "canary.owner@example.org"
EXTRA = "canary.alias@example.net"
APP_PASSWORD = "CANARYAPPPASSWD1"
FOLDER = "Canary Private Folder"
API_HASH = "ef" * 16
TG_CODE = "97531"
TG_PASSWORD = "canary-2fa-secret"
VENICE = "venice-CANARY-key"
SECRETS = (ADDRESS, EXTRA, APP_PASSWORD, FOLDER, API_HASH, TG_CODE, TG_PASSWORD, VENICE)


class FakeSetupError(Exception):
    """Stands in for ``MailSetupError(code, hint)``."""

    def __init__(self, code: str, hint: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.hint = hint


@dataclass
class FakeFolder:
    name: str
    display: str


@dataclass
class FakeFlow:
    flow_id: str = "flow_ABCDEFGH1234"
    step: str = "done"
    question: str | None = None
    gmail: bool = False
    account: str = "mail"
    folders: tuple[FakeFolder, ...] = ()


@dataclass
class FakeFlows:
    """``MailSetupFlows`` double: records calls (secrets included, to check they arrived) and scripts answers."""

    start_result: Any = field(default_factory=FakeFlow)
    finish_error: BaseException | None = None
    calls: list[tuple[str, Any]] = field(default_factory=list)
    reaped: int = 0
    cancelled_all: int = 0

    def start(self, **kwargs: Any) -> Any:
        self.calls.append(("start", kwargs))
        if isinstance(self.start_result, BaseException):
            raise self.start_result
        return self.start_result

    def finish(self, flow_id: str, *, selection: str | None) -> Any:
        self.calls.append(("finish", (flow_id, selection)))
        if self.finish_error is not None:
            raise self.finish_error
        return FakeFlow(flow_id=flow_id)

    def cancel(self, flow_id: str) -> None:
        self.calls.append(("cancel", flow_id))

    def cancel_all(self) -> None:
        self.cancelled_all += 1
        self.calls.append(("cancel_all", None))

    def reap(self) -> None:
        self.reaped += 1


class FakeMailSecrets:
    """``MailSecretStore`` double: ``flags()`` / ``residue()`` only."""

    def __init__(self, flags: Any = None, *, residue: bool = False, raises: BaseException | None = None) -> None:
        self._flags = flags
        self._residue = residue
        self._raises = raises

    def flags(self) -> Any:
        if self._raises is not None:
            raise self._raises
        return self._flags

    def residue(self) -> bool:
        return self._residue


class FakeRefused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FakeReadonlyStore:
    def __init__(self, status: Any) -> None:
        self._status = status

    def status(self) -> Any:
        return self._status


def store_status(telegram: tuple[int, int, int] = (3, 25, 25), mail: tuple[int, int, int] | None = None) -> Any:
    sources: dict[str, Any] = {}
    for name, counts in (("telegram", telegram), ("mail", mail)):
        if counts is not None:
            conversations, messages, parts = counts
            sources[name] = {
                "conversations": conversations,
                "messages": messages,
                "parts": parts,
                "uncommitted_messages": 0,
            }
    return {"schema_version": 2, "sources": sources, "runs": {}, "last_run": None}


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage() + repr(record.args) + str(record.exc_info))


@dataclass
class Desktop:
    http: TestClient
    home: Path
    events: list[tuple[str, dict[str, Any]]]
    logs: _Records
    flows: FakeFlows

    def post(self, path: str, body: Any = None, *, raw: bytes | None = None) -> dict[str, Any]:
        if raw is not None:
            response = self.http.post(PREFIX + path, content=raw, headers={"content-type": "application/json"})
        else:
            response = self.http.post(PREFIX + path, json={} if body is None else body)
        assert response.status_code == 200, response.text  # Desktop logs non-2xx; failures are ok:false
        return dict(response.json())

    def get(self, path: str) -> dict[str, Any]:
        response = self.http.get(PREFIX + path)
        assert response.status_code == 200, response.text
        return dict(response.json())

    def wait_job(self, job_id: str) -> dict[str, Any]:
        import time

        for _ in range(200):
            job = self.get(f"/jobs/{job_id}")
            if job.get("state") != "running":
                return job
            time.sleep(0.01)
        raise AssertionError("job never finished")

    def leaked(self, *extra: Any) -> list[str]:
        """Every canary found in the events, the log records or ``extra`` answers."""
        text = json.dumps([self.events, *extra], default=str) + "\n".join(self.logs.lines)
        return [secret for secret in SECRETS if secret in text]


def desktop_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Desktop]:
    """The router on a TestClient (lifespan running), as macOS, with every mail/store seam faked.

    Served as the ``desktop`` fixture by ``tests/extension/conftest.py``.
    """
    home = tmp_path / "hermes-home"
    with open_private_directory(home, create=True):
        pass
    events: list[tuple[str, dict[str, Any]]] = []
    flows = FakeFlows()
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(api, "_home", lambda: home)
    monkeypatch.setattr(api, "_emit", lambda event, payload: events.append((event, payload)))
    monkeypatch.setattr(api, "_JOBS", api.JobRegistry(emit=lambda event, payload: api._emit(event, payload)))
    monkeypatch.setattr(api, "_MAIL_FLOWS", flows)
    monkeypatch.setattr(api, "_mail_flows", lambda: flows)
    monkeypatch.setattr(api, "_VAULT_FLOWS", None)
    monkeypatch.setattr(api, "_CEREMONY_LOCK", threading.Lock())
    monkeypatch.setattr(api, "_mail_secret_store", lambda: FakeMailSecrets())
    monkeypatch.setattr(api, "_open_store_readonly", lambda home: FakeReadonlyStore(store_status()))
    monkeypatch.setattr(api, "_store_refusal", lambda exc: getattr(exc, "code", "store_unavailable"))
    monkeypatch.setattr(api, "_mail_audit", lambda done, rows: None)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: None))
    monkeypatch.setattr("mordred_hermes.wizard.telegram_setup_cli.run_checks", lambda: [])
    monkeypatch.setattr(api, "_vault_root", lambda: home / "mordred" / "vault")

    async def model_ok() -> dict[str, Any]:
        return {"model": "m", "kind": "venice", "private": True, "ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model_ok)
    records = _Records()
    root_logger = logging.getLogger("mordred_hermes")
    root_logger.addHandler(records)
    previous = root_logger.level
    root_logger.setLevel(logging.DEBUG)
    app = FastAPI()
    app.include_router(api.router, prefix=PREFIX)
    try:
        with TestClient(app) as http:
            yield Desktop(http, home, events, records, flows)
    finally:
        root_logger.removeHandler(records)
        root_logger.setLevel(previous)
