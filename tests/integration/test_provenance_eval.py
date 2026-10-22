"""Live provenance evaluation, smoke tier: real models only behind an explicit gate.

Gate: ``MORDRED_PROVENANCE_EVAL=1``. Privacy driver (one of):

- Venice: ``VENICE_API_KEY`` (optional ``MORDRED_EVAL_LLM_MODEL``, default
  ``deepseek-v4-flash``; only models Venice labels ``private`` are used);
- loopback: ``MORDRED_EVAL_LLM_BASE_URL=http://127.0.0.1:<port>/v1`` and
  ``MORDRED_EVAL_LLM_MODEL`` (optional ``MORDRED_EVAL_LLM_API_KEY``).

Hermes driver (macOS only: ``mordred.db`` is macOS-only), when
``MORDRED_EVAL_HERMES_MODEL`` is set: ``MORDRED_EVAL_HERMES_BASE_URL`` empty or
Venice (``VENICE_API_KEY``) or a loopback URL (optional
``MORDRED_EVAL_HERMES_API_KEY``); Hermes needs a model with at least a 64K
context window.

The test prepares throwaway homes under ``tmp_path`` (synthetic SQLCipher key,
``databases encrypt`` and memory encryption armed, the generated records in
``mordred.db``, ``index.enc`` retired), runs ``--tier smoke --reps 1`` and
checks that the run completed and wrote its report. Thresholds are recorded in
the report, never asserted here. No production home, key or credential is read.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "tools" / "provenance_eval"
SEED = 0
STYLE = "per_part_en"


def _module(name: str) -> ModuleType:
    """Import ``provenance_eval.<name>`` from ``tools/`` (Hermes ships its own ``tools`` package)."""
    if "provenance_eval" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "provenance_eval", PACKAGE / "__init__.py", submodule_search_locations=[str(PACKAGE)]
        )
        assert spec is not None and spec.loader is not None
        package = importlib.util.module_from_spec(spec)
        sys.modules["provenance_eval"] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"provenance_eval.{name}")


drivers = _module("drivers")
run_mod = _module("run")
cli = _module("cli")
generate_mod = _module("generate")

_PRIVACY_ENV = f"{drivers.ENV_VENICE_API_KEY} or {drivers.ENV_LLM_BASE_URL} + {drivers.ENV_LLM_MODEL}"


def _gate() -> None:
    if os.environ.get(drivers.ENV_GATE) != "1":
        pytest.skip(f"set {drivers.ENV_GATE}=1 and {_PRIVACY_ENV} (optionally {drivers.ENV_HERMES_MODEL}) to run")


def _run(out: Path, driver: str, *extra: str) -> dict[str, Any]:
    argv = ["run", "--driver", driver, "--tier", "smoke", "--reps", "1", "--seed", str(SEED), "--style", STYLE]
    assert cli.main([*argv, "--out", str(out), *extra]) == 0
    report = json.loads((out / run_mod.REPORT_JSON).read_text("utf-8"))
    assert (out / run_mod.REPORT_MD).is_file()
    lines = [json.loads(raw) for raw in (out / run_mod.RESULTS).read_text("utf-8").splitlines() if raw.strip()]
    planned = len(run_mod.select_questions(generate_mod.generate(SEED).truth, "smoke"))
    reasons = sorted({str(line.get("reason")) for line in lines if line["status"] == "unavailable"})
    assert len(lines) == planned, "the smoke run did not complete"
    # Wiring, not thresholds: at least one question reached the model and was scored.
    assert any(line["status"] == "answered" for line in lines), f"every answer unavailable: {reasons}"
    print(f"{driver}: verdict {report['verdict']}, unavailable {reasons or 'none'} -> {out}")
    return report


def test_live_privacy_driver_smoke(tmp_path: Path) -> None:
    _gate()
    if not (os.environ.get(drivers.ENV_VENICE_API_KEY) or os.environ.get(drivers.ENV_LLM_BASE_URL)):
        pytest.skip(f"set {_PRIVACY_ENV} for the privacy driver")
    settings = drivers.privacy_settings_from_env()
    assert not isinstance(settings, drivers.Unavailable), settings
    report = _run(tmp_path / "privacy", "privacy")
    assert report["meta"]["driver"] == "privacy" and report["meta"]["model"] == settings.model


def test_live_hermes_driver_smoke(tmp_path: Path) -> None:
    _gate()
    if not os.environ.get(drivers.ENV_HERMES_MODEL):
        pytest.skip(f"set {drivers.ENV_HERMES_MODEL} (and {drivers.ENV_HERMES_BASE_URL}) for the Hermes driver")
    if sys.platform != "darwin":
        pytest.skip("the Hermes driver reads mordred.db, which is macOS-only")
    root = tmp_path / "hermes-home"
    settings = drivers.hermes_settings_from_env(root, seed=SEED, style=STYLE)
    assert not isinstance(settings, drivers.Unavailable), settings
    for source in ("telegram", "mail"):
        home = drivers.prepare_hermes_home(
            root / source,
            source=source,
            seed=SEED,
            threads=settings.threads,
            style=STYLE,
            model=settings.model,
            base_url=settings.base_url,
        )
        assert home == root / source, home
        assert (home / "mordred" / "db-encryption.marker").is_file()
        assert (home / "plugin-data" / "mordred" / "mordred.db").is_file()
        assert (home / "mordred" / "telegram" / "index.enc").is_file()
    report = _run(tmp_path / "hermes", "hermes", "--hermes-home", str(root))
    assert report["meta"]["driver"] == "hermes" and report["meta"]["model"] == settings.model
