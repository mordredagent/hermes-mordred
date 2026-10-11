"""Test-only selection and provenance checks shared with the sanitized child."""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import os
import sys
import traceback
from pathlib import Path
from typing import Any

import pytest


class SeamDrift(AssertionError):
    """The selected source no longer exposes a required seam."""


class CanaryUnavailable(RuntimeError):
    """The environment could not execute the selected source reliably."""


def expected_root() -> Path | None:
    if os.environ.get("MORDRED_REQUIRE_UPSTREAM_MEMORY_SEAMS") != "1":
        return None
    value = os.environ.get("MORDRED_EXPECTED_UPSTREAM_ROOT")
    if not value or not Path(value).is_absolute() or not Path(value).is_dir():
        raise CanaryUnavailable("strict canary requires an existing absolute expected upstream root")
    return Path(value).resolve()


def verify_provenance(module: Any, name: str, root: Path) -> None:
    origin = getattr(module, "__file__", None)
    if not origin or not Path(origin).resolve().is_relative_to(root):
        raise CanaryUnavailable(f"provenance: {name} resolved outside {root}: {origin}")
    print(f"CANARY_SOURCE {name}: {Path(origin).resolve()}")


def import_target(name: str, *, optional: bool = False) -> Any:
    root = expected_root()
    if root is not None and not (root / (name.replace(".", "/") + ".py")).is_file():
        raise SeamDrift(f"required selected upstream module missing: {name}")
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name == name or (exc.name and name.startswith(exc.name + ".")):
            if optional and root is None:
                pytest.skip(f"optional later upstream module absent: {name}")
            raise SeamDrift(f"required upstream module absent: {name}") from exc
        raise CanaryUnavailable(f"{name} internal dependency unavailable: {exc.name}") from exc
    except Exception as exc:
        raise CanaryUnavailable(f"cannot import {name}: {exc}") from exc
    if root is not None:
        verify_provenance(module, name, root)
    return module


def verify_selected_source() -> None:
    """Verify target, class and all loaded release-owned/shared source origins."""
    root = expected_root()
    if root is None:
        return
    memory = import_target("tools.memory_tool")
    import_target("agent.learning_mutations")
    store = getattr(memory, "MemoryStore", None)
    if store is None:
        raise SeamDrift("selected memory module has no MemoryStore")
    defining = importlib.import_module(store.__module__)
    verify_provenance(defining, "MemoryStore", root)
    if not Path(inspect.getfile(store)).resolve().is_relative_to(root):
        raise CanaryUnavailable("MemoryStore class provenance outside selected root")
    try:
        dist = importlib.metadata.distribution("hermes-agent")
        if dist.files is None:
            raise CanaryUnavailable("Hermes distribution ownership manifest missing")
        owned = {Path(dist.locate_file(file)).resolve() for file in dist.files if str(file).endswith(".py")}
    except importlib.metadata.PackageNotFoundError as exc:
        raise CanaryUnavailable("released Hermes dependency environment missing") from exc
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if origin and (Path(origin).resolve() in owned or Path(origin).resolve().is_relative_to(root)):
            verify_provenance(module, name, root)
    for name in ("utils", "hermes_constants"):
        verify_provenance(import_target(name), name, root)


def child_main() -> int:
    """Keep provenance/import failures distinct from seam drift across the child boundary."""
    try:
        verify_selected_source()
    except SeamDrift:
        traceback.print_exc()
        return 11
    except Exception:
        traceback.print_exc()
        return 12
    return 0
