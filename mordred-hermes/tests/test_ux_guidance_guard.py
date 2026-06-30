"""Source-level guard: user-facing guidance must name the working CLI form.

Hermes 0.11 does not wire entry-point CLI commands into its argparse tree
(see ``wizard/cli.py:main``), so ``hermes mordred ...`` does nothing today —
the working spelling is the ``hermes-mordred`` console script. Telling a
user to run the space form sends them to a dead end (UX review 2026-06-11
found 13 such messages).

This test walks every non-docstring string constant in the package and
rejects the space form. Strings that mention ``0.12`` are exempt: they
*document* the future ``hermes mordred`` wiring rather than instruct the
user to run it now. Mirrors the narrower guard in
``test_keyvault_config_bootstrap.py`` (``_RECOVERY_HINT``).

Known limits (accepted): docstrings are exempt by design (developer-facing
RST docs legitimately reference the ``hermes mordred`` form), so guidance
text smuggled into a docstring position would slip through; the scan covers
the installed package only, not ``tests/``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import mordred_hermes

_PACKAGE_ROOT = Path(mordred_hermes.__file__).parent
_SPACE_FORM = "hermes mordred"
_FUTURE_FORM_MARKER = "0.12"


def _docstring_node_ids(tree: ast.Module) -> set[int]:
    """ids of every Constant that is a module/class/function docstring."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            ids.add(id(body[0].value))
    return ids


def _offending_strings(source_file: Path) -> list[str]:
    tree = ast.parse(source_file.read_text(encoding="utf-8"))
    docstrings = _docstring_node_ids(tree)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings:
            continue
        if _SPACE_FORM in node.value and _FUTURE_FORM_MARKER not in node.value:
            offenders.append(f"{source_file.name}:{node.lineno}: {node.value!r}")
    return offenders


def test_no_user_facing_space_form_guidance() -> None:
    offenders: list[str] = []
    for source_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        offenders.extend(_offending_strings(source_file))
    assert not offenders, (
        "user-facing strings must reference the working `hermes-mordred ...` "
        "spelling (Hermes 0.11 does not wire `hermes mordred ...`):\n" + "\n".join(offenders)
    )
