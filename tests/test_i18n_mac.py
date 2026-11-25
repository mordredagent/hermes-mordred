"""Mordred's words on the Mac: one English source, the same keys and placeholders in every language."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from mordred_hermes import i18n
from mordred_hermes.keyvault import _presence

ROOT = Path(__file__).resolve().parents[1]
STRINGS = ROOT / "src" / "mordred_hermes" / "i18n" / "strings"
INSTALLER = ROOT / "scripts" / "install-standalone.sh"
EN = json.loads((STRINGS / "en.json").read_text(encoding="utf-8"))


def _flat(data: dict[str, dict[str, str]]) -> dict[str, str]:
    return {f"{group}.{name}": value for group, names in data.items() for name, value in names.items()}


def _holes(text: str) -> list[str]:
    return sorted(re.findall(r"\{(\w+)\}", text))


def test_the_installers_english_is_en_json() -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    pairs = {
        key: text.replace('\\"', '"')
        for key, text in re.findall(r'msg ([a-zA-Z]+\.[a-zA-Z]+) "((?:[^"\\]|\\.)*)"', script)
    }
    flat = _flat(EN)
    assert pairs, "the installer asks for no text"
    for key, english in pairs.items():
        assert flat.get(key) == english, key


def test_the_touch_id_english_is_en_json() -> None:
    flat = _flat(EN)
    for purpose, english in _presence._REASONS.items():
        assert flat[f"touchId.{purpose}"] == english
    trust = (ROOT / "src" / "mordred_hermes" / "extension" / "trust.py").read_text(encoding="utf-8")
    assert f'"{flat["touchId.approveBrowser"]}"' in trust


@pytest.mark.parametrize("language", [p.stem for p in sorted(STRINGS.glob("*.json")) if p.stem != "en"])
def test_every_language_has_every_text_with_its_placeholders(language: str) -> None:
    flat_en = _flat(EN)
    flat = _flat(json.loads((STRINGS / f"{language}.json").read_text(encoding="utf-8")))
    assert set(flat) == set(flat_en)
    for key, english in flat_en.items():
        assert flat[key].strip(), key
        assert _holes(flat[key]) == _holes(english), key
    assert language in i18n.LANGUAGES


@pytest.mark.parametrize(
    ("tag", "language"),
    [
        ("ja-JP", "ja"),
        ("zh-Hans-CN", "zhCN"),
        ("zh-Hant-TW", "zhTW"),
        ("zh-HK", "zhTW"),
        ("pt-BR", "pt"),
        ("de_DE.UTF-8", "de"),
        ("en-GB", "en"),
        ("xx-YY", "en"),
    ],
)
def test_a_tag_names_one_of_mordreds_languages(tag: str, language: str) -> None:
    assert i18n.language_of(tag) == language


def test_a_text_is_translated_filled_in_and_falls_back_to_english() -> None:
    assert (
        i18n.text("touchId.setup", "Set up Mordred's keys and encryption", language="ja")
        == "Mordred の鍵と暗号化を準備する"
    )
    approve = i18n.text("touchId.approveBrowser", "unused", language="ja", label="Brave", code="AB12C")
    assert "Brave" in approve and "AB12C" in approve and "{" not in approve
    assert i18n.text("touchId.nothing", "English {x}", language="ja", x=1) == "English 1"
    assert i18n.text("touchId.setup", "English", language="en") == "English"


def test_the_installer_speaks_the_macs_language(tmp_path: Path) -> None:
    body = "\n".join(INSTALLER.read_text(encoding="utf-8").splitlines()[:-1])
    script = tmp_path / "functions.sh"
    script.write_text(
        body
        + f'\nSOURCE_DIR="{ROOT}"\n'
        + "defaults() { printf '(\\n    \"ja-JP\",\\n    en\\n)\\n'; }\n"
        + 'msg installer.failed "Mordred could not be installed: {reason}" reason "X"; echo\n'
        + 'msg button.ok "OK"; echo\n'
        + 'msg installer.nothing "English {a}" a "1"; echo\n'
    )
    out = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == ["Mordred を入れられませんでした: X", "OK", "English 1"]
