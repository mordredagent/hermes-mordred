"""Language detection without a model: scripts, then common words and letters."""

# ruff: noqa: RUF001 - messages as users type them, with full-width punctuation

from __future__ import annotations

import pytest

from mordred_hermes.text_language import detect, name


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("Kestrel 基板は何枚発注した？", "ja"),
        ("Homebrew で ripgrep をインストールして", "ja"),
        ("17 × 23 は？", "ja"),
        ("Orion 논문의 투고 번호는?", "ko"),
        ("我订购了多少块 Kestrel 板？", "zh"),
        ("How many Kestrel boards did I order?", "en"),
        ("What is 17 × 23?", "en"),
        ("¿Cuántas placas Kestrel pedí?", "es"),
        ("Envía un correo a Tanaka sobre el presupuesto.", "es"),
        ("Combien de cartes Kestrel ai-je commandées ?", "fr"),
        ("Wie viele Kestrel-Platinen habe ich bestellt?", "de"),
        ("Was ist sccache? In einem Satz.", "de"),
        ("Qual orçamento de pesquisa acordamos para o próximo ano?", "pt"),
        ("Привет, как дела?", "ru"),
        ("สวัสดีครับ", "th"),
        # An English sentence naming a place in kanji stays English.
        ("Arashiyama (嵐山) is best early in the morning, before the crowds.", "en"),
    ],
)
def test_detects_the_language(text: str, lang: str) -> None:
    assert detect(text) == lang


@pytest.mark.parametrize("text", ["", "   ", "391", "4471 / 11-30"])
def test_says_not_sure_without_words(text: str) -> None:
    assert detect(text) is None


def test_names_a_language_for_an_instruction() -> None:
    assert name("es") == "Spanish"
    assert name(None) is None
    assert name("xx") is None


def test_chinese_naming_a_tool_in_latin_letters_stays_chinese() -> None:
    assert detect("用 Homebrew 安装 ripgrep") == "zh"
