"""Literal fixtures for the two intentionally different dotenv dialects."""

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "mode,source,updates,want",
    [
        ("wizard", "", {"KEY": ""}, ""),
        ("extension", "", {}, "\n"),
        ("extension", "", {"KEY": ""}, "KEY=\n"),
        ("wizard", "KEY=old\r\nexport KEY=again\r\nOTHER=x", {"KEY": "new"}, "KEY=new\nOTHER=x\n"),
        ("extension", "KEY=old\r\nexport KEY=again\r\nOTHER=x", {"KEY": "new"}, "KEY=new\nexport KEY=new\nOTHER=x\n"),
        ("wizard", "export KEY=one\nKEY=two\n", {"KEY": ""}, ""),
        ("extension", "export KEY=one\nKEY=two\n", {"KEY": ""}, "export KEY=\nKEY=\n"),
        (
            "wizard",
            "# KEY=no\n KEY =old\nexport KEY =old\n",
            {"KEY": "yes"},
            "# KEY=no\n KEY =old\nexport KEY =old\nKEY=yes\n",
        ),
        ("extension", "# KEY=no\n KEY =old\n export KEY =old\n", {"KEY": "yes"}, "# KEY=no\nKEY=yes\nexport KEY=yes\n"),
        (
            "wizard",
            "export KEY=old\nX=$KEY\n",
            {"KEY": "'a=b' # raw", "NEXT": "2"},
            "export KEY='a=b' # raw\nX=$KEY\nNEXT=2\n",
        ),
        (
            "extension",
            "export KEY=old\nX=$KEY\n",
            {"KEY": "'a=b' # raw", "NEXT": "2"},
            "export KEY='a=b' # raw\nX=$KEY\nNEXT=2\n",
        ),
    ],
)
def test_preserved_merge_modes(mode, source, updates, want):
    from mordred_hermes._dotenv_text import merge_assignments

    assert merge_assignments(source, updates, mode=mode) == want


@pytest.mark.parametrize(
    "key,want", [("FOO", True), ("_9", True), ("foo", False), ("9FOO", False), ("FOO=bad", False), ("FOO\n", False)]
)
def test_wizard_key_validation(key, want):
    from mordred_hermes._dotenv_text import is_wizard_key

    assert is_wizard_key(key) is want


@pytest.mark.parametrize("value,want", [("", False), ("quoted=a#b", False), ("x\ny", True), ("x\ry", True)])
def test_newline_validation(value, want):
    from mordred_hermes._dotenv_text import contains_newline

    assert contains_newline(value) is want


def test_nonempty_detection_uses_extension_recognition_without_expansion():
    from mordred_hermes._dotenv_text import has_nonempty_key

    assert has_nonempty_key("  export KEY = ' ' # literal\n", {"KEY"})
    assert not has_nonempty_key("# KEY=hidden\nKEY= \nOTHER=1\n", {"KEY"})


@pytest.mark.parametrize("key,value", [("lower", "x"), ("KEY", "bad\nvalue"), ("KEY", "bad\rvalue")])
def test_wizard_validation_precedes_parent_creation(tmp_path: Path, key: str, value: str) -> None:
    from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

    with pytest.raises(ValueError):
        DotEnvFileWriter().upsert(tmp_path / "missing" / ".env", key=key, value=value)
    assert not (tmp_path / "missing").exists()
