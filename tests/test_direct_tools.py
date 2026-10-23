"""Hermes's direct tool calls (``wizard.direct_tools``): ``tools.tool_search.enabled`` in config.yaml.

The read follows Hermes (``ToolSearchConfig.from_raw``); the write goes through the
wizard's round-trip writer, keeps every other key and comment and the file's mode,
replaces the file atomically and writes nothing when nothing changes. A vault-managed
config.yaml is written only while its plaintext working copy is on disk.
"""

from __future__ import annotations

import os
import stat
import sys
import traceback
from pathlib import Path

import pytest

from mordred_hermes import _config_text_io
from mordred_hermes.wizard import direct_tools
from mordred_hermes.wizard import policy_writer as pw
from mordred_hermes.wizard.direct_tools import ERROR_CODES, DirectToolsError, read_mode, set_direct
from tests.test_config_io import fs as fs

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX writer path")

CANARY = "canary-model-7c1e"
CONFIG = f"""# Hermes configuration (kept)
model:
  default: {CANARY}  # the chat model
  base_url: https://api.venice.ai/api/v1
tools:
  # tool search, as Hermes ships it
  tool_search:
    listing: auto   # the catalog
    listing_max_tokens: 4000
plugins:
  enabled:
    - mordred
"""


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "hermes-home"
    (path / "mordred").mkdir(parents=True, mode=0o700)
    return path


def write(home: Path, text: str, mode: int = 0o600) -> Path:
    config = home / "config.yaml"
    config.write_text(text, encoding="utf-8")
    os.chmod(config, mode)
    return config


# -- read ------------------------------------------------------------------------------------------


@posix_only
def test_no_config_reads_as_the_default_deferred_mode(home: Path) -> None:
    assert read_mode(home) == {"direct": False, "source": "default", "raw": None}
    assert sorted(p.name for p in home.iterdir()) == ["mordred"]  # nothing created by a read


@posix_only
@pytest.mark.parametrize(
    "text,raw",
    [
        ('tools:\n  tool_search:\n    enabled: "off"\n', "off"),
        ("tools:\n  tool_search:\n    enabled: off\n", "off"),
        ("tools:\n  tool_search:\n    enabled: false\n", "false"),
        ("tools:\n  tool_search: false\n", "false"),  # Hermes's legacy shape
        ('tools:\n  tool_search:\n    enabled: " OFF "\n', " OFF "),
        ('tools:\n  tool_search:\n    enabled: "no"\n', "no"),  # Hermes reads these as off too
    ],
)
def test_off_string_and_false_boolean_read_as_direct(home: Path, text: str, raw: str) -> None:
    write(home, text)
    assert read_mode(home) == {"direct": True, "source": "config", "raw": raw}


@posix_only
@pytest.mark.parametrize(
    "text,expected",
    [
        ('tools:\n  tool_search:\n    enabled: "auto"\n', {"direct": False, "source": "config", "raw": "auto"}),
        ("tools:\n  tool_search:\n    enabled: on\n", {"direct": False, "source": "config", "raw": "on"}),
        ("tools:\n  tool_search:\n    enabled: true\n", {"direct": False, "source": "config", "raw": "true"}),
        ("tools:\n  tool_search: true\n", {"direct": False, "source": "config", "raw": "true"}),
        ("tools:\n  tool_search:\n    listing: auto\n", {"direct": False, "source": "default", "raw": None}),
        ("tools: [a, b]\n", {"direct": False, "source": "default", "raw": None}),
        ("model:\n  default: x\n", {"direct": False, "source": "default", "raw": None}),
        ("", {"direct": False, "source": "default", "raw": None}),
    ],
)
def test_anything_else_reads_as_deferred(home: Path, text: str, expected: dict[str, object]) -> None:
    write(home, text)
    assert read_mode(home) == expected


@posix_only
def test_raw_is_the_keys_own_value_and_bounded(home: Path) -> None:
    write(home, f'tools:\n  tool_search:\n    enabled: "{"x" * 100}"\nmodel: {CANARY}\n')
    mode = read_mode(home)
    assert mode["raw"] == "x" * 32 and CANARY not in repr(mode)


@posix_only
@pytest.mark.parametrize("text", [f"model: [{CANARY}\n", f"- {CANARY}\n", f"{CANARY}\n"])
def test_unreadable_config_reads_as_unknown_without_any_value(home: Path, text: str) -> None:
    write(home, text)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}


# -- write -----------------------------------------------------------------------------------------


@posix_only
def test_on_then_off_round_trips_and_keeps_comments_other_keys_and_mode(home: Path) -> None:
    config = write(home, CONFIG, mode=0o640)
    set_direct(home, True)
    text = config.read_text(encoding="utf-8")
    assert '    enabled: "off"\n' in text
    kept = (
        "# Hermes configuration (kept)",
        f"default: {CANARY}  # the chat model",
        "# tool search, as Hermes ships it",
        "listing: auto   # the catalog",
        "listing_max_tokens: 4000",
        "    - mordred",
    )
    for line in kept:
        assert line in text, line
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert read_mode(home) == {"direct": True, "source": "config", "raw": "off"}
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == CONFIG  # the key removed, everything else as it was
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert read_mode(home)["direct"] is False


@posix_only
def test_on_adds_the_tools_section_and_off_removes_what_it_added(home: Path) -> None:
    original = "model:\n  default: x  # kept\n"
    config = write(home, original)
    set_direct(home, True)
    assert config.read_text(encoding="utf-8") == original + 'tools:\n  tool_search:\n    enabled: "off"\n'
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == original


@posix_only
@pytest.mark.parametrize(
    "text,left",
    [
        ("tools:\n  tool_search: false\n  other: 1\n", "tools:\n  other: 1\n"),
        (
            "tools:\n  tool_search:\n    enabled: false\n    listing: off\n",
            "tools:\n  tool_search:\n    listing: off\n",
        ),
        ('tools:\n  tool_search:\n    enabled: "no"\nmodel: x\n', "model: x\n"),
    ],
)
def test_off_removes_only_what_makes_the_tools_direct(home: Path, text: str, left: str) -> None:
    config = write(home, text)
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == left
    assert read_mode(home)["direct"] is False


@posix_only
@pytest.mark.parametrize("text", ["tools:\n  tool_search: true\n", "tools:\n  tool_search:\n    enabled: auto\n"])
def test_on_replaces_a_deferred_value(home: Path, text: str) -> None:
    write(home, text)
    set_direct(home, True)
    assert read_mode(home) == {"direct": True, "source": "config", "raw": "off"}


@posix_only
@pytest.mark.parametrize(
    "text,enabled",
    [
        ("model: x\n", False),
        ('tools:\n  tool_search:\n    enabled: "auto"\n', False),  # explicit deferral is kept, not removed
        ("tools:\n  tool_search:\n    enabled: false\n", True),  # already direct: not rewritten as "off"
    ],
)
def test_nothing_is_written_when_the_setting_is_already_as_asked(home: Path, text: str, enabled: bool) -> None:
    config = write(home, text)
    before = config.stat()
    set_direct(home, enabled)
    after = config.stat()
    assert config.read_text(encoding="utf-8") == text
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@posix_only
def test_without_config_off_creates_nothing_and_on_creates_a_private_file(home: Path) -> None:
    set_direct(home, False)
    assert not (home / "config.yaml").exists()
    set_direct(home, True)
    config = home / "config.yaml"
    assert config.read_text(encoding="utf-8") == 'tools:\n  tool_search:\n    enabled: "off"\n'
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


@posix_only
def test_the_write_replaces_the_file_atomically_and_leaves_no_temporary_file(home: Path) -> None:
    config = write(home, CONFIG)
    inode = config.stat().st_ino
    set_direct(home, True)
    assert config.stat().st_ino != inode  # a new file renamed over the old one, never an in-place edit
    leftovers = sorted(p.name for p in home.iterdir() if p.name not in ("config.yaml", "mordred"))
    assert leftovers == []


@posix_only
def test_a_failed_replace_keeps_the_original_and_removes_the_temporary_file(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write(home, CONFIG)

    def refuse(src: object, dst: object) -> None:
        raise PermissionError(13, "denied", str(dst))

    monkeypatch.setattr(_config_text_io.os, "replace", refuse)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_write_failed"
    assert config.read_text(encoding="utf-8") == CONFIG
    assert sorted(p.name for p in home.iterdir()) == ["config.yaml", "mordred"]


@posix_only
@pytest.mark.parametrize("text", [f"model: [{CANARY}\n", f"- {CANARY}\n"])
@pytest.mark.parametrize("enabled", [True, False])
def test_an_unreadable_config_is_refused_unchanged_and_no_value_travels(home: Path, text: str, enabled: bool) -> None:
    config = write(home, text)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_unreadable" and str(error.value) == "config_unreadable"
    # The YAML error (which quotes the offending line) is dropped, never chained.
    assert CANARY not in "".join(traceback.format_exception(error.value))
    assert config.read_text(encoding="utf-8") == text


@posix_only
def test_tools_that_is_not_a_mapping_is_never_replaced(home: Path) -> None:
    config = write(home, "tools: [a, b]\n")
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unreadable"
    assert config.read_text(encoding="utf-8") == "tools: [a, b]\n"


def test_error_codes_are_closed() -> None:
    assert ERROR_CODES == ("config_unreadable", "config_vault_managed", "config_write_failed")


# -- a vault-managed config.yaml (``encryption enable config``) ---------------------------------------


def _manage(home: Path) -> None:
    from mordred_hermes.keyvault._config_bootstrap import _marker_path

    marker = _marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("vault-managed\n", encoding="utf-8")


@posix_only
@pytest.mark.parametrize("enabled", [True, False])
def test_a_sealed_away_config_is_refused_and_nothing_is_created(home: Path, enabled: bool) -> None:
    _manage(home)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_vault_managed"}
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_vault_managed"
    assert not (home / "config.yaml").exists()  # never a fresh config that the next start would adopt


@posix_only
def test_a_vault_managed_config_on_disk_is_edited_like_any_other_writer(home: Path) -> None:
    """The working copy is what Hermes reads; the reseal re-enrolls a changed copy."""
    _manage(home)
    config = write(home, CONFIG)
    set_direct(home, True)
    assert read_mode(home)["direct"] is True and CANARY in config.read_text(encoding="utf-8")
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


# -- Windows: the checked canonical transaction (fake coordinator, any host) ------------------------


@pytest.fixture
def windows(fs, monkeypatch: pytest.MonkeyPatch):
    backend, paths = fs
    monkeypatch.setattr(_config_text_io, "_windows", lambda: True)
    monkeypatch.setattr(pw, "_windows", lambda: True, raising=False)
    return backend, paths


def put(directory: object, name: str, data: bytes) -> None:
    directory.files[name] = data, directory.backend.identity()  # type: ignore[attr-defined]


def test_windows_round_trip_through_the_canonical_transaction(windows) -> None:
    b, paths = windows
    put(b.home, "config.yaml", CONFIG.encode())
    assert read_mode(paths.home) == {"direct": False, "source": "default", "raw": None}
    set_direct(paths.home, True)
    text = b.home.files["config.yaml"][0].decode()
    assert '    enabled: "off"\n' in text and "# tool search, as Hermes ships it" in text and CANARY in text
    assert read_mode(paths.home) == {"direct": True, "source": "config", "raw": "off"}
    set_direct(paths.home, False)
    assert b.home.files["config.yaml"][0].decode() == CONFIG


def test_windows_unchanged_setting_opens_no_transaction(windows) -> None:
    b, paths = windows
    put(b.home, "config.yaml", b"model: x\n")
    before = b.home.files.copy(), b.policy.files.copy()
    set_direct(paths.home, False)
    assert (b.home.files, b.policy.files) == before


def test_windows_malformed_config_is_refused_unchanged(windows) -> None:
    b, paths = windows
    put(b.home, "config.yaml", b"[unterminated")
    assert read_mode(paths.home)["code"] == "config_unreadable"
    with pytest.raises(DirectToolsError) as error:
        set_direct(paths.home, True)
    assert error.value.code == "config_unreadable"
    assert b.home.files["config.yaml"][0] == b"[unterminated"


def test_windows_never_checks_the_config_seal(windows, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(home: Path) -> Path:
        raise AssertionError("config seals are excluded on Windows")

    monkeypatch.setattr("mordred_hermes.keyvault._config_bootstrap._marker_path", unexpected)
    assert direct_tools._managed(Path("/unused")) is False


def test_windows_a_change_made_meanwhile_publishes_nothing(windows, monkeypatch: pytest.MonkeyPatch) -> None:
    """The setting became as asked between the pre-check and the transaction: nothing is rewritten."""
    b, paths = windows
    put(b.home, "config.yaml", b'tools:\n  tool_search:\n    enabled: "off"   # kept as written\n')
    before = b.home.files.copy(), b.policy.files.copy()
    monkeypatch.setattr(direct_tools, "read_mode", lambda home: {"direct": False, "source": "default", "raw": None})
    set_direct(paths.home, True)
    assert (b.home.files, b.policy.files) == before


@pytest.mark.parametrize("data", [b"", b"# only a comment\n"])
def test_windows_an_empty_config_is_unreadable_like_the_checked_writer_says(windows, data: bytes) -> None:
    b, paths = windows
    put(b.home, "config.yaml", data)
    assert read_mode(paths.home)["code"] == "config_unreadable"
    with pytest.raises(DirectToolsError) as error:
        set_direct(paths.home, True)
    assert error.value.code == "config_unreadable"
    assert b.home.files["config.yaml"][0] == data


# -- comments that follow a removed or inserted block stay where they were ----------------------------


@posix_only
@pytest.mark.parametrize(
    "text,left",
    [
        (  # the reviewer's case: the comment belongs to the next section
            'tools:\n  tool_search:\n    enabled: "off"\n# Important: provider settings below\nproviders:\n  a: 1\n',
            "# Important: provider settings below\nproviders:\n  a: 1\n",
        ),
        (
            "model: x\ntools:\n  tool_search: false\n# after legacy\nother: 1\n",
            "model: x\n# after legacy\nother: 1\n",
        ),
        (
            "model: x\ntools:\n  tool_search: false\n  # about other\n  other: 1\nend: 2\n",
            "model: x\ntools:\n  # about other\n  other: 1\nend: 2\n",
        ),
        (
            "model:\n  - a\n  - b   # eol b\ntools:\n  tool_search:\n    listing: off\n    enabled: false\n"
            "# next\nx: 1\n",
            "model:\n  - a\n  - b   # eol b\ntools:\n  tool_search:\n    listing: off\n# next\nx: 1\n",
        ),
    ],
    ids=["after-the-block", "legacy-boolean", "first-key-with-a-sibling", "a-remaining-sibling"],
)
def test_off_keeps_the_comments_that_followed_the_removed_block(home: Path, text: str, left: str) -> None:
    config = write(home, text)
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == left


@posix_only
@pytest.mark.parametrize(
    "text,turned_on",
    [
        (
            "model: x   # eol\ntools:\n  tool_search:\n    listing: auto   # eol listing\n"
            "# Important: provider settings below\n\nproviders:\n  a: 1\n",
            'model: x   # eol\ntools:\n  tool_search:\n    listing: auto   # eol listing\n    enabled: "off"\n'
            "# Important: provider settings below\n\nproviders:\n  a: 1\n",
        ),
        (
            "model:\n  list:\n    - a\n    - b   # eol b\n# end of file\n",
            'model:\n  list:\n    - a\n    - b   # eol b\ntools:\n  tool_search:\n    enabled: "off"\n# end of file\n',
        ),
        (
            "tools:\n  other: 1   # eol other\n# next section\nx: 1\n",
            'tools:\n  other: 1   # eol other\n  tool_search:\n    enabled: "off"\n# next section\nx: 1\n',
        ),
    ],
    ids=["into-tool-search", "at-the-end", "into-tools"],
)
def test_on_inserts_before_the_comments_that_follow_and_off_restores_the_file(
    home: Path, text: str, turned_on: str
) -> None:
    config = write(home, text)
    set_direct(home, True)
    assert config.read_text(encoding="utf-8") == turned_on
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == text


@posix_only
def test_a_comment_only_config_keeps_its_comment(home: Path) -> None:
    config = write(home, "# only a comment\n")
    set_direct(home, True)
    assert config.read_text(encoding="utf-8") == '# only a comment\ntools:\n  tool_search:\n    enabled: "off"\n'
    set_direct(home, False)
    assert config.read_text(encoding="utf-8").startswith("# only a comment\n")
    assert read_mode(home)["direct"] is False


# -- races and refusals --------------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("enabled", [True, False])
def test_a_reseal_between_the_checks_and_the_read_is_refused(
    home: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    """Another Hermes process exits and reseals: the plaintext vanishes just before the read."""
    _manage(home)
    config = write(home, 'tools:\n  tool_search:\n    enabled: "off"\n' if not enabled else CONFIG)
    real = pw._read_regular_text

    def resealed(path: Path) -> str | None:
        config.unlink()
        return real(path)

    monkeypatch.setattr(pw, "_read_regular_text", resealed)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_vault_managed"
    assert not config.exists()  # never a fresh partial config.yaml for the next start to adopt


@posix_only
def test_an_inaccessible_seal_marker_is_unreadable_not_a_traceback(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Denied:
        def exists(self) -> bool:
            raise PermissionError(13, "denied")

    monkeypatch.setattr("mordred_hermes.keyvault._config_bootstrap._marker_path", lambda home: Denied())
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unreadable"
    assert not (home / "config.yaml").exists()
