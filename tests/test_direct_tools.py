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


# -- read: parity with Hermes ---------------------------------------------------------------------
#
# Hermes 0.21.5 (``~/.hermes/hermes-agent``), re-implemented here independently of the module under
# test: ``hermes_yaml.safe_load`` is ruamel ``YAML(typ="safe")`` with ``version = (1, 1)`` (plain
# ``off``/``no``/``n``/``false`` are booleans, ``y``/``yes``/``on``/``true`` too); ``_deep_merge``
# puts the user's file over ``DEFAULT_CONFIG`` (``tools.tool_search.enabled: "auto"``), ignoring a
# ``None`` over a default mapping; ``ToolSearchConfig.from_raw`` turns a non-mapping into
# ``{"enabled": "off" if raw is False else "auto"}`` and reads ``enabled`` with ``_tri_state``:
# ``str(v).strip().lower()``, aliases true/1/yes -> on and false/0/no -> off, else auto/on/off or auto.


def hermes_rule(text: str) -> bool:
    """Is Hermes direct (``enabled == "off"``) for this config.yaml text?"""
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    yaml.version = (1, 1)
    user = yaml.load(text) or {}
    tools = user.get("tools")
    tools = tools if isinstance(tools, dict) else {}
    raw = tools.get("tool_search")
    raw = {"enabled": "auto"} if raw is None else raw  # None over the default mapping is ignored
    if not isinstance(raw, dict):
        raw = {"enabled": "off" if raw is False else "auto"}
    value = raw.get("enabled")
    value = "auto" if value is None else value  # the default's "auto" survives a None
    aliases = {"true": "on", "1": "on", "yes": "on", "false": "off", "0": "off", "no": "off"}
    word = str(value).strip().lower()
    return aliases.get(word, word if word in ("auto", "on", "off") else "auto") == "off"


ENABLED = "tools:\n  tool_search:\n    enabled: {}\n"
LEGACY = "tools:\n  tool_search: {}\n"
#: (YAML value, direct for Hermes): 20 values of ``enabled`` and 6 of the legacy scalar.
PARITY = [
    (ENABLED.format("off"), True),
    (ENABLED.format("Off"), True),
    (ENABLED.format("OFF"), True),
    (ENABLED.format('"off"'), True),
    (ENABLED.format("'OFF'"), True),
    (ENABLED.format("no"), True),
    (ENABLED.format("n"), True),  # YAML 1.1 boolean
    (ENABLED.format("N"), True),
    (ENABLED.format("false"), True),
    (ENABLED.format('"false"'), True),
    (ENABLED.format("0"), True),
    (ENABLED.format('"no"'), True),
    (ENABLED.format('"n"'), False),  # a string "n" is not one of _tri_state's spellings
    (ENABLED.format("auto"), False),
    (ENABLED.format("on"), False),  # YAML 1.1 true
    (ENABLED.format("yes"), False),
    (ENABLED.format("y"), False),
    (ENABLED.format("1"), False),
    (ENABLED.format('""'), False),
    (ENABLED.format(""), False),  # null: the default "auto"
    (LEGACY.format("false"), True),
    (LEGACY.format("off"), True),  # YAML 1.1 false
    (LEGACY.format("n"), True),
    (LEGACY.format('"off"'), False),  # a string is not ``False``: Hermes reads "auto"
    (LEGACY.format("0"), False),  # neither is the integer 0
    (LEGACY.format("true"), False),
]


def test_the_parity_table_has_26_cases() -> None:
    assert len(PARITY) == 26 and len({text for text, _ in PARITY}) == 26


@posix_only
@pytest.mark.parametrize("text,direct", PARITY)
def test_read_mode_reads_like_hermes(home: Path, text: str, direct: bool) -> None:
    write(home, text)
    assert hermes_rule(text) is direct  # the table itself follows Hermes's rule
    mode = read_mode(home)
    assert mode["direct"] is direct and mode["source"] in ("config", "default")


@posix_only
@pytest.mark.parametrize("text,direct", [(text, direct) for text, direct in PARITY if direct])
def test_off_turns_every_direct_spelling_deferred(home: Path, text: str, direct: bool) -> None:
    write(home, text)
    set_direct(home, False)
    assert read_mode(home)["direct"] is False and hermes_rule((home / "config.yaml").read_text()) is False


@posix_only
def test_no_config_reads_as_the_default_deferred_mode(home: Path) -> None:
    assert read_mode(home) == {"direct": False, "source": "default", "raw": None}
    assert sorted(p.name for p in home.iterdir()) == ["mordred"]  # nothing created by a read


@posix_only
@pytest.mark.parametrize(
    "text,expected",
    [
        ('tools:\n  tool_search:\n    enabled: "off"\n', {"direct": True, "source": "config", "raw": "off"}),
        ("tools:\n  tool_search:\n    enabled: off\n", {"direct": True, "source": "config", "raw": "false"}),
        ("tools:\n  tool_search: false\n", {"direct": True, "source": "config", "raw": "false"}),
        ("tools:\n  tool_search:\n    enabled: on\n", {"direct": False, "source": "config", "raw": "true"}),
        ("tools:\n  tool_search:\n    listing: auto\n", {"direct": False, "source": "default", "raw": None}),
        ("tools: [a, b]\n", {"direct": False, "source": "default", "raw": None}),
        ("tools:\n", {"direct": False, "source": "default", "raw": None}),
        ("model:\n  default: x\n", {"direct": False, "source": "default", "raw": None}),
        ("", {"direct": False, "source": "default", "raw": None}),
    ],
)
def test_source_and_raw(home: Path, text: str, expected: dict[str, object]) -> None:
    write(home, text)
    assert read_mode(home) == expected


@posix_only
def test_raw_is_the_keys_own_value_and_bounded(home: Path) -> None:
    write(home, f'tools:\n  tool_search:\n    enabled: "{"x" * 100}"\nmodel: {CANARY}\n')
    mode = read_mode(home)
    assert mode["raw"] == "x" * 32 and CANARY not in repr(mode)


@posix_only
@pytest.mark.parametrize("text", [f"model: [{CANARY}\n", f"- {CANARY}\n", f"{CANARY}\n", f"a: 1\na: {CANARY}\n"])
def test_unreadable_config_reads_as_unknown_without_any_value(home: Path, text: str) -> None:
    write(home, text)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}


DUPLICATE_ANCHOR = f"model: &m {CANARY}\nother: &m second-{CANARY}\ntools:\n  tool_search:\n    enabled: auto\n"


@posix_only
@pytest.mark.parametrize("enabled", [None, True, False])
def test_a_yaml_warning_is_a_refusal_and_nothing_reaches_any_output(
    home: Path, capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture, enabled: bool | None
) -> None:
    """ruamel's ReusedAnchorWarning quotes both source lines: it is captured, never shown."""
    write(home, DUPLICATE_ANCHOR)
    if enabled is None:
        assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}
    else:
        with pytest.raises(DirectToolsError) as error:
            set_direct(home, enabled)
        assert error.value.code == "config_unreadable"
        assert CANARY not in "".join(traceback.format_exception(error.value))
    out, err = capfd.readouterr()
    assert CANARY not in out + err + caplog.text
    assert (home / "config.yaml").read_text(encoding="utf-8") == DUPLICATE_ANCHOR


def test_warnings_are_captured_without_changing_the_process_filters() -> None:
    import warnings

    before = list(warnings.filters)
    from mordred_hermes.wizard._direct_tools_yaml import hermes_data

    with pytest.raises(DirectToolsError):
        hermes_data(DUPLICATE_ANCHOR)
    assert warnings.filters == before


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


def test_error_codes_are_closed() -> None:
    assert ERROR_CODES == (
        "config_unreadable",
        "config_vault_managed",
        "config_write_failed",
        "config_unsupported_shape",
        "config_has_setting",
    )


# -- shapes Mordred does not edit -----------------------------------------------------------------------

ALIAS = "base: &a\n  enabled: auto\n  listing: on\ntools:\n  tool_search: *a\n"
OWNER = "tools:\n  tool_search: &a\n    enabled: 'off'\nmirror: *a\n"
MERGED = "base: &b\n  enabled: 'off'\ntools:\n  tool_search:\n    <<: *b\n    listing: auto\n"
SHADOWED = "base: &b\n  enabled: 'off'\ntools:\n  tool_search:\n    <<: *b\n    enabled: auto\n"
ROOT_MERGED = "defaults: &d\n  tools:\n    tool_search:\n      enabled: 'off'\n<<: *d\nmodel: x\n"
TOOLS_MERGED = "ts: &t\n  tool_search:\n    enabled: 'off'\ntools:\n  <<: *t\n  other: 1\n"
SCALAR_ALIAS = "x: &v off\ntools:\n  tool_search:\n    enabled: *v\n"
TOOLS_ALIAS = "shared: &t\n  tool_search:\n    enabled: auto\ntools: *t\n"


@posix_only
@pytest.mark.parametrize(
    "text,enabled",
    [
        (ALIAS, True),  # editing the alias would also turn on ``base``
        (OWNER, False),  # removing from the anchor owner would also change ``mirror``
        (MERGED, False),  # the off value is inherited: removing nothing local keeps it direct
        (SHADOWED, True),  # removing or replacing the local value reveals the inherited one
        (ROOT_MERGED, False),
        (TOOLS_MERGED, False),
        (SCALAR_ALIAS, False),
        (TOOLS_ALIAS, True),
        ("tools: [a, b]\n", True),  # never replace an unknown top-level value
    ],
    ids=[
        "alias",
        "anchor-owner",
        "merge-inherited",
        "merge-shadowed",
        "root-merge",
        "tools-merge",
        "scalar-alias",
        "tools-alias",
        "tools-not-a-mapping",
    ],
)
def test_aliases_anchors_and_merges_on_the_path_are_refused_unchanged(home: Path, text: str, enabled: bool) -> None:
    config = write(home, text)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_unsupported_shape"
    assert config.read_text(encoding="utf-8") == text


@posix_only
def test_an_unused_anchor_and_merges_off_the_path_are_fine(home: Path) -> None:
    text = "defaults: &d\n  model: x\nprofile:\n  <<: *d\ntools:\n  tool_search: &own\n    listing: auto\n"
    config = write(home, text)
    set_direct(home, True)
    assert read_mode(home)["direct"] is True
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == text


@posix_only
@pytest.mark.parametrize(
    "text",
    [
        "tools:\n  tool_search:\n    enabled: maybe\n",
        "tools:\n  tool_search:\n    enabled: 2\n",
        "tools:\n  tool_search:\n    enabled: [off]\n",
        'tools:\n  tool_search: "auto"\n',
        "tools:\n  tool_search: 0\n",
    ],
)
def test_on_refuses_a_value_it_would_not_restore(home: Path, text: str) -> None:
    config = write(home, text)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_has_setting"
    assert config.read_text(encoding="utf-8") == text


@posix_only
@pytest.mark.parametrize(
    "value", ["auto", '"auto"', "on", "true", "yes", "y", "1", "Auto", ""], ids=lambda v: v or "null"
)
def test_on_replaces_an_explicit_deferral_and_off_then_removes_the_key(home: Path, value: str) -> None:
    config = write(home, f"tools:\n  tool_search:\n    enabled: {value}\n    listing: auto\n")
    set_direct(home, True)
    assert config.read_text(encoding="utf-8") == 'tools:\n  tool_search:\n    enabled: "off"\n    listing: auto\n'
    set_direct(home, False)
    # Not restored: the key goes, and Hermes's default ("auto") is the same deferral.
    assert config.read_text(encoding="utf-8") == "tools:\n  tool_search:\n    listing: auto\n"


# -- the write is verified --------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("existed", [True, False])
def test_a_write_hermes_would_not_read_as_asked_is_put_back(
    home: Path, monkeypatch: pytest.MonkeyPatch, existed: bool
) -> None:
    """The file is read back after the write; a wrong result is replaced by the old bytes."""
    original = "model: x  # kept\n"
    config = home / "config.yaml"
    if existed:
        write(home, original, mode=0o640)
    real = pw._atomic_write_text
    calls: list[str] = []

    def broken_then_real(path: Path, text: str, *, mode: int | None = None) -> None:
        calls.append(text)
        real(path, "model: x\n" if len(calls) == 1 else text, mode=mode)  # the first write loses the setting

    monkeypatch.setattr(pw, "_atomic_write_text", broken_then_real)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_write_failed"
    if existed:
        assert config.read_text(encoding="utf-8") == original and stat.S_IMODE(config.stat().st_mode) == 0o640
        assert calls[1] == original
    else:
        assert not config.exists()


@posix_only
def test_an_edit_that_changes_anything_else_is_refused_before_writing(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.wizard import _direct_tools_yaml as yamlmod

    real = yamlmod._apply

    def also_other(root: object, enabled: bool) -> None:
        real(root, enabled)
        root["model"] = "changed"  # type: ignore[index]

    monkeypatch.setattr(yamlmod, "_apply", also_other)
    config = write(home, "model: x\n")
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unsupported_shape"
    assert config.read_text(encoding="utf-8") == "model: x\n"


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
@pytest.mark.parametrize("text", ["# only a comment\n", "", "# one\n\n# two\n"], ids=["comment", "empty", "two"])
def test_an_empty_or_comment_only_config_round_trips_byte_for_byte(home: Path, text: str) -> None:
    config = write(home, text)
    set_direct(home, True)
    assert config.read_text(encoding="utf-8") == text + 'tools:\n  tool_search:\n    enabled: "off"\n'
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == text
    assert read_mode(home)["direct"] is False


@posix_only
def test_removing_a_first_key_keeps_the_head_comment_and_the_next_keys_comment(home: Path) -> None:
    text = (
        'tools:\n  tool_search:\n    # head comment for the block\n    enabled: "off"\n'
        "    # about listing\n    listing: auto\nx: 1\n"
    )
    config = write(home, text)
    set_direct(home, False)
    assert config.read_text(encoding="utf-8") == (
        "tools:\n  tool_search:\n    # head comment for the block\n    # about listing\n    listing: auto\nx: 1\n"
    )


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


@posix_only
@pytest.mark.parametrize("managed", [True, False])
def test_a_config_sealed_away_after_the_read_is_refused_and_never_recreated(
    home: Path, monkeypatch: pytest.MonkeyPatch, managed: bool
) -> None:
    """A reseal (it takes no Mordred lock) removes the plaintext between the read and the write."""
    if managed:
        _manage(home)
    config = write(home, CONFIG)
    real = direct_tools.edited

    def resealed_meanwhile(*args: object) -> str | None:
        result = real(*args)  # type: ignore[arg-type]
        config.unlink()
        return result

    monkeypatch.setattr(direct_tools, "edited", resealed_meanwhile)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == ("config_vault_managed" if managed else "config_write_failed")
    assert not config.exists()  # no partial (or any) config.yaml appeared


@posix_only
def test_a_config_rewritten_after_the_read_is_refused_and_the_other_write_kept(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write(home, CONFIG)
    real = direct_tools.edited
    other = "model:\n  default: written-by-hermes\n"

    def rewritten_meanwhile(*args: object) -> str | None:
        result = real(*args)  # type: ignore[arg-type]
        config.write_text(other, encoding="utf-8")
        return result

    monkeypatch.setattr(direct_tools, "edited", rewritten_meanwhile)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_write_failed"
    assert config.read_text(encoding="utf-8") == other


def test_windows_a_yaml_warning_publishes_nothing(windows, capfd: pytest.CaptureFixture[str]) -> None:
    b, paths = windows
    put(b.home, "config.yaml", DUPLICATE_ANCHOR.encode())
    before = b.home.files.copy(), b.policy.files.copy()
    assert read_mode(paths.home)["code"] == "config_unreadable"
    with pytest.raises(DirectToolsError) as error:
        set_direct(paths.home, True)
    assert error.value.code == "config_unreadable"
    assert (b.home.files, b.policy.files) == before
    out, err = capfd.readouterr()
    assert CANARY not in out + err


@pytest.mark.parametrize("text,enabled", [(ALIAS, True), (MERGED, False)], ids=["alias", "merge"])
def test_windows_refuses_the_same_shapes(windows, text: str, enabled: bool) -> None:
    b, paths = windows
    put(b.home, "config.yaml", text.encode())
    before = b.home.files.copy(), b.policy.files.copy()
    with pytest.raises(DirectToolsError) as error:
        set_direct(paths.home, enabled)
    assert error.value.code == "config_unsupported_shape"
    assert (b.home.files, b.policy.files) == before


def test_windows_a_write_read_back_wrong_is_put_back(windows, monkeypatch: pytest.MonkeyPatch) -> None:
    b, paths = windows
    put(b.home, "config.yaml", CONFIG.encode())
    monkeypatch.setattr(direct_tools, "read_mode", lambda home: {"direct": False, "source": "default", "raw": None})
    with pytest.raises(DirectToolsError) as error:
        set_direct(paths.home, True)
    assert error.value.code == "config_write_failed"
    assert b.home.files["config.yaml"][0] == CONFIG.encode()
