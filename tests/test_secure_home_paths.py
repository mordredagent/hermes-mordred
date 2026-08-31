"""Tests for ``mordred_hermes.wizard._secure_home_paths``.

Covers the on-disk config model (``SecureHomeConfig.__post_init__``
validation) and its persistence (``load_config`` / ``save_config`` /
``resolve_config_path``): round-tripping, the env override, and every
load/save refusal (symlinked path components, loose permissions, foreign
ownership, oversized/non-UTF-8 payloads, malformed JSON, missing/wrong-typed
fields, control characters / edge whitespace, and non-UUID ``volume_uuid``
values). Everything runs on ``tmp_path`` — no real ``~/.config`` is touched.

``volume_uuid`` is now validated with ``uuid.UUID`` at construction time, so
every config built in this suite uses a real UUID string (never a placeholder
like ``"u"`` or ``"uuid"``) — a placeholder would now fail
``SecureHomeConfig.__post_init__`` before the behaviour under test ever runs.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mordred_hermes.wizard import _secure_home_paths
from mordred_hermes.wizard._secure_home_paths import (
    CONFIG_VERSION,
    SecureHomeConfig,
    SecureHomeConfigError,
    load_config,
    resolve_config_path,
    save_config,
)

_UUID = "1956CE7B-0F1B-4CE6-A9E4-BAAAD5CF9E1C"
_OTHER_UUID = "2A6F5D3C-8B1E-4F2A-9C3D-7E8F1A2B3C4D"


def _config(tmp_path: Path, **overrides: object) -> SecureHomeConfig:
    fields: dict[str, object] = {
        "version": CONFIG_VERSION,
        "mount_point": tmp_path / "Volumes" / "SecureHermes",
        "volume_uuid": _UUID,
        "home_subdir": "hermes-home",
    }
    fields.update(overrides)
    return SecureHomeConfig(**fields)  # type: ignore[arg-type]


# -----------------------------------------------------------------------------
# SecureHomeConfig.__post_init__
# -----------------------------------------------------------------------------
class TestSecureHomeConfigValidation:
    def test_valid_config_constructs(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        assert config.home_path == config.mount_point / "hermes-home"

    def test_relative_mount_point_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="absolute"):
            _config(tmp_path, mount_point=Path("relative/mount"))

    def test_empty_volume_uuid_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="volume_uuid"):
            _config(tmp_path, volume_uuid="")

    def test_placeholder_uuid_rejected(self, tmp_path: Path) -> None:
        """A non-UUID-shaped placeholder like ``"TEST-UUID-1"`` must now fail."""
        with pytest.raises(SecureHomeConfigError, match="volume_uuid"):
            _config(tmp_path, volume_uuid="TEST-UUID-1")

    @pytest.mark.parametrize("bad_uuid", ["not-a-uuid", "12345", "uuid", "ABCD1234"])
    def test_unparsable_uuid_rejected(self, tmp_path: Path, bad_uuid: str) -> None:
        with pytest.raises(SecureHomeConfigError, match="valid UUID"):
            _config(tmp_path, volume_uuid=bad_uuid)

    @pytest.mark.parametrize("bad_subdir", ["", ".", "..", "a/b", "a\0b"])
    def test_bad_home_subdir_rejected(self, tmp_path: Path, bad_subdir: str) -> None:
        with pytest.raises(SecureHomeConfigError, match="home_subdir"):
            _config(tmp_path, home_subdir=bad_subdir)

    def test_default_home_subdir(self, tmp_path: Path) -> None:
        config = SecureHomeConfig(
            version=CONFIG_VERSION,
            mount_point=tmp_path / "mnt",
            volume_uuid=_UUID,
        )
        assert config.home_subdir == "hermes-home"

    # -- edge whitespace / control characters -------------------------------

    def test_mount_point_leading_whitespace_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="mount_point"):
            _config(tmp_path, mount_point=Path(f" {tmp_path}/mnt"))

    def test_mount_point_trailing_whitespace_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="mount_point"):
            _config(tmp_path, mount_point=Path(f"{tmp_path}/mnt "))

    def test_mount_point_control_char_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="control characters"):
            _config(tmp_path, mount_point=Path(f"{tmp_path}/mnt\x01"))

    def test_mount_point_nul_byte_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="control characters"):
            _config(tmp_path, mount_point=Path(f"{tmp_path}/mnt\x00vol"))

    def test_home_subdir_leading_whitespace_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="home_subdir"):
            _config(tmp_path, home_subdir=" hermes-home")

    def test_home_subdir_trailing_whitespace_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="home_subdir"):
            _config(tmp_path, home_subdir="hermes-home ")

    def test_home_subdir_control_char_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="control characters"):
            _config(tmp_path, home_subdir="hermes\x01home")

    def test_home_subdir_nul_byte_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeConfigError, match="control characters"):
            _config(tmp_path, home_subdir="hermes\x00home")


# -----------------------------------------------------------------------------
# _symlink_hint — the macOS /tmp, /var, /etc symlink-root hint
# -----------------------------------------------------------------------------
class TestSymlinkHint:
    @pytest.mark.parametrize("root", ["/tmp", "/var", "/etc"])
    def test_known_macos_root_gets_hint(self, root: str) -> None:
        hint = _secure_home_paths._symlink_hint(Path(root))
        assert "macOS note" in hint
        assert f"/private{root}" in hint

    def test_unrelated_path_gets_no_hint(self) -> None:
        assert _secure_home_paths._symlink_hint(Path("/opt/something")) == ""

    def test_non_root_path_matching_by_prefix_gets_no_hint(self) -> None:
        """Membership is exact — ``/tmpfoo`` must not fuzzily match ``/tmp``."""
        assert _secure_home_paths._symlink_hint(Path("/tmpfoo")) == ""


# -----------------------------------------------------------------------------
# resolve_config_path
# -----------------------------------------------------------------------------
class TestResolveConfigPath:
    def test_default_path(self) -> None:
        path = resolve_config_path(env={})
        assert path == Path.home() / ".config" / "hermes-mordred" / "secure-home.json"

    def test_env_none_uses_os_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MORDRED_SECURE_HOME_CONFIG", raising=False)
        assert resolve_config_path(env=None) == Path.home() / ".config" / "hermes-mordred" / "secure-home.json"

    def test_env_override_respected(self, tmp_path: Path) -> None:
        override = tmp_path / "custom" / "secure-home.json"
        path = resolve_config_path(env={"MORDRED_SECURE_HOME_CONFIG": str(override)})
        assert path == override

    def test_env_override_is_stripped(self, tmp_path: Path) -> None:
        override = tmp_path / "custom" / "secure-home.json"
        path = resolve_config_path(env={"MORDRED_SECURE_HOME_CONFIG": f"  {override}  "})
        assert path == override

    def test_empty_env_override_ignored(self) -> None:
        path = resolve_config_path(env={"MORDRED_SECURE_HOME_CONFIG": ""})
        assert path == Path.home() / ".config" / "hermes-mordred" / "secure-home.json"

    def test_whitespace_only_env_override_ignored(self) -> None:
        path = resolve_config_path(env={"MORDRED_SECURE_HOME_CONFIG": "   "})
        assert path == Path.home() / ".config" / "hermes-mordred" / "secure-home.json"


# -----------------------------------------------------------------------------
# load_config
# -----------------------------------------------------------------------------
class TestLoadConfig:
    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert load_config(tmp_path / "does-not-exist" / "secure-home.json") is None

    def test_round_trip(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        path = tmp_path / "config" / "secure-home.json"
        save_config(config, path)
        loaded = load_config(path)
        assert loaded == config

    def test_symlink_at_file_rejected(self, tmp_path: Path) -> None:
        real = tmp_path / "real.json"
        real.write_text("{}")
        link = tmp_path / "secure-home.json"
        link.symlink_to(real)
        with pytest.raises(SecureHomeConfigError, match="symlink"):
            load_config(link)

    def test_symlink_in_parent_chain_rejected(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "secure-home.json").write_text("{}")
        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(real_dir)
        with pytest.raises(SecureHomeConfigError, match="symlink"):
            load_config(link_dir / "secure-home.json")

    def test_symlink_refusal_gets_macos_hint_for_known_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end: the refusal message on a /tmp-rooted symlink carries the hint.

        ``_first_symlink_component`` is patched to report ``/tmp`` regardless
        of the path passed in — the filesystem state of the real ``/tmp`` on
        the machine running the test is irrelevant (it may or may not
        actually be a symlink), only the message-formatting wiring is under
        test here.
        """
        monkeypatch.setattr(_secure_home_paths, "_first_symlink_component", lambda path: Path("/tmp"))
        with pytest.raises(SecureHomeConfigError, match="macOS note"):
            load_config(tmp_path / "secure-home.json")

    def test_group_writable_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o660)
        with pytest.raises(SecureHomeConfigError, match="expected mode 0600"):
            load_config(path)

    def test_other_writable_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o606)
        with pytest.raises(SecureHomeConfigError, match="expected mode 0600"):
            load_config(path)

    def test_group_readable_only_mode_rejected(self, tmp_path: Path) -> None:
        """0640 has no write bits set for group/other, but any bit is now refused."""
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o640)
        with pytest.raises(SecureHomeConfigError, match="expected mode 0600"):
            load_config(path)

    def test_world_readable_mode_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o644)
        with pytest.raises(SecureHomeConfigError, match="expected mode 0600"):
            load_config(path)

    def test_not_owned_by_current_user_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o600)
        real_uid = path.stat().st_uid
        monkeypatch.setattr(_secure_home_paths, "_geteuid", lambda: real_uid + 1)
        with pytest.raises(SecureHomeConfigError, match="owned by the current user"):
            load_config(path)

    def test_non_regular_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home-dir.json"
        path.mkdir()
        with pytest.raises(SecureHomeConfigError, match="regular file"):
            load_config(path)

    def test_fifo_rejected_without_hanging(self, tmp_path: Path) -> None:
        """A FIFO with no writer would block a plain ``open()`` forever.

        ``load_config`` opens with ``O_NONBLOCK`` specifically so this
        refusal returns immediately instead of hanging the test suite.
        """
        path = tmp_path / "secure-home.fifo"
        os.mkfifo(path)
        with pytest.raises(SecureHomeConfigError, match="regular file"):
            load_config(path)

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_bytes(b"x" * (64 * 1024 + 1))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="implausibly large"):
            load_config(path)

    def test_non_utf8_bytes_rejected(self, tmp_path: Path) -> None:
        """A regression test: this used to escape as a raw ``UnicodeDecodeError``."""
        path = tmp_path / "secure-home.json"
        path.write_bytes(b"\xff\xfe\x00\x01not utf-8")
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="not valid UTF-8"):
            load_config(path)

    def test_invalid_json_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text("{not json")
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="JSON"):
            load_config(path)

    def test_json_not_object_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text("[1, 2, 3]")
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="JSON object"):
            load_config(path)

    def test_missing_version_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="version"):
            load_config(path)

    def test_unsupported_version_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 99, "mount_point": "/mnt", "volume_uuid": _UUID}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="version"):
            load_config(path)

    def test_missing_mount_point_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "volume_uuid": _UUID}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="mount_point"):
            load_config(path)

    def test_missing_volume_uuid_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt"}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="volume_uuid"):
            load_config(path)

    def test_wrong_type_mount_point_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": 123, "volume_uuid": _UUID}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="mount_point"):
            load_config(path)

    def test_wrong_type_volume_uuid_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": 123}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="volume_uuid"):
            load_config(path)

    def test_wrong_type_home_subdir_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID, "home_subdir": 1}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="home_subdir"):
            load_config(path)

    def test_relative_mount_point_in_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "relative", "volume_uuid": _UUID}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="absolute"):
            load_config(path)

    def test_placeholder_uuid_in_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": "TEST-UUID-1"}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="valid UUID"):
            load_config(path)

    def test_bad_home_subdir_in_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "secure-home.json"
        path.write_text(json.dumps({"version": 1, "mount_point": "/mnt", "volume_uuid": _UUID, "home_subdir": ".."}))
        path.chmod(0o600)
        with pytest.raises(SecureHomeConfigError, match="home_subdir"):
            load_config(path)


# -----------------------------------------------------------------------------
# save_config
# -----------------------------------------------------------------------------
class TestSaveConfig:
    def test_creates_dir_at_0700(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        directory = tmp_path / "config"
        save_config(config, directory / "secure-home.json")
        mode = stat.S_IMODE(directory.stat().st_mode)
        assert mode == 0o700

    def test_pre_existing_parent_dir_keeps_prior_mode(self, tmp_path: Path) -> None:
        """chmod-to-0700 only happens when ``save_config`` itself created the dir."""
        config = _config(tmp_path)
        directory = tmp_path / "config"
        directory.mkdir()
        directory.chmod(0o755)
        save_config(config, directory / "secure-home.json")
        mode = stat.S_IMODE(directory.stat().st_mode)
        assert mode == 0o755

    def test_creates_file_at_0600(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        path = tmp_path / "config" / "secure-home.json"
        save_config(config, path)
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_no_leftover_tmp_files(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        directory = tmp_path / "config"
        save_config(config, directory / "secure-home.json")
        entries = list(directory.iterdir())
        assert entries == [directory / "secure-home.json"]

    def test_overwrite_existing_config_is_atomic(self, tmp_path: Path) -> None:
        path = tmp_path / "config" / "secure-home.json"
        save_config(_config(tmp_path, volume_uuid=_UUID), path)
        save_config(_config(tmp_path, volume_uuid=_OTHER_UUID), path)
        loaded = load_config(path)
        assert loaded is not None
        assert loaded.volume_uuid == _OTHER_UUID
        entries = list(path.parent.iterdir())
        assert entries == [path]

    def test_writes_expected_json_keys(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        path = tmp_path / "config" / "secure-home.json"
        save_config(config, path)
        payload = json.loads(path.read_text())
        assert set(payload.keys()) == {"version", "mount_point", "volume_uuid", "home_subdir"}
        assert payload["version"] == CONFIG_VERSION
        assert payload["mount_point"] == str(config.mount_point)
        assert payload["volume_uuid"] == config.volume_uuid
        assert payload["home_subdir"] == config.home_subdir

    def test_refuses_symlinked_parent(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(real_dir)
        with pytest.raises(SecureHomeConfigError, match="symlink"):
            save_config(_config(tmp_path), link_dir / "secure-home.json")

    def test_refuses_symlinked_file(self, tmp_path: Path) -> None:
        directory = tmp_path / "config"
        directory.mkdir()
        real = directory / "real.json"
        real.write_text("{}")
        link = directory / "secure-home.json"
        link.symlink_to(real)
        with pytest.raises(SecureHomeConfigError, match="symlink"):
            save_config(_config(tmp_path), link)

    def test_symlink_refusal_gets_macos_hint_for_known_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_secure_home_paths, "_first_symlink_component", lambda path: Path("/etc"))
        with pytest.raises(SecureHomeConfigError, match="macOS note"):
            save_config(_config(tmp_path), tmp_path / "secure-home.json")
