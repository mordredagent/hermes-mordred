"""Generic text helpers preserve fail-closed Windows and POSIX publication."""

from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError


def test_generic_windows_helpers_refuse_before_touching_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _config_text_io as text_io

    monkeypatch.setattr(text_io, "_windows", lambda: True)
    target = tmp_path / "absent" / "config.yaml"
    with pytest.raises(PrivateFSError, match="generic_configuration_read_requires_checked_consumer"):
        text_io._read_regular_text(target)
    with pytest.raises(PrivateFSError, match="generic_configuration_write_requires_checked_consumer"):
        text_io._atomic_write_text(target, "secret")
    assert not target.parent.exists()
