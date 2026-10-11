"""Native Windows Tor route, host-emulated: checked images, torrc, reader and cookie.

Every case runs on any host. Executable discovery uses Windows path strings
with an injected filesystem and injected admission. The launch, startup
cleanup and teardown cases are in ``test_network_windows_tor_lifecycle.py``.
No Tor, VPN, registry or network setting is touched.
"""

from __future__ import annotations

import contextlib
import ntpath
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, TextIO

import pytest

from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError, open_private_directory
from mordred_hermes.network import _windows_exec as wexec
from mordred_hermes.network._exceptions import BringupFailed
from mordred_hermes.network.paths import _tor_windows as wtor
from mordred_hermes.network.paths import tor

MANAGED = r"C:\Program Files\Tor Browser\Tor\tor.exe"
PRIVATE = r"C:\Users\Jane Doe\AppData\Local\Programs\トール 実行\tor.exe"
UNTRUSTED = r"C:\Users\Public\Downloads\tor.exe"


# --------------------------------------------------------------------------- #
# Executable discovery and admission                                          #
# --------------------------------------------------------------------------- #


class Images:
    """Injected Windows filesystem view plus the two admission capabilities."""

    def __init__(self, *, files: tuple[str, ...] = (), managed: tuple[str, ...] = (), private: tuple[str, ...] = ()):
        self.files = {ntpath.normcase(path) for path in files}
        self.managed_paths = {ntpath.normcase(path) for path in managed}
        self.private_paths = {ntpath.normcase(path) for path in private}
        self.lookups: list[str] = []
        self.admissions: list[tuple[str, str]] = []

    def is_file(self, path: str) -> bool:
        self.lookups.append(path)
        return ntpath.normcase(path) in self.files

    def managed(self, path: str) -> FileMetadata:
        self.admissions.append(("managed", path))
        if ntpath.normcase(path) in self.managed_paths:
            return FileMetadata(FileIdentity(1, b"managed"), 1, 0)
        raise PrivateFSError("unsafe", "managed_image_acl")

    def private(self, path: str) -> None:
        self.admissions.append(("private", path))
        if ntpath.normcase(path) not in self.private_paths:
            raise PrivateFSError("unsafe", "confidential_acl")


def resolve(command: str, images: Images, *, path_env: str = r"C:\Program Files\Tor Browser\Tor") -> Any:
    return wexec.resolve_windows_executable(
        command,
        purpose="tor",
        environ={"Path": path_env},
        is_file=images.is_file,
        admit_managed=images.managed,
        admit_user_private=images.private,
    )


def test_absolute_path_with_spaces_and_unicode_resolves_to_the_same_image() -> None:
    images = Images(files=(PRIVATE,), private=(PRIVATE,))
    resolved = resolve(PRIVATE, images)
    assert resolved.path == PRIVATE
    assert resolved.trust == "user-private"
    # Managed admission is tried first and refused before the private check.
    assert images.admissions == [("managed", PRIVATE), ("private", PRIVATE)]


def test_managed_installation_image_is_admitted_first() -> None:
    images = Images(files=(MANAGED,), managed=(MANAGED,))
    resolved = resolve("tor", images)
    assert (resolved.path, resolved.trust) == (MANAGED, "managed")
    assert images.admissions == [("managed", MANAGED)]


def test_bare_name_searches_only_absolute_path_entries_never_the_current_directory() -> None:
    images = Images(files=(MANAGED, r".\tor.exe", r"relative\bin\tor.exe"), managed=(MANAGED,))
    path_env = r'.;relative\bin; ;\\server\share\tor;"C:\Program Files\Tor Browser\Tor";C:\Later'
    resolved = resolve("tor", images, path_env=path_env)
    assert resolved.path == MANAGED
    # Relative, empty and UNC entries are skipped; the quoted entry is honored.
    assert images.lookups == [MANAGED]


def test_bare_name_with_explicit_exe_suffix_is_accepted() -> None:
    images = Images(files=(MANAGED,), managed=(MANAGED,))
    assert resolve("TOR.EXE", images).path == ntpath.join(ntpath.dirname(MANAGED), "TOR.EXE")


@pytest.mark.parametrize(
    "command",
    ["tor.cmd", "tor.bat", "tor.com", "tor.ps1", r"C:\Tor\tor.cmd", r"C:\Tor\tor", r"C:\Tor\tor.exe.bat"],
)
def test_only_exe_images_are_accepted(command: str) -> None:
    images = Images(files=(command,), managed=(command,))
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(command, images)
    assert caught.value.reason == "executable-not-exe"
    assert images.lookups == []


@pytest.mark.parametrize("command", [r"bin\tor.exe", "./tor.exe", "C:tor.exe", r"..\Tor\tor.exe", "/opt/tor.exe"])
def test_relative_and_drive_relative_paths_refuse(command: str) -> None:
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(command, Images(files=(command,)))
    assert caught.value.reason == "executable-path-relative"


@pytest.mark.parametrize(
    "command", [r"\\server\share\tor.exe", r"\\?\C:\Tor\tor.exe", r"\\.\C:\tor.exe", "//srv/x/tor.exe"]
)
def test_device_and_network_namespaces_refuse(command: str) -> None:
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(command, Images(files=(command,)))
    assert caught.value.reason == "executable-path-unsupported"


@pytest.mark.parametrize("command", ["", "tor\x00.exe", 'to"r.exe', "tor\n", "tor|x.exe"])
def test_invalid_names_refuse(command: str) -> None:
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(command, Images())
    assert caught.value.reason == "executable-name-invalid"


def test_missing_image_refuses() -> None:
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve("tor", Images())
    assert caught.value.reason == "executable-not-found"
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(MANAGED, Images())
    assert caught.value.reason == "executable-not-found"


def test_user_writable_image_in_untrusted_namespace_is_classified_untrusted() -> None:
    resolved = resolve(UNTRUSTED, Images(files=(UNTRUSTED,)))
    assert (resolved.path, resolved.trust) == (UNTRUSTED, "untrusted")


def test_strict_refuses_an_untrusted_image_and_lenient_warns(caplog: pytest.LogCaptureFixture) -> None:
    resolved = resolve(UNTRUSTED, Images(files=(UNTRUSTED,)))
    with pytest.raises(wexec.ExecutableRefused) as caught:
        wexec.enforce_executable_trust(resolved, policy_mode="strict", purpose="tor")
    assert caught.value.reason == "executable-untrusted-location"
    assert isinstance(caught.value, BringupFailed)
    with caplog.at_level("WARNING", logger="mordred.network"):
        wexec.enforce_executable_trust(resolved, policy_mode="lenient", purpose="tor")
        wexec.enforce_executable_trust(resolved, policy_mode="off", purpose="tor")
    assert sum("untrusted" in record.getMessage() for record in caplog.records) == 2
    trusted = resolve(MANAGED, Images(files=(MANAGED,), managed=(MANAGED,)))
    wexec.enforce_executable_trust(trusted, policy_mode="strict", purpose="tor")


@pytest.mark.parametrize(
    "secret",
    ["C:\\Users\\Jane\\secret-token-1234\\evil\x07name.cmd", "C:\\Users\\Jane\\secret-token-1234\\name.cmd"],
)
def test_refusals_name_only_a_sanitized_basename(secret: str) -> None:
    with pytest.raises(wexec.ExecutableRefused) as caught:
        resolve(secret, Images(files=(secret,)))
    message = str(caught.value)
    assert "secret-token-1234" not in message
    assert "\x07" not in message
    assert "name.cmd" in message


def test_admission_errors_other_than_classified_refusals_are_not_swallowed() -> None:
    images = Images(files=(MANAGED,))

    def broken(_path: str) -> None:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        wexec.resolve_windows_executable(
            MANAGED, purpose="tor", environ={}, is_file=images.is_file, admit_managed=broken
        )


class TestCurrentUserImageAdmission:
    """The user-private admission reuses the checked directory capability."""

    @pytest.fixture(autouse=True)
    def _host_capability(self, monkeypatch: pytest.MonkeyPatch) -> None:
        if os.name != "nt":
            # The confidential adapter exists only on Windows; substitute the
            # stricter checked private directory of this host beneath it.
            monkeypatch.setattr(wexec, "open_optional_confidential_directory", _optional_private)

    def _stub(self, directory: Path) -> Path:
        # Published through the checked transaction: private ACL (0600) before bytes.
        with open_private_directory(directory, create=True) as checked, checked.transaction() as txn:
            txn.create_bytes("tor.exe", b"MZ stub")
        return directory / "tor.exe"

    def test_current_user_file_in_checked_directory_is_admitted(self, tmp_path: Path) -> None:
        image = self._stub(tmp_path / "ユーザー tools")
        wexec.admit_current_user_image(str(image))

    @pytest.mark.parametrize("damage", ["file-mode", "directory-mode", "hardlink", "missing-parent"])
    def test_unsafe_or_missing_images_refuse(self, tmp_path: Path, damage: str) -> None:
        if os.name == "nt":
            pytest.skip("POSIX-mode damage; native ACL damage is in the native module")
        image = self._stub(tmp_path / "tools")
        if damage == "file-mode":
            image.chmod(0o664)
        elif damage == "directory-mode":
            image.parent.chmod(0o775)
        elif damage == "hardlink":
            os.link(image, tmp_path / "alias.exe")
        else:
            image = tmp_path / "absent" / "tor.exe"
        with pytest.raises((OSError, ValueError)):
            wexec.admit_current_user_image(str(image))


@contextlib.contextmanager
def _optional_private(path: str | Path) -> Iterator[Any]:
    if not Path(path).is_dir():
        yield None
        return
    with open_private_directory(path) as directory:
        yield directory


# --------------------------------------------------------------------------- #
# torrc rendering                                                             #
# --------------------------------------------------------------------------- #


def test_posix_torrc_rendering_is_unchanged(tmp_path: Path) -> None:
    rendered = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path, disable_ipv6=True)
    assert rendered == (
        "SOCKSPort 127.0.0.1:9050 IsolateSOCKSAuth\n"
        "ControlPort 127.0.0.1:9051\n"
        "CookieAuthentication 1\n"
        f"DataDirectory {tmp_path}\n"
        "ClientUseIPv6 0\n"
    )


def test_windows_torrc_quotes_paths_binds_loopback_and_pins_the_owner() -> None:
    data_dir = PureWindowsPath(r'C:\Users\Jane "Q" Doe\データ\.hermes\mordred\tor-data')
    rendered = tor.render_torrc(
        socks_port=9150,
        control_port=9151,
        data_dir=data_dir,  # type: ignore[arg-type]
        quote_paths=True,
        owning_controller_pid=4242,
    )
    assert rendered.splitlines() == [
        "SOCKSPort 127.0.0.1:9150 IsolateSOCKSAuth",
        "ControlPort 127.0.0.1:9151",
        "CookieAuthentication 1",
        r'DataDirectory "C:\\Users\\Jane \"Q\" Doe\\データ\\.hermes\\mordred\\tor-data"',
        "__OwningControllerProcess 4242",
    ]


@pytest.mark.parametrize("bad", ["C:\\tor\ndata", "C:\\tor\rdata", "C:\\tor\x00x", "C:\\tor\x7fx"])
def test_windows_torrc_refuses_control_characters(bad: str) -> None:
    with pytest.raises(BringupFailed):
        tor.render_torrc(socks_port=9050, control_port=9051, data_dir=PureWindowsPath(bad), quote_paths=True)  # type: ignore[arg-type]


@pytest.mark.parametrize("pid", [0, -1, True, "1"])
def test_windows_torrc_refuses_an_invalid_owner_pid(pid: Any, tmp_path: Path) -> None:
    with pytest.raises(BringupFailed):
        tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path, owning_controller_pid=pid)


# --------------------------------------------------------------------------- #
# Bounded bootstrap reader (shared by every platform)                         #
# --------------------------------------------------------------------------- #


@pytest.fixture
def pipe() -> Iterator[tuple[TextIO, TextIO]]:
    read_fd, write_fd = os.pipe()
    reader = os.fdopen(read_fd, "r", encoding="utf-8")
    writer = os.fdopen(write_fd, "w", encoding="utf-8")
    try:
        yield reader, writer
    finally:
        with contextlib.suppress(OSError, ValueError):
            writer.close()
        with contextlib.suppress(OSError, ValueError):
            reader.close()


def test_bootstrap_reader_classifies_an_oversized_line(
    monkeypatch: pytest.MonkeyPatch, pipe: tuple[TextIO, TextIO]
) -> None:
    monkeypatch.setattr(tor, "MAX_BOOTSTRAP_LINE_CHARS", 16)
    reader, writer = pipe
    writer.write("short\n" + "x" * 200 + "\nBootstrapped 100%\n")
    writer.close()
    read_line, cleanup = tor._make_default_read_line(reader)
    try:
        assert read_line(2.0) == "short\n"
        with pytest.raises(BringupFailed, match="exceeded 16 characters"):
            read_line(2.0)
        assert read_line(2.0) is None
    finally:
        cleanup()


def test_bootstrap_reader_caps_buffered_lines(monkeypatch: pytest.MonkeyPatch, pipe: tuple[TextIO, TextIO]) -> None:
    monkeypatch.setattr(tor, "MAX_BUFFERED_BOOTSTRAP_LINES", 4)
    reader, writer = pipe
    writer.write("".join(f"line {index}\n" for index in range(50)))
    writer.close()
    read_line, cleanup = tor._make_default_read_line(reader)
    try:
        deadline = time.monotonic() + 5
        received: list[str] = []
        with pytest.raises(BringupFailed, match="buffered lines"):
            while time.monotonic() < deadline:
                time.sleep(0.2)  # let the pump overrun the bounded buffer first
                line = read_line(2.0)
                assert line is not None
                received.append(line)
        assert received == [f"line {index}\n" for index in range(4)][: len(received)]
        assert len(received) <= 4
    finally:
        cleanup()


def test_bootstrap_still_succeeds_with_a_bounded_reader(pipe: tuple[TextIO, TextIO]) -> None:
    reader, writer = pipe

    class _Process:
        stdout = reader

        def poll(self) -> None:
            return None

    writer.write("notice\nBootstrapped 100% (done)\n")
    writer.flush()
    tor.wait_for_bootstrap(_Process(), timeout=5.0)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Checked control-cookie reads                                                #
# --------------------------------------------------------------------------- #


class _AliveProcess:
    stdout = None

    def poll(self) -> None:
        return None


class _Controller:
    """stem ``Controller`` stand-in reporting ``cookie_path`` in PROTOCOLINFO."""

    def __init__(self, cookie_path: object = None) -> None:
        self.authenticated = False
        self.protocolinfo = SimpleNamespace(cookie_path=cookie_path)
        self.protocolinfo_calls = 0
        self.authentications: list[object] = []

    def __enter__(self) -> _Controller:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get_protocolinfo(self) -> SimpleNamespace:
        self.protocolinfo_calls += 1
        return self.protocolinfo

    def authenticate(self, *, protocolinfo_response: object = None) -> None:
        self.authentications.append(protocolinfo_response)
        self.authenticated = True

    def get_info(self, key: str) -> str:
        return "1 BUILT $AAAA~relay" if key == "circuit-status" else "up"

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("outcome", "expected", "factory_used"),
    [
        (PrivateFSError("missing", "open"), True, False),
        (PrivateFSError("unsafe", "public_build_source"), False, False),
        (PrivateFSError("unsafe", "public_build_bound"), False, False),
        (b"\x01" * 31, False, False),
        (b"\x01" * 32, True, True),
    ],
)
def test_windows_cookie_is_read_through_the_checked_bounded_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome: Any, expected: bool, factory_used: bool
) -> None:
    reads: list[tuple[Path, int]] = []

    def fake_reader(path: Path, *, max_bytes: int) -> bytes:
        reads.append((Path(path), max_bytes))
        if isinstance(outcome, BaseException):
            raise outcome
        return bytes(outcome)

    monkeypatch.setattr(wtor, "read_public_build_output", fake_reader)
    monkeypatch.setattr(sys, "platform", "win32")
    controllers: list[_Controller] = []

    def factory(**_kwargs: Any) -> _Controller:
        controllers.append(_Controller(str(tmp_path / "control_auth_cookie")))
        return controllers[-1]

    handle = tor.TorHandle(process=_AliveProcess(), socks_port=9050, control_port=9051, data_dir=tmp_path)
    assert tor.circuit_status_health(handle, controller_factory=factory) is expected
    assert reads == [(tmp_path / "control_auth_cookie", 32)]
    assert bool(controllers) is factory_used


# --------------------------------------------------------------------------- #
# Tor-reported cookie path pinned to the private tor-data directory           #
# --------------------------------------------------------------------------- #


def _probe_with_reported_cookie(
    monkeypatch: pytest.MonkeyPatch, data_dir: Path, reported: object
) -> tuple[bool, _Controller]:
    """Run the Windows deep probe with a checked-``ok`` cookie and ``reported`` path."""
    monkeypatch.setattr(wtor, "read_public_build_output", lambda path, *, max_bytes: b"\x01" * 32)
    monkeypatch.setattr(sys, "platform", "win32")
    controller = _Controller(reported)
    handle = tor.TorHandle(process=_AliveProcess(), socks_port=9050, control_port=9051, data_dir=data_dir)
    return tor.circuit_status_health(handle, controller_factory=lambda **_kwargs: controller), controller


@pytest.mark.parametrize("variant", ["exact", "case", "dot-segment", "parent-hop"])
def test_windows_stem_reads_only_the_pinned_private_cookie(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variant: str
) -> None:
    data_dir = tmp_path / "ホーム home" / "mordred" / "tor-data"
    cookie = str(data_dir / "control_auth_cookie")
    reported = {
        "exact": cookie,
        "case": cookie.upper(),
        "dot-segment": str(data_dir) + "/./control_auth_cookie",
        "parent-hop": str(data_dir) + "/sub/../control_auth_cookie",
    }[variant]
    healthy, controller = _probe_with_reported_cookie(monkeypatch, data_dir, reported)
    assert healthy is True
    assert controller.protocolinfo_calls == 1
    # stem receives the very response whose COOKIEFILE was pinned, so it sends
    # no second PROTOCOLINFO and opens only the checked private cookie.
    assert len(controller.authentications) == 1
    assert controller.authentications[0] is controller.protocolinfo


def _reported_cookie(kind: str, data_dir: Path) -> object:
    return {
        "none": None,
        "empty": "",
        "bytes": b"control_auth_cookie",
        "relative": "control_auth_cookie",
        "parent": str(data_dir.parent / "control_auth_cookie"),
        "subdirectory": str(data_dir / "sub" / "control_auth_cookie"),
        "escape": str(data_dir) + "/../elsewhere/control_auth_cookie",
        "renamed": str(data_dir / "control_auth_cookie.bak"),
        "public": r"C:\Users\Public\control_auth_cookie",
    }[kind]


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("none", wtor.COOKIE_PATH_UNREPORTED),
        ("empty", wtor.COOKIE_PATH_UNREPORTED),
        ("bytes", wtor.COOKIE_PATH_UNREPORTED),
        ("relative", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
        ("parent", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
        ("subdirectory", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
        ("escape", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
        ("renamed", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
        ("public", wtor.COOKIE_PATH_OUTSIDE_TOR_DATA),
    ],
)
def test_windows_cookie_path_outside_tor_data_refuses_with_a_classified_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture, kind: str, reason: str
) -> None:
    data_dir = tmp_path / "mordred" / "tor-data"
    reported = _reported_cookie(kind, data_dir)
    with caplog.at_level("WARNING", logger="mordred.network"):
        healthy, controller = _probe_with_reported_cookie(monkeypatch, data_dir, reported)
    assert healthy is False
    assert controller.protocolinfo_calls == 1
    assert controller.authentications == []  # stem never opens the reported path
    messages = [entry.getMessage() for entry in caplog.records]
    assert any(reason in message for message in messages)
    if isinstance(reported, str) and reported:
        assert not any(reported in message for message in messages)


def test_posix_deep_probe_keeps_stem_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    (tmp_path / "control_auth_cookie").write_bytes(b"\x01" * 32)
    controller = _Controller(None)
    handle = tor.TorHandle(process=_AliveProcess(), socks_port=9050, control_port=9051, data_dir=tmp_path)
    assert tor.circuit_status_health(handle, controller_factory=lambda **_kwargs: controller) is True
    assert controller.protocolinfo_calls == 0
    assert controller.authentications == [None]
