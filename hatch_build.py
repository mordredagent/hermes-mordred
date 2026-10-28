"""Ship the owned checked VFS in Windows x64 wheels, without runtime activation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import runpy
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_HEADERS = runpy.run_path(str(Path(__file__).parent / "tools/dbcrypt_build_headers.py"))
validate_headers = _HEADERS["validate_headers"]
COMPILER_LIMIT = 1024 * 1024


def _capture_compiler(argv: list[str], *, cwd: str) -> subprocess.CompletedProcess[bytes]:
    """Capture only the fixed compiler boundary, with bounded pipes and runtime."""
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(index: int, pipe: Any) -> None:
        try:
            while data := pipe.read(65536):
                remaining = COMPILER_LIMIT - len(output[index])
                output[index].extend(data[:remaining])
                if len(data) > remaining:
                    overflow.set()
                    process.kill()
                    break
        finally:
            pipe.close()

    threads = [
        threading.Thread(target=drain, args=(index, pipe), daemon=True)
        for index, pipe in enumerate((process.stdout, process.stderr))
    ]
    for thread in threads:
        thread.start()
    try:
        code = process.wait(timeout=300)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        code = -2
    for thread in threads:
        thread.join(timeout=10)
    if overflow.is_set() or any(thread.is_alive() for thread in threads):
        code = -3
    return subprocess.CompletedProcess(argv, code, bytes(output[0]), bytes(output[1]))


def _receipt_directory(root: Path, checkout: Path) -> Path:
    if not root.is_absolute() or root.is_relative_to(checkout.resolve()):
        raise RuntimeError("build receipt output must be absolute and outside checkout")
    for path in (*reversed(root.parents), root):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("unsafe build receipt output component")
    if os.name != "nt" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise RuntimeError("build receipt output must be private and owned")
    if os.name == "nt":
        _private_windows_receipt_root(root)
    destination = root / ("hook-" + uuid.uuid4().hex)
    destination.mkdir(mode=0o700)
    return destination


def _windows_security_functions() -> tuple[Any, Any]:
    import ctypes
    from ctypes import wintypes

    loader: Any = ctypes
    advapi = loader.WinDLL("advapi32", use_last_error=True)
    kernel = loader.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(pointer),
        pointer,
        ctypes.POINTER(pointer),
        pointer,
        ctypes.POINTER(pointer),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        pointer,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.EqualSid.argtypes = [pointer, pointer]
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(pointer)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [pointer]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return advapi, kernel


def _private_windows_receipt_root(path: Path) -> None:
    """Check this build-output directory's owner/DACL without product imports."""
    import ctypes
    from ctypes import wintypes

    advapi, kernel = _windows_security_functions()
    pointer = ctypes.c_void_p
    owner, dacl, descriptor = pointer(), pointer(), pointer()
    token = wintypes.HANDLE()

    def sid_text(sid: Any) -> str:
        text = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise RuntimeError("build receipt SID observation failed")
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)

    try:
        if (
            advapi.GetNamedSecurityInfoW(
                str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
            )
            or not owner
            or not dacl
        ):
            raise RuntimeError("build receipt owner/DACL observation failed")
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise RuntimeError("build receipt token observation failed")
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)) or not advapi.EqualSid(
            owner, ctypes.cast(buffer, ctypes.POINTER(pointer))[0]
        ):
            raise RuntimeError("build receipt directory must be owned by the current user")
        allowed = {sid_text(owner), "S-1-5-18", "S-1-5-32-544"}
        header = ctypes.string_at(dacl, 8)
        count = struct.unpack_from("<H", header, 4)[0]

        if not _receipt_dacl_allowed(advapi, dacl, count, allowed, sid_text):
            raise RuntimeError("build receipt directory DACL is not private")

    finally:
        if token:
            kernel.CloseHandle(token)
        if descriptor:
            kernel.LocalFree(descriptor)


def _receipt_dacl_allowed(advapi: Any, dacl: Any, count: int, allowed: set[str], sid_text: Any) -> bool:
    import ctypes

    def acceptable(index: int) -> bool:
        ace = ctypes.c_void_p()
        if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or ace.value is None:
            return False
        return ctypes.string_at(ace, 1) == b"\0" and sid_text(ctypes.c_void_p(ace.value + 8)) in allowed

    return all((bool(count), all(acceptable(index) for index in range(count))))


def _receipt_artifact(directory: Path, name: str, data: bytes) -> dict[str, Any]:
    path = directory / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
    return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _compile_receipt(
    argv: list[str], directory: Path, source_root: Path, pinned_headers: Path, version: str, receipt: dict[str, Any]
) -> None:
    receipt.update(
        {
            "schema_version": 1,
            "kind": "dbcrypt_vfs_build",
            "status": "failed",
            "version": version,
            "source_root": str(source_root.resolve()),
            "argv": argv,
            "cwd": os.getcwd(),
            "started_at": time.time(),
            "inputs": {},
        }
    )
    names = ["hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1"]
    names += sorted(
        str(path.relative_to(source_root)).replace("\\", "/")
        for pattern in ("*.c", "*.h")
        for path in (source_root / "native/dbcrypt-vfs").glob(pattern)
    )
    for name in names:
        receipt["inputs"][name] = _receipt_artifact(directory, "inputs/" + name, (source_root / name).read_bytes())
    for name in ("sqlite3.h", "sqlite3ext.h"):
        receipt["inputs"]["headers/" + name] = _receipt_artifact(
            directory, "inputs/headers/" + name, (pinned_headers / name).read_bytes()
        )
    completed = _capture_compiler(argv, cwd=receipt["cwd"])
    receipt.update(finished_at=time.time(), returncode=completed.returncode)
    for stream in ("stdout", "stderr"):
        data = getattr(completed, stream) or b""
        receipt[stream] = _receipt_artifact(directory, stream + ".bin", data[:COMPILER_LIMIT])
        if len(data) > COMPILER_LIMIT:
            receipt["returncode"] = -3
    if receipt["returncode"] != 0:
        raise RuntimeError("captured compiler failed, timed out or exceeded output bound")


def _checked_image(source: Path) -> bytes:
    if not source.is_file() or not source.stat().st_size:
        raise RuntimeError("checked database VFS compiler produced no production DLL")
    image = source.read_bytes()
    try:
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        if (
            image[:2] != b"MZ"
            or image[pe_offset : pe_offset + 4] != b"PE\0\0"
            or struct.unpack_from("<H", image, pe_offset + 4)[0] != 0x8664
        ):
            raise ValueError("not an AMD64 PE image")
    except (struct.error, ValueError):
        raise RuntimeError("checked database VFS compiler did not produce a Windows x64 DLL") from None
    return image


class CustomBuildHook(BuildHookInterface[Any]):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel" or sys.platform != "win32":
            return
        if platform.machine().lower() not in {"amd64", "x86_64"} or struct.calcsize("P") != 8:
            raise RuntimeError("checked database VFS packaging requires Windows x64")
        include = os.environ.get("MORDRED_SQLITE_INCLUDE_DIR")
        if not include:
            raise RuntimeError("set MORDRED_SQLITE_INCLUDE_DIR to the explicitly prepared SQLCipher API headers")
        headers = Path(include).resolve(strict=True)
        validate_headers(headers)
        # A unique staging directory prevents stale Probe/CheckedTest reuse.
        capture = os.environ.get("MORDRED_DBCRYPT_BUILD_RECEIPT_DIR")
        receipt_directory = _receipt_directory(Path(capture), Path(self.root)) if capture else None
        staging = Path(tempfile.mkdtemp(prefix="mordred-dbcrypt-vfs-"))
        receipt: dict[str, Any] = {}
        try:
            pinned_headers = staging / "include"
            pinned_headers.mkdir()
            for name in ("sqlite3.h", "sqlite3ext.h"):
                shutil.copyfile(headers / name, pinned_headers / name)
            validate_headers(pinned_headers)
            argv = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(Path(self.root) / "native/dbcrypt-vfs/build.ps1"),
                "-OutputDirectory",
                str(staging),
                "-SqliteIncludeDirectory",
                str(pinned_headers),
                "-Target",
                "Checked",
            ]
            if receipt_directory is None:
                subprocess.run(argv, check=True)
            else:
                _compile_receipt(argv, receipt_directory, Path(self.root), pinned_headers, version, receipt)
            source = staging / "mordred_dbcrypt_checked.dll"
            image = _checked_image(source)
            destination = Path(self.directory) / "mordred-dbcrypt-vfs" / "mordred_dbcrypt_vfs.dll"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if receipt_directory is not None:
                receipt["dll"] = {
                    **_receipt_artifact(receipt_directory, "mordred_dbcrypt_checked.dll", image),
                    "observed_path": str(source),
                }
                receipt["status"] = "succeeded"
                _receipt_artifact(
                    receipt_directory, "receipt.json", (json.dumps(receipt, sort_keys=True) + "\n").encode()
                )
            build_data.setdefault("force_include", {})[str(destination)] = (
                "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
            )
            build_data["pure_python"] = False
            build_data["tag"] = "py3-none-win_amd64"
        finally:
            if receipt_directory is not None and not (receipt_directory / "receipt.json").exists():
                receipt.setdefault("schema_version", 1)
                receipt.setdefault("kind", "dbcrypt_vfs_build")
                receipt.setdefault("status", "failed")
                _receipt_artifact(
                    receipt_directory, "receipt.json", (json.dumps(receipt, sort_keys=True) + "\n").encode()
                )
            shutil.rmtree(staging)
