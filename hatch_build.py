"""Ship the owned checked VFS in Windows x64 wheels, without runtime activation."""

from __future__ import annotations

import platform
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_HEADERS = runpy.run_path(str(Path(__file__).parent / "tools/dbcrypt_build_headers.py"))
validate_headers = _HEADERS["validate_headers"]


class CustomBuildHook(BuildHookInterface[Any]):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel" or sys.platform != "win32":
            return
        if platform.machine().lower() not in {"amd64", "x86_64"} or struct.calcsize("P") != 8:
            raise RuntimeError("checked database VFS packaging requires Windows x64")
        import os

        include = os.environ.get("MORDRED_SQLITE_INCLUDE_DIR")
        if not include:
            raise RuntimeError("set MORDRED_SQLITE_INCLUDE_DIR to the explicitly prepared SQLCipher API headers")
        headers = Path(include).resolve(strict=True)
        validate_headers(headers)
        # A unique staging directory prevents stale Probe/CheckedTest reuse.
        staging = Path(tempfile.mkdtemp(prefix="mordred-dbcrypt-vfs-"))
        try:
            pinned_headers = staging / "include"
            pinned_headers.mkdir()
            for name in ("sqlite3.h", "sqlite3ext.h"):
                shutil.copyfile(headers / name, pinned_headers / name)
            validate_headers(pinned_headers)
            subprocess.run(
                [
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
                ],
                check=True,
            )
            source = staging / "mordred_dbcrypt_checked.dll"
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
            destination = Path(self.directory) / "mordred-dbcrypt-vfs" / "mordred_dbcrypt_vfs.dll"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            build_data.setdefault("force_include", {})[str(destination)] = (
                "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
            )
            build_data["pure_python"] = False
            build_data["tag"] = "py3-none-win_amd64"
        finally:
            shutil.rmtree(staging)
