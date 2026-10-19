"""The portable proof child copies static package payload, never Cargo output."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import zipfile
from pathlib import Path

import pytest

from tests.test_packaging_native import built_wheel as built_wheel
from tests.test_windows_memory_proof import _copy_static_package


@pytest.mark.parametrize("helper", ["tpmkey-helper", "winkey-helper"])
def test_generated_target_is_never_traversed_or_read(tmp_path, monkeypatch, helper):
    package = tmp_path / "package"
    generated = package / "_native" / helper / "target"
    generated.mkdir(parents=True)
    (generated / "locked-sentinel").write_bytes(b"generated build output")
    static = {
        "__init__.py": b"# static package\n",
        f"_native/{helper}/Cargo.toml": b"[package]\n",
        f"_native/{helper}/src/main.rs": b"fn main() {}\n",
        "target/runtime.dat": b"unrelated target is static",
        "_native/unknown-helper/target/runtime.dat": b"unknown helper is static",
        "keyvault/_native/winkey-helper/target/runtime.dat": b"unrelated layout is static",
        "_native/sekey-helper/target/runtime.dat": b"non-Cargo helper is static",
    }
    for relative, payload in static.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    cache = package / "nested" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "cached.pyc").write_bytes(b"bytecode")
    real_scandir = os.scandir
    visited = []

    def guarded_scandir(path):
        visited.append(Path(path))
        assert Path(path) != generated, "generated target was traversed"
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)
    destination = tmp_path / "copy"
    _copy_static_package(package, destination)
    assert package in visited
    assert not (destination / "_native" / helper / "target").exists()
    assert not (destination / "nested" / "__pycache__").exists()
    assert {
        p.relative_to(destination).as_posix(): p.read_bytes() for p in destination.rglob("*") if p.is_file()
    } == static


def test_static_wheel_record_payload_is_preserved(built_wheel, tmp_path):
    source = tmp_path / "extracted"
    destination = tmp_path / "copied"
    with zipfile.ZipFile(built_wheel) as archive:
        archive.extractall(source)
        record = next(name for name in archive.namelist() if name.endswith(".dist-info/RECORD"))
        records = {row[0]: row[1:] for row in csv.reader(io.StringIO(archive.read(record).decode()))}
        members = {
            name: archive.read(name)
            for name in archive.namelist()
            if name.startswith("mordred_hermes/") and not name.endswith("/")
        }
    _copy_static_package(source / "mordred_hermes", destination)
    copied = {p.relative_to(destination).as_posix(): p.read_bytes() for p in destination.rglob("*") if p.is_file()}
    assert set(copied) == {name.removeprefix("mordred_hermes/") for name in members}
    for name, payload in members.items():
        actual = copied[name.removeprefix("mordred_hermes/")]
        assert actual == payload, name
        digest = base64.urlsafe_b64encode(hashlib.sha256(actual).digest()).rstrip(b"=").decode()
        assert records[name] == ["sha256=" + digest, str(len(actual))], name
