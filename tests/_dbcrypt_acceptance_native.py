"""Fixed opt-in native child operations and content-free pytest reporting.

Nothing native is imported or executed at module import/pytest collection.
Secrets stay in RAM or the real native sealed stores; exported rows are fixed
synthetic IDs/content digests and public source/filesystem metadata only.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import io
import json
import os
import runpy
import stat
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

TEXT = "今日は東京で日本語を勉強します"
PROFILES = ("root", "work", "other")
COLLECTOR_ROWS = ("sessiondb", "activity", "telegram", "mail", "credentials", "source_memory", "scoped_siblings")
SIBLING_DATABASES = (
    "shared-state.db",
    "projects.db",
    "response_store.db",
    "memory_store.db",
    "kanban.db",
    "cron/executions.db",
    "telemetry/shared_metrics/metrics.sqlite3",
)


def logical_digest(rows: list[dict[str, Any]]) -> str:
    allowed = {"id", "text", "source", "profile", "component", "count"}
    if any(set(row) - allowed or any(type(value) not in (str, int) for value in row.values()) for row in rows):
        raise ValueError("synthetic_record_fields_only")
    encoded = json.dumps(
        sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool() -> dict[str, Any]:
    return runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/dbcrypt_acceptance.py"))


def _root() -> Path:
    selected = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    if os.environ.get("MORDRED_DBCRYPT_COLLECTORS_TEST") != "1" or not selected:
        raise RuntimeError("explicit_native_collector_optin_required")
    root = Path(selected)
    if not root.is_absolute() or root != root.resolve() or not root.name.startswith("mordred-dbcrypt-"):
        raise RuntimeError("canonical_synthetic_native_root_required")
    production = Path.home() / ".hermes"
    if root == production or production in root.parents or os.environ.get("HERMES_HOME") != str(root):
        raise RuntimeError("isolated_native_home_required_before_import")
    return root


def _interfaces() -> Any:
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.keyvault import _database_authority

    required = getattr(_database_authority, "require_database_memory_enabled", None)
    annotation = inspect.signature(_migrate.migrate).parameters["key"].annotation
    if not callable(required) or "None" not in str(annotation):
        raise RuntimeError("integrated_native_memory_and_none_conversion_contract_required")
    return required


def _windows_provider() -> dict[str, Any]:
    import ctypes as c
    from ctypes import wintypes as w

    native_ctypes: Any = c
    if native_ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("ordinary_windows_token_required")
    library = native_ctypes.WinDLL("ncrypt", use_last_error=True)
    library.NCryptOpenStorageProvider.argtypes = (c.POINTER(c.c_void_p), w.LPCWSTR, w.DWORD)
    library.NCryptGetProperty.argtypes = (c.c_void_p, w.LPCWSTR, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), w.DWORD)
    library.NCryptFreeObject.argtypes = (c.c_void_p,)
    provider, flags, size = c.c_void_p(), w.DWORD(), w.DWORD()
    name = "Microsoft Platform Crypto Provider"
    if library.NCryptOpenStorageProvider(c.byref(provider), name, 0):
        raise RuntimeError("native_cng_provider_unavailable")
    try:
        if library.NCryptGetProperty(provider, "Impl Type", c.byref(flags), c.sizeof(flags), c.byref(size), 0):
            raise RuntimeError("native_cng_implementation_unobservable")
        if not flags.value & 1 or flags.value & 2:
            raise RuntimeError("hardware_only_cng_provider_required")
    finally:
        library.NCryptFreeObject(provider)
    return {"native_provider": name, "implementation_flags": flags.value, "elevated": False}


def _linux_provider() -> dict[str, Any]:
    device = next((path for path in (Path("/dev/tpmrm0"), Path("/dev/tpm0")) if path.exists()), None)
    if device is None or Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "Amazon EC2":
        raise RuntimeError("real_ec2_tpm_device_required")
    result = subprocess.run(
        ["tpm2_getcap", "-T", "device:" + str(device), "properties-fixed"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    # Manufacturer is a public TPM property. A user-provided provider label is
    # never sufficient and no helper secret-response is collected here.
    if result.returncode or 'value: "AMZN"' not in result.stdout:
        raise RuntimeError("amazon_tpm_manufacturer_unobservable")
    return {
        "native_provider": "EC2 NitroTPM",
        "device": str(device),
        "manufacturer": "AMZN",
        "dmi_vendor": "Amazon EC2",
    }


def boot_identity() -> dict[str, str]:
    if sys.platform == "linux":
        return {"method": "proc_boot_id", "identity": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    command = (
        "$o=Get-CimInstance Win32_OperatingSystem;$h=Get-CimInstance Win32_ComputerSystemProduct;"
        "@{boot=$o.LastBootUpTime.ToUniversalTime().ToString('o');host=$h.UUID}|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    value = json.loads(result.stdout)
    return {"method": "cim_last_boot_utc_and_system_uuid", "identity": value["host"] + ":" + value["boot"]}


def _observe_packaged_dll() -> dict[str, Any]:
    import base64
    import ctypes
    import importlib.metadata

    from mordred_hermes.dbcrypt import _windows_vfs

    path = _windows_vfs.packaged_library_path()
    if path is None or not _windows_vfs.driver_distribution_qualified():
        raise RuntimeError("owned_checked_distribution_required")
    path = path.resolve(strict=True)
    import sqlcipher3._sqlite3 as driver_native

    distribution = importlib.metadata.distribution("hermes-mordred")
    matches = [entry for entry in distribution.files or () if Path(entry.locate()).resolve() == path]
    assert len(matches) == 1 and matches[0].hash is not None and matches[0].hash.mode == "sha256"
    encoded = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=").decode()
    assert matches[0].hash.value == encoded, "DLL must be owned by this distribution RECORD"
    assert not os.environ.get("MORDRED_DBCRYPT_CHECKED_LIBRARY"), "runtime collector forbids environment DLL override"
    native = ctypes.CDLL(str(path))
    assert not any(hasattr(native, name) for name in ("mordred_vfs_test_hook", "mordred_vfs_test_shm_idempotence"))
    records = [entry for entry in distribution.files or () if str(entry).endswith(".dist-info/RECORD")]
    assert len(records) == 1
    record = Path(records[0].locate()).resolve(strict=True)
    return {
        "path": str(path),
        "sha256": _digest(path),
        "kind": "distribution_owned_Checked",
        "record_verified": True,
        "driver_native": str(Path(driver_native.__file__).resolve()),
        "driver_native_sha256": _digest(Path(driver_native.__file__)),
        "record": str(record),
        "record_sha256": _digest(record),
        "record_size": record.stat().st_size,
        "installed_at": record.stat().st_mtime,
    }


def _owned_windows_dll(qualified: dict[str, Any]) -> dict[str, Any]:
    observed = _observe_packaged_dll()
    tested = qualified["source" if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_MODE"] == "source" else "wheel"]
    assert observed["driver_native_sha256"] == tested["driver_native_sha256"]
    if observed["sha256"] != tested["dll_sha256"]:
        raise RuntimeError("owned_checked_distribution_required")
    return {key: observed[key] for key in ("path", "sha256", "kind", "record_verified")}


def package_qualification_observation() -> dict[str, Any]:
    """Packaged C-test facts only; no custody/native-source/bootstrap operations."""
    import ctypes
    import importlib.metadata

    import sqlcipher3.dbapi2 as driver

    import mordred_hermes
    from mordred_hermes._database_locking_windows import identify_root
    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.keyvault import kek

    kek._noop_audit = lambda _entry: None

    assert sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin()
    assert not any(
        os.environ.get(name)
        for name in (
            "MORDRED_DBCRYPT_COLLECTORS_TEST",
            "MORDRED_DBCRYPT_ACCEPTANCE_KIND",
            "MORDRED_WINKEY_HELPER",
            "HERMES_MEMORY_KEY",
            "MORDRED_DBCRYPT_CHECKED_LIBRARY",
        )
    )
    tool = _tool()
    bundle_path = Path(os.environ["DBCRYPT_BUNDLE"])
    bundle = tool["validate_bundle"](bundle_path)
    proof = tool["_local_bundle_proof"](bundle_path, bundle)
    diagnostic = tool["validate_windows_diagnostic"](
        Path(os.environ["MORDRED_DBCRYPT_VFS_DIAGNOSTIC"]).parent, checkout=Path(bundle["checkout"])
    )
    fixture_path = Path(os.environ["MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR"])
    fixture = json.loads(fixture_path.read_text())
    plan = tool["_qualification_fixture"](fixture_path.parent, fixture)
    root = Path(os.environ["MORDRED_DBCRYPT_TEST_ROOT"])
    assert str(root) == plan["test_root"]
    with open_confidential_directory(root):
        identity = asdict(identify_root(root))
    sid = tool["canonical_windows_owner_sid"](identity["owner"])
    assert sid == plan["owner_sid"]
    mode = os.environ["MORDRED_DBCRYPT_VFS_PACKAGE_MODE"]
    dll = _observe_packaged_dll()
    connection = driver.connect(":memory:")
    try:
        versions = {
            "sqlite": driver.sqlite_version,
            "sqlcipher": connection.execute("pragma cipher_version").fetchone()[0],
        }
    finally:
        connection.close()
    from mordred_hermes.dbcrypt import _windows_vfs

    declared = tool["windows_activation_declaration"](Path(_windows_vfs.__file__).read_text())
    assert _windows_vfs.NATIVE_QUALIFIED is True
    observed = {
        "eligibility": {
            "declared_qualified": declared,
            "observed_qualified": True,
            "bootstrap": "automatic_production" if declared else "explicit_candidate",
        },
        "mode": mode,
        "role": "packaged_editable" if mode == "source" else "packaged_wheel",
        "commit": bundle["commit"],
        "bundle_manifest_sha256": _digest(bundle_path / "manifest.json"),
        "product_module": str(Path(mordred_hermes.__file__).resolve()),
        "executable": str(Path(sys.executable).resolve()),
        "python_sha256": _digest(Path(sys.executable)),
        "dll": dll["path"],
        "dll_sha256": dll["sha256"],
        **{
            key: dll[key]
            for key in (
                "driver_native",
                "driver_native_sha256",
                "record",
                "record_sha256",
                "record_size",
                "installed_at",
            )
        },
        "driver_version": importlib.metadata.version("sqlcipher3-wheels"),
        "versions": versions,
        "elevated": False,
        "sid": sid,
        "fixture_root": str(root),
        "filesystem": {"method": "checked_confidential_fixed_local_ntfs", "identity": identity},
        "test_exports_absent": True,
        "env_dll_override": None,
        "observed_at": time.time(),
    }
    observed["build_receipts"] = tool["matching_build_receipts"](
        observed, bundle=bundle, proof=proof, directory=bundle_path, headers=diagnostic["provenance"]["headers"]
    )
    tool["validate_package_observation"](
        observed,
        mode=mode,
        bundle=bundle,
        proof=proof,
        directory=bundle_path,
        headers=diagnostic["provenance"]["headers"],
    )
    assert observed["driver_native_sha256"] == diagnostic["diagnostic"]["driver_native_sha256"]
    return observed


def native_facts(root: Path) -> dict[str, Any]:
    _interfaces()  # Before native calls or provisioning, including memory enable.
    if sys.platform not in {"linux", "win32"}:
        raise RuntimeError("native_platform_required")
    forbidden = (
        "HERMES_MEMORY_KEY",
        "MORDRED_TPM_TEST",
        "MORDRED_TPMKEY_STORE",
        "MORDRED_TEST_INJECT_BACKEND",
        "TPM2TOOLS_TCTI",
        "TSS2_TCTI",
    )
    if any(os.environ.get(name) for name in forbidden):
        raise RuntimeError("native_emulator_and_ambient_keys_forbidden")
    helper_name = "MORDRED_WINKEY_HELPER" if sys.platform == "win32" else "MORDRED_TPMKEY_HELPER"
    from mordred_hermes.keyvault import _seckey_helper

    found = _seckey_helper.find_winkey_helper() if sys.platform == "win32" else _seckey_helper.find_tpmkey_helper()
    helper = Path(os.environ[helper_name])
    if not found or helper.resolve(strict=True) != Path(found).resolve(strict=True) or not helper.is_file():
        raise RuntimeError("explicit_production_native_helper_required")
    tool = _tool()
    copied = tool["validate_withdrawable_helper"](
        Path(os.environ["MORDRED_DBCRYPT_WITHDRAWABLE_HELPER_MANIFEST"]),
        production=helper,
        parent=Path(os.environ["MORDRED_DBCRYPT_PARENT"]),
    )
    if sys.platform == "win32":
        directory = Path(os.environ["MORDRED_DBCRYPT_QUALIFICATION_DIRECTORY"])
        qualification = tool["validate_windows_qualification"](directory, checkout=Path(os.environ["DBCRYPT_CHECKOUT"]))
        facts = _windows_provider()
        facts["dll"] = _owned_windows_dll(qualification)
        facts["qualification_manifest_sha256"] = qualification["manifest_sha256"]
        from mordred_hermes._database_locking_windows import identify_root
        from mordred_hermes._private_fs import open_confidential_directory

        observed_root = root if root.exists() else root.parent
        # Stat/mode cannot establish Windows privacy. Check the actual owned
        # executable directory with the same native confidential-FS contract
        # before any memory enable/provisioning operation can run.
        with open_confidential_directory(observed_root), open_confidential_directory(Path(copied["path"]).parent):
            identity = identify_root(observed_root)
        facts["filesystem"] = {"method": "checked_confidential_fixed_local_ntfs", "identity": asdict(identity)}
    else:
        facts = _linux_provider()
        from mordred_hermes._database_locking_posix import identify_root
        from mordred_hermes._private_fs import open_private_directory

        observed_root = root if root.exists() else root.parent
        with open_private_directory(observed_root):
            identity = identify_root(observed_root)
        facts["filesystem"] = {"method": "checked_private_posix", "identity": asdict(identity)}
    facts["filesystem"].update(observed_path=str(observed_root), scope="root" if observed_root == root else "parent")
    facts.update(
        helper={
            "path": str(helper.resolve()),
            "sha256": _digest(helper),
            "version_method": "binary_identity_no_version_command",
        },
        boot=boot_identity(),
    )
    return facts


@contextlib.contextmanager
def candidate_eligibility(root: Path) -> Iterator[None]:
    """Translate only platform eligibility, after real native facts succeeded."""
    if os.environ.get("MORDRED_DBCRYPT_ACCEPTANCE_KIND") != "candidate":
        yield
        return
    native_facts(root)  # Context itself refuses before touching eligibility.
    from unittest.mock import patch

    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _capability

    original = _capability.database_status

    def status(home: Path) -> Any:
        observed = original(home)
        allowed = {
            "database runtime activation is unavailable on this platform",
            "Windows VFS native qualification is incomplete",
        }
        if observed.reason in allowed:
            if observed.dependencies is None or not _capability._driver_present():
                raise RuntimeError("candidate_driver_or_inventory_unavailable")
            return replace(
                observed,
                capability="unknown",
                authenticated=False,
                reason="native database authority has not been authenticated",
            )
        return observed

    with contextlib.ExitStack() as stack:
        if sys.platform == "win32":
            # native_facts revalidated all full-C/source/release-wheel receipts.
            from mordred_hermes.dbcrypt import _windows_vfs

            if not _windows_vfs.driver_distribution_qualified() or _windows_vfs.packaged_library_path() is None:
                raise RuntimeError("owned_checked_distribution_required")
            stack.enter_context(patch.object(_windows_vfs, "NATIVE_QUALIFIED", True))
        stack.enter_context(patch.object(_capability, "database_status", status))
        stack.enter_context(patch.object(dbcrypt, "database_status", status))
        yield


def _homes(root: Path) -> list[tuple[str, Path]]:
    return [(name, root if name == "root" else root / "profiles" / name) for name in PROFILES]


def _memory_probe(seed: bool) -> dict[str, Any]:
    from mordred_hermes.keyvault import _memory_hook, kek

    kek._noop_audit = lambda _entry: None
    import mordred_hermes
    from tools import memory_tool

    home = Path(os.environ["HERMES_HOME"])
    assert Path(memory_tool.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    tool = _tool()
    tool["validate_import_provenance"](
        Path(mordred_hermes.__file__),
        checkout=Path(os.environ["DBCRYPT_CHECKOUT"]),
        environment=Path(os.environ["DBCRYPT_BUNDLE"]) / "wheel-env",
        mode=os.environ["MORDRED_DBCRYPT_ACCEPTANCE_MODE"],
    )
    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        assert _memory_hook.install_memory_hook(home=home, memory_tool_module=memory_tool, environ={})
        bootstrap = "explicit_native_memory_hook"
    else:
        assert _memory_hook.memory_hook_installed(memory_tool)
        bootstrap = "automatic_native_memory_hook"
    store = memory_tool.MemoryStore(memory_char_limit=2048)
    # Upstream's public lifecycle initializes the directory and loads sealed
    # entries through the already-installed hook before either seed or read.
    store.load_from_disk()
    path = home / "memories/MEMORY.md"
    if seed:
        store._write_file(path, [TEXT])
    assert store._read_file(path) == [TEXT]
    assert TEXT.encode() not in path.read_bytes()
    return {"bootstrap": bootstrap, "memory_module": str(Path(memory_tool.__file__).resolve()), "count": 1}


def _fresh_memory(home: Path, *, seed: bool) -> dict[str, Any]:
    helper = Path(__file__).resolve()
    code = f"import runpy, json; print(json.dumps(runpy.run_path({str(helper)!r})['_memory_probe']({seed!r})))"
    environment = {**os.environ, "HERMES_HOME": str(home)}
    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        command = [sys.executable, "-c", code]
    else:
        directory = home / "native-memory-driver"
        directory.mkdir(mode=0o700, exist_ok=True)
        driver = directory / ("hermes-seed" if seed else "hermes-read")
        # argv[0] must be named exactly hermes for the production startup gate.
        driver_directory = directory / ("seed" if seed else "read")
        driver_directory.mkdir(mode=0o700, exist_ok=True)
        driver = driver_directory / "hermes"
        if driver.exists():
            assert driver.read_text() == code
        else:
            driver.write_text(code)
        command = [sys.executable, str(driver)]
    result = subprocess.run(
        command,
        env=environment,
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, "fresh native memory subprocess failed"
    return dict(json.loads(result.stdout))


def _maintenance(home: Path, arguments: list[str]) -> dict[str, Any]:
    """Execute the installed, genuine public ceremony; never imitate its argv."""
    from importlib.metadata import distribution

    entry = tuple(distribution("hermes-mordred").entry_points.select(group="console_scripts", name="hermes-mordred"))
    assert len(entry) == 1 and entry[0].value == "mordred_hermes.wizard.cli:main"
    executable = Path(sys.prefix) / ("Scripts/hermes-mordred.exe" if sys.platform == "win32" else "bin/hermes-mordred")
    digest = _digest(executable)
    manifest = json.loads((Path(os.environ["DBCRYPT_BUNDLE"]) / "manifest.json").read_text())
    expected = manifest[os.environ["MORDRED_DBCRYPT_ACCEPTANCE_MODE"] + "_probe"]["maintenance_entrypoint"]
    if expected != {"path": str(executable), "sha256": digest}:
        raise RuntimeError("owned_checked_distribution_required")
    if arguments not in (["encryption", "enable", "memory"], ["databases", "encrypt"]):
        raise RuntimeError("unsupported_fixed_native_operation")
    argv = [str(executable), *arguments]
    started = time.time()
    result = subprocess.run(
        argv,
        env={**os.environ, "HERMES_HOME": str(home)},
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )
    finished = time.time()
    if result.returncode != 0:
        raise RuntimeError(
            "native_memory_enable_failed_retain_root" if arguments[0] == "encryption" else "native_operation_failed"
        )
    assert _digest(executable) == digest, "native maintenance entrypoint changed"
    return {
        "home": str(home),
        "argv": argv,
        "entrypoint_sha256": digest,
        "started_at": started,
        "finished_at": finished,
        "returncode": result.returncode,
    }


def provision(root: Path) -> dict[str, Any]:
    from mordred_hermes import dbcrypt
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes._private_fs import open_confidential_directory, open_private_directory
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.keyvault._database_authority import enroll_database_source
    from mordred_hermes.wizard import memory_cli

    if root.exists():
        raise RuntimeError("native_provision_requires_new_root_no_repair")
    opening = open_confidential_directory if sys.platform == "win32" else open_private_directory
    with opening(root, create=True):
        pass
    homes = [("root", root)] if root.name.endswith("-crash") else _homes(root)
    if len(homes) > 1:
        with opening(root / "profiles", create=True):
            pass
    require_enabled = _interfaces()
    ceremonies = []
    production = os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "production"
    for _name, home in homes:
        with opening(home, create=True):
            pass
        if production:
            ceremonies.append(_maintenance(home, ["encryption", "enable", "memory"]))
        elif memory_cli.enable(home=home, root=home / "mordred/keyvault/vault", platform=sys.platform) != 0:
            raise RuntimeError("native_memory_enable_failed_retain_root")
        require_enabled(root=home)
        _fresh_memory(home, seed=True)
        _fresh_memory(home, seed=False)
    if production:
        ceremonies.append(_maintenance(root, ["databases", "encrypt"]))
    else:
        with acquire_exclusive(root) as lease:
            enroll_database_source(root=root, lease=lease)
        # Candidate entry point owns its EX; never upgrade a live SH.
        _migrate.migrate(root, None, arm=dbcrypt.arm)
    from mordred_hermes.keyvault._database_authority import observe_database_source

    snapshot = observe_database_source(root=root)
    return {"fixture": {"root": asdict(snapshot.root), "source": asdict(snapshot)}, "ceremonies": ceremonies}


def _telegram_store(home: Path) -> Any:
    if sys.platform == "win32":
        from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

        return WindowsCustodySecretStore(home, audit_sink=lambda _entry: None)
    from mordred_hermes.extension.telegram.tee import TeeSecretStore, hardware_backend

    return TeeSecretStore(
        home / "mordred/telegram", backend_factory=lambda: hardware_backend(home), audit_sink=lambda _entry: None
    )


def _seed_credentials(home: Path) -> tuple[Any, Any]:
    import secrets

    from mordred_hermes.extension.telegram.secrets import TelegramSecrets
    from mordred_hermes.imports.mail.secrets import MailCredentials, MailSecretStore

    telegram = _telegram_store(home)
    telegram.ensure_key(require_presence=False)
    value = TelegramSecrets(
        api_id=12345,
        api_hash=secrets.token_hex(16),
        store_key=secrets.token_bytes(32),
        session=secrets.token_urlsafe(24),
    )
    telegram.store(value)
    assert _telegram_store(home).load(fresh=True) == value
    mail = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None)
    # Explicit no-presence is never a policy patch or silent downgrade.
    from mordred_hermes.imports.mail.secrets import MailSecretsError

    try:
        mail.ensure_key(require_presence=True)
    except MailSecretsError as exc:
        assert exc.code == "presence_unsupported"
        assert not mail.residue()
    else:
        raise RuntimeError("requested_presence_must_refuse_before_writes")
    mail.ensure_key(require_presence=False)
    credentials = MailCredentials(
        "owner@example.invalid",
        secrets.token_urlsafe(32),
        "imap.example.invalid",
        993,
        ("owner@example.invalid",),
        "native_sync",
        False,
        {"inbox": "INBOX"},
    )
    mail.store(credentials, require_presence=False)
    assert MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None).load() == credentials
    return value, credentials


def _private_credential_values(telegram: Any, mail: Any) -> str:
    """RAM/Root-protected SQL only: never return this value in public evidence."""
    values = {"telegram": asdict(telegram), "mail": asdict(mail)}
    values["telegram"]["store_key"] = telegram.store_key.hex()
    return json.dumps(values, sort_keys=True, separators=(",", ":"))


def _assert_original_credentials(reference: str, telegram: Any, mail: Any) -> None:
    if reference != _private_credential_values(telegram, mail):
        raise RuntimeError("original_native_credentials_changed")


def _credential_reference(root: Path, home: Path, authority: Any, original: tuple[Any, Any] | None) -> None:
    # This table must NEVER enter sacrificial roots whose lifecycle probes may
    # legitimately decrypt their databases before dependency refusal.
    if not root.name.endswith("-persistence") or home not in {path for _name, path in _homes(root)}:
        raise RuntimeError("credential_reference_requires_persistence_root")
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports.mail.secrets import MailSecretStore

    connection = open_protected(home / "state.db", authority=authority)
    try:
        if original is not None:
            connection.execute(
                "CREATE TABLE task15_private_credential_reference("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO task15_private_credential_reference VALUES(1, ?)", (_private_credential_values(*original),)
            )
            connection.commit()
        rows = connection.execute("SELECT value FROM task15_private_credential_reference WHERE singleton=1").fetchall()
        if len(rows) != 1:
            raise RuntimeError("original_native_credentials_reference_missing")
        telegram = _telegram_store(home).load(fresh=True)
        mail = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None).load()
        if telegram is None or mail is None:
            raise RuntimeError("original_native_credentials_changed")
        _assert_original_credentials(rows[0][0], telegram, mail)
    finally:
        connection.close()


def _credential_replacement_probe(root: Path, home: Path, authority: Any, original: tuple[Any, Any]) -> None:
    """Real sealing of different valid values must fail the original-value oracle.

    Runs only while seeding one finite persistence profile, before its baseline.
    It updates credentials, never rotates/deletes native keys, and restores the
    original values in finally. No reference is allocated on a destructive Root.
    """
    if not root.name.endswith("-persistence") or home not in {path for _name, path in _homes(root)}:
        raise RuntimeError("credential_reference_requires_persistence_root")
    import secrets

    from mordred_hermes.imports.mail.secrets import MailSecretStore

    telegram, mail = original
    tg_store = _telegram_store(home)
    mail_store = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None)
    replacements = (
        (tg_store, replace(telegram, session=secrets.token_urlsafe(24))),
        (tg_store, replace(telegram, store_key=secrets.token_bytes(32))),
        (mail_store, replace(mail, app_password=secrets.token_urlsafe(32))),
    )
    try:
        for store, replacement in replacements:
            if store is mail_store:
                store.store(replacement, require_presence=False)
            else:
                store.store(replacement)
            try:
                _credential_reference(root, home, authority, None)
            except RuntimeError as exc:
                if str(exc) != "original_native_credentials_changed":
                    raise
            else:
                raise RuntimeError("different_valid_sealed_credential_accepted")
            if store is mail_store:
                store.store(mail, require_presence=False)
            else:
                store.store(telegram)
    finally:
        tg_store.store(telegram)
        mail_store.store(mail, require_presence=False)
    _credential_reference(root, home, authority, None)


def _role_isolation(home: Path) -> None:
    from mordred_hermes.imports.mail.secrets import KEY_ID as mail_id
    from mordred_hermes.imports.mail.secrets import MailSecretStore, _unpack
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._exceptions import WrapError
    from mordred_hermes.keyvault._mail_key import mail_backend

    sealed = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None).sealed_path.read_bytes()
    wrapped, _nonce, _ciphertext = _unpack(sealed)
    if sys.platform == "win32":
        from mordred_hermes.keyvault._windows_custody import windows_custody_session

        with windows_custody_session(home) as session:
            leases = [session.lease(role) for role in ("memory", "telegram", "mail")]
            assert len({lease.native_key_id for lease in leases}) == 3
            try:
                wrap.unwrap_dek(
                    wrapped,
                    mail_id,
                    native_key_id=leases[1].native_key_id,
                    backend=session.backend_for(leases[1]),
                    audit_sink=lambda _entry: None,
                )
            except WrapError:
                pass
            else:
                raise AssertionError("mail ciphertext crossed the Telegram role binding")
    else:
        from mordred_hermes.extension.telegram.tee import KEY_ID as telegram_id
        from mordred_hermes.extension.telegram.tee import hardware_backend
        from mordred_hermes.imports.mail.secrets import KEY_ID as mail_id
        from mordred_hermes.keyvault._memory_key import linux_memory_backend, memory_key_id

        keys = [
            wrap.get_wrapping_key_public(memory_key_id(home), backend=linux_memory_backend(home)),
            wrap.get_wrapping_key_public(telegram_id, backend=hardware_backend(home)),
            wrap.get_wrapping_key_public(mail_id, backend=mail_backend(home=home)),
        ]
        assert len(set(keys)) == 3
        try:
            wrap.unwrap_dek(
                wrapped,
                mail_id,
                native_key_id=telegram_id,
                backend=hardware_backend(home),
                audit_sink=lambda _entry: None,
            )
        except WrapError:
            pass
        else:
            raise AssertionError("mail ciphertext crossed the Telegram role binding")


def _session(home: Path, profile: str, seed: bool) -> str:
    import hermes_state

    database = hermes_state.SessionDB(home / "state.db")
    session = "task15-" + profile
    try:
        if seed:
            database.create_session(session, source="cli")
            database.append_message(session, "user", TEXT)
        rows = database.get_messages(session)
        assert [row["content"] for row in rows] == [TEXT]
        assert database._fts_enabled and database._trigram_available
        hits = [hit for hit in database.search_messages("日本語") if hit["session_id"] == session]
        assert len(hits) == 1 and hits[0]["session_id"] == session
        assert hits[0]["context"] == [{"role": "user", "content": TEXT}]
        return logical_digest([{"id": session, "text": rows[0]["content"]}])
    finally:
        database.close()


def _activity(home: Path, seed: bool) -> str:
    from mordred_hermes.activity import history
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.activity.contracts import normalize_event

    store = open_store(home)
    raw = {
        "event_id": "1029743a-d98a-48bb-a6dc-655062261e38",
        "seq": 1,
        "episode_id": "native-japanese",
        "source": "operator",
        "actor": "human",
        "observed_at": 1001.0,
        "phase": "boundary",
        "action": {"op": "task_start", "site": "example.invalid"},
        "text": TEXT,
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
    }
    if seed:
        event = normalize_event(raw, excluded_sites=frozenset())
        assert store.append_batch("operator:native", "native-producer", [event]).accepted == 1
        assert store.append_batch("operator:native", "native-producer", [event]).accepted == 0
    found = history.episodes_for_terms(store, {"日本", "本語"}, excluded_sites=frozenset(), since=0, until=2000)
    assert [item.episode_id for item in found.episodes] == ["native-japanese"]
    rows = store.events_for_episode("native-japanese")
    assert len(rows) == 1 and rows[0].text == TEXT
    return logical_digest([{"id": raw["event_id"], "text": TEXT}])


class SyntheticTelegramTransport:
    """Only the network transport is synthetic; native stores/guards stay real."""

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def get_me(self) -> Any:
        return SimpleNamespace(id=7, first_name="Synthetic", last_name=None, username=None)

    async def iter_dialogs(self, **_kwargs: Any) -> AsyncIterator[Any]:
        items: tuple[Any, ...] = ()
        for item in items:
            yield item


def _telegram(home: Path, seed: bool) -> str:
    import asyncio

    from mordred_hermes.extension.telegram import service
    from mordred_hermes.extension.telegram.migrate import migrate_telegram_store
    from mordred_hermes.extension.telegram.store import ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage
    from mordred_hermes.imports.store import open_import_store

    secret_store = _telegram_store(home)
    value = secret_store.load(fresh=True)
    assert value is not None and secret_store.load(fresh=True) == value
    if seed:
        archive = ArchiveStore(value.store_key, home / "mordred/telegram")
        message = StoredMessage(id=1, date=1001, sender="Synthetic", text=TEXT, out=True)
        archive.append_messages(11, [message])
        archive.save_index(
            ArchiveIndex(
                account_label="Synthetic",
                account_id=7,
                dialogs={11: DialogInfo(11, "user", "Synthetic", last_message_id=1, message_count=1, last_date=1001)},
            )
        )
        assert migrate_telegram_store(home / "mordred/telegram", home=home) == 1
        assert migrate_telegram_store(home / "mordred/telegram", home=home) == 0
        svc = service.TelegramService(
            secret_store=secret_store,
            archive_root=home / "mordred/telegram",
            client_factory=lambda *_args, **_kwargs: SyntheticTelegramTransport(),
            home=home,
        )

        async def sync() -> None:
            await svc.start_sync()
            await svc.wait_for_sync()
            assert (await svc.status())["last_error"] is None

        asyncio.run(sync())
    reopened_archive = ArchiveStore(value.store_key, home / "mordred/telegram")
    assert reopened_archive.load_index().account_id == 7
    assert [(message.id, message.text) for message in reopened_archive.load_messages(11)] == [(1, TEXT)]
    store = open_import_store(home)
    hits = store.search("日本語", source="telegram")
    assert len(hits) == 1
    parts = store.parts_for(hit.part_uid for hit in hits)
    assert [item.part.text for item in parts.values()] == [TEXT]
    return logical_digest([{"id": hit.source_uid, "text": TEXT} for hit in hits])


def _mail(home: Path, seed: bool) -> str:
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, default_env, run_fetch
    from mordred_hermes.imports.mail.secrets import MailSecretStore
    from mordred_hermes.imports.mail.source import MboxBytes
    from mordred_hermes.imports.store import open_import_store
    from mordred_hermes.wizard import mail_cli
    from tests._fake_imap import FakeImapServer, FakeMailbox, FakeMessage

    credentials = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None).load()
    assert credentials is not None
    data = (
        (
            "From: owner@example.invalid\\r\\nTo: other@example.invalid\\r\\nDate: Thu, 1 Oct 2026 12:00:00 +0000\\r\\n"
            "Message-ID: <native@example.invalid>\\r\\nSubject: 日本語\\r\\n"
            "Content-Type: text/plain; charset=utf-8\\r\\n\\r\\n" + TEXT
        )
        .replace("\\r\\n", "\r\n")
        .encode()
    )
    if seed:
        store = open_import_store(home)
        request = mail_cli._Request(
            (MboxBytes(b"From synthetic Thu Oct 1 12:00:00 2026\n" + data),),
            "native-mbox",
            (credentials.address,),
            "Sent",
            False,
            True,
            0,
        )
        with mail_cli._writer_lock(home):
            assert mail_cli._locked_import(store, request) == 0
        server = FakeImapServer(
            {"INBOX": FakeMailbox(11, messages={1: FakeMessage(data)})},
            user=credentials.address,
            password=credentials.app_password,
        )
        environment = default_env(home)
        environment.connect = lambda _credentials, limits: server.session(limits)
        environment.audit = lambda _entry: None
        first = run_fetch(FetchOptions(max_messages=5), environment)
        second = run_fetch(FetchOptions(max_messages=5), environment)
        assert first.error is None and second.error is None
        assert first.inserted == 1 and second.inserted == 0 and not first.partial and not second.partial
        assert not server.violations
    store = open_import_store(home)
    found = store.search("日本語", source="mail")
    assert len(found) == 2
    hydrated = store.parts_for(hit.part_uid for hit in found)
    assert all(item.part.text == TEXT for item in hydrated.values())
    return logical_digest([{"id": hit.source_uid, "text": TEXT} for hit in found])


def _scoped_siblings(home: Path, authority: Any, seed: bool) -> str:
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.dbcrypt._policy import DENY_DIRS, in_scope

    rows = []
    for relative in SIBLING_DATABASES:
        path = home / relative
        assert in_scope(path, home)
        if seed:
            current = home
            for part in Path(relative).parts[:-1]:
                current /= part
                with open_private_directory(current, create=True):
                    pass
        connection = open_protected(path, authority=authority)
        try:
            if seed:
                connection.execute("CREATE TABLE native_fixture(id TEXT PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO native_fixture VALUES (?, ?)", (relative, TEXT))
                connection.commit()
            assert connection.execute("SELECT id, body FROM native_fixture").fetchall() == [(relative, TEXT)]
            rows.append({"id": relative, "text": TEXT})
        finally:
            connection.close()
    assert all(not in_scope(home / name / "forbidden.db", home) for name in DENY_DIRS)
    assert not in_scope(home.parent.parent.parent / "foreign-native-home/forbidden.db", home)
    return logical_digest(rows)


def collect(root: Path, *, seed: bool) -> dict[str, Any]:
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim
    from mordred_hermes.keyvault._database_authority import observe_database_source
    from mordred_hermes.keyvault._memory_key import resolve_memory_key
    from mordred_hermes.keyvault.memory_crypto import seal, unseal

    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        assert dbcrypt._install_native(root, None)
    else:
        assert _shim.is_installed(), "automatic production startup required"
    logical = {}
    try:
        for profile, home in _homes(root):
            # The actual installed provider owns Root SH before credential custody.
            authority = dbcrypt._PROVIDER.authority
            assert authority.snapshot == observe_database_source(root=root)
            original = _seed_credentials(home) if seed else None
            _role_isolation(home)
            _fresh_memory(home, seed=False)
            key = resolve_memory_key(home=home, platform=sys.platform, environ={})
            assert (
                key is not None
                and unseal(seal(TEXT.encode(), key=key, name="MEMORY.md"), key=key, name="MEMORY.md") == TEXT.encode()
            )
            logical[profile + ":source_memory"] = logical_digest([{"id": profile, "text": TEXT}])
            logical[profile + ":sessiondb"] = _session(home, profile, seed)
            if root.name.endswith("-persistence"):
                _credential_reference(root, home, authority, original)
                if original is not None and profile == "work":
                    _credential_replacement_probe(root, home, authority, original)
            logical[profile + ":scoped_siblings"] = _scoped_siblings(home, authority, seed)
            logical[profile + ":activity"] = _activity(home, seed)
            logical[profile + ":telegram"] = _telegram(home, seed)
            logical[profile + ":mail"] = _mail(home, seed)
            logical[profile + ":credentials"] = logical_digest(
                [{"id": profile, "component": "real_native_sealed_reload", "count": 2}]
            )
        import importlib.metadata

        import hermes_state

        return {
            "logical": logical,
            "hermes": {
                "module": str(Path(hermes_state.__file__).resolve()),
                "sha256": _digest(Path(hermes_state.__file__)),
                "version": importlib.metadata.version("hermes-agent"),
            },
            "fixture": {"root": asdict(authority.snapshot.root), "source": asdict(authority.snapshot)},
            "rows": list(COLLECTOR_ROWS),
            "transport": "synthetic_transport_real_native_custody_sqlcipher",
            "credential_continuity": "original_native_protected_reference"
            if root.name.endswith("-persistence")
            else "reload_only_sacrificial_no_reference",
        }
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()


def _runtime(root: Path) -> Any:
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        assert dbcrypt._install_native(root, None)
    else:
        assert _shim.is_installed(), "automatic production startup required"
    return dbcrypt._PROVIDER


def backup_restore(root: Path, *, finalization_failure: bool = False) -> dict[str, Any]:
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.activity.store import restore_activity_store
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.dbcrypt._monitor import monitor_runtime

    provider = _runtime(root)
    home = root / "profiles/work"
    store = open_store(home)
    expected = store.events_for_episode("native-japanese")
    before = store.meta().store_generation
    from mordred_hermes._private_fs import open_private_directory

    backup_directory = root.parent / (root.name + "-backups")
    with open_private_directory(backup_directory, create=True):
        pass
    backup = backup_directory / ("finalization.backup" if finalization_failure else "registered.backup")
    independent = Authority.acquire(home)
    try:
        with (
            contextlib.closing(open_protected(root / "state.db", authority=provider.authority)) as session,
            contextlib.closing(open_protected(store.path, authority=independent)) as activity,
        ):
            # Exercise the actual Python consumers, not only raw C connections.
            # Windows ordinary writable stat attributes must need no chmod.
            if sys.platform == "win32":
                assert root.stat().st_mode & 0o022 and store.path.stat().st_mode & 0o022
            session.execute("SELECT count(*) FROM messages").fetchone()
            cursor = activity.execute("SELECT count(*) FROM sqlite_master")
            assert monitor_runtime(provider.authority) == ()
            store.backup(backup)
            provider.close()
            assert cursor.fetchone()[0] > 0
            assert activity.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] > 0
    finally:
        independent.close()
        provider.close()
    provider.close()  # All connection methods have already closed their handles.
    assert _migrate.holders([store.path, backup]) == [], "actual native holder proof unavailable"
    if finalization_failure:
        from unittest.mock import patch

        from mordred_hermes.activity._gate import ActivityRefused
        from mordred_hermes.activity.store import ActivityStore
        from mordred_hermes.dbcrypt._authority import Authority

        def fail_finalization(*_args: Any) -> Any:
            raise RuntimeError("owned component finalization fault")

        with acquire_exclusive(root) as lease, patch.object(ActivityStore, "_after_restore", fail_finalization):
            try:
                restore_activity_store(backup, home=home, lease=lease)
            except ActivityRefused as exc:
                assert exc.code == "restore_incomplete"
            else:
                raise AssertionError("publication/finalization failure was hidden")
        assert backup.is_file()
        authority = Authority.acquire(root)
        authority.close()
        return {
            "rows": ["restore_finalization_failure"],
            "result": "restore_incomplete",
            "backup_and_native_key_retained": True,
        }
    with acquire_exclusive(root) as lease:
        result = restore_activity_store(backup, home=home, lease=lease)
    assert result.store_generation != before
    # Fresh-process read is a separate collected node after this operation.
    assert len(expected) == 1
    return {
        "rows": ["backup_restore"],
        "component_generation_before": before,
        "component_generation_after": result.store_generation,
        "backup_retained": True,
        "guarded_runtime_monitor_backup": True,
    }


def _forget_roles(root: Path) -> None:
    from unittest.mock import patch

    from mordred_hermes.extension.telegram.store import forget_telegram_storage, wipe_archive
    from mordred_hermes.imports.mail.forget import MailForgetError, forget
    from mordred_hermes.imports.mail.secrets import MailSecretStore
    from mordred_hermes.imports.store import open_import_store
    from mordred_hermes.keyvault._database_authority import observe_database_source

    before = observe_database_source(root=root)
    home = root / "profiles/other"
    mail = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None)
    store = open_import_store(home)
    # Real native retirement must precede this owned SQL failure. A later
    # unnamed retry cannot turn absent credentials into proof of erasure.
    with patch.object(store, "delete_source", side_effect=RuntimeError("owned post-retirement SQL fault")):
        try:
            forget(mail, home, rows=True, open_store=lambda _home: store)
        except MailForgetError:
            pass
        else:
            raise AssertionError("owned SQL failure was hidden")
    assert mail.load() is None
    unknown = forget(mail, home, rows=True, open_store=lambda _home: store)
    assert unknown.warnings == ("account_unknown",)
    completed = forget(mail, home, account="native_sync", rows=True, open_store=lambda _home: store)
    assert completed.warnings == () and completed.account == "native_sync"
    assert store.search("日本語", source="telegram")
    assert store.search("日本語", source="mail")  # independent native-mbox account remains.
    assert forget_telegram_storage(home=home, remove_records=True) == 1
    telegram = _telegram_store(home)
    if sys.platform == "win32":
        wipe_archive(home / "mordred/telegram", forget=True)
    else:
        telegram.forget_from_snapshot(telegram.load_snapshot())
    assert telegram.load(fresh=True) is None
    assert observe_database_source(root=root) == before
    assert _session(root, "root", False)


def _writer(root: Path, name: str) -> dict[str, Any]:
    provider = _runtime(root)
    try:
        return {"writer": name, "logical": _session(root, name, True)}
    finally:
        provider.close()


def _multiprocess(root: Path, connection: Any) -> None:
    source = (
        f"import runpy; raise SystemExit(runpy.run_path({str(Path(__file__).resolve())!r})"
        "['main'](__import__('sys').argv[1]))"
    )
    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        command = [sys.executable, "-c", source]
    else:
        driver = Path(os.environ["MORDRED_DBCRYPT_PRODUCTION_DRIVER"])
        assert driver.name == "hermes" and driver.is_file()
        command = [sys.executable, str(driver)]
    processes = [
        subprocess.Popen(
            [*command, "writer_" + name],
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for name in ("a", "b")
    ]
    try:
        for child in processes:
            stdout, _stderr = child.communicate(timeout=180)
            assert child.returncode == 0 and json.loads(stdout)["status"] == "executed"
    finally:
        for child in processes:
            if child.poll() is None:
                child.kill()
                child.wait()
    for name in ("writer_a", "writer_b"):
        assert connection.execute("SELECT count(*) FROM sessions WHERE id=?", ("task15-" + name,)).fetchone()[0] == 1


def _cached_and_boundaries(root: Path) -> list[str]:
    from unittest.mock import patch

    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _authority, _shim
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected

    authority = Authority.acquire(root)
    connection = open_protected(root / "state.db", authority=authority)
    try:

        def access_unavailable(**_kwargs: Any) -> Any:
            raise DatabaseRefused("injected native access failure; metadata intact")

        with patch.object(_authority, "load_database_source", access_unavailable):
            assert connection.execute("SELECT count(*) FROM messages").fetchone()[0] > 0
            try:
                Authority.acquire(root)
            except DatabaseRefused:
                pass
            else:
                raise AssertionError("fresh acquisition bypassed native access failure")
        foreign = root.parent / (root.name + "-denied.db")
        actions: tuple[Callable[[], Any], ...] = (
            lambda: connection.execute("ATTACH DATABASE ? AS denied", (str(foreign),)),
            lambda: open_protected(foreign, authority=authority),
            lambda: _shim.build_module(authority=authority).connect(
                "file:" + foreign.as_posix() + "?mode=ro", uri=True
            ),
        )
        for action in actions:
            try:
                action()
            except Exception:
                pass
            else:
                raise AssertionError("foreign SQL destination admitted")
        assert not foreign.exists()
        _multiprocess(root, connection)
    finally:
        connection.close()
        authority.close()
    return ["cached_access_failure_injected", "attach_uri_destinations", "multiprocess_reader_writers"]


def _missing_and_generation(root: Path) -> list[str]:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._exceptions import WrapKeyNotFound

    marker = root / "mordred/db-encryption.marker"
    original = marker.read_bytes()
    record = json.loads(original)
    record["generation"] = "0" * len(record["generation"])
    marker.write_text(json.dumps(record))
    try:
        try:
            Authority.acquire(root)
        except DatabaseRefused:
            pass
        else:
            raise AssertionError("foreign source generation admitted")
    finally:
        marker.write_bytes(original)
    record = json.loads(original)
    identity = record["root"]["file_id"]
    record["root"]["file_id"] = ("1" if identity[0] == "0" else "0") + identity[1:]
    marker.write_text(json.dumps(record))
    try:
        try:
            Authority.acquire(root)
        except DatabaseRefused:
            pass
        else:
            raise AssertionError("wrong physical Root binding admitted")
    finally:
        marker.write_bytes(original)
    name = "windows-custody.json" if sys.platform == "win32" else "db-key-source.json"
    source = root / "mordred" / name
    retained = source.with_name(source.name + ".negative-retained")
    source.rename(retained)
    try:
        try:
            Authority.acquire(root)
        except DatabaseRefused:
            pass
        else:
            raise AssertionError("missing source was repaired or admitted")
        assert not source.exists()
    finally:
        retained.rename(source)
    if sys.platform == "win32":
        from mordred_hermes.keyvault._windows_custody import windows_backend

        backend = windows_backend()
    else:
        from mordred_hermes.keyvault._memory_key import linux_memory_backend

        backend = linux_memory_backend(root)
    try:
        wrap.get_wrapping_key_public("mordred-hermes.task15.nonexistent.native.selector", backend=backend)
    except WrapKeyNotFound:
        pass
    else:
        raise AssertionError("missing native selector unexpectedly exists")
    return ["wrong_generation", "wrong_root_binding", "missing_source_no_repair", "missing_native_key_observed"]


def _wrong_profile_key(root: Path) -> None:
    import sqlcipher3.dbapi2 as driver

    from mordred_hermes._database_lifecycle import acquire_runtime
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._shim import apply_key
    from mordred_hermes.keyvault._memory_key import resolve_memory_key

    with acquire_runtime(root):
        child = resolve_memory_key(home=root / "profiles/work", platform=sys.platform, environ={})
        assert child is not None
        wrong = derive(child)
    connection = driver.connect(str(root / "state.db"))
    try:
        apply_key(connection, wrong)
        try:
            connection.execute("SELECT count(*) FROM messages").fetchone()
        except driver.DatabaseError:
            pass
        else:
            raise AssertionError("independent profile memory key decrypted Root database")
    finally:
        connection.close()


def _holder_uncertainty(root: Path) -> None:
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.keyvault._database_authority import observe_database_source

    before = observe_database_source(root=root)
    try:
        _migrate.migrate(root, None, arm=dbcrypt.arm, holders_of=lambda _paths: None)
    except _migrate.MigrationError:
        pass
    else:
        raise AssertionError("uncertain holder result permitted maintenance")
    assert observe_database_source(root=root) == before


def _move_owned_helper(source: Path, destination: Path, value: dict[str, Any]) -> None:
    info = source.lstat()
    if {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size} != value["identity"]:
        raise RuntimeError("owned_helper_identity_changed")
    if sys.platform == "win32":
        from mordred_hermes._private_fs import open_confidential_directory, open_private_directory

        with (
            open_confidential_directory(source.parent),
            open_private_directory(source.parent) as directory,
            directory.transaction() as transaction,
        ):
            identity = transaction.stat(source.name).identity
            transaction.rename_file(source.name, destination.name, expected_identity=identity)
        return
    # PrivateFS deliberately admits mode-0600 data files, not executable
    # binaries. Keep that product contract unchanged. This fixed binary-only
    # move uses no-replace link/unlink under the already checked private parent.
    fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.stat(source.name, dir_fd=fd, follow_symlinks=False)
        expected = value["identity"]
        assert {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size} == expected
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0
        ):
            raise RuntimeError("owned_helper_identity_changed")
        os.link(source.name, destination.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        current = os.stat(source.name, dir_fd=fd, follow_symlinks=False)
        assert (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
        os.unlink(source.name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def withdraw_owned_helper(manifest: Path, *, production: Path, parent: Path) -> Iterator[dict[str, Any]]:
    """Withdraw/restore only one declared owned binary, never replace a path."""
    tool = _tool()
    value = tool["validate_withdrawable_helper"](manifest, production=production, parent=parent)
    copied, retained = Path(value["path"]), Path(value["retained_path"])
    _move_owned_helper(copied, retained, value)
    try:
        assert not copied.exists()
        yield value
    finally:
        if _digest(retained) != value["sha256"]:
            raise RuntimeError("owned_withdrawn_helper_changed_retain_for_operator")
        _move_owned_helper(retained, copied, value)
    tool["validate_withdrawable_helper"](manifest, production=production, parent=parent)


def fresh_unpatched_authority_probe() -> int:
    """A fresh process calls actual Authority; no eligibility context or runtime patch."""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = _root()
            if sys.platform not in {"linux", "win32"}:
                raise RuntimeError("native_platform_required")
            from mordred_hermes.keyvault import _seckey_helper, kek

            kek._noop_audit = lambda _entry: None
            from mordred_hermes._database_contracts import DatabaseRefused
            from mordred_hermes.dbcrypt._authority import Authority
            from mordred_hermes.keyvault._database_authority import observe_database_source

            before = asdict(observe_database_source(root=root))
            found = (
                _seckey_helper.find_winkey_helper() if sys.platform == "win32" else _seckey_helper.find_tpmkey_helper()
            )
            authority = None
            try:
                authority = Authority.acquire(root)
                authority.check()
                outcome = "acquired"
            except DatabaseRefused:
                outcome = "refused"
            finally:
                if authority is not None:
                    authority.close()
            after = asdict(observe_database_source(root=root))
        payload = {
            "schema_version": 2,
            "operation": "fresh_unpatched_authority",
            "outcome": outcome,
            "bootstrap": "direct_unpatched_authority",
            "helper_found": found,
            "source_before": before,
            "source_after": after,
        }
        print(json.dumps(payload, sort_keys=True))
        return 0 if outcome == "acquired" else 2
    except BaseException:
        print(json.dumps({"schema_version": 2, "operation": "fresh_unpatched_authority", "outcome": "probe_failed"}))
        return 3


def _fresh_authority_call(root: Path, copy: Path) -> dict[str, Any]:
    helper_name = "MORDRED_WINKEY_HELPER" if sys.platform == "win32" else "MORDRED_TPMKEY_HELPER"
    environment = {
        **os.environ,
        helper_name: str(copy),
        "HERMES_HOME": str(root),
        "MORDRED_DBCRYPT_TEST_ROOT": str(root),
    }
    code = (
        f"import runpy; raise SystemExit(runpy.run_path({str(Path(__file__).resolve())!r})"
        "['fresh_unpatched_authority_probe']())"
    )
    argv = [sys.executable, "-c", code]
    started = time.time()
    result = subprocess.run(
        argv,
        env=environment,
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    payload = json.loads(result.stdout)
    return {
        "argv": argv,
        "returncode": result.returncode,
        "started_at": started,
        "finished_at": time.time(),
        "payload": payload,
    }


def real_helper_unavailability(root: Path) -> dict[str, Any]:
    if not root.name.endswith("-negative"):
        raise RuntimeError("damaging_operations_require_separate_negative_root")
    tool = _tool()
    manifest = Path(os.environ["MORDRED_DBCRYPT_WITHDRAWABLE_HELPER_MANIFEST"])
    production_name = "MORDRED_WINKEY_HELPER" if sys.platform == "win32" else "MORDRED_TPMKEY_HELPER"
    production = Path(os.environ[production_name])
    parent = Path(os.environ["MORDRED_DBCRYPT_PARENT"])
    copied = tool["validate_withdrawable_helper"](manifest, production=production, parent=parent)
    path = Path(copied["path"])
    first = _fresh_authority_call(root, path)
    if first["returncode"] != 0 or first["payload"].get("outcome") != "acquired":
        raise RuntimeError("owned_helper_initial_unpatched_acquisition_failed")
    with withdraw_owned_helper(manifest, production=production, parent=parent):
        missing = _fresh_authority_call(root, path)
    restored = tool["validate_withdrawable_helper"](manifest, production=production, parent=parent)
    result = {
        "kind": "owned_helper_withdrawal",
        "copy": copied,
        "initial_acquisition": first,
        "missing_helper_acquisition": missing,
        "restored": {"sha256": restored["sha256"], "identity": restored["identity"]},
    }
    tool["validate_helper_withdrawal"](result)
    return result


def _public_lifecycle_guards(root: Path) -> list[str]:
    from unittest.mock import patch

    from mordred_hermes.keyvault._database_authority import observe_database_source
    from mordred_hermes.wizard import uninstall_cli
    from mordred_hermes.wizard.cli import main

    before = observe_database_source(root=root)
    commands = [
        ["encryption", "disable", "memory", "--non-interactive"],
        ["encryption", "purge", "memory", "--yes"],
        ["keyvault", "reset", "--yes"],
    ]
    if sys.platform != "win32":
        commands.append(["vault", "set-memory-key", "--root", str(root / "mordred/vault"), "--rotate"])
    rows = []
    for argv in commands:
        assert main(argv) == 1, "existing protected dependencies must refuse the actual parsed lifecycle command"
        assert observe_database_source(root=root) == before
        rows.append("public_" + "_".join(argv[:2]))
    removals: list[str] = []

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        removals.append("irreversible_removal")
        raise AssertionError("uninstall reached package/helper removal before dependency refusal")

    # These are irreversible side-effect tripwires, not replacements for native
    # custody, restoration, dependency inventory, auth, or the low-level broker.
    with (
        patch.object(uninstall_cli, "uninstall_packages", forbidden),
        patch.object(uninstall_cli, "_remove_helpers", forbidden),
    ):
        assert main(["uninstall", "--yes", "--remove-helper"]) == 1
    assert removals == [], "uninstall must refuse before package/helper removal is attempted"
    assert observe_database_source(root=root) == before
    rows.append("public_uninstall_helper_guard")
    return rows


def negative(root: Path) -> dict[str, Any]:
    from unittest.mock import patch

    import sqlcipher3.dbapi2 as driver

    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _authority, _migrate
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.keyvault._database_mutation import assert_database_helper_removal_safe, database_key_mutation

    provider = _runtime(root)
    _forget_roles(root)
    unwraps = []
    original = _authority.load_database_source

    def observe_unwrap(**kwargs: Any) -> Any:
        unwraps.append(1)
        return original(**kwargs)

    with patch.object(_authority, "load_database_source", observe_unwrap):
        authority = Authority.acquire(root)
        connection = open_protected(root / "state.db", authority=authority)
        try:
            for _ in range(5):
                connection.execute("SELECT count(*) FROM messages").fetchone()
                connection.commit()
            assert len(unwraps) == 1
            before = list(unwraps)
            from mordred_hermes.dbcrypt._capability import database_status

            database_status(root)
            assert unwraps == before
            with contextlib.suppress(DatabaseRefused), acquire_exclusive(root):
                raise AssertionError("SH-to-EX upgrade unexpectedly succeeded")
            cursor = connection.cursor()
            marker = root / "mordred/db-encryption.marker"
            public_marker = marker.read_bytes()
            damage = (
                "from pathlib import Path; import os; "
                "(Path(os.environ['HERMES_HOME'])/'mordred/db-encryption.marker')"
                ".write_bytes(b'invalid owned negative fixture')"
            )
            damaged = subprocess.run(
                [sys.executable, "-c", damage], env=os.environ.copy(), capture_output=True, timeout=30, check=False
            )
            assert damaged.returncode == 0
            try:
                for surface in (connection, cursor):
                    try:
                        surface.execute("SELECT count(*) FROM messages")
                    except DatabaseRefused:
                        pass
                    else:
                        raise AssertionError("held SQL surface survived metadata loss")
                assert authority.terminal
                try:
                    Authority.acquire(root)
                except DatabaseRefused:
                    pass
                else:
                    raise AssertionError("damaged source reacquired authority")
            finally:
                marker.write_bytes(public_marker)
        finally:
            connection.close()
            authority.close()
    provider.close()
    other_rows = _cached_and_boundaries(root)
    other_rows.extend(_missing_and_generation(root))
    _wrong_profile_key(root)
    _holder_uncertainty(root)
    other_rows.extend(["wrong_profile_key", "holder_uncertainty_injected"])
    assert _migrate.holders([root / "state.db"]) == [], "actual native holder observation unavailable"
    with acquire_exclusive(root) as lease:
        try:
            assert_database_helper_removal_safe(root, lease)
        except DatabaseRefused:
            pass
        else:
            raise AssertionError("helper removal would strand a protected dependency")
    try:
        with database_key_mutation(root=root, generation=None):
            raise AssertionError("key destruction broker admitted existing databases")
    except DatabaseRefused:
        pass
    for key in (None, "owned-negative-wrong-key"):
        offline = driver.connect(str(root / "state.db"))
        try:
            if key is not None:
                offline.execute("PRAGMA key='owned-negative-wrong-key'")
            try:
                offline.execute("SELECT count(*) FROM messages").fetchone()
            except driver.DatabaseError:
                pass
            else:
                raise AssertionError("keyless/wrong-key ciphertext read succeeded")
        finally:
            offline.close()
    withdrawal = real_helper_unavailability(root)
    other_rows.append("fresh_unpatched_native_provider_unavailable")
    other_rows.extend(_public_lifecycle_guards(root))
    return {
        "owned_helper_withdrawal": withdrawal,
        "rows": [
            "held_terminality",
            "unwrap_count",
            "metadata_loss",
            "wrong_key",
            "role_forget",
            "mail_retired_sql_failure_named_retry",
            "broker_helper_guards",
            *other_rows,
        ],
        "initial_unwraps": len(unwraps),
        "operation_unwraps": 0,
        "limitations": ["physical_hardware_disable_not_performed"],
    }


def operation(name: str) -> dict[str, Any]:
    root = _root()
    if name in {
        "negative",
        "backup_restore",
        "backup_restore_failure",
        "writer_a",
        "writer_b",
    } and not root.name.endswith("-negative"):
        raise RuntimeError("damaging_operations_require_separate_negative_root")
    from mordred_hermes.keyvault import kek

    kek._noop_audit = lambda _entry: None
    facts = native_facts(root)
    from mordred_hermes.extension.telegram import migrate, service
    from mordred_hermes.wizard import mail_cli

    mail_cli._audit = lambda _entry: None
    service._audit = lambda *_args, **_kwargs: None
    migrate.audit_event = lambda *_args, **_kwargs: None
    if name == "preflight":
        return {"facts": facts}
    with candidate_eligibility(root):
        if name == "provision":
            payload = provision(root)
        elif name in {"seed", "read"}:
            payload = collect(root, seed=name == "seed")
        elif name in {"backup_restore", "backup_restore_failure"}:
            payload = backup_restore(root, finalization_failure=name == "backup_restore_failure")
        elif name == "negative":
            payload = negative(root)
        elif name in {"writer_a", "writer_b"}:
            payload = _writer(root, name)
        else:
            raise RuntimeError("unsupported_fixed_native_operation")
    return {**payload, "facts": facts}


def main(name: str) -> int:
    # Arbitrary library/native logs never enter exported evidence, including
    # secret-bearing exception text or pytest locals. No plaintext log spool.
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            payload = operation(name)
    except BaseException as exc:
        safe = _tool()["NATIVE_REFUSAL_REASONS"]
        reason = str(exc) if type(exc) is RuntimeError and str(exc) in safe else "native_operation_failed"
        print(json.dumps({"schema_version": 2, "operation": name, "status": "refused", "reason": reason}))
        return 2
    print(
        json.dumps(
            {
                "schema_version": 2,
                "operation": name,
                "status": "executed",
                "acceptance_kind": os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"],
                "bootstrap": _tool()["native_operation_bootstrap"](os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"], name),
                "implementation_sha256": _digest(Path(__file__)),
                **payload,
            },
            sort_keys=True,
        )
    )
    return 0


class NativeReport:
    """Safe hook report: outcome/node IDs only; no traceback or local values."""

    def __init__(self) -> None:
        self.nodeids: list[str] = []
        self.deselected: list[str] = []
        self.reports: list[dict[str, Any]] = []
        self.collection_errors: list[dict[str, str]] = []
        self.qualification: dict[str, Any] | None = None
        self.pytest_argv: list[str] = []
        self.fixture_manifest_sha256: str | None = None

    def pytest_collection_finish(self, session: Any) -> None:
        self.nodeids = [item.nodeid for item in session.items]

    def pytest_deselected(self, items: Any) -> None:
        self.deselected.extend(item.nodeid for item in items)

    def pytest_collectreport(self, report: Any) -> None:
        if report.failed or report.skipped:
            self.collection_errors.append({"nodeid": report.nodeid, "outcome": report.outcome})

    def pytest_runtest_logreport(self, report: Any) -> None:
        outcome = "failed" if getattr(report, "wasxfail", None) else report.outcome
        reason_code = None
        if outcome == "skipped":
            raw = report.longrepr
            reason = raw[2].removeprefix("Skipped: ") if isinstance(raw, tuple) and len(raw) == 3 else None
            reason_code = (
                _tool()["platform_na_reason"](
                    report.nodeid, reason, platform=sys.platform, suite=os.environ.get("MORDRED_DBCRYPT_RUN_SUITE", "")
                )
                if reason is not None
                else None
            )
            reason_code = reason_code or "unrecognized_skip"
        self.reports.append(
            {"nodeid": report.nodeid, "when": report.when, "outcome": outcome, "reason_code": reason_code}
        )

    def pytest_sessionfinish(self, session: Any, exitstatus: int) -> None:
        path = os.environ.get("MORDRED_DBCRYPT_PYTEST_REPORT")
        if path:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            result: dict[str, Any] = {
                "nodeids": self.nodeids,
                "deselected": self.deselected,
                "reports": self.reports,
                "collection_errors": self.collection_errors,
                "exitstatus": int(exitstatus),
            }
            if self.qualification is not None:
                result.update(
                    qualification=self.qualification,
                    qualification_after=package_qualification_observation(),
                    pytest_argv=self.pytest_argv,
                    fixture_manifest_sha256=self.fixture_manifest_sha256,
                )
            with os.fdopen(fd, "w") as handle:
                json.dump(result, handle)


def pytest_configure(config: Any) -> None:
    reporter = NativeReport()
    if os.environ.get("MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY") == "1":
        from mordred_hermes.dbcrypt import _windows_vfs

        declared = _tool()["windows_activation_declaration"](Path(_windows_vfs.__file__).read_text())
        assert _windows_vfs.NATIVE_QUALIFIED is declared, "runtime eligibility differs from installed declaration"
        if not declared:
            _windows_vfs.NATIVE_QUALIFIED = True
            config.add_cleanup(lambda: setattr(_windows_vfs, "NATIVE_QUALIFIED", False))
        reporter.qualification = package_qualification_observation()
        reporter.pytest_argv = list(config.invocation_params.args)
        reporter.fixture_manifest_sha256 = _digest(Path(os.environ["MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR"]))
        config.pluginmanager.register(reporter, "dbcrypt-safe-native-report")
        return
    if (
        os.environ.get("MORDRED_DBCRYPT_RUN_SUITE") == "windows-vfs"
        and os.environ.get("MORDRED_DBCRYPT_ACCEPTANCE_MODE") == "wheel"
        and os.environ.get("MORDRED_DBCRYPT_ACCEPTANCE_KIND") == "candidate"
    ):
        root = Path(os.environ["MORDRED_DBCRYPT_PERSISTENCE_ROOT"])
        native_facts(root)
        eligibility = candidate_eligibility(root)
        eligibility.__enter__()
        config.add_cleanup(lambda: eligibility.__exit__(None, None, None))
    config.pluginmanager.register(reporter, "dbcrypt-safe-native-report")
