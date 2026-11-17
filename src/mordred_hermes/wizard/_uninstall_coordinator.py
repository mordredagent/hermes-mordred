"""Root-wide uninstall: prove all inputs before restoring any of them."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from .._core._database_contracts import DatabaseRefused
from .._core._database_lifecycle import ExclusiveLease
from ..dbcrypt import _migrate
from ..dbcrypt._uninstall import preflight, verified
from ..keyvault._uninstall_authority import check_authorization, fingerprint, profile_fingerprint
from . import _term, _uninstall_databases, _uninstall_windows
from . import uninstall_cli as cli
from ._flow_session import FlowSession
from ._uninstall_hermes_env import uninstall_packages

if TYPE_CHECKING:
    from .uninstall_cli import UninstallContext, UninstallOptions, UninstallPlan


def _restore_inputs(  # noqa: C901, PLR0912 - authenticate each restoration type before writes
    ctx: UninstallContext, plan: UninstallPlan, flow: FlowSession
) -> dict[Path, bytes]:
    from ..keyvault._memory_key import load_linux_memory_key
    from ..keyvault.memory_crypto import unseal
    from . import memory_cli

    needed = any(r.needs_vault for r in plan.restores)
    if needed and not cli._open_vault_for_flow(ctx, flow, needed=True):
        raise DatabaseRefused(f"the vault could not be opened for {ctx.home}; no restoration started")
    expected = {}
    for restore in plan.restores:
        if restore.target in {"env", "config"}:
            path = ctx.home / (".env" if restore.target == "env" else "config.yaml")
            if path.is_symlink():
                raise DatabaseRefused(f"restore target is an alias: {path}")
            if path.exists():
                value = path.read_bytes()
            else:
                opened = flow.lend_vault(ctx.vault_root)
                if opened is None or path.name not in opened.list_files():
                    raise DatabaseRefused(f"missing recoverable configuration: {path}")
                value = opened.read_file(path.name)
            value.decode("utf-8")
            if restore.target == "config":
                from ruamel.yaml import YAML

                data = YAML(typ="safe").load(value)
                if data is not None and not isinstance(data, dict):
                    raise DatabaseRefused("restored configuration is not a YAML mapping")
            else:
                expected[path] = hashlib.sha256(value).digest()
        elif restore.target == "memory":
            paths = memory_cli._sealed_memory_files(ctx.home)
            if not paths:
                continue
            key: bytes | None
            if memory_cli._uses_tpm_memory(ctx.home):
                key = load_linux_memory_key(home=ctx.home, backend=ctx.backend)
            else:
                key = memory_cli._memory_key_from_vault(
                    root=ctx.vault_root, backend=ctx.backend, store=ctx.store, flow_session=flow
                )
            if key is None:
                raise DatabaseRefused("memory could not be restored: sealed memory has no recoverable key")
            for path in paths:
                if path.is_symlink():
                    raise DatabaseRefused(f"memory restore target is an alias: {path}")
                expected[path] = hashlib.sha256(unseal(path.read_bytes(), key=key, name=path.name)).digest()
    return expected


def _check_restored(expected: dict[Path, bytes]) -> None:
    for path, digest in expected.items():
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).digest() != digest:
            raise DatabaseRefused(f"restored file verification failed: {path}")


def execute(  # noqa: C901, PLR0912, PLR0915 - explicit ordered platform lifecycle
    ctx: UninstallContext, plan: UninstallPlan, opts: UninstallOptions
) -> int:
    if plan.hermes_env.problem:
        raise DatabaseRefused(f"package environment unavailable: {plan.hermes_env.problem}")
    targets = [(ctx, plan), *plan.profiles]
    from ..keyvault._identity import resolve_backend, resolve_store

    targets = [
        (dataclasses.replace(target, backend=resolve_backend(target.backend), store=resolve_store(target.store)), item)
        if target.platform == "darwin" and target.vault_root.exists()
        else (target, item)
        for target, item in targets
    ]
    ctx = targets[0][0]
    _check_profiles(ctx, plan)
    if opts.remove_helper and not opts.purge_data and any(item.device_keys for _, item in targets):
        raise DatabaseRefused("helper is required for retained recovery keys; keep it or use --purge-data")
    for target, item in targets:
        if restoration_fingerprint(target) != item.file_observation:
            raise DatabaseRefused("restoration targets changed after confirmation; review a new plan")
        if (target.gateways or cli._default_gateways)(target.home):
            raise DatabaseRefused(f"Hermes is running for {target.home}; stop it before uninstall")
    if _uninstall_databases.needed(ctx.home):
        from ..dbcrypt import database_status

        capability = database_status(ctx.home)
        if capability.capability == "unavailable":
            raise DatabaseRefused(capability.reason or "native database restoration unavailable")
    windows = ctx.platform == "win32"
    proofs = []
    if windows and opts.remove_helper:
        for target, _ in targets:
            roles, error = _uninstall_windows.custody_roles(target.home)
            if (
                error
                or any(role != "memory" for role in roles)
                or target.vault_root.exists()
                or (target.home / "mordred/keyvault").exists()
            ):
                raise DatabaseRefused("helper is required by retained Windows custody or vault data")
    if windows:
        from . import _windows_memory
        from ._windows_databases import refusal

        for target, item in targets:
            blocked = refusal(target.home)
            if blocked is not None:
                raise DatabaseRefused(blocked)
            proofs.append(
                _windows_memory.prepare_uninstall(target.home)
                if any(r.target == "memory" for r in item.restores)
                else None
            )
    with _migrate.migration_lock(ctx.home) as lease, contextlib.ExitStack() as stack:
        if fingerprint(ctx.home) != plan.database_observation:
            raise DatabaseRefused("database targets changed after the plan was displayed; review a new plan")
        erased = frozenset(path for _, item in targets for path in item.erase_files)
        report = preflight(ctx.home, lease=lease, purge=opts.purge_data or opts.remove_helper, erase=erased)
        if opts.erase_encrypted and report.encrypted:
            raise DatabaseRefused("encrypted databases outside the reviewed erase targets would remain")
        flows = [stack.enter_context(FlowSession()) for _ in targets]
        expected = [
            {} if windows or opts.erase_encrypted else _restore_inputs(target, item, flow)
            for (target, item), flow in zip(targets, flows, strict=True)
        ]
        if windows:
            for (target, _), proof in zip(targets, proofs, strict=True):
                try:
                    _windows_memory.verify_uninstall_inputs(target.home, proof)
                except Exception as exc:
                    raise DatabaseRefused(f"memory could not be restored to plaintext: {exc}") from exc
        if opts.purge_data and not windows:
            for (target, _), flow in zip(targets, flows, strict=True):
                _purge_preflight(target, flow)
        _check_profiles(ctx, plan)
        report.unchanged(lease)
        for target, item in targets:
            if restoration_fingerprint(target) != item.file_observation:
                raise DatabaseRefused("restoration inputs changed during authentication; nothing restored")
        if opts.erase_encrypted:
            for target, item in targets:
                restores = [r for r in item.restores if r.target != "databases" or target.home == ctx.home]
                if cli._erase_encrypted(target, restores, reviewed=item.erase_files) != 0:
                    return 1
        elif report.encrypted or _uninstall_databases._live_needed(ctx.home):
            _uninstall_databases.restore(ctx, None)
        with verified(report, lease=lease) as permit:
            for index, ((target, item), flow, files) in enumerate(zip(targets, flows, expected, strict=True)):
                restores = [r for r in item.restores if r.target != "databases"]
                if opts.erase_encrypted:
                    continue
                if windows and not any(r.target == "memory" for r in restores):
                    continue
                if windows:
                    rc = _windows_memory._disable(home=target.home, proof=proofs[index], uninstall=permit)
                else:
                    rc = cli._restore_all(target, restores, flow, uninstall=permit)
                if rc != 0:
                    # `_restore_all` restores config/env as well as memory and has
                    # already named the failed target; only Windows restores memory alone.
                    what = "memory" if windows else "an encrypted target"
                    _term.emit_error(
                        f"uninstall stopped: {what} could not be restored to plaintext; later cleanup stopped"
                    )
                    return 1
                _check_restored(files)
        if opts.purge_data:
            for index, ((target, item), flow) in enumerate(zip(targets, flows, strict=True)):
                _check_profiles(ctx, plan)
                if windows:
                    with verified(
                        preflight(ctx.home, lease=lease, purge=True, source=report.snapshot if index == 0 else None),
                        lease=lease,
                    ) as permit:
                        rc = _windows_memory.purge(home=target.home, uninstall=permit)
                else:
                    rc = _purge_profile(target, item, flow, ctx.home, lease)
                if rc != 0:
                    _term.emit_error(
                        "uninstall stopped: Windows memory custody could not be purged"
                        if windows
                        else "uninstall stopped: native source purge failed"
                    )
                    return 1
                if windows:
                    for line in _uninstall_windows.purge_lines(target.home):
                        if line.startswith("keep "):
                            print(line[0].upper() + line[1:] + ".")
        final_report = preflight(ctx.home, lease=lease, purge=opts.purge_data or opts.remove_helper)
        with verified(final_report, lease=lease) as permit:
            for target, item in targets:
                _check_profiles(ctx, plan)
                check_authorization(permit, root=ctx.home, lease=lease, purpose="restore")
                if cli._clean_hermes_files(target, item) != 0:
                    return 1
            cli._remove_launchers(plan)
            if opts.purge_data and not windows:
                for target, item in targets:
                    if cli._purge_data(target, item) != 0:
                        return 1
            for target, item in targets:
                item.data = cli._data_inventory(target)
                if opts.purge_data:
                    item.device_keys = cli._device_keys(target, item.telegram_configured) if windows else []
            if not windows or opts.remove_helper:
                cli._remove_helpers(plan, opts, ctx, lease, uninstall=permit)
            check_authorization(permit, root=ctx.home, lease=lease, purpose="restore")
            _check_profiles(ctx, plan)
            return _remove_package(ctx, plan, opts)


def _remove_package(ctx: UninstallContext, plan: UninstallPlan, opts: UninstallOptions) -> int:
    farewell = (
        _uninstall_windows.kept_lines(plan)
        if ctx.platform == "win32"
        else cli._render_kept(plan, purged=opts.purge_data)
    )
    ok, output = uninstall_packages(plan.hermes_env, runner=ctx.runner)
    if output:
        print(output)
    if not ok:
        _term.emit_error(
            f"uv pip uninstall failed in {plan.hermes_env.root}; Hermes's files are already restored. "
            "Keep the retained keys and backups, repair the package environment, then rerun uninstall."
        )
        return 1
    print(farewell)
    for target, item in plan.profiles:
        print(f"Profile {target.home}:")
        print(
            _uninstall_windows.kept_lines(item)
            if ctx.platform == "win32"
            else cli._render_kept(item, purged=opts.purge_data)
        )
    if not opts.purge_data:
        print(
            "Recovery: keep the native key, wrapper, source binding, backup registry and helper. "
            "Reinstall hermes-mordred on this same physical home and device, then run "
            "`hermes-mordred databases backup export --source PATH --output NEW_PATH` "
            "(add `--member NAME` for a ZIP database). External/offline backups are not inventoried."
        )
    print("Done. Restart Hermes (and Hermes Desktop) so it stops loading Mordred.")
    return 0


def _purge_profile(
    ctx: UninstallContext, plan: UninstallPlan, flow: FlowSession, root: Path, lease: ExclusiveLease
) -> int:
    from ..keyvault._memory_key import delete_linux_memory_key, memory_key_path
    from . import keyvault_cli, memory_cli

    wrapped = memory_key_path(ctx.home)
    if wrapped.exists() or wrapped.is_symlink():
        if memory_cli._sealed_memory_files(ctx.home):
            raise DatabaseRefused("sealed memory remains; native source retained")
        with verified(preflight(root, lease=lease, purge=True), lease=lease) as permit:
            delete_linux_memory_key(home=ctx.home, backend=ctx.backend, database_lease=lease, uninstall=permit)
    if ctx.vault_root.exists():
        with verified(preflight(root, lease=lease, purge=True), lease=lease) as permit:
            cli._delete_vault_keys(ctx, flow, lease, uninstall=permit)
    if plan.telegram_configured:
        cli._forget_telegram_for_uninstall(ctx)
    if (ctx.home / "mordred/keyvault").exists():
        with verified(preflight(root, lease=lease, purge=True), lease=lease) as permit:
            if ctx.keyvault_reset is not None:
                return ctx.keyvault_reset(ctx.home)
            return keyvault_cli._reset_with_memory_guard(
                home=ctx.home, backend=ctx.backend, assume_yes=True, database_lease=lease, uninstall=permit
            )
    return 0


def _purge_preflight(ctx: UninstallContext, flow: FlowSession) -> None:
    from ..keyvault import _storage
    from ..keyvault._memory_key import load_linux_memory_key, memory_key_path
    from . import keyvault_cli

    wrapped = memory_key_path(ctx.home)
    if (wrapped.exists() or wrapped.is_symlink()) and load_linux_memory_key(home=ctx.home, backend=ctx.backend) is None:
        raise DatabaseRefused("memory source authentication is required before deletion")
    if ctx.vault_root.exists():
        if not cli._open_vault_for_flow(ctx, flow, needed=True):
            raise DatabaseRefused("vault authentication is required before source deletion")
        opened = flow.lend_vault(ctx.vault_root)
        if opened is None or opened._store is None:
            raise DatabaseRefused("vault deletion requires the device anchor")
    root = ctx.home / "mordred/keyvault"
    if _storage.reset_journal_path(root).exists():
        raise DatabaseRefused("unfinished keyvault reset requires explicit recovery before uninstall")
    if root.exists() and ctx.keyvault_reset is None:
        _, legacy, incomplete = keyvault_cli._collect_reset_key_ids(root)
        if legacy or incomplete:
            raise DatabaseRefused("keyvault ownership is incomplete; reconcile it before uninstall")


def restoration_fingerprint(ctx: UninstallContext) -> tuple[tuple[object, ...], ...]:
    """Read-only identities/revisions for confirmation and authentication gaps."""
    from .encryption_cli import _memory_file_paths

    paths = {ctx.home / ".env", ctx.home / "config.yaml", *_memory_file_paths(ctx.home)}
    state = ctx.home / "mordred"
    for name in ("config-vault.marker", "memory-vault.marker", "memory-key.wrapped", "memory-vault.optout"):
        paths.add(state / name)
    if ctx.vault_root.is_dir():
        paths.update(ctx.vault_root.glob("manifest.*.mvmf"))
    result: list[tuple[object, ...]] = []
    for path in sorted(paths):
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.append((path, None))
        else:
            result.append(
                (path, info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            )
    return tuple(result)


def _check_profiles(ctx: UninstallContext, plan: UninstallPlan) -> None:
    if profile_fingerprint(ctx.home) != plan.profile_observation:
        raise DatabaseRefused("profile inventory changed; review a new root uninstall plan")
