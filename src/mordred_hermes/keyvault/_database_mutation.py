"""No-SQL database exclusion broker, acquired before native-key custody."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .._custody_order import active_custody_scopes, assert_preceding_database_lease
from .._database_contracts import DatabaseRefused
from .._database_inventory import assert_mutation_safe
from .._database_lifecycle import ExclusiveLease, acquire_exclusive, current_thread_exclusive_leases
from ._database_authority import resolve_database_domain
from ._uninstall_authority import UninstallAuthorization, check_authorization


def _assert_memory_database_mutation_safe(
    *, home: Path, database_lease: ExclusiveLease | None, uninstall: UninstallAuthorization | None = None
) -> None:
    """Fresh final all-generations guard; never acquire locks or retire metadata."""
    assert_preceding_database_lease(database_lease)
    if database_lease is None:  # Narrowing only: the registry assertion refuses None.
        raise DatabaseRefused("a preceding exclusive database lease is required")
    domain = resolve_database_domain(home)
    ExclusiveLease.assert_held(database_lease, domain.root)
    if uninstall is None:
        assert_mutation_safe(domain.root, None, database_lease)
    else:
        check_authorization(uninstall, root=domain.root, lease=database_lease, purpose="delete")
    if resolve_database_domain(home) != domain:
        raise DatabaseRefused("database home relationship changed during inventory")


def assert_database_helper_removal_safe(
    root: Path, lease: ExclusiveLease, *, uninstall: UninstallAuthorization | None = None
) -> None:
    """Helper removal can strand any native source generation in the domain."""
    _assert_memory_database_mutation_safe(home=root, database_lease=lease, uninstall=uninstall)


@contextmanager
def database_key_mutation(
    *, root: Path, generation: str | None, uninstall: UninstallAuthorization | None = None
) -> Iterator[ExclusiveLease]:
    """Lease -> custody -> final inventory -> mutation, with exact nested borrowing.

    ``generation`` is only a caller consistency hint. It never excludes older or
    unknown dependencies from the conservative all-generations safety scan.
    """
    domain = resolve_database_domain(root)
    for lease in current_thread_exclusive_leases():
        # Root comparison is metadata, with no opening/acquisition of OS locks.
        if lease.root == domain.identities[0]:
            assert_preceding_database_lease(lease)
            _assert_memory_database_mutation_safe(home=root, database_lease=lease, uninstall=uninstall)
            yield lease
            return
    if active_custody_scopes():
        raise DatabaseRefused("database mutation must begin before custody")
    with acquire_exclusive(domain.root) as lease:
        if resolve_database_domain(root) != domain:
            raise DatabaseRefused("database home relationship changed before exclusion")
        _assert_memory_database_mutation_safe(home=root, database_lease=lease, uninstall=uninstall)
        yield lease
