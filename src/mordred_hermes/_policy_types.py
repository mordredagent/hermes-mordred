"""Canonical policy-mode / network-path types shared across plugin packages.

Single-sources the two closed string sets that were independently declared
across the tree — ``PolicyMode`` five times (``network.runtime``,
``network.provider_transport_flagger``, ``network.vpn_providers.base``,
``network.paths.vpn``, ``privacy_check.policy``), ``ActivePath`` four times
(``network.runtime``, ``network.api``, ``network.proxy_env``,
``privacy_check.policy``), plus four hand-maintained validation sets
(``network.hooks``, ``network.__init__``, ``network.api``,
``wizard._network_answers``). Nine-plus declarations of the same closed sets
can drift silently: adding a fourth path or mode used to require touching
every one of those sites in lockstep.

Declaring-package modules keep re-exporting these names for their existing
importers; only the definitions collapse to here.

The value tuples are derived from the ``Literal`` types via
:func:`typing.get_args`, so the type-level and runtime-level views cannot
disagree, and the declaration order is preserved for callers that display
the values to operators (e.g. ``wizard._network_answers`` choice listings).

Stdlib-only on purpose — this must stay importable at plugin registration
time without pulling optional dependencies (same constraint as
``_policy_io``).
"""

from __future__ import annotations

from typing import Final, Literal, TypeAlias, get_args

PolicyMode: TypeAlias = Literal["strict", "lenient", "off"]
ActivePath: TypeAlias = Literal["tor", "vpn", "clearnet"]

POLICY_MODES: Final[tuple[str, ...]] = get_args(PolicyMode)
ACTIVE_PATHS: Final[tuple[str, ...]] = get_args(ActivePath)

VALID_POLICY_MODES: Final[frozenset[str]] = frozenset(POLICY_MODES)
VALID_ACTIVE_PATHS: Final[frozenset[str]] = frozenset(ACTIVE_PATHS)
