"""``policy.json`` -> ``_PolicySettings`` reader for strict-mode enforcement.

Split out of ``enforce.py`` (LOC-reduction sweep): this module owns turning
the on-disk ``policy.json`` mapping into the small, typed settings bundle
(``_PolicySettings``) that ``enforce.check_session_provider`` /
``enforce.check_runtime_provider`` decide against, including every
failure-closed default (``allow_cloud_llm=False``, empty allowlist, the
default local endpoint, ``cloud_attempt_action="always-block"``). It does
not itself decide anything — no audit writes, no raising — that stays in
``enforce.py``.

``CloudAttemptAction`` lives here too since it is the type of
``_PolicySettings.cloud_attempt_action``; ``enforce.py`` imports it for
:func:`enforce._resolve_cloud_attempt`'s signature.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Final, Literal, TypeAlias

from .._policy_io import load_policy_mapping
from ._cloud_endpoint import policy_provider_id

_LOG = logging.getLogger("mordred.llm_guard.enforce")

# What strict mode does when a non-allowlisted cloud provider is reached.
# Mirrors the wizard's ``PolicySnapshot.cloud_attempt_action`` Literal
# (``wizard/policy_writer.py``). ``always-block`` is the safe default;
# ``prompt-once`` asks the operator once per provider at an interactive
# terminal (see :func:`enforce._resolve_cloud_attempt`).
CloudAttemptAction: TypeAlias = Literal["always-block", "prompt-once"]

_DEFAULT_LOCAL_ENDPOINT: Final = "http://localhost:1234/v1"


class _PolicySettings:
    """Subset of ``policy.json`` consumed by enforce."""

    __slots__ = ("allow_cloud_llm", "cloud_allowlist", "cloud_attempt_action", "local_endpoint")

    def __init__(
        self,
        *,
        allow_cloud_llm: bool,
        cloud_allowlist: frozenset[str],
        local_endpoint: str,
        cloud_attempt_action: CloudAttemptAction = "always-block",
    ) -> None:
        self.allow_cloud_llm = allow_cloud_llm
        self.cloud_allowlist = cloud_allowlist
        self.local_endpoint = local_endpoint
        self.cloud_attempt_action = cloud_attempt_action


def _read_policy_settings(policy_json_path: Path) -> _PolicySettings:
    """Read ``allow_cloud_llm`` / ``cloud_provider_allowlist`` / ``local_llm_endpoint``.

    Missing or malformed fields fall back to the safe-by-default values:
    ``allow_cloud_llm=False``, empty allowlist, default local endpoint.
    Under strict mode these defaults result in refusal for any cloud
    provider — i.e. failure-closed. A missing / unreadable / malformed /
    non-object ``policy.json`` loads as ``{}`` (via
    :func:`_policy_io.load_policy_mapping`), so the ``.get(...)`` chain
    below reproduces exactly those safe-by-default values.
    """
    data = load_policy_mapping(policy_json_path, log=_LOG)

    # Codex review P2: ``bool("false")`` is ``True`` in Python — using
    # ``bool(...)`` here would let a hand-edited or migrated
    # ``allow_cloud_llm: "false"`` (string) flip strict mode open. Require
    # the JSON value to be a real boolean ``true``; anything else is
    # failure-closed False.
    allow_cloud_llm = data.get("allow_cloud_llm") is True
    raw_allowlist = data.get("cloud_provider_allowlist", [])
    # Codex review P2 round 5 (revised): normalize allowlist entries through
    # the SAME alias table the runtime provider id is canonicalized through
    # (``__init__.py::_on_pre_api_request_enforce`` /
    # ``_resolve_active_provider`` both call ``canonicalize_provider``). A
    # bare ``.strip().lower()`` here handled casing/whitespace but not
    # aliases: a hand-edited ``cloud_provider_allowlist: ["claude"]`` (a real
    # Hermes alias for ``"anthropic"``) or ``["google"]`` / ``["aws"]`` would
    # never match the canonicalized runtime id and strict mode would refuse
    # a provider the user clearly intended to allow. ``canonicalize_provider``
    # already strips + lowers before the alias lookup, so this is not a
    # double-normalization. Empty strings still drop out (``if s``) so a
    # stray comma in the wizard CSV doesn't widen the allowlist.
    #
    # ``"custom"`` is dropped: it is Hermes' wildcard bucket for an arbitrary
    # OpenAI-compatible ``base_url`` (and the canonical form of the ``ollama``
    # local-endpoint alias). Letting an allowlist entry resolve to it would turn
    # a narrow grant (e.g. a user writing ``["ollama"]`` meaning "allow my local
    # model") into permission for ANY custom cloud endpoint — a fail-open
    # widening in a strict CLOUD allowlist. Fail closed instead; a deliberate
    # arbitrary-endpoint grant is not something strict mode should make easy.
    cloud_allowlist = (
        frozenset(
            s for s in (policy_provider_id(x) for x in raw_allowlist if isinstance(x, str)) if s and s != "custom"
        )
        if isinstance(raw_allowlist, list)
        else frozenset()
    )
    raw_endpoint = data.get("local_llm_endpoint")
    local_endpoint = raw_endpoint if isinstance(raw_endpoint, str) and raw_endpoint else _DEFAULT_LOCAL_ENDPOINT
    # Only the exact string ``"prompt-once"`` opts into the prompt path;
    # missing / unknown / non-string values fall back to the safe default
    # ``"always-block"`` (failure-closed, mirroring the allow_cloud_llm
    # ``is True`` coercion above).
    cloud_attempt_action: CloudAttemptAction = (
        "prompt-once" if data.get("cloud_attempt_action") == "prompt-once" else "always-block"
    )
    return _PolicySettings(
        allow_cloud_llm=allow_cloud_llm,
        cloud_allowlist=cloud_allowlist,
        local_endpoint=local_endpoint,
        cloud_attempt_action=cloud_attempt_action,
    )
