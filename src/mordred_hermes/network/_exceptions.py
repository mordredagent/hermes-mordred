"""Exception hierarchy for ``mordred_network``.

Two propagation regimes, mirroring ``llm_guard._exceptions`` (Codex review
H2, Phase 2 PR1):

- :class:`MordredNetworkError` and its subclasses inherit :class:`Exception`.
  ``api.use(path)`` callers (CLI, internal API, tests) catch them to surface
  user-actionable failures *without* aborting the session — silent fallback
  is forbidden, but the caller decides how to react.

- :class:`MordredPathBringupFailed` and :class:`MordredPathDropped` inherit
  :class:`BaseException` directly. Phase 3 PR2 raises them from
  ``on_session_start`` and the liveness worker / ``pre_tool_call`` hook
  respectively. They escape the ``except Exception:`` filter inside
  ``hermes_cli.plugins.invoke_hook`` (see
  ``mordred-docs/mordred/HOOK_PAYLOADS.md`` §1) so strict-mode network
  refusals actually abort the session, and they are *not* :class:`SystemExit`
  subclasses so cleanup-style ``except SystemExit:`` blocks do not mistake
  a policy refusal for an ordinary CLI exit.

The classes are defined in PR1 (before PR2 wires the hooks) so the
propagation contract is testable up-front, matching the pattern used in
``llm_guard._exceptions`` where ``MordredSessionRefused`` was defined in
PR1 and consumed by the PR2 ``enforce`` handler.
"""

from __future__ import annotations


class MordredNetworkError(Exception):
    """Base class for recoverable network-path errors.

    Raised by :mod:`mordred_hermes.network.api` (``use(path)`` and friends)
    when the request cannot be satisfied but the session itself is not
    refused. Callers in CLI / internal API contexts catch this base.
    """


class BringupFailed(MordredNetworkError):
    """Synchronous bring-up of a path failed.

    Distinct from :class:`MordredPathBringupFailed`: this is the
    *API-level* error returned by ``api.use(path)`` so callers can
    surface a message and pick an alternative. Strict-mode hooks
    translate this into :class:`MordredPathBringupFailed` to abort the
    session, but the API itself does not.
    """


class AlreadySwitching(MordredNetworkError):
    """A path switch is in progress; concurrent ``use(path)`` rejected."""


class UnknownPath(MordredNetworkError):
    """Path name is not one of ``tor`` / ``vpn`` / ``clearnet``."""


class UnknownVpnProvider(MordredNetworkError):
    """Configured ``vpn_provider`` name is not a registered provider.

    Raised by :func:`mordred_hermes.network.vpn_providers.build_provider`
    when ``plugins.mordred_network.vpn_provider`` names a provider the
    registry does not know. Recoverable: the wizard / CLI surfaces the
    list of known providers so the operator can fix the config.
    """


class BlackoutNotAsserted(MordredNetworkError):
    """Network reachable when ``api.blackout_assert`` required isolation.

    Raised by :func:`mordred_hermes.network.api.blackout_assert` when the
    injected probe reports that an outbound socket connect succeeded —
    e.g. before showing a Seed Phrase (Phase 4 `keyvault.seed_display`)
    the caller must prove the host has no live network paths.
    """


class MordredPathBringupFailed(BaseException):
    """Strict-mode ``on_session_start`` refusal: path failed to bring up.

    Phase 3 PR2 ``hooks.on_session_start`` raises this when strict policy
    requires a path that fails its bring-up handshake (Tor bootstrap
    timeout, Mullvad CLI missing, etc.).

    BaseException-derived so it escapes the ``except Exception:`` filter
    inside ``hermes_cli.plugins.invoke_hook`` (see
    ``mordred-docs/mordred/HOOK_PAYLOADS.md`` §1). Distinct from
    :class:`BringupFailed` so ``except MordredNetworkError`` does not
    accidentally swallow a strict-mode abort.
    """


class MordredPathDropped(BaseException):
    """Strict-mode mid-session liveness drop.

    Phase 3 PR2 raises this from the next ``pre_tool_call`` hook after the
    liveness worker detects two consecutive health failures on the active
    path. Strict policy aborts the session rather than letting a tool call
    leak onto the clearnet via silent fallback.

    BaseException-derived for the same propagation reason as
    :class:`MordredPathBringupFailed`.
    """
