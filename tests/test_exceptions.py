"""Tests for ``mordred_hermes.llm_guard._exceptions``.

Codex review H2 (Phase 2 PR1): strict-mode aborts must propagate past
the ``except Exception:`` wrapper inside ``hermes_cli.plugins.invoke_hook``
*and* be semantically distinguishable from a generic ``SystemExit`` (which
would look like an ordinary CLI exit). The refusal classes therefore inherit
directly from :class:`BaseException`.

M2 stream-interrupted (``policy.strict.local_stream_interrupted``) is
deferred to v2: confirmed in Phase 2 PR1 prep that Hermes core owns the
streaming pipeline (``agent/error_classifier.py`` handles
``httpx.RemoteProtocolError``), so a plugin-side ``transport.py`` wrapper
cannot capture the audit fields. No ``MordredLocalStreamInterrupted`` class
in v1.
"""

from __future__ import annotations

import pytest


def test_unreachable_is_exception_subclass() -> None:
    """Local-endpoint unreachable is a recoverable error — runtime can catch."""
    from mordred_hermes.llm_guard._exceptions import MordredLocalUnreachable

    assert issubclass(MordredLocalUnreachable, Exception)
    # Bare ``Exception`` catch (Hermes invoke_hook style) must swallow it
    # so that lenient-mode health probe failures do not abort the session.
    try:
        raise MordredLocalUnreachable("test")
    except Exception:
        pass


def test_harness_refused_is_base_exception() -> None:
    """Strict-mode harness refusal must escape ``except Exception``."""
    from mordred_hermes.llm_guard._exceptions import MordredHarnessRefused

    assert issubclass(MordredHarnessRefused, BaseException)
    assert not issubclass(MordredHarnessRefused, Exception)


def test_session_refused_is_base_exception() -> None:
    """Strict-mode provider refusal must escape ``except Exception``."""
    from mordred_hermes.llm_guard._exceptions import MordredSessionRefused

    assert issubclass(MordredSessionRefused, BaseException)
    assert not issubclass(MordredSessionRefused, Exception)


def test_harness_refused_propagates_past_exception_wrapper() -> None:
    """Simulate Hermes ``invoke_hook`` ``except Exception:`` wrapper.

    Mirrors the propagation contract documented in
    ``docs/dev/HOOK_PAYLOADS.md`` §1 and the privacy_check
    hook handler reasoning in
    ``mordred-hermes/src/mordred_hermes/privacy_check/hooks.py:10-14``.
    """
    from mordred_hermes.llm_guard._exceptions import MordredHarnessRefused

    def hermes_invoke_hook(callback: object) -> None:
        try:
            assert callable(callback)
            callback()
        except Exception:
            pytest.fail("MordredHarnessRefused was incorrectly swallowed by except Exception")

    def harness_handler() -> None:
        raise MordredHarnessRefused("codex primary detected under strict policy")

    with pytest.raises(MordredHarnessRefused):
        hermes_invoke_hook(harness_handler)


def test_session_refused_propagates_past_exception_wrapper() -> None:
    """Symmetric propagation test for the provider-refusal class."""
    from mordred_hermes.llm_guard._exceptions import MordredSessionRefused

    def hermes_invoke_hook(callback: object) -> None:
        try:
            assert callable(callback)
            callback()
        except Exception:
            pytest.fail("MordredSessionRefused was incorrectly swallowed by except Exception")

    def session_handler() -> None:
        raise MordredSessionRefused("non-allowlisted provider under strict policy")

    with pytest.raises(MordredSessionRefused):
        hermes_invoke_hook(session_handler)


def test_session_refused_escapes_double_nested_exception_wrappers() -> None:
    """``pre_api_request`` is called with TWO nested ``except Exception``
    filters: ``hermes_cli/plugins.py::invoke_hook`` (line 1112) AND the
    call-site wrapper at ``run_agent.py:11319-11338``. Both catch only
    :class:`Exception`, not :class:`BaseException`, so
    :class:`MordredSessionRefused` (BaseException-derived) escapes both —
    this is what makes pre_api_request enforcement actually abort the
    API call despite the hook being documented as "observer-only" for
    return-value purposes.

    Pins the propagation contract Codex review P1 round 3 questioned.
    """
    from mordred_hermes.llm_guard._exceptions import MordredSessionRefused

    def hermes_invoke_hook(callback: object) -> None:
        # plugins.py:1108-1118 — per-callback wrapper.
        try:
            assert callable(callback)
            callback()
        except Exception:
            pytest.fail("MordredSessionRefused incorrectly swallowed by invoke_hook")

    def run_agent_call_site(callback: object) -> None:
        # run_agent.py:11319-11338 — outer try/except wrapping the hook call.
        try:
            hermes_invoke_hook(callback)
        except Exception:
            pytest.fail("MordredSessionRefused incorrectly swallowed by run_agent wrapper")

    def enforce_handler() -> None:
        raise MordredSessionRefused("runtime provider not allowlisted")

    with pytest.raises(MordredSessionRefused):
        run_agent_call_site(enforce_handler)


def test_refusal_classes_distinguishable_from_systemexit() -> None:
    """Codex H2: refusal must be distinguishable from a process-level exit.

    A handler catching ``SystemExit`` (e.g. signal/cleanup code) must NOT
    catch a Mordred refusal — they have different remediation paths.
    """
    from mordred_hermes.llm_guard._exceptions import (
        MordredHarnessRefused,
        MordredSessionRefused,
    )

    assert not issubclass(MordredHarnessRefused, SystemExit)
    assert not issubclass(MordredSessionRefused, SystemExit)


def test_no_stream_interrupted_class_in_v1() -> None:
    """M2 is deferred to v2 — class must NOT exist in PR1 to prevent silent half-impl.

    Repo audit: the freeze in
    ``mordred-hermes/src/mordred_hermes/privacy_check/_audit_reasons.py``
    still lists ``policy.strict.local_stream_interrupted`` because the enum
    is frozen for the whole phase; the *exception class* is what we defer
    so callers cannot accidentally raise it without an audit path.
    """
    import mordred_hermes.llm_guard._exceptions as exc_mod

    assert not hasattr(exc_mod, "MordredLocalStreamInterrupted"), (
        "MordredLocalStreamInterrupted should be deferred to v2 — Hermes core owns "
        "streaming (see Phase 2 PR1 prep H1 verify)."
    )
