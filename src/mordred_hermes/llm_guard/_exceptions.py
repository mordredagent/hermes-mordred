"""Exception hierarchy for ``mordred_llm_guard``.

Two propagation regimes (Codex review H2, Phase 2 PR1):

- :class:`MordredLocalUnreachable` inherits :class:`Exception`. Callers
  (notably lenient-mode health probes) can ``except Exception:`` and
  degrade gracefully.

- :class:`MordredHarnessRefused` and :class:`MordredSessionRefused`
  inherit :class:`BaseException` directly. They escape the
  ``except Exception:`` wrapper inside ``hermes_cli.plugins.invoke_hook``
  (see ``mordred-docs/dev/HOOK_PAYLOADS.md`` §1) so strict-mode policy
  refusals actually abort the session, and they are *not* :class:`SystemExit`
  subclasses so cleanup-style ``except SystemExit:`` blocks do not mistake
  a policy refusal for an ordinary CLI exit.

``MordredLocalStreamInterrupted`` (M2) is intentionally absent in v1.
Phase 2 PR1 prep verified that Hermes core owns the streaming pipeline
(``agent/error_classifier.py`` handles ``httpx.RemoteProtocolError``), so a
plugin-side ``transport.py`` wrapper cannot capture the
``policy.strict.local_stream_interrupted`` audit fields. The class will be
reintroduced when a streaming hook lands upstream (tracked as v2 follow-up
in ``mordred-docs/dev/TODO.md`` §2 and ROADMAP).
"""

from __future__ import annotations


class MordredLocalUnreachable(Exception):
    """Local OpenAI-compatible endpoint failed a health probe.

    Recoverable in lenient/off mode (the session falls back to whatever
    provider is configured). In strict mode the session is aborted via
    :class:`MordredSessionRefused`; the translation happens in
    :func:`enforce._probe_local` (Codex review P2 round 2) so the
    underlying :class:`MordredLocalUnreachable` is preserved as
    ``__cause__`` while a ``BaseException``-derived refusal escapes
    Hermes' ``except Exception`` hook dispatch
    (``hermes_cli/plugins.py::invoke_hook`` line 1112). Raising this
    class alone — outside ``enforce._probe_local`` — does not constitute
    a refusal.
    """


class MordredHarnessRefused(BaseException):
    """Strict-mode primary agent is a harness whose daemon traffic bypasses Hermes.

    Examples: Codex CLI, Claude CLI, Cursor, ACP clients. These run their
    own LLM call paths that Mordred hooks never see, so under strict policy
    the session is refused rather than silently degraded.
    """


class MordredSessionRefused(BaseException):
    """Strict-mode active provider is not in the cloud allowlist.

    Raised by the enforce handler (Phase 2 PR2). Defined here in PR1 so the
    propagation contract is testable against the harness path that lands in
    PR1 first.
    """
