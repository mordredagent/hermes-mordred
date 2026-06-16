"""``hermes mordred configure`` -- interactive Mordred setup.

Two-step flow:

1. Delegate first-run Hermes setup via ``subprocess.run(["hermes", "setup", ...])``
   (Hermes uses its own curses TUI -- ``hermes_cli/main.py:8704``).
2. Collect Mordred-specific prompts (policy mode, cloud allowlist, local LLM
   endpoint, agent harness) via :class:`PromptIO`.
3. Persist via :class:`PolicyWriter` (writes ``~/.hermes/mordred/policy.json``
   and the ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``
   sections of ``~/.hermes/config.yaml``).

Both side effects -- the Hermes setup spawn AND the prompt collection -- go
through Protocol-typed seams (:class:`SetupRunner`, :class:`PromptIO`) so
tests inject scripted doubles. Production impls (:class:`SubprocessSetupRunner`,
:class:`PromptToolkitIO`) wrap subprocess and prompt_toolkit respectively.

Network-privacy setup (Tor / VPN / clearnet, Mullvad) is NOT part of first-run
configure. It is opt-in via the dedicated, re-runnable
``hermes-mordred network init`` command (see :mod:`mordred_hermes.wizard.network_cli`).
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

from .policy_writer import PolicySnapshot, PolicyWriter

if TYPE_CHECKING:
    from prompt_toolkit.application import Application
    from prompt_toolkit.formatted_text import StyleAndTextTuples
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.key_processor import KeyPressEvent

_LOG = logging.getLogger("mordred.wizard.configure")

#: Cloud providers offered as checkbox choices for the allowlist prompt.
#: Sourced from the network flagger's canonical registry so the wizard and the
#: transport-compat layer never drift. Localhost-only providers
#: (``mordred-local``) are excluded -- a local endpoint is never a *cloud*
#: allowlist entry.
_SELECTABLE_CLOUD_PROVIDERS: Final[tuple[str, ...]] = tuple(
    name for name, entry in KNOWN_PROVIDERS.items() if not entry.localhost_only
)

#: One-line description shown inline next to each policy mode in the
#: ``configure`` radio dialog (UX request 2026-06-15: the bare strict/lenient/off
#: labels gave no hint of what each mode does). Copy mirrors the policy-mode
#: table in ``mordred-docs/mordred/QUICKSTART.md`` so the TUI and the docs never
#: drift. A mode missing here simply renders without a description.
_POLICY_MODE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "strict": "Blocks cloud LLMs, disables IPv6, refuses known AI harnesses",
    "lenient": "Guards active but stay out of your way (recommended)",
    "off": "Disables all guards entirely",
}

#: One-line description shown inline next to each cloud-attempt action in the
#: ``configure`` radio dialog (UX request 2026-06-15, mirroring the policy-mode
#: descriptions above). ``prompt-once`` is a reserved value -- enforcement is
#: refuse-only today, so it behaves like ``always-block`` -- and the copy says
#: so to keep users from expecting an interactive prompt that does not yet
#: exist. Mirrors the Q6 note in ``mordred-docs/mordred/QUICKSTART.md`` so the
#: TUI and the docs never drift.
_CLOUD_ATTEMPT_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "always-block": "Silently refuse the cloud call every time (recommended)",
    "prompt-once": "Reserved — currently behaves like always-block",
}

#: Help text shown above the cloud-LLM yes/no prompt. The bare question gave no
#: hint about the privacy trade-off or what answering yes leads to (UX request
#: 2026-06-15, sibling of the policy-mode inline descriptions above). It replaces
#: the old jargon suffix "(passes through provider override)", which named an
#: implementation detail instead of the choice the user is actually making.
_CLOUD_LLM_PROMPT_DESCRIPTION: Final[str] = (
    "Cloud providers (e.g. OpenAI, Anthropic) run models on their own servers, so "
    "your prompts leave this machine. Choose No to stay fully local and private, or "
    "Yes to also permit cloud models — you'll pick which providers at the next prompt."
)


# -----------------------------------------------------------------------------
# Protocols -- production wraps subprocess / prompt_toolkit, tests script.
# -----------------------------------------------------------------------------


class SetupRunner(Protocol):
    """Spawn ``hermes setup``. Return its exit code (0 = success)."""

    def run(self, *, non_interactive: bool) -> int: ...


class PromptIO(Protocol):
    """Collect Mordred-specific answers from the user.

    Production impl wraps ``prompt_toolkit``. Tests inject a scripted FIFO
    that pops pre-recorded answers per call -- nothing in this module
    touches a real TTY.

    :meth:`ask_password` keeps secret prompts (e.g. the Mullvad account number
    collected by ``network init``) out of shell history and test diagnostics.
    This shared prompt surface is reused by
    :mod:`mordred_hermes.wizard.network_cli`.
    """

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str: ...
    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str: ...
    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool: ...
    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]: ...
    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str: ...


# -----------------------------------------------------------------------------
# Production implementations.
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubprocessSetupRunner:
    """Default :class:`SetupRunner` -- shells out to ``hermes setup``.

    Returns the child process exit code on success. Returns ``1`` (with
    a logged warning) if the ``hermes`` binary is missing from PATH so
    that callers do not crash with an unhandled :class:`FileNotFoundError`
    -- the Mordred prompt sequence still runs and the user gets a clean
    exit code rather than a stack trace.
    """

    def run(self, *, non_interactive: bool) -> int:
        cmd = ["hermes", "setup"]
        if non_interactive:
            cmd.append("--non-interactive")
        try:
            completed = subprocess.run(cmd, check=False)
        except FileNotFoundError:
            _LOG.warning("`hermes` executable not found on PATH; skipping `hermes setup` step")
            return 1
        return completed.returncode


#: ImportError guidance for every PromptToolkitIO method. Deliberately does
#: NOT suggest ``--non-interactive``: that flag installs _RefusingPromptIO,
#: which aborts on the first prompt, so it can never be a fix for a missing
#: prompt_toolkit (UX review 2026-06-11).
_PROMPT_TOOLKIT_REQUIRED = (
    "prompt_toolkit is required for interactive `hermes-mordred configure`; install it via `pip install prompt_toolkit`"
)

#: Answers accepted as "yes" at a [y/N]-style prompt. Anything else that is
#: non-empty is "no"; empty input keeps the default.
_TRUTHY_ANSWERS = frozenset({"y", "yes", "true", "1", "on"})


def _parse_bool_answer(answer: str, *, default: bool) -> bool:
    """Interpret a yes/no prompt answer robustly (UX review 2026-06-11).

    Users coming from config files type ``true`` / ``1`` / ``on``; treating
    those as "no" silently inverted their intent.
    """
    normalized = answer.strip().lower()
    if not normalized:
        return default
    return normalized in _TRUTHY_ANSWERS


def _choice_label(choice: str, descriptions: Mapping[str, str] | None) -> str:
    """Build the displayed radio label for ``choice``.

    With no description the label is just the bare value; otherwise it becomes
    ``"<choice> — <description>"`` so the explanation sits inline next to the
    button. The returned *value* of the list widget is always
    ``values[i][0]`` (the bare ``choice``), so this affects display only --
    callers and persisted answers keep the bare ``"strict"`` / ``"lenient"`` /
    ``"off"`` string.
    """
    description = (descriptions or {}).get(choice)
    return f"{choice} — {description}" if description else choice


def _choice_values(choices: Sequence[str], descriptions: Mapping[str, str] | None) -> list[tuple[str, str]]:
    """Map ``choices`` to ``(value, label)`` pairs for the radio dialog.

    The first element (the dialog's returned value) stays the bare choice; only
    the second (the displayed label) carries any inline description.
    """
    return [(c, _choice_label(c, descriptions)) for c in choices]


#: Shown beside the single-select question so keyboard users know the controls.
#: The picker renders inline (no full-screen takeover): arrows move a live
#: highlight and Enter confirms it (UX request 2026-06-15 — the prior dialog
#: jumped to the alternate screen, jarring against the inline text prompts).
_CHOICE_NAV_HINT: Final[str] = "↑/↓ move · Enter select"

#: Same idea for the multi-select list, where Space toggles rows so Enter is
#: free to confirm the whole set (UX request 2026-06-15).
_MULTICHOICE_NAV_HINT: Final[str] = "↑/↓ move · Space toggle · Enter confirm"


def _list_picker_fragments(
    *,
    title: str,
    hint: str,
    values: list[tuple[str, str]],
    multiple: bool,
    index: int,
    selected: set[str],
) -> StyleAndTextTuples:
    """Render the inline picker for the current state: a question line plus one
    row per choice. ``▸`` marks the highlighted ``index``; multi-select rows
    also show a ``◉`` / ``◯`` checkbox driven by ``selected`` (see
    :func:`_build_list_app`)."""
    fragments: StyleAndTextTuples = [
        ("class:qmark", "? "),
        ("class:question", title),
        ("", "  "),
        ("class:hint", f"({hint})"),
        ("", "\n"),
    ]
    last = len(values) - 1
    for i, (value, label) in enumerate(values):
        focused = i == index
        fragments.append(("class:pointer", " ▸ ") if focused else ("", "   "))
        if multiple:
            fragments.append(("class:mark", "◉ ") if value in selected else ("", "◯ "))
        fragments.append(("class:highlighted" if focused else "", label))
        if i != last:
            fragments.append(("", "\n"))
    return fragments


def _attach_list_bindings(
    bindings: KeyBindings,
    *,
    multiple: bool,
    option_values: list[str],
    state: dict[str, int],
    selected: set[str],
) -> None:
    """Register the inline picker's key handlers on ``bindings``.

    ``↑`` / ``↓`` move ``state['index']`` (wrapping); ``Ctrl-C`` aborts. In
    multi-select, ``Space`` toggles the highlighted row into ``selected`` and
    ``Enter`` confirms the set in display order; in single-select, ``Enter``
    confirms the highlighted row (see :func:`_build_list_app`)."""
    count = len(option_values)

    @bindings.add("up")
    def _move_up(event: KeyPressEvent) -> None:
        state["index"] = (state["index"] - 1) % count

    @bindings.add("down")
    def _move_down(event: KeyPressEvent) -> None:
        state["index"] = (state["index"] + 1) % count

    @bindings.add("c-c")
    def _abort(event: KeyPressEvent) -> None:
        # Raise rather than return a value so Ctrl-C aborts the whole flow,
        # matching the surrounding text prompts (``prompt()`` raises
        # KeyboardInterrupt on Ctrl-C). Returning the default here would instead
        # silently accept it and march on through every remaining prompt.
        event.app.exit(exception=KeyboardInterrupt)

    if multiple:

        @bindings.add(" ")
        def _toggle(event: KeyPressEvent) -> None:
            value = option_values[state["index"]]
            if value in selected:
                selected.discard(value)
            else:
                selected.add(value)

        @bindings.add("enter")
        def _confirm_multi(event: KeyPressEvent) -> None:
            event.app.exit(result=[v for v in option_values if v in selected])

    else:

        @bindings.add("enter")
        def _confirm_single(event: KeyPressEvent) -> None:
            event.app.exit(result=option_values[state["index"]])


def _build_list_app(
    *,
    title: str,
    hint: str,
    values: list[tuple[str, str]],
    multiple: bool,
    default: str | None = None,
    default_values: Sequence[str] = (),
) -> Application[Any]:
    """Build an inline list picker (radio or checkbox) as an ``Application``.

    Renders in the normal terminal scroll instead of taking over the screen:
    ``full_screen=False`` keeps the main buffer, so the picker sits directly
    under the surrounding prompts rather than flashing a separate dialog screen
    (UX request 2026-06-15 — the prior prompt_toolkit ``Dialog`` switched to the
    alternate screen, which jarred against the inline text prompts around it).

    A single :class:`FormattedTextControl` paints the question line plus one row
    per choice, with ``▸`` marking the highlighted row. Key bindings:

    * ``↑`` / ``↓`` move the highlight (wrapping at the ends);
    * single-select (``multiple=False``): ``Enter`` confirms the highlighted row;
    * multi-select (``multiple=True``): ``Space`` toggles the highlighted row and
      ``Enter`` confirms the whole set; and
    * ``Ctrl-C`` aborts (raises ``KeyboardInterrupt``, like the surrounding
      ``prompt()`` text prompts) rather than accepting the default.

    The app exits with the chosen value (single) / chosen-value list in display
    order (multi); ``Ctrl-C`` raises ``KeyboardInterrupt``.
    ``erase_when_done=True`` wipes the interactive render on exit so the caller
    can echo a one-line summary in its place (see
    :meth:`PromptToolkitIO.ask_choice`). Lazy-imports prompt_toolkit (see
    :class:`PromptToolkitIO`).
    """
    try:
        from prompt_toolkit.application import Application
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import Layout, Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.styles import Style
    except ImportError as e:
        raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e

    option_values = [value for value, _ in values]
    selected: set[str] = set(default_values)
    state = {"index": option_values.index(default) if default in option_values else 0}

    def _render() -> StyleAndTextTuples:
        return _list_picker_fragments(
            title=title,
            hint=hint,
            values=values,
            multiple=multiple,
            index=state["index"],
            selected=selected,
        )

    control = FormattedTextControl(_render, focusable=True, show_cursor=False)
    window = Window(content=control, dont_extend_height=True)

    bindings = KeyBindings()
    _attach_list_bindings(bindings, multiple=multiple, option_values=option_values, state=state, selected=selected)

    # Pink ▸/? matches the magenta selection cursor the old dialog used; the
    # terminal's own background shows through (no full-screen backdrop).
    style = Style.from_dict(
        {
            "qmark": "#ff5fd7 bold",
            "question": "bold",
            "hint": "#8a8a8a italic",
            "pointer": "#ff5fd7 bold",
            "highlighted": "bold",
            "mark": "#5fd75f",
        }
    )

    app: Application[Any] = Application(
        layout=Layout(window),
        key_bindings=bindings,
        style=style,
        mouse_support=False,
        full_screen=False,
        erase_when_done=True,
    )
    return app


def _build_choice_app(
    *, title: str, values: list[tuple[str, str]], default: str, hint: str = _CHOICE_NAV_HINT
) -> Application[str | None]:
    """Single-select inline picker (see :func:`_build_list_app`). Returns the
    chosen value; ``Ctrl-C`` raises ``KeyboardInterrupt``."""
    app: Application[str | None] = _build_list_app(
        title=title, hint=hint, values=values, multiple=False, default=default
    )
    return app


def _build_multichoice_app(
    *,
    title: str,
    values: list[tuple[str, str]],
    default_values: Sequence[str],
    hint: str = _MULTICHOICE_NAV_HINT,
) -> Application[list[str] | None]:
    """Multi-select inline picker (see :func:`_build_list_app`). Returns the
    chosen values; ``Ctrl-C`` raises ``KeyboardInterrupt``."""
    app: Application[list[str] | None] = _build_list_app(
        title=title, hint=hint, values=values, multiple=True, default_values=default_values
    )
    return app


def _echo_selection(label: str, value: str) -> None:
    """Print the ``? <label>  <value>`` record left behind after an inline
    picker erases itself (see :func:`_build_list_app`).

    The picker runs with ``erase_when_done=True`` so its multi-line render
    vanishes on exit; echoing this one line keeps a scrolled-back transcript
    showing what was answered, mirroring the ``questionary`` convention and the
    inline text prompts' own echoes. Lazy-imports prompt_toolkit for styled
    output, matching the rest of :class:`PromptToolkitIO`.
    """
    try:
        from prompt_toolkit import print_formatted_text
        from prompt_toolkit.formatted_text import FormattedText
        from prompt_toolkit.styles import Style
    except ImportError as e:
        raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e

    print_formatted_text(
        FormattedText(
            [
                ("class:qmark", "? "),
                ("class:question", label),
                ("", "  "),
                ("class:answer", value),
            ]
        ),
        style=Style.from_dict({"qmark": "#ff5fd7 bold", "question": "bold", "answer": "#5fd75f"}),
    )


def _emit_prompt_help(description: str) -> None:
    """Print a text prompt's help line once, on its own line above the prompt.

    The help text is emitted here — before ``prompt()`` is invoked — rather than
    folded into the ``prompt()`` message as a leading ``f"{description}\\n"`` line.
    prompt_toolkit repaints its prompt message when the line is accepted, and a
    multi-line message is repainted in full, so the help text appeared twice in
    the scrollback. Keeping the ``prompt()`` message single-line and printing the
    help separately renders it exactly once (UX request 2026-06-16). ``flush``
    guarantees it lands before ``prompt()`` takes over the terminal.
    """
    print(description, flush=True)


class PromptToolkitIO:
    """Default :class:`PromptIO` -- thin wrapper around ``prompt_toolkit``.

    Lazy-imports prompt_toolkit so that the test impl never has to install
    it. Single- and multi-select prompts use the custom dialog builders
    (:func:`_build_choice_app` / :func:`_build_multichoice_app`) instead of
    prompt_toolkit's ``radiolist_dialog`` / ``checkboxlist_dialog`` shortcuts,
    gaining keyboard-confirm affordances and dropping the blue backdrop while
    still rendering well in SSH / Docker / TTY-without-tput environments.
    """

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        app = _build_choice_app(
            title=label,
            values=_choice_values(choices, descriptions),
            default=default,
            hint=_CHOICE_NAV_HINT,
        )
        result: str | None = app.run()
        chosen = result if result is not None else default
        # The picker erased itself on exit; echo the resolved choice so the
        # transcript records what was picked (see :func:`_echo_selection`).
        _echo_selection(label, chosen)
        return chosen

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = f" [{default}]" if default else ""
        # An optional help line prints above the question (mirrors ``ask_bool`` /
        # ``ask_choice``) so the label stays short while still explaining the
        # setting. It is emitted separately rather than folded into the prompt()
        # message: a multi-line prompt is repainted in full on accept, which
        # doubled the help text in the scrollback (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        answer = prompt(f"{label}{suffix}: ")
        return answer.strip() or default

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = "[Y/n]" if default else "[y/N]"
        # Optional help line above the [y/N] question, printed separately so the
        # prompt stays single-line (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        return _parse_bool_answer(prompt(f"{label} {suffix}: "), default=default)

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        """Inline multi-select picker.

        Returns the chosen subset (empty tuple if the user selects nothing).
        Arrows move the highlight, Space toggles the highlighted row, and Enter
        confirms the whole set (see :func:`_build_list_app`). Replaces the old
        free-text comma-separated entry so users pick from known providers
        instead of guessing names (UX request 2026-06-14).
        """
        app = _build_multichoice_app(
            title=label,
            values=_choice_values(choices, None),
            default_values=default,
        )
        result: list[str] | None = app.run()
        chosen = tuple(result) if result is not None else ()
        _echo_selection(label, ", ".join(chosen) if chosen else "(none)")
        return chosen

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        """Read a secret with shell-history-safe echoing.

        ``is_password=True`` masks the input. Empty input → ``default`` so
        a user who already has the secret set elsewhere can decline to
        re-enter it. An optional ``description`` prints as a help line above
        the prompt (mirrors ``ask_text`` / ``ask_bool``); ``is_password`` masks
        only the typed secret, never the help text or the label.
        """
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        # Help line printed separately so the masked prompt stays single-line
        # (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        answer = prompt(f"{label}: ", is_password=True)
        return answer.strip() or default


# -----------------------------------------------------------------------------
# NonInteractive guard -- rejects prompts in CI / scripted use.
# -----------------------------------------------------------------------------


class NonInteractiveAbort(RuntimeError):
    """Raised when --non-interactive is set and a prompt would be required."""


@dataclass(frozen=True, slots=True)
class _RefusingPromptIO:
    """:class:`PromptIO` impl used when ``--non-interactive`` is set.

    Every method raises :class:`NonInteractiveAbort` -- the only way through
    an interactive flow is for every value to be pre-specified, which the
    prompt-driven commands do not yet support.
    """

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")


# -----------------------------------------------------------------------------
# Mordred-specific prompt sequence + run().
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    """Resolved answers from the prompt sequence."""

    snapshot: PolicySnapshot


def collect_answers(prompt_io: PromptIO) -> ConfigureResult:
    """Run the Mordred prompt sequence.

    Order matters -- snapshot tests assert on the label / default sequence.
    Network-privacy prompts are NOT collected here; run
    ``hermes-mordred network init`` to set up Tor / VPN / Mullvad on demand.
    """
    policy = prompt_io.ask_choice(
        label="Mordred policy mode",
        choices=("strict", "lenient", "off"),
        default="lenient",
        descriptions=_POLICY_MODE_DESCRIPTIONS,
    )
    allow_cloud_llm = prompt_io.ask_bool(
        label="Allow cloud LLM providers?",
        default=False,
        description=_CLOUD_LLM_PROMPT_DESCRIPTION,
    )
    # Only ask *which* providers to permit when cloud is actually allowed. An
    # allowlist is meaningless under "no cloud", and it has no effect at all
    # outside strict mode (see ``llm_guard.enforce``), so skipping it keeps the
    # common local-only flow short (UX request 2026-06-14). The choices come
    # from a checkbox so users pick known provider ids instead of typing them.
    if allow_cloud_llm:
        cloud_provider_allowlist = prompt_io.ask_multi(
            label="Cloud provider allowlist (select which providers to permit)",
            choices=_SELECTABLE_CLOUD_PROVIDERS,
            default=(),
        )
    else:
        cloud_provider_allowlist = ()

    local_llm_endpoint = prompt_io.ask_text(
        label="Local LLM endpoint URL",
        default="http://localhost:1234/v1",
    )
    local_llm_model_id = prompt_io.ask_text(
        label="Local LLM model id",
        default="",
    )
    cloud_attempt_action_raw = prompt_io.ask_choice(
        label="On cloud LLM attempt under strict mode",
        choices=("always-block", "prompt-once"),
        default="always-block",
        descriptions=_CLOUD_ATTEMPT_DESCRIPTIONS,
    )
    cloud_attempt_action = _coerce_cloud_attempt_action(cloud_attempt_action_raw)

    # The declared harness controls strict-mode abort behaviour in
    # ``mordred_llm_guard.harness_detect``. ``"none"`` is the safe default --
    # it doesn't match any harness pattern so existing users don't lose the
    # session. The known choices mirror the regex allowlist in
    # ``harness_detect._HARNESS_PATTERNS``.
    harness_primary = prompt_io.ask_choice(
        label="Agent harness (strict mode refuses if a known harness is detected)",
        choices=("none", "codex", "claude-cli", "cursor", "acp-claude", "acp-cline"),
        default="none",
    )

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=cloud_provider_allowlist,
        local_llm_endpoint=local_llm_endpoint,
        local_llm_model_id=local_llm_model_id,
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=harness_primary,
        # strict → disable IPv6 by default (mirrors the network reader's
        # ``_resolve_disable_ipv6``: strict → True, lenient/off → False).
        disable_ipv6=(policy == "strict"),
    )
    return ConfigureResult(snapshot=snapshot)


def _coerce_cloud_attempt_action(raw: str) -> Literal["always-block", "prompt-once"]:
    """Narrow ``ask_choice``'s ``str`` return to the snapshot Literal.

    The prompt only offers two choices so this never raises in production;
    the explicit check protects against test doubles that script invalid
    answers and satisfies mypy --strict at the construction site.
    """
    if raw == "always-block":
        return "always-block"
    if raw == "prompt-once":
        return "prompt-once"
    raise ValueError(f"invalid cloud_attempt_action: {raw!r}")


def run(
    *,
    setup_runner: SetupRunner,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    non_interactive: bool = False,
    skip_hermes_setup: bool = False,
) -> ConfigureResult:
    """Top-level configure entry point.

    Args:
        setup_runner: Spawns ``hermes setup``. Production = :class:`SubprocessSetupRunner`.
        prompt_io: Collects Mordred answers. Tests inject a scripted double.
        policy_writer: Persists the resolved snapshot (policy.json +
            ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``).
            The ``plugins.mordred_network`` section is intentionally left alone
            -- it is owned by ``hermes-mordred network init``.
        non_interactive: Forwarded to :class:`SetupRunner`. Mordred prompts
            still run -- pass a :class:`_RefusingPromptIO` to abort on any
            prompt requirement.
        skip_hermes_setup: Tests use this to avoid spawning ``hermes setup``
            entirely. Production should leave it ``False``.

    Returns:
        :class:`ConfigureResult` holding the resolved :class:`PolicySnapshot`.
    """
    if not skip_hermes_setup:
        rc = setup_runner.run(non_interactive=non_interactive)
        if rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred prompts anyway", rc)

    result = collect_answers(prompt_io)
    policy_writer.write(result.snapshot)
    return result


def _render_configure_summary(snapshot: PolicySnapshot) -> str:
    """A structured recap printed after a successful ``configure``.

    Shown once all prompts complete (so it survives the full-screen
    dialog prompts, which clear the terminal). Echoes the
    resolved choices and points the user at the on-demand network-privacy
    command, which first-run setup deliberately does not cover.
    """
    cloud = "yes" if snapshot.allow_cloud_llm else "no"
    return "\n".join(
        [
            "",
            "Mordred configured:",
            f"  policy mode       : {snapshot.policy}",
            f"  cloud LLM allowed : {cloud}",
            f"  agent harness     : {snapshot.harness_primary}",
            "",
            "Next: run `hermes-mordred network init` to set up network privacy (Tor / VPN / clearnet).",
        ]
    )


# -----------------------------------------------------------------------------
# Non-interactive (flag-driven) configure — mirrors network init's
# ``network_answers_from_args``: unspecified flags fall back to the existing
# on-disk settings, then to the same defaults the prompts use, so a re-run
# never clobbers prior answers (UX review 2026-06-11 Phase 4).
# -----------------------------------------------------------------------------


def _read_existing_policy_inputs(policy_writer: PolicyWriter) -> dict[str, object]:
    """Best-effort read of the current settings for non-interactive seeding.

    policy.json carries every snapshot field except ``harness_primary``,
    which lives in config.yaml under ``plugins.mordred_llm_guard`` (the
    same split the writers maintain). Any read/parse error collapses to
    ``{}`` — the flags then fall back to the prompt defaults.
    """
    import json

    existing: dict[str, object] = {}
    try:
        body = json.loads(policy_writer.policy_json_path.read_text(encoding="utf-8"))
        if isinstance(body, dict):
            existing.update(body)
    except (OSError, ValueError):
        pass

    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        with policy_writer.config_path.open(encoding="utf-8") as f:
            data = YAML(typ="safe", pure=True).load(f)
        plugins = data.get("plugins") if isinstance(data, dict) else None
        guard = plugins.get("mordred_llm_guard") if isinstance(plugins, dict) else None
        if isinstance(guard, dict) and isinstance(guard.get("harness_primary"), str):
            existing["harness_primary"] = guard["harness_primary"]
    except (OSError, ValueError, YAMLError):
        pass  # any unreadable config falls back to defaults
    return existing


def snapshot_from_args(
    args: argparse.Namespace,
    *,
    existing: Mapping[str, Any] | None = None,
) -> ConfigureResult:
    """Build a :class:`PolicySnapshot` from CLI flags (no prompts).

    Precedence per field: explicit flag > existing on-disk value > the
    default the interactive prompt would offer. ``disable_ipv6`` mirrors
    :func:`collect_answers`: derived from the resolved policy mode.
    """
    existing = existing or {}

    def _seeded(flag: str, existing_key: str, fallback: object) -> object:
        value = getattr(args, flag, None)
        if value is not None:
            return value
        value = existing.get(existing_key)
        return value if value is not None else fallback

    # Existing values come from a hand-editable policy.json — sanitize the
    # closed-set fields back to their defaults instead of crashing the
    # non-interactive path on a corrupt or downgraded file (review 2026-06-12).
    policy = str(_seeded("policy", "policy", "lenient"))
    if policy not in ("strict", "lenient", "off"):
        policy = "lenient"
    # M2 (security review 2026-06-11): only a real bool may enable —
    # ``bool(...)`` truthy-coerced a hand-edited ``"allow_cloud_llm": "false"``
    # into a written ``allow_cloud_llm: true``.
    raw_allow_cloud = _seeded("allow_cloud_llm", "allow_cloud_llm", False)
    allow_cloud_llm = raw_allow_cloud if isinstance(raw_allow_cloud, bool) else False
    raw_allowlist = _seeded("cloud_allowlist", "cloud_provider_allowlist", ())
    if isinstance(raw_allowlist, str):
        allowlist = tuple(p.strip() for p in raw_allowlist.split(",") if p.strip())
    elif isinstance(raw_allowlist, (list, tuple)):
        allowlist = tuple(str(p) for p in raw_allowlist)
    else:
        allowlist = ()
    raw_action = str(_seeded("cloud_attempt_action", "cloud_attempt_action", "always-block"))
    if raw_action not in ("always-block", "prompt-once"):
        raw_action = "always-block"
    cloud_attempt_action = _coerce_cloud_attempt_action(raw_action)

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=allowlist,
        local_llm_endpoint=str(_seeded("local_llm_endpoint", "local_llm_endpoint", "http://localhost:1234/v1")),
        local_llm_model_id=str(_seeded("local_llm_model_id", "local_llm_model_id", "")),
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=str(_seeded("harness", "harness_primary", "none")),
        disable_ipv6=(policy == "strict"),
    )
    return ConfigureResult(snapshot=snapshot)


def cli_handler(args: argparse.Namespace) -> int:
    """Adapter from argparse Namespace to :func:`run`. Wired in cli.py.

    Production behavior:
    - ``--non-interactive``: flag-driven, no prompts — answers come from the
      CLI flags, seeded from the existing policy.json / config.yaml (so a
      bare re-run keeps prior settings).
    - Otherwise: real :class:`SubprocessSetupRunner` + :class:`PromptToolkitIO`,
      then a hint pointing the user at the on-demand network-privacy command.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    if non_interactive:
        setup_rc = SubprocessSetupRunner().run(non_interactive=True)
        if setup_rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred flags anyway", setup_rc)
        writer = PolicyWriter()
        result = snapshot_from_args(args, existing=_read_existing_policy_inputs(writer))
        try:
            writer.write(result.snapshot)
        except OSError as e:
            print(f"hermes-mordred configure: failed to write policy: {e}", file=sys.stderr)
            return 1
        print(_render_configure_summary(result.snapshot))
        return 0

    result = run(
        setup_runner=SubprocessSetupRunner(),
        prompt_io=PromptToolkitIO(),
        policy_writer=PolicyWriter(),
        non_interactive=False,
    )
    print(_render_configure_summary(result.snapshot))
    return 0
