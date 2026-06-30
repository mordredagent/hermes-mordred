"""Shared interactive prompt surface for the ``hermes-mordred`` wizard.

This module owns the dependency-light prompt-IO primitives that several wizard
commands reuse:

* :class:`PromptIO` -- the Protocol every prompt-driven command accepts so tests
  can inject a scripted FIFO double instead of touching a real TTY. It is the
  shared seam imported by ``configure``, ``network_cli``, ``keyvault_cli``,
  ``vault_cli``, ``config_decrypt_cli``, ``env_decrypt_cli`` and ``memory_cli``.
* The inline ``prompt_toolkit`` picker engine (:func:`_build_choice_app` /
  :func:`_build_multichoice_app` and their helpers) plus the small text helpers
  (:func:`_parse_bool_answer`, :func:`_echo_selection`, :func:`_emit_prompt_help`).
* :class:`_RefusingPromptIO` / :class:`NonInteractiveAbort` -- the
  ``--non-interactive`` guard that aborts rather than block on a prompt.

The production :class:`PromptIO` implementation, ``PromptToolkitIO``, lives in
:mod:`mordred_hermes.wizard.configure` (it is constructed and monkeypatched
through that module's namespace), but it is a thin wrapper that calls the picker
builders defined here. ``prompt_toolkit`` itself is imported lazily inside each
function so the scripted test double never needs it installed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:
    from prompt_toolkit.application import Application
    from prompt_toolkit.formatted_text import StyleAndTextTuples
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.key_processor import KeyPressEvent


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
