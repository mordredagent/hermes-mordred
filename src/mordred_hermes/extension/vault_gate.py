"""Whether ``extension serve``'s vault is open, and opening it when the user asks.

The vault holds the server's ``.env`` secrets and the browser trust state (the
approval keys and revocations), so no browser can be admitted while it is
closed. Opening it unwraps its master key, which asks for Touch ID. The server
used to open it before binding and exit when the prompt went unanswered (a
two-minute helper timeout), so a Mac left alone at start had no server at all.

Now the server binds first and opens the vault in the background
(:meth:`VaultGate.open_at_start`). Until it is open:

- a browser's hello is answered ``auth_fail: vault_locked`` at once, without a
  prompt, so an extension retrying on its own never raises Touch ID;
- a hello that asks for it (``"unlock": true``, sent only after the user pressed
  the extension's unlock button) tries again, one prompt at a time
  (:meth:`VaultGate.unlock`).

Only an unanswered or refused prompt (:class:`~..keyvault._exceptions.WrapAuthCancelled`)
leaves the vault closed and the server running. Any other failure — a tampered
vault, a missing anchor, an unreadable ``.env`` — is still fatal: the server
stops, as it did when the check ran before binding.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Final, Literal

_log = logging.getLogger(__name__)

State = Literal["open", "locked"]

#: ``auth_fail`` reason while the vault is closed.
LOCKED_REASON: Final = "vault_locked"


class VaultFatal(Exception):
    """The vault is present but cannot be trusted; the server must not keep running."""


class VaultGate:
    """One process's vault: open or locked, opened at most one prompt at a time.

    ``opener`` opens the vault and injects its ``.env`` (returns the number of
    variables; ``0`` when there is no vault). It raises ``WrapAuthCancelled``
    when the prompt is refused or times out; anything else it raises is fatal.
    """

    def __init__(self, opener: Callable[[], int]) -> None:
        self._opener = opener
        self._state: State = "locked"
        self._lock = threading.Lock()
        self._listeners: list[Callable[[], None]] = []
        self._fatal = False
        self._fatal_listeners: list[Callable[[], None]] = []

    @property
    def state(self) -> State:
        return self._state

    def is_open(self) -> bool:
        return self._state == "open"

    def on_open(self, listener: Callable[[], None]) -> None:
        """Call ``listener`` once the vault is open (now, if it already is)."""
        with self._lock:
            if self._state != "open":
                self._listeners.append(listener)
                return
        listener()

    def on_fatal(self, listener: Callable[[], None]) -> None:
        """Call ``listener`` (from any thread) when the vault turns out not to be trustworthy."""
        self._fatal_listeners.append(listener)

    def unlock(self) -> State:
        """Open the vault unless it is open; a second caller waits for the first prompt.

        Raises :class:`VaultFatal` for a vault that cannot be trusted.
        """
        from ..keyvault._exceptions import WrapAuthCancelled

        with self._lock:
            if self._state == "open":
                return "open"
            if self._fatal:
                raise VaultFatal("refused earlier")
            try:
                self._opener()
            except WrapAuthCancelled:
                _log.info("vault not opened: the Touch ID prompt was refused or not answered")
                return "locked"
            except Exception as exc:
                # The cause can name vault paths or native details; keep the log content-free.
                self._fatal = True
                for listener in self._fatal_listeners:
                    listener()
                raise VaultFatal(type(exc).__name__) from exc
            self._state = "open"
            listeners, self._listeners = self._listeners, []
        _log.info("vault open")
        for listener in listeners:
            try:
                listener()
            except Exception:
                _log.exception("vault open listener failed")
        return "open"

    def open_at_start(self) -> State:
        """The start-up attempt: one prompt, as before binding used to ask."""
        state = self.unlock()
        if state == "locked":
            _log.warning(
                "serving with the vault locked; browsers are admitted after it is opened "
                "(the extension's unlock button asks for Touch ID again)"
            )
        return state


def always_open() -> VaultGate:
    """A gate for a server whose secrets were provided another way (the Hermes plugin path, tests)."""
    gate = VaultGate(lambda: 0)
    gate.unlock()
    return gate
