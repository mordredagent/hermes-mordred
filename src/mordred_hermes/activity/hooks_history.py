"""Hermes hooks that bring the browser history to the model at the moment it helps.

- ``transform_tool_result``: after a successful ``browser_navigate`` — and a
  ``browser_snapshot`` or ``browser_back`` whose page host differs from the
  last host this session saw — the site's recent episodes are added to the
  JSON result under :data:`RESULT_KEY`. Hermes then wraps the whole result as
  untrusted data (``<untrusted_tool_result source="browser_…">``), so page
  titles may appear in this block; page text and typed text never do.
- ``pre_llm_call``: when the user message names a host or URL, or shares task
  terms with recent episodes, ``{"context": block}`` is returned. Hermes
  appends it to the API copy of the user message and persists it with the
  turn, outside the untrusted wrapper, so this block holds only human-authored
  text (task boundaries, corrections) and metadata (site, route path,
  outcome, time).

Both hooks read configuration on every call (cached by file modification
time), so ``history_enabled`` and the per-surface switches apply from the next
call. Both fail open and fast: a refused or unavailable store, a malformed
result or any other ``Exception`` leaves the result or the turn unchanged,
and a store problem is audited once per process and code. Episodes already
shown to a session are not repeated until they change, and the injected
characters of a session are capped (:data:`._history_access.BUDGET`).
"""

from __future__ import annotations

import collections
import json
import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from .config import ActivityConfig
    from .history import EpisodeSummary, Matches
    from .store import ActivityStore

__all__ = [
    "NAVIGATION_TOOLS",
    "RESULT_KEY",
    "pre_llm_call",
    "register_hooks",
    "transform_tool_result",
]

_LOG = logging.getLogger(__name__)

#: The JSON key under which the site block joins a browser tool result.
RESULT_KEY: Final = "mordred_browser_history"
#: Tools whose successful result names the page that is now open.
NAVIGATION_TOOLS: Final = frozenset({"browser_navigate", "browser_snapshot", "browser_back"})
#: A block smaller than this is not worth injecting (header, one episode line and the footer); the session
#: budget is treated as spent and the store is not read.
MIN_BLOCK_CHARS: Final = 200
#: Only this much of a user message is scanned for hosts and terms.
MAX_MESSAGE_CHARS: Final = 4000
#: Browser results larger than this are passed through untouched (never parsed).
MAX_RESULT_CHARS: Final = 1_000_000
_DAY: Final = 86400.0
_MAX_SESSIONS: Final = 256

_hosts_lock = threading.Lock()
#: The page host each session last saw through a browser tool result (bounded, oldest forgotten).
_last_hosts: collections.OrderedDict[str, str] = collections.OrderedDict()


def _host_changed(key: str, host: str) -> bool:
    with _hosts_lock:
        previous = _last_hosts.get(key)
        _last_hosts[key] = host
        _last_hosts.move_to_end(key)
        while len(_last_hosts) > _MAX_SESSIONS:
            _last_hosts.popitem(last=False)
    return previous != host


def _json_object(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, str) or len(result) > MAX_RESULT_CHARS:
        return None
    try:
        payload = json.loads(result)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _page_url(tool_name: str, args: Any, payload: dict[str, Any]) -> Any:
    """The page URL a successful browser result reports (the CDP frame tree for a snapshot)."""
    url = payload.get("url")
    if url:
        return url
    if tool_name == "browser_navigate" and isinstance(args, dict):
        return args.get("url")
    frames = payload.get("frame_tree")
    top = frames.get("top") if isinstance(frames, dict) else None
    return top.get("url") if isinstance(top, dict) else None


def _room(config: ActivityConfig, key: str) -> tuple[int, frozenset[tuple[str, int]]]:
    from ._history_access import BUDGET

    spent, shown = BUDGET.snapshot(key)
    room = min(config.history_max_chars, config.history_session_budget_chars - spent)
    return (room if room >= MIN_BLOCK_CHARS else 0), shown


def _charge(key: str, block: str, shown: tuple[EpisodeSummary, ...]) -> None:
    from ._history_access import BUDGET

    BUDGET.charge(key, len(block), [episode.key for episode in shown])


# --------------------------------------------------------------------------- #
# transform_tool_result
# --------------------------------------------------------------------------- #


def _site_block(home: Path, config: ActivityConfig, host: str, key: str) -> str | None:
    from . import _history_access as access
    from . import history

    room, shown = _room(config, key)
    if not room:
        return None
    try:
        store = access.reader(home)
        matches = history.episodes_for_site(
            store,
            host,
            excluded_sites=config.excluded_sites,
            since=time.time() - config.history_lookback_days * _DAY,
            limit=config.history_max_episodes,
            shown=shown,
            subdomains=False,  # this host only (``www.`` ignored): no public-suffix guesswork
        )
    except access.NoHistory:
        return None
    except Exception as exc:
        access.unavailable(home, exc)
        return None
    header = history.NAVIGATION_HEADER.format(site=history.clean(host, 120))
    block, included = history.render_block(
        header, matches.episodes, max_chars=room, more=matches.more, titles=True, focus_site=host
    )
    if not included:
        return None
    _charge(key, block, included)
    return block


def _navigation_result(tool_name: str, args: Any, result: Any, session_id: Any, task_id: Any) -> str | None:
    from . import _history_access as access
    from .contracts import site_excluded
    from .history import host_of

    home = access.home()
    config = access.config(home)
    if not (config.history_active and config.history_on_navigate):
        return None
    payload = _json_object(result)
    if payload is None or payload.get("success") is not True or RESULT_KEY in payload:
        return None
    host = host_of(_page_url(tool_name, args, payload))
    if host is None:
        return None
    key = access.session_key(session_id, task_id)
    if not _host_changed(key, host) and tool_name != "browser_navigate":
        return None
    if site_excluded(host, config.excluded_sites):
        return None
    block = _site_block(home, config, host, key)
    if not block:
        return None
    payload[RESULT_KEY] = block
    return json.dumps(payload, ensure_ascii=False)


def transform_tool_result(
    tool_name: Any = None,
    args: Any = None,
    result: Any = None,
    session_id: Any = None,
    task_id: Any = None,
    **_kwargs: Any,
) -> str | None:
    """Return the browser result with the site's history added, or ``None`` to leave it unchanged."""
    try:
        if not isinstance(tool_name, str) or tool_name not in NAVIGATION_TOOLS:
            return None
        return _navigation_result(tool_name, args, result, session_id, task_id)
    except Exception as exc:  # never break a tool result
        _LOG.debug("mordred activity history: navigation block skipped (%s)", type(exc).__name__)
        return None


# --------------------------------------------------------------------------- #
# pre_llm_call
# --------------------------------------------------------------------------- #


def _turn_matches(
    store: ActivityStore, config: ActivityConfig, text: str, shown: frozenset[tuple[str, int]]
) -> Matches:
    """Episodes with human-authored text on the hosts the message names, then episodes whose task or
    correction text shares its terms; newest first.

    Episodes without a task boundary or correction text never qualify, and host labels are not matched:
    the turn-start block must stand on what the user wrote.
    """
    from . import history
    from .matching import terms

    since = time.time() - config.history_lookback_days * _DAY
    limit = config.history_max_episodes
    by_host = history.episodes_for_sites(
        store,
        history.hosts_in(text),
        excluded_sites=config.excluded_sites,
        since=since,
        limit=limit,
        shown=shown,
        require_human_text=True,
    )
    found = {episode.episode_id: episode for episode in by_host.episodes}
    more = by_host.more
    wanted = terms(text)
    if len(found) < limit and wanted:
        by_terms = history.episodes_for_terms(
            store,
            wanted,
            excluded_sites=config.excluded_sites,
            since=since,
            limit=limit - len(found),
            min_shared=min(2, len(wanted)),
            host_labels=False,
            shown=shown | {episode.key for episode in found.values()},
        )
        found.update((episode.episode_id, episode) for episode in by_terms.episodes)
        more = max(more, by_terms.more)  # the two counts overlap; report the larger, never their sum
    episodes = sorted(found.values(), key=lambda episode: -episode.last_event_at)
    return history.Matches(tuple(episodes), more)


def _turn_block(user_message: Any, session_id: Any, task_id: Any) -> str | None:
    from . import _history_access as access
    from . import history

    if not isinstance(user_message, str) or not user_message.strip():
        return None  # Hermes drops plugin context on multimodal turns anyway
    home = access.home()
    config = access.config(home)
    if not (config.history_active and config.history_turn_context):
        return None
    key = access.session_key(session_id, task_id)
    room, shown = _room(config, key)
    if not room:
        return None
    try:
        store = access.reader(home)
        matches = _turn_matches(store, config, user_message[:MAX_MESSAGE_CHARS], shown)
    except access.NoHistory:
        return None
    except Exception as exc:
        access.unavailable(home, exc)
        return None
    block, included = history.render_block(
        history.TURN_HEADER, matches.episodes, max_chars=room, more=matches.more, titles=False
    )
    if not included:
        return None
    _charge(key, block, included)
    return block


def pre_llm_call(user_message: Any = None, session_id: Any = None, task_id: Any = None, **_kwargs: Any) -> Any:
    """``{"context": block}`` with relevant human-authored history, or ``None``; never raises ``Exception``."""
    try:
        block = _turn_block(user_message, session_id, task_id)
    except Exception as exc:  # a history problem must never abort the turn
        _LOG.debug("mordred activity history: turn context skipped (%s)", type(exc).__name__)
        return None
    return {"context": block} if block else None


def register_hooks(ctx: Any) -> None:
    """Register both hooks; registration never reads configuration or opens the store."""
    ctx.register_hook("transform_tool_result", transform_tool_result)
    ctx.register_hook("pre_llm_call", pre_llm_call)
