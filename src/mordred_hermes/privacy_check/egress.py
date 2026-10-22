"""Tool-egress levels: stop the agent from sending data out through its tools.

Whatever LLM the agent runs on — a private Venice model, a local model — a
prompt-injected or runaway agent can still leak data by *calling tools* that
reach the internet (fetch a URL with data in the query string, run ``curl``,
post to a webhook, generate an image from a prompt, schedule a delivery...).
This module decides, before every tool call, whether the call may reach the
internet at the configured level:

=============  ================================================================
``lockdown``   No internet from tools. Local tools and Mordred's own Telegram
               tools (fixed Venice/loopback destination) only.
``search``     ``lockdown`` + ``web_search``. No URL fetching,
               browsing, remote APIs, or arbitrary commands.
``ask``        (default) Tools work. ``web_search`` and local work run as
               usual; every other call that may reach the internet (URL
               fetch, browser, remote API, a command that uses the network,
               an unknown tool) asks the user first through Hermes's approval
               prompt, showing where it goes and what it sends. Blocklisted
               domains and bare IP addresses are refused outright.
``blocklist``  Everything except blocklisted domains and tools; URL
               arguments are checked against the domain blocklist.
``off``        Mordred does not restrict tools.
=============  ================================================================

Rules that hold at every restricted level:

- **Fail closed on what cannot be inspected.** ``terminal`` / ``execute_code``
  / browser scripting run free-form code whose destination cannot be parsed
  reliably, so under ``lockdown`` and ``search`` only exact first-party
  read-only commands (``hermes-mordred telegram doctor`` ...) may run. A tool
  this module does not know is treated as internet-capable.
- **Taint.** Once a session has read private data (the Telegram tools), that
  session is raised to ``lockdown`` for the rest of its life: a search query
  is an exfiltration channel too. Delegation is refused for a tainted session
  because a child agent would start untainted, and tools that write plaintext
  to disk (files, skills, memory, kanban) are refused so private data stays in
  memory only.

**Reader mode** holds at every level, ``off`` included. Once a session has
read imported private history (:data:`READER_TOOLS`), text from that history
must never trigger an action: only the read-only tools in
:data:`READER_ALLOWED` keep running (under the level's normal rules), web
access (:data:`READER_WEB_TOOLS`) always asks the user, and every other tool
(writes, commands, messaging, scheduling, delegation, payments, MCP tools,
unknown tools) is refused until a new session. The pre-tool hook records the
session durably (:mod:`._reader_sessions`) before the first read runs, so a
restarted Hermes keeps the restriction; a reader tool without a session id,
or whose record cannot be written, is refused.

Configuration (``config.yaml``)::

    plugins:
      mordred_privacy_check:
        tool_egress:
          level: search            # lockdown | search | blocklist | off
          blocklist: [pastebin.com]  # extra domains for level "blocklist"
          blocked_tools: []        # extra tool names blocked below "off"
          taint: true              # lockdown after private data is read

A missing section means ``search``; an unreadable or invalid one fails closed
to ``lockdown``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from ._audit_reasons import EgressRule

_platform = os.name

LEVELS = ("lockdown", "search", "ask", "blocklist", "off")
DEFAULT_LEVEL = "ask"
_RANK = {"off": 0, "blocklist": 1, "ask": 2, "search": 3, "lockdown": 4}

# Tools that never leave this machine.
LOCAL_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "patch",
        "search_files",
        "todo",
        "todo_list",
        "clarify",
        "skills_list",
        "skill_view",
        "skill_manage",
        "memory",
        "session_search",
        "tool_search",
        "tool_describe",
        "process_manage",
        # Hermes Desktop UI: arranges and reads the local app only.
        "annotate_preview",
        "apply_layout",
        "close_terminal",
        "focus_pane",
        "gui_tour",
        "read_terminal",
        "read_window_below",
        "show_tip",
        "react_to_message",
        "desktop_project",
    }
)
# Tools that read imported private history (Telegram, the imported-message
# store) into the session. Calling one puts the session into reader mode.
READER_TOOLS = frozenset({"telegram_ask", "telegram_chats", "mordred_history_search"})
# Mordred's own tools: the destination is fixed in code (Venice, loopback or
# the local store).
FIRST_PARTY_TOOLS = READER_TOOLS
# Reading any of these puts private data into the session (taint source).
TAINT_SOURCES = READER_TOOLS
SEARCH_TOOLS = frozenset({"web_search"})
# Tools that write to disk in plaintext. A tainted session may not use them:
# imported private data must exist in plaintext only in memory.
PERSIST_TOOLS = frozenset({"write_file", "patch", "skill_manage", "memory"})
_READ_ONLY_KANBAN = frozenset({"kanban_list", "kanban_show", "kanban_attachments"})
# Tool → argument names holding URLs that the tool will fetch.
URL_ARGS: dict[str, tuple[str, ...]] = {
    "web_extract": ("urls", "url"),
    "browser_navigate": ("url",),
    "vision_analyze": ("image_url",),
    "video_analyze": ("video_url",),
    "video_generate": ("image_url", "reference_image_urls"),
    "kanban_attach_url": ("url",),
    "a2a_discover": ("url",),
    "a2a_call": ("agent", "url"),
    "desktop_preview": ("url",),
}
# Free-form code: destinations cannot be inspected.
EXEC_TOOLS = frozenset({"terminal", "execute_code", "browser_console", "browser_exec", "browser_cdp"})
# Reader mode: tools that only read or plan locally and so may keep running
# once the session has read imported history.
READER_ALLOWED = READER_TOOLS | frozenset(
    {
        "read_file",
        "search_files",
        "session_search",
        "skill_view",
        "skills_list",
        "tool_search",
        "tool_describe",
        "todo",
        "todo_list",
        "clarify",
    }
)
# URL-carrying tools that act rather than fetch (generate, attach, call an agent).
_URL_ACTION_TOOLS = frozenset({"video_generate", "kanban_attach_url", "a2a_call"})
# Reader mode: tools that search or load a web address. They always ask the
# user in a reader session (a query or URL can carry imported text out).
READER_WEB_TOOLS = (
    SEARCH_TOOLS | (frozenset(URL_ARGS) - _URL_ACTION_TOOLS) | frozenset({"fetch_url", "fetch", "browser_back"})
)
# Hermes's Tool Search bridge: deferred tools (Mordred's Telegram tools among
# them) are invoked as `tool_call {calls: [{name, arguments}]}`, and the agent
# loop fires pre_tool_call with the bridge name. Decide on the tools inside.
BRIDGE_CALL_TOOL = "tool_call"
_LOCAL_PREFIXES = ("kanban_",)
_LOCAL_EXCEPTIONS = frozenset({"kanban_attach_url"})

# Commands the agent may run under lockdown/search: Mordred's own read-only
# status commands, exact shape, no shell metacharacters.
_FIRST_PARTY_COMMAND = re.compile(
    r"\s*(?:\S*/)?hermes-mordred\s+"
    r"(?:status|policy\s+show|network\s+status|egress\s+status|telegram\s+(?:doctor|status))"
    r"(?:\s+--json)?\s*"
)
_SHELL_META = re.compile(r"[;&|`$<>\n\\(){}]")

DEFAULT_BLOCKLIST = (
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.co",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "interact.sh",
    "oast.fun",
    "burpcollaborator.net",
    "discord.com/api/webhooks",
    "hooks.slack.com",
)


@dataclass(frozen=True)
class EgressPolicy:
    level: str = DEFAULT_LEVEL
    blocklist: tuple[str, ...] = DEFAULT_BLOCKLIST
    blocked_tools: frozenset[str] = frozenset()
    taint: bool = True
    lockdown_after_private_data: bool = False


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: EgressRule | Literal[""] = ""
    message: str = ""
    taints: bool = False
    #: Ask the user (Hermes's approval prompt) instead of deciding here.
    approve: bool = False
    rule_key: str = ""
    #: The call runs a reader tool: the caller must durably record the
    #: session as a reader session before letting it run (allow or approve).
    reader: bool = False


@dataclass
class _Sessions:
    tainted: set[str] = field(default_factory=set)
    #: Sessions whose reader mode was durably recorded by this process's hook.
    reader: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)


_SESSIONS = _Sessions()


def mark_tainted(session_id: str | None) -> None:
    if session_id:
        with _SESSIONS.lock:
            _SESSIONS.tainted.add(session_id)


def is_tainted(session_id: str | None) -> bool:
    if not session_id:
        return False
    with _SESSIONS.lock:
        return session_id in _SESSIONS.tainted


def mark_reader(session_id: str) -> None:
    """Enter reader mode in this process; call only after the durable record."""
    with _SESSIONS.lock:
        _SESSIONS.reader.add(session_id)
        _SESSIONS.tainted.add(session_id)


def reader_mode_established(session_id: str | None) -> bool:
    """Whether this process's pre-tool hook put ``session_id`` into reader mode.

    The check reader-tool handlers make before returning imported text. It
    answers from the in-process set only, which the hook fills after the
    durable record succeeded: if the hook did not run in this process (plugin
    disabled, a call path that skips ``pre_tool_call``), nothing guards the
    session's later tool calls, so the handler must refuse even when an
    earlier process left a durable record.
    """
    if not session_id:
        return False
    with _SESSIONS.lock:
        return session_id in _SESSIONS.reader


def is_reader_session(session_id: str | None, *, home: Path | None = None) -> bool:
    """Whether the reader guard applies: this process's set or the durable record.

    ``home`` is the Hermes home holding ``mordred/reader_sessions.json``; without
    it only the in-process set is consulted. An unreadable record raises
    :class:`._reader_sessions.ReaderRecordError` (callers fail closed).
    """
    if not session_id:
        return False
    if reader_mode_established(session_id):
        return True
    if home is None:
        return False
    from . import _reader_sessions

    return _reader_sessions.contains(home, session_id)


# -- policy loading -------------------------------------------------------------------


def parse_policy(section: Any) -> EgressPolicy:
    """Parse ``tool_egress``; absent → default, damaged → lockdown."""
    if section is None:
        return EgressPolicy()
    if not isinstance(section, dict):
        return EgressPolicy(level="lockdown")
    level = section.get("level", DEFAULT_LEVEL)
    if level not in LEVELS:
        return EgressPolicy(level="lockdown")
    extra = section.get("blocklist", [])
    tools = section.get("blocked_tools", [])
    if not isinstance(extra, list) or not isinstance(tools, list):
        return EgressPolicy(level="lockdown")
    domains = tuple(dict.fromkeys([*DEFAULT_BLOCKLIST, *(str(d).strip().casefold() for d in extra if str(d).strip())]))
    return EgressPolicy(
        level=level,
        blocklist=domains,
        blocked_tools=frozenset(str(t) for t in tools),
        taint=section.get("taint", True) is not False,
        lockdown_after_private_data=section.get("lockdown_after_private_data") is True,
    )


_cache: dict[str, Any] = {}


def load_policy(config_path: Path | None = None) -> EgressPolicy:
    """Read tool-egress settings; Windows refreshes the pair and propagates refusal.

    POSIX retains the historical mtime cache and lockdown fallback.
    """
    from .._home import hermes_home
    from .._yaml_io import load_plugin_section

    path = config_path or (hermes_home() / "config.yaml")
    if _platform == "nt":
        from ._checked_policy import read_checked_policy

        return read_checked_policy(path).egress
    try:
        stat = path.stat()
        stamp = (str(path), stat.st_mtime_ns, stat.st_size)
    except FileNotFoundError:
        return EgressPolicy()
    except OSError:
        return EgressPolicy(level="lockdown")
    if _cache.get("stamp") == stamp:
        cached: EgressPolicy = _cache["policy"]
        return cached
    try:
        section = load_plugin_section(path, "mordred_privacy_check")
    except Exception:
        policy = EgressPolicy(level="lockdown")
    else:
        policy = parse_policy(section.get("tool_egress") if isinstance(section, dict) else None)
    _cache.update(stamp=stamp, policy=policy)
    return policy


# -- classification -------------------------------------------------------------------


def _urls(tool: str, args: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for key in URL_ARGS.get(tool, ()):
        value = args.get(key)
        values = value if isinstance(value, list) else [value]
        found.extend(v for v in values if isinstance(v, str) and v)
    if tool == "browser_cdp":
        params = args.get("params")
        if isinstance(params, dict) and isinstance(params.get("url"), str):
            found.append(params["url"])
    return found


def _ip_literal(host: str) -> bool:
    """A bare IP address that is not this machine (loopback)."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not address.is_loopback


# ``scheme://<IPv4 or [IPv6]>`` inside free-form command text.
_URL_IP_IN_TEXT = re.compile(r"[a-z][a-z0-9+.-]*://(\[[0-9a-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)


def _host_blocked(url: str, blocklist: tuple[str, ...]) -> str | None:
    lowered = url.casefold()
    try:
        host = (urlsplit(url if "://" in url else f"https://{url}").hostname or "").casefold()
    except ValueError:
        return "unparseable URL"
    if _ip_literal(host):
        return f"bare IP address {host}"
    for entry in blocklist:
        if "/" in entry:
            if entry in lowered:
                return entry
        elif host == entry or host.endswith("." + entry):
            return entry
    return None


def is_first_party_command(command: Any) -> bool:
    return (
        isinstance(command, str)
        and _SHELL_META.search(command) is None
        and _FIRST_PARTY_COMMAND.fullmatch(command) is not None
    )


def _is_local_target(url: str) -> bool:
    """A file path or a loopback address (e.g. a local dev server)."""
    if "://" not in url:
        return url.startswith(("/", "~", "./", "../")) or url.casefold().startswith("localhost")
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme == "file":
        return True
    host = (parts.hostname or "").casefold()
    return host in {"localhost", "127.0.0.1", "::1"}


def _is_local(tool: str) -> bool:
    if tool in LOCAL_TOOLS:
        return True
    return tool.startswith(_LOCAL_PREFIXES) and tool not in _LOCAL_EXCEPTIONS


def _block(level: str, reason: EgressRule, detail: str) -> Decision:
    return Decision(
        allow=False,
        reason=reason,
        message=(
            f"Blocked by Mordred tool-egress policy (level '{level}'): {detail} "
            "Do not try to reach the internet another way (other tools, code, commands, "
            "delegation, or scheduling); tell the user what you wanted to do and why it was blocked."
        ),
    )


def _decide_blocklist(tool: str, args: dict[str, Any], policy: EgressPolicy) -> Decision:
    for url in _urls(tool, args):
        hit = _host_blocked(url, policy.blocklist)
        if hit:
            return _block(
                "blocklist", "egress.blocklisted_domain", f"{tool} targets a blocklisted destination ({hit})."
            )
    if tool in EXEC_TOOLS:
        text = " ".join(str(v) for v in args.values() if isinstance(v, str)).casefold()
        for entry in policy.blocklist:
            if entry in text:
                return _block("blocklist", "egress.blocklisted_domain", f"{tool} mentions a blocklisted destination.")
        for match in _URL_IP_IN_TEXT.finditer(text):
            if _ip_literal(match.group(1)):
                return _block("blocklist", "egress.blocklisted_domain", f"{tool} contacts a bare IP address.")
    return Decision(allow=True)


def _decide_restricted(level: str, tool: str, args: dict[str, Any]) -> Decision:
    """``lockdown`` / ``search``: only provably local or fixed-destination calls."""
    if tool in SEARCH_TOOLS:
        if level == "search":
            return Decision(allow=True)
        return _block(level, "egress.lockdown", "web search is disabled.")
    if tool == "terminal" and is_first_party_command(args.get("command")):
        return Decision(allow=True)
    if tool in EXEC_TOOLS:
        return _block(
            level,
            "egress.uninspectable_exec",
            f"{tool} runs free-form code whose network destination cannot be checked.",
        )
    if tool == "desktop_preview":
        targets = _urls(tool, args)
        if all(_is_local_target(u) for u in targets):
            return Decision(allow=True)  # close/read, or a local file / dev server
    if tool in URL_ARGS or tool.startswith("browser_"):
        return _block(level, "egress.url_fetch", f"{tool} would contact a web address.")
    return _block(level, "egress.outbound_tool", f"{tool} can send data outside this machine.")


# Commands that (usually) talk to the network. Anything else a command does
# stays local and runs without asking.
_NETWORK_COMMAND = re.compile(
    r"://|\b(?:curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|telnet|ftp|socat|ping|dig|nslookup|whois"
    r"|git\s+(?:clone|fetch|pull|push|ls-remote|submodule)|gh|aws|gcloud|az|kubectl|docker\s+(?:pull|push|login|run)"
    r"|pip3?\s+(?:install|download)|uv\s+(?:pip\s+install|add|sync|tool\s+install)|npm|npx|pnpm|yarn|bun"
    r"|brew\s+(?:install|upgrade|update|tap)|cargo\s+(?:install|add|update)|go\s+(?:get|install)"
    r"|requests|urllib|httpx|aiohttp|http\.client|socket|websocket|fetch\()\b",
    re.IGNORECASE,
)
_PREVIEW_CHARS = 600


def _preview(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= _PREVIEW_CHARS else text[:_PREVIEW_CHARS] + " …"


def _ask(tool: str, where: str, what: Any, rule_key: str, *, tainted: bool) -> Decision:
    warning = "This chat has read your private (Telegram) data. " if tainted else ""
    return Decision(
        allow=False,
        approve=True,
        reason="egress.ask",
        rule_key=rule_key,
        message=f"{warning}Mordred: {tool} wants to use the internet ({where}). It will send: {_preview(what)}",
    )


def _decide_ask(tool: str, args: dict[str, Any], policy: EgressPolicy, *, tainted: bool) -> Decision:
    """``ask``: run local work, allow web search, ask before any other internet use."""
    hard = _decide_blocklist(tool, args, policy)
    if not hard.allow:
        return hard
    if tool in SEARCH_TOOLS:
        return Decision(allow=True)
    if tool in EXEC_TOOLS:
        if tool == "terminal" and is_first_party_command(args.get("command")):
            return Decision(allow=True)
        text = " ".join(str(v) for v in args.values() if isinstance(v, str))
        if not _NETWORK_COMMAND.search(text):
            return Decision(allow=True)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return _ask(tool, "a command that uses the network", text, f"mordred.egress:{tool}:{digest}", tainted=tainted)
    urls = _urls(tool, args)
    if tool == "desktop_preview" and all(_is_local_target(u) for u in urls):
        return Decision(allow=True)
    if urls:
        hosts = sorted({(urlsplit(u if "://" in u else f"https://{u}").hostname or u) for u in urls})
        return _ask(tool, ", ".join(hosts), args, f"mordred.egress:{tool}:{','.join(hosts)}", tainted=tainted)
    return _ask(tool, "an external service", args, f"mordred.egress:{tool}", tainted=tainted)


def _session_guard(tool: str, tainted: bool, effective: str) -> Decision | None:
    """Rules for tools that could carry this session's data somewhere else."""
    if tainted and (tool in PERSIST_TOOLS or (tool.startswith("kanban_") and tool not in _READ_ONLY_KANBAN)):
        return _block(
            "lockdown",
            "egress.tainted_persist",
            f"this session has read private data, which may not be written to disk in plaintext ({tool}).",
        )
    if tool == "delegate_task" and (tainted or effective == "lockdown"):
        return _block(effective, "egress.delegate_tainted", "delegation is disabled for this session.")
    return None


def _bridge_entries(args: dict[str, Any]) -> list[tuple[str, dict[str, Any]]] | None:
    """The ``(name, arguments)`` calls inside a ``tool_call`` bridge, or ``None`` if malformed.

    Mirrors Hermes's tolerant parsing: the ``calls`` batch (a list, one object
    or a JSON string) or the legacy single ``{name, arguments}``; ``arguments``
    may be a JSON string.
    """
    raw: Any = args.get("calls")
    if raw is None:
        raw = [{"name": args.get("name"), "arguments": args.get("arguments")}]
    raw = _loads(raw)
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        return None
    entries = [_bridge_entry(item) for item in raw]
    return None if any(entry is None for entry in entries) else [e for e in entries if e is not None]


def _loads(value: Any) -> Any:
    """Parse a JSON string (``None`` on bad JSON, ``{}`` for blank); other values pass through."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value) if value.strip() else {}
    except json.JSONDecodeError:
        return None


def _bridge_entry(item: Any) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    arguments = item.get("arguments")
    arguments = {} if arguments is None else _loads(arguments)
    if not name or name == BRIDGE_CALL_TOOL or not isinstance(arguments, dict):
        return None
    return name, arguments


def _decide_bridge(
    args: dict[str, Any], session_id: str | None, policy: EgressPolicy, home: Path | None
) -> Decision | None:
    """Decide a ``tool_call`` by its inner calls; ``None`` if it is malformed.

    A refusal of any entry refuses the batch, also after an entry that only
    asks. Entries that ask are combined into one prompt that lists every one
    of them (:func:`_combine_approvals`), so approving the batch never runs an
    entry the user was not shown. A batch that reads imported history runs
    every entry under the reader guard, so ``[telegram_ask, terminal]`` is
    refused as a whole.
    """
    entries = _bridge_entries(args)
    if entries is None:
        # Hermes cannot run a malformed bridge either. Say what is wrong with
        # the call, not "egress", so the model fixes it instead of giving up.
        return Decision(
            allow=False,
            reason="egress.malformed_bridge",
            message=(
                "tool_call is malformed (this is not a Mordred privacy block): every entry in `calls` "
                'needs a "name" and an object "arguments", e.g. {"calls": [{"name": "telegram_ask", '
                '"arguments": {"question": "...", "start_date": "YYYY-MM-DD", "end_date": "YYYY-MM-DD"}}]}. '
                "Fix the call and try again."
            ),
        )
    reader_batch = any(name in READER_TOOLS for name, _ in entries)
    taints = False
    approvals: list[Decision] = []
    for name, arguments in entries:
        inner = _decide_tool(name, arguments, session_id, policy, home=home, reader_batch=reader_batch)
        if not inner.allow and not inner.approve:
            return inner
        if inner.approve:
            approvals.append(inner)
        taints = taints or inner.taints
    if approvals:
        return replace(_combine_approvals(approvals), taints=taints, reader=reader_batch)
    return Decision(allow=True, taints=taints, reader=reader_batch)


def _combine_approvals(approvals: list[Decision]) -> Decision:
    """One approval prompt for every entry of a ``tool_call`` batch that asks.

    Hermes asks once for the whole bridge call, so the prompt must show each
    entry that needs approval. The ``rule_key`` covers exactly this set of
    entries: answering "always" for a batch never pre-approves a different
    batch or one of its entries on its own.
    """
    if len(approvals) == 1:
        return approvals[0]
    keys = "\n".join(sorted(decision.rule_key for decision in approvals))
    digest = hashlib.sha256(keys.encode("utf-8")).hexdigest()[:12]
    listed = "\n".join(f"{number}. {decision.message}" for number, decision in enumerate(approvals, start=1))
    return replace(
        approvals[0],
        rule_key=f"mordred.egress.batch:{digest}",
        message=f"Mordred: this tool_call batch has {len(approvals)} calls that need your approval:\n{listed}",
    )


def decide(
    tool: str,
    args: dict[str, Any] | None,
    session_id: str | None,
    policy: EgressPolicy,
    *,
    home: Path | None = None,
) -> Decision:
    """Allow or block one tool call.

    Pure apart from reading the taint/reader sets and, when ``home`` is given,
    the durable reader record (:func:`is_reader_session`).
    """
    args = args if isinstance(args, dict) else {}
    if tool == BRIDGE_CALL_TOOL:
        bridged = _decide_bridge(args, session_id, policy, home)
        if bridged is not None:
            return bridged
    return _decide_tool(tool, args, session_id, policy, home=home)


def _decide_tool(
    tool: str,
    args: dict[str, Any],
    session_id: str | None,
    policy: EgressPolicy,
    *,
    home: Path | None = None,
    reader_batch: bool = False,
) -> Decision:
    level = policy.level
    # The operator's tool blocklist wins first; at level "off" it still
    # covers the reader tools (an operator may switch imports off entirely).
    if tool in policy.blocked_tools and (level != "off" or tool in READER_TOOLS):
        return _block(level, "egress.blocked_tool", f"the tool {tool} is blocklisted.")
    if tool in READER_TOOLS:
        if session_id is None:
            return _block(
                level, "egress.reader_no_session", f"{tool} reads imported history and needs a session identity."
            )
        return Decision(allow=True, taints=True, reader=True)
    web = False
    if reader_batch or is_reader_session(session_id, home=home):
        if tool not in READER_ALLOWED and tool not in READER_WEB_TOOLS:
            return _block(
                "lockdown",
                "egress.reader_locked",
                f"this session has read imported history; {tool} is disabled until a new session.",
            )
        web = tool in READER_WEB_TOOLS
    decision = _decide_level(tool, args, session_id, policy)
    if web and (decision.allow or decision.approve):
        # Stricter level rules (a block) win; otherwise the user decides.
        return _reader_web(tool, args, policy)
    return decision


def _reader_web(tool: str, args: dict[str, Any], policy: EgressPolicy) -> Decision:
    """Ask before a reader session searches or loads a web address, at every level."""
    hard = _decide_blocklist(tool, args, policy)
    if not hard.allow:
        return hard
    urls = _urls(tool, args)
    where = ", ".join(sorted({(urlsplit(u if "://" in u else f"https://{u}").hostname or u) for u in urls}))
    digest = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:12]
    return Decision(
        allow=False,
        approve=True,
        reason="egress.reader_web",
        rule_key=f"mordred.egress.reader_web:{tool}:{digest}",
        message=(
            "This chat has read imported private history. "
            f"Mordred: {tool} wants to use the internet ({where or 'a web search'}). It will send: {_preview(args)}"
        ),
    )


def _decide_level(tool: str, args: dict[str, Any], session_id: str | None, policy: EgressPolicy) -> Decision:
    """The configured level's rules (reader tools and the reader guard come first)."""
    level = policy.level
    if level == "off":
        return Decision(allow=True)
    tainted = policy.taint and is_tainted(session_id)
    # Under "ask" a tainted session keeps asking (the prompt says the chat has
    # read private data); the stricter levels still lock it down.
    lock = tainted and (level != "ask" or policy.lockdown_after_private_data)
    effective = "lockdown" if lock else level
    guard = _session_guard(tool, tainted, effective)
    if guard is not None:
        return guard
    if _is_local(tool):
        return Decision(allow=True)
    if tool == "delegate_task":
        return Decision(allow=True)  # child agents' tools pass through this hook too
    if effective == "ask":
        return _decide_ask(tool, args, policy, tainted=tainted)
    if tool == "cronjob_manage" and _RANK[effective] >= _RANK["search"]:
        return _block(effective, "egress.schedule", "scheduled jobs can deliver data outside this session.")
    if effective == "blocklist":
        return _decide_blocklist(tool, args, policy)
    return _explain_lock(_decide_restricted(effective, tool, args), tool, locked=lock and level != "lockdown")


def _explain_lock(decision: Decision, tool: str, *, locked: bool) -> Decision:
    """Say why a session raised to ``lockdown`` by taint refuses ``tool``."""
    if decision.allow or not locked:
        return decision
    return _block(
        "lockdown",
        "egress.tainted_session",
        f"this session has read private data, so {tool} (and all internet access) is disabled for it.",
    )
