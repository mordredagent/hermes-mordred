"""Canonical Hermes provider-id normalization.

Mordred matches provider identifiers — for strict-mode enforcement
(:mod:`mordred_hermes.llm_guard.enforce`) and for transport-compatibility
flagging (:mod:`mordred_hermes.network.provider_transport_flagger`) — against
canonical slugs. Hermes accepts many *aliases* for the same provider
(``claude`` → ``anthropic``, ``glm`` → ``zai``, ``aws`` → ``bedrock`` …).

Without normalization a user whose ``config.yaml`` says
``model.provider: claude`` is matched as the literal ``"claude"`` — absent
from ``KNOWN_PROVIDERS`` — and is mis-handled as an *unknown* provider: the
transport flagger emits a generic "unknown provider" warning instead of the
real anthropic transport facts, and the strict-mode allowlist check compares
against the wrong identifier.

``PROVIDER_ALIASES`` is a faithful replica of
``hermes_cli/models.py::_PROVIDER_ALIASES`` (Hermes 0.17.0). It is *replicated*
rather than imported: ``hermes_cli`` is a private module with no stability
contract, so importing it would couple Mordred's enforcement to Hermes'
internal layout. ``tests/test_provider_identity.py`` guards the replica's
shape; a follow-up registry-drift test keeps it aligned with upstream.

``canonicalize_provider`` mirrors Hermes' own application of the table
(``models.py:1830`` — ``_PROVIDER_ALIASES.get(name_lower, name_lower)``):
an alias resolves to its canonical slug; an unknown id passes through
unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

#: Faithful replica of ``hermes_cli/models.py::_PROVIDER_ALIASES`` (Hermes
#: 0.14.0). Identity entries (e.g. ``xai-oauth`` → ``xai-oauth``) are kept
#: verbatim from upstream so the replica diffs cleanly against the source.
#: The bare ``ollama`` → ``custom`` mapping is upstream's "local endpoint"
#: sentinel (use ``ollama-cloud`` for the hosted product); it is preserved
#: as-is so Mordred's normalization never diverges from Hermes'.
PROVIDER_ALIASES: Final[Mapping[str, str]] = {
    "glm": "zai",
    "z-ai": "zai",
    "z.ai": "zai",
    "zhipu": "zai",
    "github": "copilot",
    "github-copilot": "copilot",
    "github-models": "copilot",
    "github-model": "copilot",
    "github-copilot-acp": "copilot-acp",
    "copilot-acp-agent": "copilot-acp",
    "google": "gemini",
    "google-gemini": "gemini",
    "google-ai-studio": "gemini",
    "kimi": "kimi-coding",
    "moonshot": "kimi-coding",
    "kimi-cn": "kimi-coding-cn",
    "moonshot-cn": "kimi-coding-cn",
    "step": "stepfun",
    "stepfun-coding-plan": "stepfun",
    "arcee-ai": "arcee",
    "arceeai": "arcee",
    "gmi-cloud": "gmi",
    "gmicloud": "gmi",
    "minimax-china": "minimax-cn",
    "minimax_cn": "minimax-cn",
    "minimax-portal": "minimax-oauth",
    "minimax-global": "minimax-oauth",
    "minimax_oauth": "minimax-oauth",
    "claude": "anthropic",
    "claude-code": "anthropic",
    "deep-seek": "deepseek",
    "opencode": "opencode-zen",
    "zen": "opencode-zen",
    "go": "opencode-go",
    "opencode-go-sub": "opencode-go",
    "kilo": "kilocode",
    "kilo-code": "kilocode",
    "kilo-gateway": "kilocode",
    "dashscope": "alibaba",
    "aliyun": "alibaba",
    "qwen": "alibaba",
    "alibaba-cloud": "alibaba",
    "qwen-portal": "qwen-oauth",
    "gemini-cli": "google-gemini-cli",
    "gemini-oauth": "google-gemini-cli",
    "hf": "huggingface",
    "hugging-face": "huggingface",
    "huggingface-hub": "huggingface",
    "novita-ai": "novita",
    "novitaai": "novita",
    "mimo": "xiaomi",
    "xiaomi-mimo": "xiaomi",
    "tencent": "tencent-tokenhub",
    "tokenhub": "tencent-tokenhub",
    "tencent-cloud": "tencent-tokenhub",
    "tencentmaas": "tencent-tokenhub",
    "aws": "bedrock",
    "aws-bedrock": "bedrock",
    "amazon-bedrock": "bedrock",
    "amazon": "bedrock",
    "grok": "xai",
    "grok-oauth": "xai-oauth",
    "xai-oauth": "xai-oauth",
    "x-ai-oauth": "xai-oauth",
    "xai-grok-oauth": "xai-oauth",
    "x-ai": "xai",
    "x.ai": "xai",
    "nim": "nvidia",
    "nvidia-nim": "nvidia",
    "build-nvidia": "nvidia",
    "nemotron": "nvidia",
    "lmstudio": "lmstudio",
    "lm-studio": "lmstudio",
    "lm_studio": "lmstudio",
    "ollama": "custom",
    "ollama_cloud": "ollama-cloud",
}


def canonicalize_provider(name: str) -> str:
    """Resolve a provider alias to its canonical Hermes slug.

    The input is stripped and lowercased before lookup so callers can pass a
    raw ``config.yaml`` / ``auth.json`` value directly. Mirrors Hermes'
    ``_PROVIDER_ALIASES.get(name_lower, name_lower)`` (``models.py:1830``):
    a known alias maps to its canonical slug, and any unknown id (including
    the empty string and canonical slugs themselves) passes through unchanged.

    Callers are typed ``str`` (enforced by ``mypy --strict`` on src), but this
    also runs inside :func:`provider_transport_flagger.evaluate`, which
    executes in a session-start / audit hook. A malformed config yielding a
    non-str must degrade to "unknown provider" (empty key → no registry match)
    rather than raise out of the hook — mirroring the flagger's prior
    tolerance of ``catalog.get(<non-str>)`` → ``None``.
    """
    if not isinstance(name, str):
        return ""
    key = name.strip().lower()
    return PROVIDER_ALIASES.get(key, key)
