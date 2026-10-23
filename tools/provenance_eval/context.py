"""Reference rendering of one thread for one source: what a driver shows the model.

The mail side is ALWAYS the real collector's output for the generated mbox
(:func:`mail_threads`), never the generator's prediction. Each part is
rendered by :func:`mordred_hermes.imports.render.render_part` and every body
is truncated to the truth's ``render_cap`` by ``render_selection``. The
context also carries the evidence selection (for ``imports.evidence.validate``)
and the map from every rendered speaker label to the person it denotes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from mordred_hermes.imports.aliases import IdentityAliases
from mordred_hermes.imports.mail import MboxBytes, plan_import
from mordred_hermes.imports.records import ImportPart, OwnerClass, SenderKind
from mordred_hermes.imports.render import (
    DEFAULT_HEAD_STYLE,
    HeadStyle,
    RenderedPartRef,
    conversation_label,
    part_ref,
    render_part,
    render_selection,
)

from .encode_mail import SENT_LABEL
from .encode_telegram import IMPORTED_AT, EncodedThread
from .truth import Truth

__all__ = ["RenderedContext", "mail_threads", "person_of_part", "render_context"]


@dataclass(frozen=True, kw_only=True)
class RenderedContext:
    """Everything a driver needs about one thread in one source."""

    thread_id: str
    source: str  # telegram | mail
    style: str  # a HeadStyle value
    render_cap: int  # body characters per part (heads are never cut)
    text: str  # conversation label line, then head line + indented body per part
    selection: Mapping[str, RenderedPartRef]  # evidence id -> stored facts (de-aliased)
    speaker_labels: Mapping[str, str | None]  # rendered speaker label -> person id (None: unknown sender)

    @property
    def rendered_chars(self) -> int:
        return len(self.text)


def mail_threads(truth: Truth, mbox: bytes) -> dict[str, EncodedThread]:
    """Run the real mail collector on ``mbox``; threads keyed by truth thread id."""
    plan = plan_import(
        [MboxBytes(mbox)],
        account=truth.account,
        own_addresses=truth.own_addresses,
        sent_label=SENT_LABEL,
        imported_at=IMPORTED_AT,
    )
    by_conv = {thread.mail_conv_uid: thread.thread_id for thread in truth.threads}
    found: dict[str, EncodedThread] = {}
    for planned in plan.threads:
        thread_id = by_conv.get(planned.conversation.conv_uid)
        if thread_id is not None:
            found[thread_id] = EncodedThread(thread_id, planned.conversation, tuple(planned.messages))
    return found


def person_of_part(truth: Truth, source: str, part: ImportPart) -> str | None:
    """The person an imported part's author fields denote (``None`` for unknown or unmapped).

    A named channel or bot with an unknown owner class (a Telegram broadcast
    post) is that channel or bot, exactly as the renderer names it.
    """
    if part.author_owner_class == OwnerClass.ACCOUNT_OWNER:
        return truth.owner_id
    named = part.author_kind in (SenderKind.CHANNEL, SenderKind.BOT) and bool(part.author_name)
    if part.author_owner_class != OwnerClass.OTHER and not named:
        return None
    return truth.person_for_handle(source, part.author_id)


def render_context(
    thread: EncodedThread,
    truth: Truth,
    source: str,
    *,
    style: HeadStyle | str = DEFAULT_HEAD_STYLE,
    aliases: IdentityAliases | None = None,
) -> RenderedContext:
    """Render ``thread`` with real names kept apart (``IdentityAliases(enabled=False)`` by default)."""
    table = aliases if aliases is not None else IdentityAliases(enabled=False)
    conv = thread.conversation
    head_style = HeadStyle(style)
    label = conversation_label(conv, aliases=table, style=head_style)
    rendered = []
    selection: dict[str, RenderedPartRef] = {}
    labels: dict[str, str | None] = {}
    for msg in thread.messages:
        for part in sorted(msg.parts, key=lambda item: item.ordinal):
            rendered.append(
                render_part(conv, msg, part, aliases=table, style=head_style, tz_offset_minutes=truth.tz_offset_minutes)
            )
            ref = part_ref(conv, msg, part, aliases=table, style=head_style)
            selection[ref.evidence_id] = ref
            labels.setdefault(ref.speaker, person_of_part(truth, source, part))
    body = render_selection(rendered, max_body_chars=truth.render_cap)
    return RenderedContext(
        thread_id=thread.thread_id,
        source=source,
        style=str(head_style),
        render_cap=truth.render_cap,
        text=f"{label}\n{body}",
        selection=selection,
        speaker_labels=labels,
    )
