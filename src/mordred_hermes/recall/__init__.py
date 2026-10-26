"""Recall: the user's own stored messages that match a page selection.

Deterministic and extractive, with no model in the path. A selection becomes a
few keywords (:mod:`.derive`); each keyword runs through the import store's
trigram search; hits are scored by one transparent linear combination
(:mod:`.fusion`) and returned as evidence cards whose excerpt is a substring of
the stored part (:mod:`.cards`). A weak or flat result set says ``none``
instead of showing a doubtful card.

Reads ``mordred.db``'s ``import_*`` tables through :class:`~.index.RecallIndex`.
The only write is :meth:`~.index.RecallIndex.dismiss`, which hides a
conversation for a week in the ``recall_suppression`` table.

The browser extension reaches this over the ``/ext`` gateway
(``recall_query`` / ``recall_open`` / ``recall_dismiss``), so the pairing is
the only credential and nothing listens on another port.
"""
