"""Exception taxonomy for ``mordred_keyvault.wrap`` and ``.native``.

Frozen in SPEC.md §Wrap wire format & algorithm (Phase 4 PR3 freeze,
2026-05-14). 6 classes: 1 base + 5 sibling subclasses (codex review
NIT-1 — the originally-proposed single ``WrapAuthFailed`` was too
ambiguous; callers need to catch parse failures separately from
integrity failures separately from auth cancellations).

``WrapError`` inherits :class:`Exception` (not :class:`BaseException`).
PR3 has no need for the ``BaseException``-derived propagation regime
used by ``llm_guard._exceptions.MordredSessionRefused`` /
``network._exceptions.MordredPathBringupFailed`` — those classes have
to escape Hermes' ``invoke_hook`` ``except Exception:`` filter to abort
a session, whereas wrap/unwrap is called from inside
``mordred_keyvault.api`` and has no such constraint.

This module is intentionally tiny and pure-Python: ``native.py`` imports
it before doing any pyobjc work, so non-macOS callers can introspect
the taxonomy (e.g. for ``isinstance`` checks in CLI error formatting)
without triggering the lazy pyobjc import.

Existing per-module keyvault exceptions stay where they are
(``VerificationDigestMismatch`` in ``digest.py``, ``BackupCorrupt`` in
``backup.py``, ``RecoveryDigestMismatch`` in ``recovery.py``) — they
have a single owning module and don't cross boundaries. Only the
``WrapError`` taxonomy is shared between ``native.py`` and ``wrap.py``,
which is why it lives here.
"""

from __future__ import annotations


class WrapError(Exception):
    """Base for all Phase 4 PR3 wrap/unwrap exceptions.

    Sibling subclasses (NOT a chain — codex review NIT-1):

    - :class:`WrapParseError` — malformed blob (length, magic, version,
      ``alg_suite``, ``key_id_hash`` mismatch, invalid EC point).
    - :class:`WrapIntegrityError` — AES-KW AIV check failed (tampered
      ``wrapped_dek`` or ``ephemeral_pub``).
    - :class:`WrapNativeUnavailable` — ``Security.framework`` not
      importable (non-macOS, or macOS without pyobjc-framework-Security).
    - :class:`WrapAuthCancelled` — user denied the biometry / passcode
      prompt; paired with ``keyvault.unwrap_denied`` audit emit.
    - :class:`WrapKeyNotFound` — Keychain has no item for the given
      ``key_id`` (key was revoked, deleted, or wrong device). Has one
      nested subclass: :class:`WrapKeyAlreadyExists` (duplicate
      ``key_id`` at generation time — kept under ``WrapKeyNotFound``
      for back-compat with callers that catch the historical mapping).
    """


class WrapParseError(WrapError):
    """Blob is structurally invalid.

    Covers all parse-time rejections before any Enclave call:

    - Wrong length (``len(blob) != 127`` for ``version=1``).
    - Bad magic (``magic != b"MRKW"``).
    - Unknown version (``version != 1``).
    - Unknown algorithm suite (``alg_suite != 1``).
    - ``key_id_hash`` does not match ``SHA-256(key_id)[:16]`` for the
      caller-supplied ``key_id``.
    - ``ephemeral_pub`` is not a valid SEC1 P-256 uncompressed point.
    """


class WrapIntegrityError(WrapError):
    """AES-KW AIV check failed during unwrap.

    The integrity of the blob is end-to-end protected by binding all
    non-secret fields into the HKDF ``info`` parameter (SPEC.md
    §Wrap wire format & algorithm, ``wrap_dek`` step 4). A tampered
    ``ephemeral_pub`` produces a different KEK and
    AES-KW fails the AIV check. A tampered ``wrapped_dek`` fails the
    AIV check directly. Both surface as this single class so callers
    cannot distinguish them — leaking which byte ranges are integrity-
    protected helps an attacker craft chosen-blob attacks.
    """


class WrapNativeUnavailable(WrapError):
    """``Security.framework`` is not reachable.

    Two cases:

    1. ``sys.platform != "darwin"`` — short-circuit, ``__cause__`` is
       ``None``. The message names the actual platform.
    2. macOS without ``pyobjc-framework-Security`` installed — the
       underlying :class:`ImportError` is chained via ``__cause__``.
       The message mentions ``pip install hermes-mordred[macos]``.
    """


class WrapAuthCancelled(WrapError):
    """The user denied the access-control prompt during ``unwrap_dek``.

    Paired with a ``keyvault.unwrap_denied`` audit log entry (POLICY.md
    code #20). The underlying ``NSError`` is chained via ``__cause__``;
    the translated ``native_error_code`` is one of the four prompt-
    denied codes — ``user_cancelled``, ``auth_failed``,
    ``biometry_lockout``, ``passcode_not_set``.

    Note: ``key_not_found`` is the fifth member of the
    :data:`mordred_hermes.keyvault.wrap.NativeErrorCode` closed set,
    but it never surfaces as :class:`WrapAuthCancelled`. The Enclave
    returning ``errSecItemNotFound`` mid-unwrap is a pre-authorization
    failure: :func:`mordred_hermes.keyvault.wrap.unwrap_dek` branches
    on ``denied.code == "key_not_found"`` and raises the more specific
    :class:`WrapKeyNotFound` with **no audit emit** (review-fix-1
    HIGH-1, codex review-fix-2 LOW-1).
    """


class WrapKeyNotFound(WrapError):
    """Keychain has no Enclave key for the given ``key_id``.

    Caused by:

    - Key was never generated (``generate_wrapping_key`` was not called).
    - Key was deleted via ``delete_wrapping_key`` or Keychain Access.
    - The user is on a different device (Enclave keys are
      ``.thisDeviceOnly`` and never sync).
    - Biometry-change invalidation kicked in (``.biometryCurrentSet``
      flag) — the key is technically still in the Keychain but the
      Enclave refuses to use it.

    The fourth case is indistinguishable from "key deleted" without
    additional Keychain introspection, which is intentional: an
    attacker who can see the difference learns whether the user
    re-enrolled biometrics, a privacy leak.
    """


class WrapKeyAlreadyExists(WrapKeyNotFound):
    """A wrapping key with this ``key_id`` already exists — generation refused.

    Raised by ``generate_enclave_key`` when the Keychain tag is already
    taken (the backend translates ``errSecDuplicateItem`` / a helper's
    ``exists`` reason). Historically this condition was reported as plain
    :class:`WrapKeyNotFound` on the rationale that both mean "cannot
    generate here"; the dedicated subclass restores the semantic
    distinction for new callers while remaining catchable by every
    pre-existing ``except WrapKeyNotFound`` site (review follow-up,
    2026-06-11).
    """
