"""mordred_hermes.keyvault.api — public Python API surface.

Steps landed so far:

- step-A: split-normalization helpers + ``verify_digest`` wrapper.
- step-B: ``_storage`` module (file-safety helpers; consumed by api.py).
- step-C: MREN envelope wire format + ``encrypt`` / ``decrypt`` (managed
  storage; per-ciphertext DEK wrapped under the Enclave wrapping key).

Step-D will add ``prepare_generate`` / ``confirm_generate`` / ``generate``
/ ``export_backup`` / ``import_backup`` / ``SeedDisplayHandle``.

Authoritative contract lives in ``mordred-docs/mordred/SPEC.md``
§"PR4 API contract & MREN envelope wire format". Codex pre-implementation
review (3 BLOCKER + 5 HIGH) drove the split normalization in this
module: applying ``casefold`` and whitespace-collapse uniformly to the
passphrase weakens entropy, so the two normalizers diverge intentionally.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _storage, wrap
from ._exceptions import WrapParseError
from .digest import VerificationDigestMismatch
from .digest import verify_digest as _digest_verify
from .wrap import AuditSink, NativeBackend

__all__ = [
    "VerificationDigestMismatch",
    "decrypt",
    "encrypt",
    "verify_digest",
]


# ----------------------------- MREN envelope constants -----------------------------
# Wire format frozen in SPEC.md §"PR4 API contract / MREN envelope".

_ENVELOPE_MAGIC = b"MREN"
_ENVELOPE_VERSION = 1
_KEY_ID_HASH_LEN = 16
_PURPOSE_HASH_LEN = 16
_WRAPPED_DEK_LEN = 127  # PR3 MRKW blob, SPEC §"Wrap wire format & algorithm"
_AES_BLOB_LEN_FIELD_LEN = 4
_ENVELOPE_AAD_LEN = 4 + 1 + _KEY_ID_HASH_LEN + _PURPOSE_HASH_LEN + _WRAPPED_DEK_LEN  # 164
_ENVELOPE_HEADER_LEN = _ENVELOPE_AAD_LEN + _AES_BLOB_LEN_FIELD_LEN  # 168

_DEK_LEN = 32
_AES_NONCE_LEN = 12
_AES_TAG_LEN = 16
_ENVELOPE_ID_RAND_BYTES = 16


def _normalize_seed_phrase(s: str) -> str:
    """Normalize a seed phrase: NFKD + strip Cf chars + casefold + collapse whitespace.

    BIP39 word-list tolerance — the canonical word list is lowercase ASCII
    and word-separated by a single ASCII space; mixed case and runs of
    whitespace (incl. compatibility-decomposed NBSP / ideographic space)
    are operator-typo noise and are folded away.

    Unicode Cf-category chars (Format) are also stripped: ZWSP / ZWJ /
    ZWNJ / BOM / LRM / RLM / Mongolian Vowel Separator / soft hyphen are
    invisible to the user and are NFKD-stable, so without an explicit
    drop step a clipboard-injected ZWSP would silently produce a different
    digest from typed-by-hand input (code-reviewer MEDIUM-1, 2026-05-15).
    """
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Cf")
    return " ".join(stripped.casefold().split())


def _normalize_passphrase(s: str) -> str:
    """Normalize a passphrase: NFKD only.

    BIP39 reference behavior (no casefold, no whitespace collapse, no Cf
    strip). Case is significant; whitespace is preserved; Cf-category chars
    (ZWSP / ZWJ / BOM / soft hyphen / …) are preserved. Trimming any of
    these would conflate distinct entropy choices. A user who chose to
    embed an invisible char did so intentionally and must reproduce the
    exact bytes on recovery. See codex review HIGH #1 and code-reviewer
    MEDIUM-1.
    """
    return unicodedata.normalize("NFKD", s)


def verify_digest(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    *,
    expected: bytes,
) -> None:
    """Verify the verification digest with split normalization applied.

    Inputs are normalized at this layer before reaching ``compute_digest``.
    The length-confusion guard (Codex review #6) is inherited from
    :func:`mordred_hermes.keyvault.digest.verify_digest`: any ``expected`` of
    length != 32 raises :exc:`VerificationDigestMismatch` (which is re-
    exported from this module for caller convenience).
    """
    _digest_verify(
        _normalize_seed_phrase(seed_phrase),
        _normalize_passphrase(passphrase),
        pow_bytes,
        expected=expected,
    )


# ----------------------------- MREN envelope helpers (step-C) -----------------------------


def _validate_purpose(purpose: str) -> None:
    """Reject any purpose string that could escape the storage layout or
    appear inside an audit log as a control sequence.

    Allowed: alphanumeric, dash, underscore, dot (but not the bare
    relative-path components ``"."`` / ``".."``). Rejected: empty string,
    path separators (``/`` / ``\\``), control characters (``\\x00``-``\\x1f``
    / ``\\x7f``), and the relative-path components ``"."`` / ``".."``.
    """
    if not purpose:
        raise ValueError("purpose must not be empty")
    if purpose in {".", ".."}:
        raise ValueError("purpose must not be a relative-path component")
    if "/" in purpose or "\\" in purpose:
        raise ValueError("purpose must not contain path separators")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in purpose):
        raise ValueError("purpose must not contain control characters")


def _hash_id(value: str) -> bytes:
    """Return the first 16 bytes of ``sha256(value.encode("utf-8"))``.

    Used for both ``key_id_hash`` and ``purpose_hash`` (same algorithm
    and width).
    """
    return hashlib.sha256(value.encode("utf-8")).digest()[:_KEY_ID_HASH_LEN]


def _new_envelope_id() -> str:
    """Return a URL-safe base64 string of 16 random bytes (22 chars, no padding)."""
    raw = secrets.token_bytes(_ENVELOPE_ID_RAND_BYTES)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Exactly 22 URL-safe-base64 chars (alphabet ``[A-Za-z0-9_-]``, no padding).
# Matches the output of :func:`_new_envelope_id` and rejects any caller-supplied
# value containing path separators, traversal sequences, or wrong length.
_ENVELOPE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _validate_envelope_id(envelope_id: str) -> None:
    """Reject ``envelope_id`` values that could escape the managed storage path.

    Codex pre-merge P1: ``envelope_id`` was appended verbatim into the
    filesystem path. A caller supplying ``"../something"`` or ``"a/b"``
    would make :func:`decrypt` open a ``.gcm`` file outside the keyvault
    tree. Rejecting anything that does not match the exact format
    produced by :func:`_new_envelope_id` is the simplest correct fix.
    """
    if not _ENVELOPE_ID_RE.match(envelope_id):
        raise ValueError("invalid envelope_id: must be 22 URL-safe-base64 characters (no padding)")


def _envelope_path_for(root: Path, key_id: str, purpose: str, envelope_id: str) -> Path:
    """Construct the on-disk path for an MREN envelope."""
    return root / "ciphertexts" / _hash_id(key_id).hex() / _hash_id(purpose).hex() / f"{envelope_id}.gcm"


def _encode_envelope(
    dek: bytes,
    plaintext: bytes,
    key_id: str,
    purpose: str,
    wrapped_dek_blob: bytes,
) -> bytes:
    """Build an MREN envelope (AAD-bound AES-GCM) from a pre-wrapped DEK.

    Layout (SPEC.md §"PR4 API contract / MREN envelope"):

        magic(4) || version(1) || key_id_hash(16) || purpose_hash(16) ||
        wrapped_dek(127) || aes_blob_len(4 BE) ||
        aes_blob = nonce(12) || ciphertext(N) || tag(16)

    AAD = the first 164 bytes; AES-GCM tag therefore covers every field
    except ``aes_blob`` itself.
    """
    if len(wrapped_dek_blob) != _WRAPPED_DEK_LEN:
        raise ValueError(f"wrapped_dek must be exactly {_WRAPPED_DEK_LEN} bytes")
    aad = _ENVELOPE_MAGIC + bytes([_ENVELOPE_VERSION]) + _hash_id(key_id) + _hash_id(purpose) + wrapped_dek_blob
    # Use ``if/raise`` rather than ``assert`` so the check is not stripped
    # under ``python -O`` / ``PYTHONOPTIMIZE=1`` (in-tree code-reviewer MEDIUM).
    if len(aad) != _ENVELOPE_AAD_LEN:
        raise AssertionError(f"internal error: assembled AAD is {len(aad)} bytes, expected {_ENVELOPE_AAD_LEN}")
    nonce = secrets.token_bytes(_AES_NONCE_LEN)
    ct_tag = AESGCM(dek).encrypt(nonce, plaintext, aad)
    aes_blob = nonce + ct_tag
    return aad + len(aes_blob).to_bytes(_AES_BLOB_LEN_FIELD_LEN, "big") + aes_blob


def _parse_envelope(
    blob: bytes,
    expected_key_id: str,
    expected_purpose: str,
) -> tuple[bytes, bytes, bytes]:
    """Validate the MREN header and return ``(aad, wrapped_dek_blob, aes_blob)``.

    Raises :exc:`mordred_hermes.keyvault._exceptions.WrapParseError` on any
    structural mismatch, magic/version disagreement, key_id_hash mismatch,
    or purpose_hash mismatch. The purpose_hash compare uses
    :func:`hmac.compare_digest` so cross-purpose attempts cannot be
    distinguished by timing (the wrap layer is then never reached, so the
    user is not prompted — codex HIGH #2).
    """
    if len(blob) < _ENVELOPE_HEADER_LEN:
        raise WrapParseError(f"envelope too short: {len(blob)} bytes, expected at least {_ENVELOPE_HEADER_LEN}")
    if blob[0:4] != _ENVELOPE_MAGIC:
        raise WrapParseError(f"envelope magic mismatch: {blob[0:4]!r}")
    if blob[4] != _ENVELOPE_VERSION:
        raise WrapParseError(f"envelope version mismatch: {blob[4]}")

    expected_kid_hash = _hash_id(expected_key_id)
    if not hmac.compare_digest(blob[5 : 5 + _KEY_ID_HASH_LEN], expected_kid_hash):
        raise WrapParseError("envelope key_id_hash does not match expected key_id")

    expected_purpose_hash = _hash_id(expected_purpose)
    purpose_offset = 5 + _KEY_ID_HASH_LEN
    if not hmac.compare_digest(
        blob[purpose_offset : purpose_offset + _PURPOSE_HASH_LEN],
        expected_purpose_hash,
    ):
        raise WrapParseError("envelope purpose_hash does not match expected purpose")

    wrapped_dek_start = purpose_offset + _PURPOSE_HASH_LEN
    wrapped_dek_blob = blob[wrapped_dek_start : wrapped_dek_start + _WRAPPED_DEK_LEN]
    aes_blob_len_offset = wrapped_dek_start + _WRAPPED_DEK_LEN  # = 164
    declared_len = int.from_bytes(blob[aes_blob_len_offset : aes_blob_len_offset + _AES_BLOB_LEN_FIELD_LEN], "big")
    if len(blob) != _ENVELOPE_HEADER_LEN + declared_len:
        raise WrapParseError(
            f"envelope aes_blob_len mismatch: header says {declared_len}, actual {len(blob) - _ENVELOPE_HEADER_LEN}"
        )
    # codex second-pass P2-A: aes_blob must hold at least one AES-GCM nonce
    # plus the 16-byte tag. Anything shorter is structurally invalid; reject
    # BEFORE unwrap_dek so a truncated envelope cannot spend a biometric
    # prompt and emit keyvault.unwrap_authorized only to fail at AES-GCM.
    if declared_len < _AES_NONCE_LEN + _AES_TAG_LEN:
        raise WrapParseError(
            f"envelope aes_blob too short: {declared_len} bytes, "
            f"need at least {_AES_NONCE_LEN + _AES_TAG_LEN} (nonce + tag)"
        )
    # ``safe_read`` returns ``bytes``; slicing ``bytes`` returns ``bytes`` —
    # the explicit wrap is redundant (in-tree code-reviewer NIT-1).
    aad = blob[:_ENVELOPE_AAD_LEN]
    aes_blob = blob[_ENVELOPE_HEADER_LEN:]
    return aad, wrapped_dek_blob, aes_blob


def encrypt(
    key_id: str,
    plaintext: bytes,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Encrypt ``plaintext`` under a fresh per-call DEK; return ``envelope_id``.

    The DEK is wrapped offline via :func:`mordred_hermes.keyvault.wrap.wrap_dek`
    (no biometric prompt, no audit emit). The resulting envelope is persisted
    to ``<keyvault>/ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``
    via the step-B atomic-write helpers under ``keyvault_lock``.
    Returns the URL-safe-base64 ``envelope_id`` (22 chars, no padding).

    ``audit_sink`` is accepted so this surface matches the rest of the
    api.py contract; codex OD-3 specifies that ``encrypt`` does NOT emit
    audit entries at this layer (no authorization gate, and the wrap
    layer never emits on the wrap path).
    """
    del audit_sink  # documented no-op for encrypt; reserved for symmetry with decrypt
    _validate_purpose(purpose)
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)

    dek = secrets.token_bytes(_DEK_LEN)
    try:
        wrapped_dek_blob = wrap.wrap_dek(dek, key_id, backend=backend)
        envelope = _encode_envelope(dek, plaintext, key_id, purpose, wrapped_dek_blob)
    finally:
        # Best-effort wipe — Python bytes are immutable so we cannot zero
        # them in place; leaving the reference unbound lets the GC reclaim
        # sooner than a function-level local would.
        del dek

    envelope_id = _new_envelope_id()

    key_id_hash_hex = _hash_id(key_id).hex()
    purpose_hash_hex = _hash_id(purpose).hex()
    key_dir = root / "ciphertexts" / key_id_hash_hex
    purpose_dir = key_dir / purpose_hash_hex
    envelope_path = purpose_dir / f"{envelope_id}.gcm"

    with _storage.keyvault_lock(root):
        # codex pre-merge P2-1: validate any pre-existing directory before
        # writing inside it. Without this an attacker who pre-creates the
        # key_dir as a symlink (or with wrong mode) could redirect the
        # envelope into attacker-controlled territory.
        #
        # Cross-module private access (in-tree code-reviewer LOW-3,
        # 2026-05-15): ``_storage._check_dir_mode`` is intentionally
        # consumed across the api.py / _storage.py boundary inside the
        # same ``mordred_hermes.keyvault`` package. The underscore prefix
        # signals "package-internal", not "module-internal" — the same
        # pattern PR3 uses for ``_exceptions.py`` shared between
        # ``native.py`` and ``wrap.py``. Step-G may promote the helper to
        # ``_storage.validate_existing_dir`` if a third call site appears.
        if key_dir.exists() or key_dir.is_symlink():
            _storage._check_dir_mode(key_dir)
        else:
            key_dir.mkdir(mode=0o700)
            os.chmod(key_dir, 0o700)
        if purpose_dir.exists() or purpose_dir.is_symlink():
            _storage._check_dir_mode(purpose_dir)
        else:
            purpose_dir.mkdir(mode=0o700)
            os.chmod(purpose_dir, 0o700)
        _storage.atomic_write(envelope_path, envelope)

    return envelope_id


def decrypt(
    key_id: str,
    envelope_id: str,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    """Decrypt an MREN envelope and return the plaintext.

    Reads ``ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``;
    rejects mismatched ``key_id_hash`` or ``purpose_hash`` with
    :exc:`WrapParseError` *before* calling
    :func:`mordred_hermes.keyvault.wrap.unwrap_dek` so a cross-purpose
    replay attempt does not spend a biometric prompt (codex HIGH #2).

    On purpose match the wrap layer is invoked, which may prompt the user
    for biometric authorization and emits exactly one
    ``keyvault.unwrap_authorized`` or ``keyvault.unwrap_denied`` audit
    entry via the supplied ``audit_sink``. ``decrypt`` does NOT
    double-emit at the api layer (codex OD-3).
    """
    _validate_purpose(purpose)
    _validate_envelope_id(envelope_id)
    root = _storage.resolve_keyvault_dir(home)
    envelope_path = _envelope_path_for(root, key_id, purpose, envelope_id)

    # codex second-pass P2-B: O_NOFOLLOW in safe_read only protects the
    # final .gcm component. Refuse symlinked intermediate dirs (key_dir /
    # purpose_dir) explicitly so an attacker who has swapped one of them
    # for a symlink cannot redirect the read into attacker territory.
    # Each existing dir must also be mode 0o700.
    key_dir = envelope_path.parent.parent
    purpose_dir = envelope_path.parent
    if key_dir.exists() or key_dir.is_symlink():
        _storage._check_dir_mode(key_dir)
    if purpose_dir.exists() or purpose_dir.is_symlink():
        _storage._check_dir_mode(purpose_dir)

    blob = _storage.safe_read(envelope_path)
    aad, wrapped_dek_blob, aes_blob = _parse_envelope(blob, key_id, purpose)
    dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
    try:
        nonce = aes_blob[:_AES_NONCE_LEN]
        ct_tag = aes_blob[_AES_NONCE_LEN:]
        return AESGCM(dek).decrypt(nonce, ct_tag, aad)
    finally:
        del dek
