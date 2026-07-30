"""mordred_keyvault._bip39 — BIP39 24-word mnemonic generation.

``keyvault init`` (Phase 4 PR10) generates the Seed Phrase the user
transcribes by hand. SPEC.md §"Key hierarchy" fixes v1 at a 24-word
BIP39 seed (256-bit entropy), so this module deliberately supports
*only* 256-bit entropy — other lengths raise ``ValueError`` rather than
silently producing a shorter phrase.

The 2048-word English wordlist is vendored verbatim from the canonical
BIP-0039 reference (``bitcoin/bips`` ``bip-0039/english.txt``,
SHA-256 ``2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda``)
as ``_bip39_wordlist.txt`` — vendored rather than added as a dependency
to keep the keyvault dependency surface minimal.

Stdlib-only (``hashlib`` for the SHA-256 checksum, ``secrets`` for
entropy), so this module imports on every platform.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from importlib.resources import files

#: BIP39 PBKDF2 parameters (BIP-0039 §"From mnemonic to seed"): HMAC-SHA512,
#: 2048 iterations, 64-byte output. The salt is "mnemonic" concatenated with
#: the (optional) passphrase. Both mnemonic and passphrase are NFKD-normalized.
_SEED_PBKDF2_ROUNDS = 2048
_SEED_LEN = 64
_SEED_SALT_PREFIX = "mnemonic"

#: v1 keyvault: 256-bit entropy → 24 words. No other size is accepted.
_ENTROPY_BYTES = 32
_WORD_COUNT = 24
_BITS_PER_WORD = 11
_CHECKSUM_BITS = _ENTROPY_BYTES * 8 // 32  # BIP39: ENT/32 = 8 bits
_TOTAL_BITS = _ENTROPY_BYTES * 8 + _CHECKSUM_BITS  # 264
_WORDLIST_SIZE = 2048
_WORDLIST_FILE = "_bip39_wordlist.txt"


def _load_wordlist() -> tuple[str, ...]:
    raw = files("mordred_hermes.keyvault").joinpath(_WORDLIST_FILE).read_text(encoding="utf-8")
    words = tuple(raw.split())
    if len(words) != _WORDLIST_SIZE:
        raise RuntimeError(f"BIP39 wordlist must have {_WORDLIST_SIZE} words, got {len(words)}")
    return words


#: The canonical 2048-word BIP39 English wordlist, index-ordered.
WORDLIST: tuple[str, ...] = _load_wordlist()
_WORD_INDEX: dict[str, int] = {word: index for index, word in enumerate(WORDLIST)}


def canonicalize_mnemonic(mnemonic: str) -> str:
    """Return the canonical BIP39 sentence represented by ``mnemonic``.

    BIP39 applies NFKD Unicode normalization, and the mnemonic itself is a
    sequence of words separated by single spaces. Validation has always used
    ``str.split()``, so leading/repeated/alternate whitespace was accepted;
    canonicalizing at the same boundary prevents those ignored characters
    from later changing the PBKDF2 seed.
    """
    return " ".join(unicodedata.normalize("NFKD", mnemonic).split())


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Encode 32 bytes of entropy as a 24-word BIP39 mnemonic.

    Raises:
        ValueError: ``entropy`` is not exactly 32 bytes.
    """
    if len(entropy) != _ENTROPY_BYTES:
        raise ValueError(f"v1 keyvault requires {_ENTROPY_BYTES}-byte (256-bit) entropy, got {len(entropy)}")
    checksum = hashlib.sha256(entropy).digest()[0]  # first _CHECKSUM_BITS bits
    bits = (int.from_bytes(entropy, "big") << _CHECKSUM_BITS) | checksum
    words = []
    for i in range(_WORD_COUNT):
        shift = _TOTAL_BITS - (i + 1) * _BITS_PER_WORD
        words.append(WORDLIST[(bits >> shift) & 0x7FF])
    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Decode a 24-word BIP39 mnemonic back to its 32-byte entropy.

    Validates that every word is in the wordlist and that the trailing
    BIP39 checksum matches — the cross-check that catches a
    mis-transcribed Seed Phrase.

    Raises:
        ValueError: wrong word count, an unknown word, or a checksum
            mismatch.
    """
    words = canonicalize_mnemonic(mnemonic).split()
    if len(words) != _WORD_COUNT:
        raise ValueError(f"v1 keyvault requires a {_WORD_COUNT}-word mnemonic, got {len(words)}")
    bits = 0
    for word in words:
        try:
            index = _WORD_INDEX[word]
        except KeyError:
            raise ValueError(f"word not in the BIP39 English wordlist: {word!r}") from None
        bits = (bits << _BITS_PER_WORD) | index
    entropy = (bits >> _CHECKSUM_BITS).to_bytes(_ENTROPY_BYTES, "big")
    checksum = bits & ((1 << _CHECKSUM_BITS) - 1)
    if checksum != hashlib.sha256(entropy).digest()[0]:
        raise ValueError("BIP39 checksum mismatch — mnemonic is corrupt or mis-transcribed")
    return entropy


def generate_mnemonic() -> str:
    """Generate a fresh random 24-word BIP39 mnemonic (256-bit entropy)."""
    return entropy_to_mnemonic(secrets.token_bytes(_ENTROPY_BYTES))


#: Standard BIP39 mnemonic word counts (ENT = 128..256 bits).
_VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


def validate_mnemonic(mnemonic: str) -> None:
    """Validate any standard BIP39 mnemonic: wordlist membership + checksum.

    Unlike :func:`mnemonic_to_entropy` (v1 keyvault is 24-word-only), this
    accepts every standard BIP39 length (12/15/18/21/24 words) so the HD
    wallet can also store an imported external seed (e.g. a 12-word
    MetaMask phrase). Raises :class:`ValueError` on a wrong word count, an
    unknown word, or a checksum mismatch.
    """
    words = canonicalize_mnemonic(mnemonic).split()
    count = len(words)
    if count not in _VALID_WORD_COUNTS:
        raise ValueError(f"BIP39 mnemonic must be one of {_VALID_WORD_COUNTS} words, got {count}")
    bits = 0
    for word in words:
        try:
            index = _WORD_INDEX[word]
        except KeyError:
            raise ValueError(f"word not in the BIP39 English wordlist: {word!r}") from None
        bits = (bits << _BITS_PER_WORD) | index
    total_bits = count * _BITS_PER_WORD  # MS = ENT + ENT/32
    checksum_bits = total_bits // 33  # CS = MS/33 = ENT/32
    entropy_bits = total_bits - checksum_bits
    entropy = (bits >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    checksum = bits & ((1 << checksum_bits) - 1)
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if checksum != expected:
        raise ValueError("BIP39 checksum mismatch — mnemonic is corrupt or mis-transcribed")


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive the 64-byte BIP39 seed from a mnemonic + optional passphrase.

    Implements BIP-0039 §"From mnemonic to seed": the binary seed is
    ``PBKDF2(HMAC-SHA512, password=NFKD(mnemonic), salt="mnemonic"||NFKD(passphrase),
    2048 rounds, dklen=64)``. Both inputs are NFKD-normalized as the spec
    mandates; no casefolding (the wordlist is already lowercase, and a
    passphrase's case is significant).

    The ``passphrase`` here is the BIP39 "25th word", independent of the
    keyvault's own Passphrase used for the verification digest / backup KDF.
    """
    norm_mnemonic = canonicalize_mnemonic(mnemonic)
    salt = unicodedata.normalize("NFKD", _SEED_SALT_PREFIX + passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512",
        norm_mnemonic.encode("utf-8"),
        salt.encode("utf-8"),
        _SEED_PBKDF2_ROUNDS,
        dklen=_SEED_LEN,
    )
