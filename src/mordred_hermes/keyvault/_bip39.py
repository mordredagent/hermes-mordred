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
from importlib.resources import files

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
    words = mnemonic.split()
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
