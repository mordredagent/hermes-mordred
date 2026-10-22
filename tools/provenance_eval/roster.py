"""The synthetic roster: Japanese and English names, RFC 2606 addresses only.

Two pairs of different people share a display name (``田中 太郎`` and
``John Smith``); one person writes under two names and addresses (the alias
case). Telegram ids are synthetic and never collide with real accounts' meaning.
"""

from __future__ import annotations

from typing import Final

from .truth import Identity, Person, Role

__all__ = [
    "ALIAS",
    "BOT",
    "CHANNEL",
    "OTHERS_BY_LANG",
    "OWNER",
    "PEOPLE",
    "SAME_NAME_BY_LANG",
]


def _person(
    person_id: str,
    role: Role,
    identities: tuple[tuple[str, str], ...],
    telegram_id: int,
    short_names: tuple[str, ...],
) -> Person:
    return Person(
        person_id=person_id,
        role=role,
        identities=tuple(Identity(name=name, address=address) for name, address in identities),
        telegram_id=telegram_id,
        short_names=short_names,
    )


OWNER: Final = _person("p00", Role.OWNER, (("佐々木 葵", "owner@example.com"),), 5_000_001, ("佐々木", "Sasaki"))
_TANAKA_A: Final = _person("p01", Role.OTHER, (("田中 太郎", "tanaka@example.org"),), 5_000_101, ("田中", "Tanaka"))
_TANAKA_B: Final = _person(
    "p02", Role.OTHER, (("田中 太郎", "taro.tanaka@example.net"),), 5_000_102, ("田中", "Tanaka")
)
ALIAS: Final = _person(
    "p03",
    Role.OTHER,
    (("Hanako Suzuki", "hanako@example.org"), ("鈴木 花子", "h.suzuki@example.net")),
    5_000_103,
    ("Suzuki", "鈴木", "Hanako", "花子"),
)
_SMITH_A: Final = _person("p04", Role.OTHER, (("John Smith", "john.smith@example.com"),), 5_000_104, ("Smith",))
_SMITH_B: Final = _person("p05", Role.OTHER, (("John Smith", "jsmith@example.org"),), 5_000_105, ("Smith",))
_CLARK: Final = _person("p06", Role.OTHER, (("Emily Clark", "emily.clark@example.net"),), 5_000_106, ("Clark", "Emily"))
_SATO: Final = _person("p07", Role.OTHER, (("佐藤 一郎", "ichiro.sato@example.net"),), 5_000_107, ("佐藤", "Sato"))
_YAMAMOTO: Final = _person(
    "p08", Role.OTHER, (("山本 健", "ken.yamamoto@example.org"),), 5_000_108, ("山本", "Yamamoto")
)
_WONG: Final = _person("p09", Role.OTHER, (("Lisa Wong", "lisa.wong@example.org"),), 5_000_109, ("Wong", "Lisa"))
_TAKAHASHI: Final = _person(
    "p10", Role.OTHER, (("高橋 美咲", "misaki.takahashi@example.com"),), 5_000_110, ("高橋", "Takahashi")
)
_BROOKS: Final = _person(
    "p11", Role.OTHER, (("Daniel Brooks", "dan.brooks@example.com"),), 5_000_111, ("Brooks", "Daniel")
)
BOT: Final = _person("p12", Role.BOT, (("Example Notifier", "no-reply@notify.example.com"),), 5_000_112, ("Notifier",))
CHANNEL: Final = _person("p13", Role.CHANNEL, (("Example Status", "status@lists.example.org"),), 5_000_113, ())

PEOPLE: Final = (
    OWNER,
    _TANAKA_A,
    _TANAKA_B,
    ALIAS,
    _SMITH_A,
    _SMITH_B,
    _CLARK,
    _SATO,
    _YAMAMOTO,
    _WONG,
    _TAKAHASHI,
    _BROOKS,
    BOT,
    CHANNEL,
)
#: Ordinary participants, drawn per thread language.
OTHERS_BY_LANG: Final = {"ja": (_SATO, _YAMAMOTO, _TAKAHASHI), "en": (_CLARK, _WONG, _BROOKS)}
#: Two different people with one display name, per thread language.
SAME_NAME_BY_LANG: Final = {"ja": (_TANAKA_A, _TANAKA_B), "en": (_SMITH_A, _SMITH_B)}
