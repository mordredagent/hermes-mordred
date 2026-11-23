"""Recognise the exact objects Hermes's connection tracking hands the guarded runtime.

``hermes_cli.sqlite_safe_read.connect_tracked`` (Hermes 2026-07+) always passes
a tracking connection factory, and after opening registers a no-argument SQL
function whose callable releases its registry entry once SQLite frees it.
Both are matched only against the module already in ``sys.modules`` and its
own attributes; Hermes is never imported from here.
"""

from __future__ import annotations

import re
import sys
import types
from collections.abc import Mapping
from typing import Any, Final

MODULE: Final = "hermes_cli.sqlite_safe_read"
#: Class-body entries CPython 3.11-3.15 itself puts in ``class X(_TrackingMixin,
#: Connection): """doc"""`` and ``type(name, (_TrackingMixin, Connection), {})``,
#: plus the caches annotation introspection adds later (``__annotations__`` on
#: 3.11-3.13; ``__annotate_func__``/``__annotations_cache__`` on 3.14+).
#: Anything else is a method or attribute of the factory's own.
_FACTORY_KEYS: Final = frozenset(
    {
        "__module__",
        "__doc__",
        "__dict__",
        "__weakref__",
        "__firstlineno__",
        "__static_attributes__",
        "__annotations__",
        "__annotate_func__",
        "__annotations_cache__",
    }
)
_RELEASE_NAME: Final = re.compile(r"_hermes_release_[0-9a-f]{16}")


def _attributes() -> dict[str, Any] | None:
    module = sys.modules.get(MODULE)
    return vars(module) if isinstance(module, types.ModuleType) else None


def _plain_class(value: object) -> bool:
    return type(value) is type and value.__bases__ == (object,)


def is_tracking_factory(factory: object, bases: tuple[type, ...]) -> bool:
    """Whether ``factory`` is exactly Hermes's ``_TrackingMixin`` over one of ``bases``.

    Hermes passes ``TrackedConnection`` or a cached ``Tracked<X>``. Any own
    class attribute, extra or reordered base, foreign mixin or metaclass refuses.
    """
    if type(factory) is not type:
        return False
    attributes = _attributes()
    if attributes is None:
        return False
    mixin = attributes.get("_TrackingMixin")
    if not _plain_class(mixin):
        return False
    if len(factory.__bases__) != 2 or factory.__bases__[0] is not mixin:
        return False
    base = factory.__bases__[1]
    return any(base is allowed for allowed in bases) and set(vars(factory)) <= _FACTORY_KEYS


def is_release_function(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> bool:
    """Whether ``create_function(*args, **kwargs)`` registers Hermes's release sentinel.

    Exactly ``(_RELEASE_FUNCTION, 0, <_ReleaseOnClose instance>)`` as Hermes's
    own module defines them, with no options; a subclass instance refuses.
    """
    if kwargs or len(args) != 3:
        return False
    attributes = _attributes()
    if attributes is None:
        return False
    name, narg, function = args
    expected = attributes.get("_RELEASE_FUNCTION")
    if type(name) is not str or type(expected) is not str or name != expected:
        return False
    if not _RELEASE_NAME.fullmatch(name) or type(narg) is not int or narg != 0:
        return False
    cls = attributes.get("_ReleaseOnClose")
    return _plain_class(cls) and type(function) is cls
