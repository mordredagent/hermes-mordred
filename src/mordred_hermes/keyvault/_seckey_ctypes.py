"""ctypes bypass for ``SecKeyCreateRandomKey`` Secure-Enclave generation.

The pyobjc-framework-Security C extension has a long-standing bridge bug
where ``SecKeyCreateRandomKey(attrs, None)`` raises a bare Python
``KeyError`` for CFString constants ``'public'`` / ``'private'`` /
``'applepay'`` when ``kSecAttrTokenIDSecureEnclave`` is present in
``attrs`` — version-independent across pyobjc 10 / 11 / 12 and not fixed
upstream. The root cause is not the ``SecKeyCreateRandomKey`` call site;
it is the pyobjc-managed ``NSDictionary`` attrs argument: Apple's
framework probes the dictionary for token-handler keys via
``CFDictionaryGetValue``, and pyobjc's NSDictionary proxy raises Python
``KeyError`` on missing keys instead of returning ``NULL`` as
``CFDictionary`` does.

This module avoids the bridge entirely by:

1. Loading ``Security.framework`` and ``CoreFoundation.framework`` via
   :mod:`ctypes`.
2. Building the ``attrs`` argument as a real ``CFDictionary`` via
   ``CFDictionaryCreate`` — no pyobjc ``NSDictionary`` in the picture.
3. Calling ``SecKeyCreateRandomKey`` through the ``ctypes`` function
   pointer.
4. Wrapping the returned ``SecKeyRef`` and ``CFErrorRef`` back as pyobjc
   objects so the rest of the Security API (``SecKeyCopyPublicKey``,
   ``SecKeyCopyExternalRepresentation``, ``SecItemDelete``) — which is
   *not* affected by the bridge bug — keeps working unchanged.

The module is macOS-only. On other platforms importing
``_lazy_import_security`` already raises
:class:`~mordred_hermes.keyvault._exceptions.WrapNativeUnavailable`, so
the ctypes path is only entered after the Darwin / Secure-Enclave gates
have passed.

Memory ownership follows Core Foundation rules: every CF object this
module creates with ``Create`` / ``Copy`` has +1 retain and is
``CFRelease``-d before the helper returns. The returned ``SecKeyRef``
has +1 retain; pyobjc's :func:`objc.objc_object` takes ownership of
that retain so the Python wrapper releases on GC. Same for the
``CFErrorRef``.
"""

from __future__ import annotations

import ctypes
import threading
from ctypes import (
    POINTER,
    byref,
    c_bool,
    c_char_p,
    c_int32,
    c_int64,
    c_long,
    c_uint32,
    c_void_p,
)
from typing import Any

# kCFNumberType values from CFNumber.h. SInt64 lets callers pass arbitrary
# Python ints without overflow on 64-bit builds.
_kCFNumberSInt64Type = 4

# CFString encoding for CFStringCreateWithBytes — UTF-8.
_kCFStringEncodingUTF8 = 0x08000100


# CFString constant names whose value (a Python str) the production attrs
# dict uses as keys / values. The pyobjc-exported value happens to equal
# the CFString constant's contents (e.g. ``sec.kSecAttrKeyType`` is the
# Python str ``"type"``). We translate each occurrence back to the raw
# CFString constant pointer via ``dlsym`` so the framework sees the
# canonical interned CFString rather than a bridged copy.
_SEC_CONST_NAMES = (
    "kSecAttrKeyType",
    "kSecAttrKeyTypeECSECPrimeRandom",
    "kSecAttrKeySizeInBits",
    "kSecAttrTokenID",
    "kSecAttrTokenIDSecureEnclave",
    # Reserved: re-introduce when iOS Data Protection Keychain support
    # is added. Phase 4 dropped DPK from `_PyobjcSecKeyOps._create` and
    # `_keychain_query` for unsigned-Python compatibility, but the
    # bridge layer still resolves the dlsym address so a future
    # callsite can re-add it without touching this constant table.
    "kSecUseDataProtectionKeychain",
    "kSecPrivateKeyAttrs",
    "kSecAttrIsPermanent",
    "kSecAttrApplicationTag",
    "kSecAttrLabel",
    "kSecAttrAccessControl",
)


class _LibBundle:
    """Lazy-loaded handles for CoreFoundation + Security ctypes bindings."""

    def __init__(self) -> None:
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")

        # --- CoreFoundation -------------------------------------------
        self.cf.CFDictionaryCreate.restype = c_void_p
        self.cf.CFDictionaryCreate.argtypes = [
            c_void_p,  # allocator (NULL = default)
            POINTER(c_void_p),  # keys
            POINTER(c_void_p),  # values
            c_long,  # count
            c_void_p,  # keyCallBacks
            c_void_p,  # valueCallBacks
        ]
        self.cf.CFNumberCreate.restype = c_void_p
        self.cf.CFNumberCreate.argtypes = [c_void_p, c_int32, c_void_p]
        self.cf.CFDataCreate.restype = c_void_p
        self.cf.CFDataCreate.argtypes = [c_void_p, c_char_p, c_long]
        self.cf.CFStringCreateWithBytes.restype = c_void_p
        self.cf.CFStringCreateWithBytes.argtypes = [
            c_void_p,
            c_char_p,
            c_long,
            c_uint32,
            c_bool,
        ]
        self.cf.CFRelease.restype = None
        self.cf.CFRelease.argtypes = [c_void_p]

        true_ptr = c_void_p.in_dll(self.cf, "kCFBooleanTrue").value
        false_ptr = c_void_p.in_dll(self.cf, "kCFBooleanFalse").value
        if true_ptr is None or false_ptr is None:
            raise RuntimeError("CoreFoundation kCFBoolean constants are NULL")
        self.kCFBooleanTrue: int = true_ptr
        self.kCFBooleanFalse: int = false_ptr
        self.key_callbacks = ctypes.addressof(c_void_p.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks"))
        self.value_callbacks = ctypes.addressof(c_void_p.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks"))

        # --- Security -------------------------------------------------
        self.sec.SecKeyCreateRandomKey.restype = c_void_p
        self.sec.SecKeyCreateRandomKey.argtypes = [c_void_p, POINTER(c_void_p)]

        self.consts: dict[str, int] = {}
        for name in _SEC_CONST_NAMES:
            const_ptr = c_void_p.in_dll(self.sec, name).value
            if const_ptr is None:
                raise RuntimeError(f"Security constant {name} is NULL")
            self.consts[name] = const_ptr
        self._str_const_lookup: dict[str, int] | None = None


_BUNDLE: _LibBundle | None = None
_BUNDLE_LOCK = threading.Lock()


def _bundle() -> _LibBundle:
    global _BUNDLE
    if _BUNDLE is None:
        with _BUNDLE_LOCK:
            if _BUNDLE is None:
                _BUNDLE = _LibBundle()
    return _BUNDLE


def _str_const_lookup(sec_module: Any) -> dict[str, int]:
    """Map ``sec.kFoo`` (Python str) → the raw CFString constant pointer.

    Each pyobjc-exported ``kSec*`` constant is a Python str whose value
    equals the CFString constant's contents. The lookup recognises each
    pyobjc constant by value and substitutes the canonical interned
    CFString from ``dlsym`` so the Apple framework code sees the same
    pointer it would in a native call.
    """
    bundle = _bundle()
    cached = bundle._str_const_lookup
    if cached is not None:
        return cached
    lookup = {getattr(sec_module, name): bundle.consts[name] for name in _SEC_CONST_NAMES}
    bundle._str_const_lookup = lookup
    return lookup


def _cf_number(bundle: _LibBundle, value: int, owned: list[int]) -> int:
    """Allocate a CFNumber (SInt64) for ``value`` and record it in ``owned``."""
    n = c_int64(value)
    cfn: int = bundle.cf.CFNumberCreate(None, _kCFNumberSInt64Type, byref(n))
    if not cfn:
        raise MemoryError("CFNumberCreate returned NULL")
    owned.append(cfn)
    return cfn


def _cf_data(bundle: _LibBundle, value: bytes | bytearray, owned: list[int]) -> int:
    """Allocate a CFData copy of ``value`` and record it in ``owned``."""
    buf = bytes(value)
    d: int = bundle.cf.CFDataCreate(None, buf, len(buf))
    if not d:
        raise MemoryError("CFDataCreate returned NULL")
    owned.append(d)
    return d


def _cf_string(bundle: _LibBundle, value: str, sec_module: Any, owned: list[int]) -> int:
    """Return the interned ``kSec*`` constant for ``value``, else a new CFString.

    Only the freshly allocated CFString is recorded in ``owned`` — the
    interned constants have their own lifetimes.
    """
    lookup = _str_const_lookup(sec_module)
    const_ptr = lookup.get(value)
    if const_ptr is not None:
        return const_ptr
    b = value.encode("utf-8")
    s: int = bundle.cf.CFStringCreateWithBytes(None, b, len(b), _kCFStringEncodingUTF8, False)
    if not s:
        raise MemoryError("CFStringCreateWithBytes returned NULL")
    owned.append(s)
    return s


def _build_cf(value: Any, sec_module: Any, owned: list[int]) -> int:
    """Convert a Python value to a CF pointer.

    Anything allocated (``CFNumber``, ``CFData``, ``CFString``, nested
    ``CFDictionary``) is appended to ``owned`` so the caller can release
    it after the SecKey call returns. Constants and pyobjc-owned objects
    are *not* appended — they have their own lifetimes.
    """
    bundle = _bundle()

    # bool MUST be checked before int — `isinstance(True, int)` is True.
    if isinstance(value, bool):
        return bundle.kCFBooleanTrue if value else bundle.kCFBooleanFalse

    if isinstance(value, int):
        return _cf_number(bundle, value, owned)

    if isinstance(value, (bytes, bytearray)):
        return _cf_data(bundle, value, owned)

    if isinstance(value, str):
        return _cf_string(bundle, value, sec_module, owned)

    if isinstance(value, dict):
        return _build_dict(value, sec_module, owned)

    # pyobjc object (e.g. SecAccessControl produced by SecAccessControlCreateWithFlags).
    # objc.pyobjc_id returns the raw NSObject id; CFDictionaryCreate will
    # CFRetain it via the value callbacks. The pyobjc wrapper keeps its
    # own retain for `value`'s lifetime, so the CF object stays alive
    # across the call.
    import objc  # local import — pyobjc unavailable on non-Darwin

    pyobjc_id: int = objc.pyobjc_id(value)
    return pyobjc_id


def _build_dict(py_dict: dict[Any, Any], sec_module: Any, owned: list[int]) -> int:
    """Recursively convert a Python dict to a CFDictionaryRef."""
    bundle = _bundle()
    n = len(py_dict)
    keys = (c_void_p * n)()
    vals = (c_void_p * n)()
    for i, (k, v) in enumerate(py_dict.items()):
        keys[i] = c_void_p(_build_cf(k, sec_module, owned))
        vals[i] = c_void_p(_build_cf(v, sec_module, owned))
    d: int = bundle.cf.CFDictionaryCreate(
        None,
        keys,
        vals,
        n,
        bundle.key_callbacks,
        bundle.value_callbacks,
    )
    if not d:
        raise MemoryError("CFDictionaryCreate returned NULL")
    owned.append(d)
    return d


def create_random_key_via_ctypes(sec_module: Any, attrs: dict[Any, Any]) -> tuple[Any, Any]:
    """Call ``SecKeyCreateRandomKey`` via ``ctypes`` to bypass the pyobjc
    NSDictionary bridge bug.

    Mirrors ``sec.SecKeyCreateRandomKey(attrs, None)``'s return shape:

    - On success, returns ``(SecKeyRef, None)`` — the key wrapped as a
      pyobjc object so downstream pyobjc calls (``SecKeyCopyPublicKey``
      etc.) accept it unchanged.
    - On failure, returns ``(None, CFErrorRef)`` — the error wrapped as
      a pyobjc ``NSError`` so the caller's existing
      ``_nserror_code`` / ``_nserror_domain`` extraction works without
      branching.

    Raises only on programming bugs (e.g. ``CFDictionaryCreate`` running
    out of memory), never on Apple-framework rejections.
    """
    bundle = _bundle()
    owned: list[int] = []
    try:
        attrs_cf = _build_dict(attrs, sec_module, owned)
        err_ptr = c_void_p(0)
        key_ptr = bundle.sec.SecKeyCreateRandomKey(attrs_cf, byref(err_ptr))

        import objc  # local import — pyobjc unavailable on non-Darwin

        # objc.objc_object takes ownership of the +1 retain the C call
        # produced for SecKeyRef and the CFErrorRef out-param.
        key_obj = objc.objc_object(c_void_p=key_ptr) if key_ptr else None
        err_obj = objc.objc_object(c_void_p=err_ptr.value) if err_ptr.value else None
        return key_obj, err_obj
    finally:
        # Release every CF object we created during dict construction.
        # Bottom-up order is safe: a child's refcount drops to 1
        # (parent dict's retain still holds it) and only reaches 0 when
        # the parent is released later in this loop.
        cf_release = bundle.cf.CFRelease
        for ptr in owned:
            if ptr:
                cf_release(ptr)
