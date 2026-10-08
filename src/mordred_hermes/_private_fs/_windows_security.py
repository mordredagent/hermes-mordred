"""Pure DACL policy, kept independent from ctypes and account-name localization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ._types import PrivateFSError

if TYPE_CHECKING:
    from ._windows_api import OwnedHandle


def _sid(authority: int, *subauthorities: int) -> bytes:
    return (
        bytes((1, len(subauthorities)))
        + authority.to_bytes(6, "big")
        + b"".join(x.to_bytes(4, "little") for x in subauthorities)
    )


SYSTEM = _sid(5, 18)
ADMINISTRATORS = _sid(5, 32, 544)
TRUSTED_INSTALLER = _sid(5, 80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464)
OWNER_RIGHTS = _sid(3, 4)
FULL_CONTROL = 0x1F01FF

# Position of an inspected object relative to the managed image: the image
# file, its immediate parent directory, or any directory strictly above that
# parent (including the volume root unless the root is the parent).
ManagedImageRole = Literal["image", "image_parent", "upper_ancestor"]


@dataclass(frozen=True)
class Ace:
    kind: int
    flags: int
    mask: int
    sid: bytes


@dataclass(frozen=True)
class Descriptor:
    owner: bytes
    protected: bool
    aces: list[Ace] | None


def _mapped(mask: int) -> int:
    for generic, specific in (
        (0x10000000, FULL_CONTROL),
        (0x80000000, 0x120089),
        (0x40000000, 0x120116),
        (0x20000000, 0x1200A0),
    ):
        if mask & generic:
            mask = (mask & ~generic) | specific
    return mask


def check_private(descriptor: Descriptor, user: bytes) -> None:
    trustees = {user, SYSTEM, ADMINISTRATORS}
    if descriptor.owner != user or not descriptor.protected or descriptor.aces is None:
        raise PrivateFSError("unsafe", "private_acl")
    found: set[bytes] = set()
    for ace in descriptor.aces:
        if (
            ace.kind != 0
            or ace.flags != 0
            or ace.sid not in trustees
            or ace.sid in found
            or _mapped(ace.mask) != FULL_CONTROL
        ):
            raise PrivateFSError("unsafe", "private_acl")
        found.add(ace.sid)
    if found != trustees:
        raise PrivateFSError("unsafe", "private_acl")


def check_ancestor(descriptor: Descriptor, user: bytes, *, creating_child: bool) -> None:
    trusted = {user, SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER}
    # Directory FILE_ADD_FILE also permits reparse-relevant data mutation.
    forbidden = 0x10000 | 0x40000 | 0x80000 | 0x100 | 0x40 | 0x10 | 0x2
    if creating_child:
        forbidden |= 0x4
    _check_mutation_grants(descriptor, trusted, forbidden, "ancestor_acl")


def _check_mutation_grants(
    descriptor: Descriptor, trusted: set[bytes], forbidden: int, operation: str, *, strict: bool = False
) -> None:
    if descriptor.owner not in trusted or descriptor.aces is None:
        raise PrivateFSError("unsafe", operation)
    for ace in descriptor.aces:
        if ace.kind not in (0, 1) or ace.flags & ~0x1F or (strict and _mapped(ace.mask) & ~FULL_CONTROL):
            raise PrivateFSError("unsafe", operation)
        if ace.flags & 0x08 or ace.kind == 1:
            continue  # Deny ACEs cannot excuse an unsafe allow ACE.
        mask = _mapped(ace.mask)
        principal = descriptor.owner if ace.sid == OWNER_RIGHTS else ace.sid
        if mask & ~FULL_CONTROL or (principal not in trusted and mask & forbidden):
            raise PrivateFSError("unsafe", operation)


def check_managed_image(descriptor: Descriptor, user: bytes, service_sid: bytes, *, role: ManagedImageRole) -> None:
    """Separate role-based installation policy; the current principal is never a writer.

    service_sid must come from the bounded native fixed-account validation.
    Every role requires a trusted owner, refuses unknown ACE kinds/flags/rights
    and refuses untrusted DELETE, FILE_DELETE_CHILD, WRITE_DAC and WRITE_OWNER,
    the rights that replace, rename or re-secure an existing component.

    The image and its immediate parent also refuse untrusted write-data/add-file,
    append/add-subdirectory, write-EA and write-attributes: the application
    directory leads the DLL search order, so a planted DLL or ``<image>.local``
    folder would run inside the admitted image. Upper ancestors admit those
    entry-creation rights (the Windows default ProgramData ACL): new entries are
    creator-owned and cannot collide with an existing child, and every component
    is separately verified to be a non-reparse directory on pinned handles and
    named reopens. Storage admission (check_ancestor) is deliberately unchanged.
    """
    if service_sid != TRUSTED_INSTALLER:
        raise PrivateFSError("unsafe", "managed_service_sid")
    forbidden = 0x10000 | 0x40000 | 0x80000 | 0x40
    if role in ("image", "image_parent"):
        forbidden |= 0x2 | 0x4 | 0x10 | 0x100
    elif role != "upper_ancestor":
        raise PrivateFSError("unsafe", "managed_image_role")
    trusted = {SYSTEM, ADMINISTRATORS, service_sid} - {user}
    _check_mutation_grants(descriptor, trusted, forbidden, "managed_image_acl", strict=True)


def current_user_sid() -> bytes:
    from ._windows_api import get_api

    return get_api().user_sid()


def validate_private(handle: OwnedHandle, *, directory: bool) -> None:
    metadata = handle.api.metadata(handle)
    if metadata.directory != directory or metadata.reparse or (not directory and metadata.links != 1):
        raise PrivateFSError("unsafe", "object_type")
    check_private(handle.api.descriptor(handle), handle.api.user_sid())


def validate_ancestor(handle: OwnedHandle, *, creating_child: bool) -> None:
    metadata = handle.api.metadata(handle)
    if not metadata.directory or metadata.reparse:
        raise PrivateFSError("unsafe", "ancestor_type")
    check_ancestor(handle.api.descriptor(handle), handle.api.user_sid(), creating_child=creating_child)


def check_confidential(descriptor: Descriptor, user: bytes) -> None:
    """Admit inherited safe grants without changing an existing descriptor."""
    if descriptor.owner != user or descriptor.aces is None:
        raise PrivateFSError("unsafe", "confidential_acl")
    for ace in descriptor.aces:
        mask = _mapped(ace.mask)
        if ace.kind not in (0, 1) or ace.flags & ~0x1F or mask & ~FULL_CONTROL:
            raise PrivateFSError("unsafe", "confidential_acl")
        principal = descriptor.owner if ace.sid == OWNER_RIGHTS else ace.sid
        if ace.kind == 0 and not ace.flags & 0x08 and mask and principal not in (user, SYSTEM, ADMINISTRATORS):
            raise PrivateFSError("unsafe", "confidential_acl")


def validate_confidential_file(handle: OwnedHandle) -> None:
    metadata = handle.api.metadata(handle)
    if metadata.directory or metadata.reparse or metadata.links != 1:
        raise PrivateFSError("unsafe", "object_type")
    check_confidential(handle.api.descriptor(handle), handle.api.user_sid())
