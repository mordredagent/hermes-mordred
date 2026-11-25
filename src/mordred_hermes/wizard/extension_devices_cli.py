"""``hermes-mordred extension devices`` — the browsers this Hermes trusts.

A browser is added from the browser itself: it connects, shows a check code,
and Hermes asks for Touch ID or the Mac login password with the same code
(:mod:`mordred_hermes.extension.trust`). This command lists the approved
browsers and removes one, which closes its open connections. Removing needs no
approval; adding always does.
"""

from __future__ import annotations

import argparse
import sys
import time


def extension_devices(*, remove: str | None = None) -> int:
    from ..extension import trust

    store = trust.store()
    try:
        if remove is not None:
            if not store.remove(remove):
                print(f"No approved browser with id {remove}.", file=sys.stderr)
                return 1
            print(f"Removed {remove}. Its connections close on their next request.")
            return 0
        state = store.load(fresh=True)
    except trust.TrustError as exc:
        print(f"Could not read the trusted browsers ({exc.reason}).", file=sys.stderr)
        return 2
    if state is None:
        print("No browser has connected yet.")
        return 0
    print(f"Approval key (V): {trust.fingerprint(state.v_spki)}" + ("  [test root]" if state.kind == "test" else ""))
    if not state.devices:
        print("No approved browsers.")
        return 0
    for device in sorted(state.devices.values(), key=lambda d: d.added_at):
        added = time.strftime("%Y-%m-%d %H:%M", time.localtime(device.added_at))
        print(f"{device.device_id}  {added}  {device.label}")
    return 0


def cli_extension_devices(args: argparse.Namespace) -> int:
    return extension_devices(remove=getattr(args, "remove", None))
