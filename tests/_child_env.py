"""Child interpreters that import the ``mordred_hermes`` under test.

A child launched with a scrubbed or replaced ``PYTHONPATH`` imports whatever
copy its site-packages holds. In a source checkout run against another
interpreter (for example a Hermes venv that already has an installed
hermes-mordred) that is a different, older package. These helpers name the
directory the parent actually imported the package from (``src`` for a
checkout, site-packages for a wheel) so the child sees the same code.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import mordred_hermes

PACKAGE_ROOT = Path(os.path.realpath(mordred_hermes.__file__)).parents[1]


def with_package_under_test(env: Mapping[str, str], *extra: Path) -> dict[str, str]:
    """Return ``env`` with ``PYTHONPATH`` = package root, ``extra``, then any prior value."""
    result = dict(env)
    entries = [str(PACKAGE_ROOT), *map(str, extra)]
    if result.get("PYTHONPATH"):
        entries.append(result["PYTHONPATH"])
    result["PYTHONPATH"] = os.pathsep.join(entries)
    return result


def site_pth_for_package_under_test(site_directory: str) -> str:
    """``.pth`` text exposing ``site_directory`` (with its ``.pth`` hooks) behind the package root.

    A path line is appended to ``sys.path`` before ``addsitedir`` appends the
    dependency site, so the package under test wins over any other copy there.
    """
    return f"{PACKAGE_ROOT}\nimport site; site.addsitedir({site_directory!r})\n"
