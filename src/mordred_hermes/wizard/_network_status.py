"""Network configuration readers that keep "unconfigured" and "unreadable" apart.

A missing file or an absent key is legitimate unconfigured state. Damaged config
or a refused Windows generation is not: ``status`` and ``network status`` report
it as :data:`NETWORK_UNAVAILABLE`, and ``network init`` and ``setup`` refuse it.
``read_default_path_strict`` decides damage for both, with one exception: the
write flows accept what they can repair without losing saved settings, an invalid
``default_path`` or a blank ``plugins`` / ``mordred_network`` key.
Heavy imports stay function-local so the module imports on any platform.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Final

from .._core._config_io import passive_canonical_reads
from .._core._yaml_io import load_yaml_mapping

NETWORK_UNAVAILABLE: Final[str] = "unavailable"
NETWORK_UNAVAILABLE_DETAIL: Final[str] = "configuration could not be safely read"
NETWORK_UNAVAILABLE_REMEDY: Final[str] = "stop other Mordred processes or repair config.yaml"
_SECTION: Final[str] = "mordred_network"


def read_configured_network_path(config_path: Path, *, log: logging.Logger) -> str:
    """Return the configured path, or :data:`NETWORK_UNAVAILABLE`; never raises ``Exception``."""
    from ..network.settings import read_default_path_strict

    try:
        with passive_canonical_reads():
            return read_default_path_strict(config_path)
    except Exception as exc:
        # Parser diagnostics can quote config values: keep only the type name.
        log.warning("could not read network configuration from %s: %s", config_path, type(exc).__name__)
        return NETWORK_UNAVAILABLE


def read_network_section_or_raise(config_path: Path) -> dict[str, Any] | None:
    """Return the ``mordred_network`` section, ``None`` when unconfigured, or raise on damage.

    For flows that may write: an invalid ``default_path`` inside a readable
    section is returned so re-running setup can repair it, and a blank key is
    ``None`` because the writers fill it in.
    """
    from ..network.settings import read_default_path_strict

    root = load_yaml_mapping(config_path, catch=())
    plugins = root.get("plugins")
    section = plugins.get(_SECTION) if isinstance(plugins, dict) else None
    if isinstance(section, dict):
        return section
    blank_plugins = "plugins" in root and plugins is None
    blank_section = isinstance(plugins, dict) and _SECTION in plugins and section is None
    if not (blank_plugins or blank_section):
        # The loader also yields an empty mapping for a non-mapping root. The
        # strict reader raises for that and for non-mappings below it, and
        # accepts true absence.
        read_default_path_strict(config_path)
    return None
