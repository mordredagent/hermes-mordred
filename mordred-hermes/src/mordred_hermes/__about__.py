# Single source of truth for the mordred-hermes package version.
#
# Hatchling reads ``__version__`` from this file at build time
# (``[tool.hatch.version] path`` in pyproject.toml), so the version is NOT
# hardcoded in pyproject. This file lives INSIDE the importable package —
# not in the docs tree (mordred-docs/dev/VERSION) — because a
# sdist->wheel build runs in an isolated directory that does not contain
# anything outside mordred-hermes/. Reading the docs-tree VERSION marker at
# build time would therefore break (TODO 0.5 L64). Keeping the canonical
# value here is the build-isolation-safe resolution of that follow-up.
#
# Bump with `python tools/bump_version.py <new-version>`, which rewrites this
# file, the docs VERSION marker, and every plugin.yaml in lockstep. The
# consistency is pinned by tests/test_packaging_versions.py.
__version__ = "0.1.0a0"
