"""Shared foundation helpers (formerly the flat ``mordred_hermes/_*.py`` files).

Everything here is private to hermes-mordred and must not import any component
package (``keyvault``, ``network``, ...); the import-linter contracts in
``pyproject.toml`` (``[tool.importlinter]``) enforce that. The two interpreter
startup modules named by the shipped ``.pth`` files (``_pth_bootstrap``,
``_runtime_bootstrap``) and the ``_private_fs`` package deliberately stay at
the package root.
"""
