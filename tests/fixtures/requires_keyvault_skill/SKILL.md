---
name: requires-keyvault-skill
description: Synthetic test fixture — a skill that opts into Mordred keyvault protection.
metadata:
  mordred:
    network_requirements: local-only
    requires_keyvault: true
---

# Requires-Keyvault Skill (test fixture)

This skill is used by `tests/test_install_wrapper.py` to assert that
`hermes-mordred install` enforces `metadata.mordred.requires_keyvault`:
strict mode blocks the install when the keyvault holds no keys, lenient
mode warns, and off mode allows. `network_requirements: local-only` keeps
the network decision at `allow` so the keyvault decision is observed in
isolation.
