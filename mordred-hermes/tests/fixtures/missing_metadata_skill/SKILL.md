---
name: missing-metadata-skill
description: Synthetic test fixture — a skill with no metadata.mordred extension at all.
---

# Missing-metadata Skill (test fixture)

This skill is used by `tests/test_install_wrapper.py` to assert that
strict-mode blocks installation of skills missing Mordred metadata, and
that lenient mode warns + allows.
