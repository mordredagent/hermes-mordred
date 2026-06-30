---
name: clearnet-skill
description: Synthetic test fixture — a skill that declares clearnet network access.
metadata:
  mordred:
    network_requirements: clearnet
---

# Clearnet Skill (test fixture)

This skill is used by `tests/test_install_wrapper.py` to assert that
strict-mode policy blocks installation of clearnet-declared skills.
