---
name: tor-skill
description: Synthetic test fixture — a skill that declares Tor as its required network path.
metadata:
  mordred:
    network_requirements: tor
---

# Tor Skill (test fixture)

This skill is used by `tests/test_install_wrapper.py` to assert that
strict-mode policy allows installation of Tor-declared skills.
