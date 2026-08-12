#!/usr/bin/env python3
"""PreToolUse guard: block destructive hermes-mordred ceremonies without HERMES_HOME.

``configure`` / ``keyvault init`` / ``network init`` read and write the real
``~/.hermes/`` profile unless HERMES_HOME points elsewhere (see
docs/dev/setup.md, "Verifying the local build"). This hook blocks such
commands in AI sessions unless the command string sets HERMES_HOME.

Heuristic only: it inspects the single command string, so an HERMES_HOME
exported in an earlier command is not seen. Prefer the one-line form:
    env HERMES_HOME=/tmp/mordred-test-home .venv/bin/hermes-mordred configure
"""

import json
import re
import sys

DESTRUCTIVE = re.compile(
    r"hermes-mordred\s+(?:-\S+\s+)*"
    r"(?:configure\b|keyvault\s+(?:-\S+\s+)*init\b|network\s+(?:-\S+\s+)*init\b)"
)

BLOCK_MESSAGE = (
    "Blocked by guard_hermes_home hook: this hermes-mordred ceremony mutates "
    "the production ~/.hermes/ profile.\n"
    "Re-run with an isolated home, e.g.:\n"
    "  env HERMES_HOME=/tmp/mordred-test-home .venv/bin/hermes-mordred configure\n"
    "(see docs/dev/setup.md, 'Verifying the local build')\n"
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # malformed input: never block unrelated calls
    command = payload.get("tool_input", {}).get("command", "")
    if DESTRUCTIVE.search(command) and "HERMES_HOME" not in command:
        sys.stderr.write(BLOCK_MESSAGE)
        return 2  # exit 2 = blocking error; stderr is fed back to the model
    return 0


if __name__ == "__main__":
    sys.exit(main())
