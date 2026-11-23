"""``python -m mordred_hermes`` — the ``hermes-mordred`` CLI.

Runs the same entry as the console script (``[project.scripts]`` in
``pyproject.toml``). On the Hermes Desktop layout the installer's
``hermes-mordred`` wrapper goes through the managed launcher,
``hermes --run-module mordred_hermes ...``, so it follows whichever environment
Hermes currently selects instead of naming one that a Hermes update deletes.
That bootstrap calls ``sys.exit(0)`` after ``runpy.run_module`` returns, so the
CLI's exit code must leave through ``SystemExit`` here.
"""

from __future__ import annotations

if __name__ == "__main__":
    from mordred_hermes.wizard.cli import main

    raise SystemExit(main())
