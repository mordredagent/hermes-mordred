---
name: release
description: Run the hermes-mordred release runbook — version bump, dev PR, dev→main release PR, canonical-first TestPyPI/PyPI verification, compatibility shim, tag. Use when the user asks to release, publish, or bump the package version.
---

# hermes-mordred release runbook

**Source of truth: `docs/dev/CI.md` §"Normal release (runbook)".** This skill is
a thin operational wrapper. If anything below disagrees with CI.md, CI.md wins —
re-read it before proceeding, and update this skill in the same PR.

## Ground rules

- **PyPI is irreversible.** A published version/filename can never be reused,
  even after deletion. Always bump; never re-release an existing version.
- **The `pypi` Environment has no required reviewers** (billing-plan
  constraint) — dispatching the production workflow publishes immediately.
  **Never run steps 7 or 9 without the user's explicit go-ahead in this
  session, covering both production projects.**
- Parallel Claude sessions may share this checkout: re-check
  `git status` / `git log` / open PRs immediately before any branch, commit,
  or PR mutation.
- Feature PRs (including the bump PR) target `dev`, never `main`.

## Steps

1. **Version bump** (mandatory, PEP 440 — e.g. `0.1.0a4`, `0.1.0b0`, `0.1.0`):

   ```sh
   uv run python tools/bump_version.py <new-version>
   uv run pytest tests/test_packaging_versions.py -q   # all pinned surfaces agree
   ```

2. **Bump PR into `dev`** — normal feature branch → PR with `--base dev`.
   Include `### Changes` / `### Fixes` lines as usual. Wait for CI green, merge.

3. **dev→main release PR** — open a PR from `dev` to `main`. In the
   description, aggregate the `### Changes` / `### Fixes` entries from every
   PR included since the last release (this becomes the release notes).
   Confirm CI green, merge.

4. **TestPyPI canonical publish** (from the `main` ref):

   ```sh
   gh workflow run release.yml --ref main -f target=testpypi -f mode=release \
     -f expected-version=<version>
   gh run watch   # confirm success
   ```

5. **Verify the TestPyPI install** in a fresh venv:

   ```sh
   pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ "hermes-mordred==<version>"
   ```

   Then confirm entry-point discovery is 6/6 (`PluginManager.discover_and_load`
   snippet in `docs/dev/setup.md`) and `hermes-mordred --version` runs.

   **Always run the discovery snippet with an isolated `HERMES_HOME`**
   (e.g. `HERMES_HOME=$(mktemp -d)`). A bare install has no `argon2`, so a
   discovery probe against the real home triggers the plaintext audit-writer
   takeover and rotates the production encrypted audit log aside.

6. **TestPyPI compatibility publish** — publish only after step 5 succeeds:

   ```sh
   gh workflow run release.yml --ref main -f target=testpypi -f mode=compat \
     -f expected-version=<version>
   ```

   In another fresh venv, install `mordred-hermes==<version>`. Confirm it
   resolves the matching `hermes-mordred` release, then uninstall only
   `mordred-hermes` and confirm the import package and CLI still work.

7. **Production canonical publish — STOP and confirm with the user first**
   that both the canonical publish here and the compatibility publish in step
   9 are authorized (both are immediate and irreversible):

   ```sh
   gh workflow run release.yml --ref main -f target=pypi -f mode=release \
     -f expected-version=<version>
   ```

8. **Verify the production install** — fresh venv, pinned `hermes-mordred`
   install from PyPI,
   re-confirm discovery 6/6 + CLI.

9. **Production compatibility publish** — publish `mode=compat` only after
   step 8 succeeds, then repeat the shim install/uninstall ownership checks
   from step 6. Proceed only when the step-7 confirmation explicitly covered
   both production projects.

10. **Tag + GitHub Release** — annotated tag `v<version>` on main's release
   merge commit; create a GitHub Release (use `--prerelease` for pre-release
   versions) with the notes aggregated in step 3.

## After finishing

Report the published version, the PyPI URL, the tag, and any deviations from
this runbook.
