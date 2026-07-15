---
name: release
description: Run the mordred-hermes release runbook — version bump, dev PR, dev→main release PR, TestPyPI dry run, verification, PyPI publish, tag. Use when the user asks to release, publish, or bump the package version.
---

# mordred-hermes release runbook

**Source of truth: `docs/dev/CI.md` §"Normal release (runbook)".** This skill is
a thin operational wrapper. If anything below disagrees with CI.md, CI.md wins —
re-read it before proceeding, and update this skill in the same PR.

## Ground rules

- **PyPI is irreversible.** A published version/filename can never be reused,
  even after deletion. Always bump; never re-release an existing version.
- **The `pypi` Environment has no required reviewers** (billing-plan
  constraint) — dispatching the production workflow publishes immediately.
  **Never run step 6 without the user's explicit go-ahead in this session.**
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

4. **TestPyPI dry run** (from the `main` ref):

   ```sh
   gh workflow run release.yml --ref main -f target=testpypi -f mode=release
   gh run watch   # confirm success
   ```

5. **Verify the TestPyPI install** in a fresh venv:

   ```sh
   pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ "mordred-hermes==<version>"
   ```

   Then confirm entry-point discovery is 5/5 (`PluginManager.discover_and_load`
   snippet in `docs/dev/setup.md`) and `hermes-mordred --version` runs.

6. **Production publish — STOP and confirm with the user first** (immediate,
   irreversible):

   ```sh
   gh workflow run release.yml --ref main -f target=pypi -f mode=release
   ```

7. **Verify the production install** — fresh venv, pinned install from PyPI,
   re-confirm discovery 5/5 + CLI.

8. **Tag + GitHub Release** — annotated tag `v<version>` on main's release
   merge commit; create a GitHub Release (use `--prerelease` for pre-release
   versions) with the notes aggregated in step 3.

## After finishing

Report the published version, the PyPI URL, the tag, and any deviations from
this runbook.
