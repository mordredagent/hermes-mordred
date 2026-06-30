# mordred-hermes — name reservation stub

This directory builds an **intentionally empty `0.0.0.dev0` package**.

It is **not** the real Mordred privacy plugin bundle. Its only purpose is
to claim the `mordred-hermes` name on TestPyPI and PyPI *before* the
public documentation launch, so a third party cannot squat the name and
ship a malicious package (Mordred `TODO.md` §0.5 L70, milestone "M7").

The real package — the sibling [`mordred-hermes/`](../../) project,
version `0.1.0a0` and up — is published later. PEP 440 orders
`0.0.0.dev0 < 0.1.0a0`, so this stub never blocks the real release.
`mordred-hermes/tests/test_packaging_versions.py` enforces that ordering.

## Build & publish

The publish path is `.github/workflows/release.yml`:

- `mode=reserve` — builds and uploads **this stub** (run once, TestPyPI then PyPI).
- `mode=release` — builds and uploads the **real** `mordred-hermes/` package.

See `docs/dev/CI.md` § `release.yml` for the operator runbook
(PyPI Trusted Publishing / pending-publisher setup).
