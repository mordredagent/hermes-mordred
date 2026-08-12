# hermes-mordred — name reservation stub

This directory builds an intentionally empty `0.0.0.dev0` distribution. It
reserves the future canonical `hermes-mordred` name on TestPyPI and PyPI before
the real plugin bundle moves from its legacy `mordred-hermes` distribution
name.

It contains no Mordred plugins, console scripts, or migration behavior. The
real implementation continues to ship as `mordred-hermes` until the staged
rename documented in `docs/dev/MIGRATION.md` is complete.

Publish this stub only through `.github/workflows/release.yml` with
`mode=reserve-rename`, first to TestPyPI and then to PyPI.
