# hermes-mordred — name reservation stub

This directory builds an intentionally empty `0.0.0.dev0` distribution. It
reserved the canonical `hermes-mordred` name on TestPyPI and PyPI before the
real plugin bundle moved from its legacy `mordred-hermes` distribution name.

It contains no Mordred plugins, console scripts, or migration behavior. The
reservation was published on 2026-08-12 and this source is retained for audit;
the real implementation ships as `hermes-mordred` from `0.1.0a16`.

Do not publish this stub again. PyPI version files are immutable, and both
indexes already contain `0.0.0.dev0`.
