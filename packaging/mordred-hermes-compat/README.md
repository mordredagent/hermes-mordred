# mordred-hermes compatibility package

The real Mordred plugin bundle moved to the `hermes-mordred` distribution in
version `0.1.0a16`. This package preserves existing install commands by
depending on the exact matching `hermes-mordred` release and forwarding every
optional extra.

This wheel deliberately contains no `mordred_hermes` modules and no console
scripts. All runtime files are owned by `hermes-mordred`, which keeps install
and uninstall behavior safe when both distribution names are present.
