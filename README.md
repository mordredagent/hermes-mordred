# hermes-mordred

[![PyPI](https://img.shields.io/pypi/v/hermes-mordred)](https://pypi.org/project/hermes-mordred/)
[![CI](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml/badge.svg)](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml)

Privacy-preserving plugins for the
[Hermes agent](https://github.com/NousResearch/hermes-agent): hardware-backed
keys, Tor/VPN routing, local-LLM policy enforcement, encrypted audit data,
end-to-end gateway messages, and macOS-integrated at-rest encryption.

**Status: active alpha.** New users should start with the
**[Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)**.

## The plugins

The package exposes six `hermes_agent.plugins` entry points:

| Plugin | Purpose |
|---|---|
| `mordred_privacy_check` | Skill-metadata policy enforcement and audit logging |
| `mordred_wizard` | The `hermes-mordred` CLI |
| `mordred_llm_guard` | Strict-mode local-LLM enforcement |
| `mordred_network` | Tor, VPN, and clearnet path management |
| `mordred_keyvault` | Secure Enclave / TPM-backed key management |
| `mordred_e2e` | Encrypted Slack and Discord gateway commands and replies |

## Requirements

- Python 3.11 or newer and `hermes-agent>=0.13.0`.
- macOS or Linux. Windows and mobile support are deferred.
- macOS provides the complete transparent `.env`, configuration, memory, and
  workspace lifecycle. Linux supports the TPM-backed keyvault, while those
  transparent encryption targets remain inactive.

Mordred is a cooperative control layer inside Hermes, not an operating-system
sandbox. See the
[specification](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/SPEC.md#threat-model--accepted-limitations)
for the security boundary and accepted limitations.

## Install (users, from PyPI)

Start with an installed Hermes Agent, then run the Mordred installer:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
hermes-mordred setup
hermes-mordred status
```

The installer does not configure Mordred or create keys. Version pins, optional
features, inspect-before-running steps, platform commands, and expected output
are documented in the
[Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md).

### Enable the plugins

`hermes-mordred setup` runs `configure`, which enables all six `mordred_*`
plugins. Manual configuration is covered by the
[usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#2-first-run-quickstart).

### Use it

Use `hermes-mordred status` for the overall state. On macOS, guided setup also
offers agent-memory protection through `hermes-mordred encryption enable memory`.
The complete command reference and security ceremonies live in the
[usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md).

Once Hermes 0.19.0+ is configured and the plugins are enabled,
`hermes mordred <command>` exposes the same command tree. On older Hermes
versions, or before the first `configure`, keep using `hermes-mordred`.

### Verify discovery

```sh
hermes-mordred plugins list
```

Use Mordred's command rather than `hermes plugins list`, which does not list
package entry points.

## Browser-extension WebSocket gateway (preview)

The optional browser-extension server, encrypted gateway messaging, history,
wallet bridge, installation, pairing, and troubleshooting are documented in
the dedicated
[Extension guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md).

### How it works

See the Extension guide's
[security model](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#security-model)
and
[gateway encryption](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#gateway-message-encryption).

### Run it (standalone)

Follow
[Start and pair](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#start-and-pair).
The server is optional and does not start automatically.

### Standalone behavior notes

Deployment and lifecycle behavior are maintained under
[Standalone behavior](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#standalone-behavior).

## Install (development)

Follow the
[development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md)
for the editable `.venv`, safe `HERMES_HOME` isolation, and validation suite.

## Troubleshooting

Use the [general troubleshooting guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#8-troubleshooting)
or the [Extension troubleshooting table](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#troubleshooting).

## Upgrading

Package upgrades, feature extras, and configuration migration are documented
under [Package upgrades and removal](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#9-package-upgrades-and-removal).

## Uninstall

Follow the [safe uninstall procedure](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#uninstall-safely)
before removing the package or native keys.

## Repository layout

See the [development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md#repository-layout)
and [developer documentation index](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/README.md).

## Documentation

| Audience | Document | Purpose |
|---|---|---|
| Users | [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md) | Install and first protected setup |
| Users | [Usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md) | Commands, ceremonies, upgrades, and removal |
| Users | [Extension guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md) | Browser extension, E2E messaging, and wallet bridge |
| Developers | [Development index](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/README.md) | Maintained sources of truth |
| Developers | [Development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md) | Editable environment and validation workflow |

## License

MIT
