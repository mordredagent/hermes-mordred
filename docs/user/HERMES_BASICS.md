# Running the base Hermes agent (host CLI)

> **This is different from Mordred.** `hermes` runs the agent;
> `hermes-mordred` configures the privacy layer. The authoritative source for
> Hermes itself is the
> [official Hermes documentation](https://github.com/NousResearch/hermes-agent/tree/main/website/docs).

## Install Hermes

On macOS, the Hermes Desktop installer is the recommended graphical route. For
a command-line installation on macOS or Linux, use the official installer:

```sh
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

Open a new terminal after it finishes. The installer provisions Python, `uv`,
dependencies, a managed environment under `~/.hermes/hermes-agent/`, and the
`hermes` command on `PATH`. You do not need to create a project virtual
environment for normal use.

Verify the installation without configuring a provider:

```sh
hermes doctor
hermes version
```

## The `hermes` binary is already in `.venv`

This applies to a development checkout: `uv sync --all-extras` creates the
repository's `.venv` with both `hermes` and `hermes-mordred`. Normal users do
not need that environment; the official installer puts Hermes in its managed
environment under `~/.hermes/hermes-agent/venv` and exposes `hermes` on `PATH`.

## First-time setup

The fastest provider setup uses Nous Portal OAuth:

```sh
hermes setup --portal
```

For the full interactive wizard instead:

```sh
hermes setup
```

It configures the model, terminal, messaging gateway, tools, agent behavior,
and optional speech features. Re-run only missing items with
`hermes setup --quick`, or choose a provider later with `hermes model`.

## Good first commands to try

| Command | Purpose |
|---|---|
| `hermes` | Start the interactive agent. |
| `hermes -z "Say hi"` | Run one prompt and exit. |
| `hermes doctor` | Diagnose environment and configuration problems. |
| `hermes status` | Show model, authentication, and runtime status. |
| `hermes tools` | Configure available tools. |
| `hermes model` | Select the provider and model. |
| `hermes update` | Update an installer-managed Hermes checkout. |

## Run it in the background (messaging gateway)

Configure a messaging platform first:

```sh
hermes gateway setup
```

Then choose a run mode:

| Command | Purpose |
|---|---|
| `hermes gateway run` | Run in the foreground until Ctrl+C. |
| `hermes gateway install` | Install a launchd/systemd service. |
| `hermes gateway start` | Start the installed service. |
| `hermes gateway status` | Check the service. |
| `hermes gateway restart` | Restart after configuration or plugin updates. |

## Launch this repo's copy (not the global one)

Contributors who need the repository's editable Hermes dependency should use
[`docs/dev/setup.md`](../dev/setup.md). That environment is deliberately
separate from the normal installer-managed Hermes environment.

## Back to Mordred

- [`QUICKSTART.md`](./QUICKSTART.md) — install and configure Mordred.
- [`USAGE.md`](./USAGE.md) — complete Mordred command reference.
