# Running the base Hermes agent (host CLI)

> **This is a different CLI from Mordred.** [`QUICKSTART.md`](./QUICKSTART.md)
> and [`USAGE.md`](./USAGE.md) drive `hermes-mordred` — the privacy layer. This
> page covers the **base Hermes agent**, the `hermes` command itself, run from
> *this* dev checkout. You do not need any of it to set Mordred up; it is here
> because both commands live in the **same** `.venv` (`hermes` arrives as the
> `hermes-agent` dependency), and newcomers reasonably want to know how to drive
> the agent underneath.
>
> For anything beyond the basics below, the authority is
> [hermes-agent's own documentation](https://pypi.org/project/hermes-agent/) —
> this repo deliberately does not mirror it.


## The `hermes` binary is already in `.venv`

The base `hermes` agent ships inside the **same** `.venv` you built in
[Build the venv](./QUICKSTART.md#build-the-venv) — it comes from the `hermes-agent`
dependency, so there is **nothing extra to build**. If you skipped that step, a
plain `uv sync` from the repo root creates `.venv` with both binaries:

```sh
cd <repo-root>            # /Users/.../Mordred-Hermes
uv sync                   # reads ./uv.lock, creates ./.venv with `hermes` + `hermes-mordred`
```

Plain `uv sync` (no `--extra`) is enough to run the base agent; the
`--extra macos` / `--extra keyvault` from
[QUICKSTART](./QUICKSTART.md#build-the-venv) only adds Mordred's keyvault
crypto stack. (Base-agent integrations such as the messaging gateway and local
voice are `hermes-agent`'s own extras, not re-exposed by this repo — see the
hermes-agent docs to enable them.) Confirm it landed:

```sh
.venv/bin/hermes --version   # prints  Project: <repo-root>
```

> **No uv?** `brew install uv` (macOS), or
> `curl -LsSf https://astral.sh/uv/install.sh | sh`. Re-running `uv sync` is safe
> and idempotent.

## Launch this repo's copy (not the global one)

A global `hermes` may already be on your `PATH` at `~/.local/bin/hermes` — that
is a **separate install** (`~/.hermes/hermes-agent/`), not this checkout. Once
you've [built `.venv`](./QUICKSTART.md#build-the-venv), activate it to run this repo's
pinned copy:

```sh
cd <repo-root>                 # /Users/.../Mordred-Hermes
source .venv/bin/activate      # fish: source .venv/bin/activate.fish
which hermes                   # → <repo-root>/.venv/bin/hermes  (confirms the repo copy)
hermes --version               # prints  Project: <repo-root>
```

- **Purpose**: make `hermes` resolve to this repo's `.venv` copy, overriding the global one.
- **Result**: activation prepends `.venv/bin` to `PATH`, so `hermes` now runs the
  `hermes-agent` version pinned in `uv.lock` (installed into `.venv`, not the
  global `~/.local/bin/hermes`). `deactivate` reverts to the global `hermes`.

> One-shot without activating: run the binary directly — `.venv/bin/hermes <args>`.

## Good first commands to try

No provider or auth needed — pure sanity checks:

| Do (command) | Purpose |
|---|---|
| `hermes doctor` | Diagnose environment / config problems. |
| `hermes status` | One-screen dashboard (model, keys, auth). |
| `hermes tools` | List / toggle the 40+ tools. |
| `hermes config list` | Dump current config. |
| `hermes model` | Interactive provider + model picker. |

Real end-to-end smoke test — needs a provider. The free path is Nous Portal OAuth:

```sh
hermes auth add nous --type oauth        # free login, opens a browser
hermes -z "Say hi and list your tools"   # one-shot prompt — fastest "does it work"
hermes                                    # full interactive TUI
```

> Have an API key instead? Put e.g. `OPENROUTER_API_KEY=…` in a `.env`, or run
> `hermes config set`, then skip the Portal login.

## First-time setup

```sh
hermes setup                  # full interactive wizard
```

Walks six sections in order: **model** (provider + model — the key one),
**terminal** (where the agent runs), **gateway** (messaging platforms — skip if
CLI-only), **tools**, **agent**, **tts** (optional). Variants:

| Do (command) | Purpose |
|---|---|
| `hermes setup --quick` | Only prompt for what is missing / unset. |
| `hermes setup model` | Re-run a single section. |
| `hermes setup --reset` | Reset config back to defaults. |

Verify with `hermes status` (keys show ✓), then `hermes -z "say hi"`.

## Run it in the background (messaging gateway)

The agent CLI is not a daemon — the long-running background process is the
**messaging gateway** (Telegram / Discord / Slack / …). Configure a platform
first, then pick a run mode:

```sh
hermes gateway setup          # configure a platform (e.g. Telegram bot token)
```

| Do (command) | Purpose | Result |
|---|---|---|
| `hermes gateway install` → `hermes gateway start` | Install + run as a macOS **launchd** service. | Background service surviving logout/restart; manage with `gateway status` / `stop` / `restart`. |
| `hermes gateway run` | Foreground (good for testing, WSL, Docker, Termux). | Runs until Ctrl-C. |
| `nohup hermes gateway run > ~/hermes-gateway.log 2>&1 &` | Quick detached background run. | Logs to the file; survives the shell. |

> **Dev-copy caveat.** `gateway install` writes a launchd unit pointing at
> whichever `hermes` resolves *at install time*. To bind the service to **this
> repo's** copy, run `install` with the venv activated; otherwise it picks up the
> global `~/.local/bin/hermes`. For day-to-day repo testing, `gateway run` inside
> tmux/screen is simpler and unambiguous.

---

## Back to Mordred

- [`QUICKSTART.md`](./QUICKSTART.md) — the Mordred setup path.
- [`USAGE.md`](./USAGE.md) — full Mordred command reference.
