# Mordred — Specification (Hermes-base)

> **Note**: 本 SPEC は `Hermes (NousResearch/hermes-agent)` を基盤とした Mordred の仕様書です。
> OpenClaw 基準の旧版仕様は `../../mordred/mordred-mvp-docs/SPEC.md` (deprecated) に残置。
> Hermes 化の根拠と用語マッピングは `MIGRATION.md` を参照。

## Vision

**Hermes 上に privacy-enhancement レイヤをプラグインバンドルとして提供する**。

Mordred は Hermes の plugin SDK と既存の機能 (4 種の plugin source、16 種の lifecycle hook、`PluginContext` 経由の登録 API) を全面的に利用し、core を改変しない (plugin 開発リポジトリとして独立) ことを基本とする。プライバシーレイヤは **5 つのプラグイン + 1 つのスキルメタデータ規約** として配布される。

ユーザは `pip install mordred-hermes` だけで導入でき、`hermes mordred ...` サブコマンドで設定・運用する。

Privacy concerns addressed:

1. **network-path observability** (Phase 3、 macOS / Linux / WSL2)
2. **cloud LLM dependency** (Phase 2、 macOS / Linux / WSL2)
3. **local secret custody at rest** (Phase 4、 **v1 では macOS Apple Silicon のみ**。 Linux/WSL2 ユーザは Phase 1–3 の保護のみで v1 を運用し、 at-rest secret protection は OS のファイルパーミッション (`0600`) に頼る。 Linux TPM 2.0 / Windows DPAPI / master-password Tier 3 fallback は `v2-OS2`)

Phase 4 が macOS-only である事実は Vision レベルでも明示する。 §Platform Support と §Threat Model の caveat を併読のこと (H2)。

## Project Identity

### Relationship to Hermes

- **Upstream**: github.com/NousResearch/hermes-agent (MIT License)
- **Current repo**: `Mordred-Hermes/` (Mordred plugin 開発リポジトリ。 Hermes upstream の fork/clone ではない)
- **Strategy**: **案 C + Vendored-fork escape hatch** (zero-PR commitment、 MIGRATION.md §10 row 1 / §5 確定 2026-05-07) — Hermes core は改変せず、5 plugin を `pip install mordred-hermes` で配布。 **Hermes 上流への PR は提出しない**
  - `Mordred-Hermes/` は upstream の rebase 不要 (純粋な plugin 開発リポジトリ + 必要時の vendored modules)
  - 5 plugin は `src/mordred_hermes/<name>/` (pip 配布レイアウト) で開発、`pyproject.toml` の `[project.entry-points."hermes_agent.plugins"]` で expose
  - 旧 SPEC の "core seam" 相当は **plugin-side wrapper + audit log** (`mordred.degraded.*` 系列) で defense-in-depth (Tier A、 v1 default)
  - 真に hard-enforce が必要な項目は **vendored fork extra** (Tier B、 v2): `pip install mordred-hermes[hard-lock]` 等で Hermes core モジュールのパッチ版を再配布。 v1 範囲外
- **Compatibility goal**: 既存 Hermes ユーザは `pip install mordred-hermes && hermes mordred upgrade` だけで privacy レイヤを足せる。OpenClaw からの移行ユーザは `hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade` の 3 ステップ

### Platform Support (v1)

| Phase | プラットフォーム |
|-------|-------------------|
| Phase 1–3 (network/privacy-check/llm-guard/wizard) | **macOS / Linux / WSL2** (Hermes が動く全環境) |
| Phase 4 (keyvault, Tier 1) | **macOS Apple Silicon only** (Secure Enclave, `Security.framework`) |
| Phase 4 (keyvault, Tier 2/3) | v2: Linux (TPM 2.0) / Windows (DPAPI) は ROADMAP `v2-OS2` 据え置き |

iOS / Android: Hermes 自体に Termux 対応があるが、Mordred Phase 4 (keyvault) は対象外。Phase 1–3 のみ Termux で動作可能 (Tor は要追加検証)。

### License Note

Hermes は MIT-licensed。フォーク、商用利用、派生製品は許可されている。Mordred 自身も MIT で配布する。

## Threat Model & Accepted Limitations

Mordred defends against:

- **Network observers** (ISP, hostile Wi-Fi, local-network adversaries) — addressed by `mordred_network` (Tor / VPN paths)
- **Cloud LLM operators** seeing prompts and outputs — addressed by `mordred_llm_guard` redirecting to a local-only provider under strict policy
- **Accidental cloud egress** when a user thinks they are local-only — addressed by `mordred_llm_guard` unconditional override under strict policy
- **At-rest secret theft** — addressed by `mordred_keyvault`: local seeds, backups, audit logs, and future signing material are encrypted with AES-GCM data-encryption keys (DEKs) whose wrapping keys are protected by Apple Secure Enclave authorization. The Enclave protects key unwrapping; it does not hold signing keys or run AES itself. Tier 2 (HSM/Keychain/TPM/DPAPI) fallbacks are v2

Mordred does **not** defend against:

- **Malicious skills with truthful metadata** — a skill declaring `network_requirements: clearnet` and being allowed by lenient policy can exfiltrate freely
- **Malicious skills with lying metadata** — Mordred has no skill-metadata signing or integrity verification in v1
- **Local malware / co-resident processes** — `HTTPS_PROXY` env injection is bypassable by direct `connect()` from any process on the same machine. Closing this requires OS-level process isolation (seccomp / sandbox-exec / Endpoint Security), out of reach for the plugin layer (v2)
- **`PATH` hijack of the sekey/tpmkey/winkey helper binary** — `_seckey_helper._find_named_helper()`'s third resolution tier (`shutil.which(name)`, after the `MORDRED_*_HELPER` env override and `~/.local/bin`) trusts whatever the process's `PATH` resolves to. An attacker who can already prepend a writable directory to the user's `PATH` could plant a binary that intercepts the JSON-over-stdio protocol. This requires the same "attacker can already alter the victim's shell environment" precondition as the co-resident-process item above, and the two supported install paths (env var, `~/.local/bin`) are unaffected; kept as v1 accepted risk rather than removing the documented `PATH` fallback (2026-07-07 security review)
- **Skills Hub / agentskills.io registry compromise** — Mordred trusts the registry; no separate signature chain
- **Side-channel timing / traffic analysis** even on Tor
- **Silent plugin-disable** (H3、 zero-PR strategy 下の v1 mitigation) — Hermes 上流への PR を提出しない方針 (MIGRATION.md §10 row 4) のため、 v1 default は plugin-side **strict-mode startup refusal** で防御 (Tier A、 下記 §Plugin-disable protection)。 「次回セッション開始時に block」 する設計なので、 セッション running 中の disable 編集は次起動まで影響しない (Hermes が動的 disable を反映しない前提、 Phase 0.8 で verify)。 hard-enforce (disable 操作そのものを refuse) は v2 `[hard-lock]` extra (vendored fork) で対応
- **Audit-log tampering by attacker with write access as the user** — file mode `0600` is access control, not tamper evidence. Any process running as the user can rewrite history with no detectable trace until Phase 4's HMAC-chain upgrade (v2; PATHS.md §Audit log policy)
- **Air-gap enforcement beyond the standard network stack** — `mordred_network.api.blackout_assert()` detects routable interfaces only; physical air-gap (Bluetooth/USB tethering, hotspot, kernel-level adversaries) remains user responsibility (M4)
- **Screen recording during Seed display** — the 60-second Seed window can be captured by macOS `screencapture`, Loom, Zoom share, OBS, etc. v1 does best-effort screenshot detection only; screen-recording detection is out of scope (M5)

These limitations are explicit; mitigation work is v2+ scope.

### Newly defended via Hermes plugin hooks (no core seam needed)

Hermes は OpenClaw より hook palette が広いため、旧 SPEC で「core seam が必要」とされていた多くの項目が **plugin だけで実現可能**:

- **Per-tool gating** (e.g. blocking `web_fetch` under strict mode without VPN/Tor active) → `pre_tool_call` で実装可能
- **LLM provider override under strict mode** → ~~`pre_llm_call`~~ では **実装不可** (Phase 0.8 verify 完了、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5)。 v0.11.0 の `pre_llm_call` payload は `model` のみで `provider` を含まず、 戻り値も context-injection 専用。 v1 は `on_session_start` で session-scoped enforcement に切り替え (§Story 4 / §Plugin: `mordred_llm_guard` 参照)
- **Gateway dispatch policy** → `pre_gateway_dispatch` で実装可能 (旧 SPEC には無かった追加の防御層)
- **Approval lifecycle observability** → `pre_approval_request` / `post_approval_response` で実装可能 (危険な tool 実行時の audit 強化)

### Defended via plugin-side strict-mode startup refusal (zero-PR strategy)

- **Silent disablement via `hermes plugins disable mordred_*`** → v1 default は **plugin-only**: `plugin.yaml` の `privacy_lock: true` は Mordred 内部 hint として機能し、 各 Mordred plugin の `on_session_start` が sibling-disabled を検出した時点で strict mode 起動を `BaseException` 派生例外で abort する (下記 §Plugin-disable protection 参照)。 Hermes 上流への PR は提出しない (MIGRATION.md §10 row 4 zero-PR commitment)。 hard-enforce が必要なら v2 で `[hard-lock]` extra に vendored fork で対応

### Plugin-only fallback for missing seams

旧 SPEC の S2 (`originSkill` in tool_call) と S3 (`resolvedProvider` in model_resolve) 相当が Hermes 側で payload に含まれていない場合は、 plugin 側で degraded mode (audit log に `mordred.degraded.*` を記録、 generic な tool-name allowlist と unconditional override にフォールバック) で動かす。 zero-PR commitment (`MIGRATION.md` §5、 2026-05-07) のため **Hermes 上流への PR は出さない**。 plugin-only で実現できないと判断した場合は v2 で vendored fork extra (Tier B、 `[hard-lock]`) に escalate するか、 fallback 動作を恒久化するかを再評価する。

**Out-of-band agent harnesses** (Codex, Claude CLI, Cursor, Copilot, ACP adapter): Hermes は ACP adapter を持つので一部はハンドリング可能。strict mode 下では Mordred が enforce できない harness を primary に設定している場合 `hermes mordred` 起動を refuse する。

## Plugin-Only Architecture (Hermes Core 改変ゼロ、 zero-PR strategy)

旧 SPEC の "Core Minimal-Change Policy" は **MIGRATION.md §10 row 1 / §5 確定 (2026-05-07)** で **zero upstream PR** に再定義された。 Hermes core への改変は v1 では一切提出しない:

| 旧改修案 | v1 戦略 | v2 escape hatch |
|----------|---------|-------------------|
| ~~HSeam-1: `plugin.yaml` の `privacy_lock: boolean` を Hermes 上流に追加~~ | **plugin-side のみ**: `privacy_lock: true` は Mordred 内部 hint として保持、 各 Mordred plugin の `on_session_start` が sibling-disabled を検出して `RuntimeError` で abort (§Plugin-disable protection) | `pip install mordred-hermes[hard-lock]` で vendored fork (`hermes_cli/plugins_cmd.py` のパッチ版) を再配布。 v2 で hard-enforce が必要になれば導入 |

**core 改修が必要になりそうな項目は v1 では plugin 側 fallback で動かす方針** (将来も PR は出さず、 必要なら v2 vendored fork に escape):

- ~~`pre_llm_call` payload に `provider_id` / `model_id` を含める拡張~~ → **Phase 0.8 verify (2026-05-10) 完了**: v0.11.0 の `pre_llm_call` payload は `model` のみで `provider` を含まず、 戻り値は **context-injection 専用** (provider override は構造的に不可能)。 `pre_api_request` には provider/model/base_url が乗るが **observer-only** (戻り値捨てられる)。 詳細と Phase 2 再設計案は [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5 を参照。 v1 の `mordred_llm_guard` は `pre_llm_call` 経由のターン毎 override を諦め、 `on_session_start` で provider 設定 (`~/.hermes/config.yaml` または `register_provider`) を strict policy に照らして refuse-or-rewrite する設計に切り替える
- ~~`pre_tool_call` payload に `origin_skill` を含める拡張~~ → **Phase 0.8 verify 完了**: v0.11.0 では payload に `origin_skill` は含まれない (`tool_name`/`args`/`task_id`/`session_id`/`tool_call_id` のみ、 詳細は [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)。 per-skill ポリシーは `pre_tool_call` 経由では実装できないため、 install-time guard (`hermes mordred install` ラッパ CLI) で SKILL.md frontmatter を検査する経路を **唯一の per-skill enforcement 経路** として確定。 runtime の `pre_tool_call` は generic tool-name allowlist のみ
- skill install 時 (`hermes_cli/skills_hub.py`) の pre-install hook → 必要なら新設、それまでは `hermes mordred install` ラッパで代替
- agent process init / shutdown hook → 既存 `on_session_start` / `on_session_end` で代替

各 plugin は `on_session_start` で hook payload の shape を probe し、欠落時は audit log に `mordred.degraded.<seam>` を記録して degraded mode で動作する。 Phase 0.8 verify で確定した payload 形状は [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) (canonical) に集約 — drift watch は `.github/workflows/upstream-check.yml` (週次、 hook **名** drift のみ; payload field shape の再 verify は名前 drift signal を受けた本 doc の手動 bump)。

### What Mordred Adds (5 plugins)

すべての plugin は `src/mordred_hermes/<name>/` にあり、Hermes plugin SDK (`PluginContext`) のみを使う。配布は単一 pip パッケージ `mordred-hermes` で entry-point `hermes_agent.plugins` 経由のロードに対応する。

1. **`mordred_network`** — dynamic 3-layer path switching across Tor / VPN / Clearnet。子プロセス (`tor`/`arti`/Mullvad WireGuard CLI) のライフサイクルを Python `subprocess` で管理。Hermes 子プロセスへの proxy 環境変数注入 (`HTTPS_PROXY`, `ALL_PROXY` 等) と内部 Python API (`mordred_network.api.use`, `status`, `blackout_assert`) を提供。
2. **`mordred_privacy_check`** — privacy policy enforcement at two checkpoints:
   - **Skill install ガード**: 純 hook が無い間は `hermes mordred install <skill>` ラッパ CLI 経由で frontmatter の `metadata.mordred.network_requirements` を読み policy 判定。将来 Hermes に install hook が追加された時点で hook ベースに移行
   - `pre_tool_call` — 汎用 per-tool policy (例: strict mode 下で `web_fetch` を Clearnet で blocking)。`origin_skill` が payload にあれば per-skill ポリシーも、無ければ tool-name allowlist のみ
3. **`mordred_llm_guard`** — Hermes provider adapter として `mordred_llm_guard/local_adapter.py` を登録 + `pre_llm_call` hook で strict mode 下に provider override。local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM) を `mordred-local` として synthetic provider 化
4. **`mordred_keyvault`** — Apple Secure Enclave-backed AES key wrapping (Python から `pyobjc-framework-Security` 経由で `Security.framework` を呼び出し)。CLI の `hermes mordred keyvault ...` サブツリーから操作
5. **`mordred_wizard`** — `hermes mordred ...` サブコマンドツリーを `register_cli_command` で登録。configure / upgrade / install / network / policy / audit / keyvault のすべての CLI を統括

### Conventions (not plugins)

- **Mordred skill metadata** — additive privacy fields under the `metadata.mordred.*` namespace (e.g. `metadata.mordred.network_requirements`, `metadata.mordred.requires_keyvault`)。Hermes/agentskills.io の標準 frontmatter とは namespace が分かれているので衝突しない。Hermes 本体のスキルローダは `metadata.mordred.*` を解釈しない (privacy-check plugin が SKILL.md を再度パースして判定)。

### What Mordred Inherits from Hermes (never modified)

- Full CLI surface: `hermes`, `hermes model`, `hermes tools`, `hermes config`, `hermes gateway`, `hermes setup`, `hermes claw migrate`, `hermes update`, `hermes doctor`, `hermes plugins`, `hermes skills`, `hermes logs`, etc.
- `~/.hermes/config.yaml` 設定形式 (YAML) と `~/.hermes/.env` (API キー)
- `get_hermes_home()` による profile-aware なパス解決
- Messaging gateway (Telegram, Discord, Slack, WhatsApp, Signal, iMessage, Email, ACP, etc.)
- Skills Hub (組み込み) と agentskills.io 規格
- Plugin loader (4 sources: bundled / user / project / pip entry-point)
- Plugin lifecycle hooks (16 種、`hermes_cli/plugins.py:VALID_HOOKS`)
- Provider adapter system (`agent/anthropic_adapter.py`, `bedrock_adapter.py`, etc.)
- Subagent system (`subagent_stop` hook + `delegate_task` tool)
- Cron scheduler (`cron/`)
- Memory system (`plugins/memory/`、 honcho/mem0/supermemory)
- Context engine (`plugins/context_engine/`)
- Terminal backends (local/docker/ssh/singularity/modal/daytona/vercel)

### Conditionally inherited (lenient mode only)

- **Agent harnesses** (Codex / Claude CLI / Cursor / ACP clients): inherited under lenient mode. Under strict mode, `mordred_llm_guard` refuses startup if a non-local harness is the configured primary, because harnesses bypass `pre_llm_call` for their own daemon traffic.

### Naming Convention

- Project name: **Mordred**
- CLI command name: **`hermes mordred ...`** (Hermes の `register_cli_command` 経由)
- Plugin Python module IDs: `mordred_network`, `mordred_privacy_check`, `mordred_keyvault`, `mordred_llm_guard`, `mordred_wizard` (snake_case、Python module 命名規則)
- pip distribution: **`mordred-hermes`** (single package, all 5 plugins included)
- Configuration topology: per-plugin config under `plugins.mordred_<plugin-id>` in `~/.hermes/config.yaml`。Mordred plugins coordinate shared state (effective policy, active network path) via Hermes 内部 import 共有モジュール、 **not** via a single `mordred:` top-level key
- Skill metadata: `metadata.mordred.*` (旧 SPEC と同じ、互換維持)
- Mordred-owned filesystem paths: `~/.hermes/mordred/` (audit log, policy snapshot, keyvault state)

## Target User (v1)

**Privacy-focused individual developers**

Persona:

- macOS Apple Silicon または Linux / WSL2 ユーザ (Phase 1–3 はマルチプラットフォーム、Phase 4 のみ macOS Apple Silicon)
- Already using Hermes、または OpenClaw からの移行ユーザ (`hermes claw migrate` 経由)
- Comfortable with the Python ecosystem
- Has experience or willingness to learn local LLM operation (Ollama / LM Studio / vLLM)
- _Nice-to-have, not required_: Web3 / cryptocurrency familiarity (relevant only when v2+ Payment skills land)

Out of scope (v2+): journalists, enterprise IT teams, GUI-only users, Windows native (use WSL2), iOS native.

## User Stories (v1)

### Story 1: 既存 Hermes ユーザの privacy 層追加

As an existing Hermes user, I want to add the privacy layer with `pip install mordred-hermes && hermes mordred upgrade`、 reusing my existing `~/.hermes/config.yaml` and skills unchanged.

Behavior:

- Idempotent: re-running は state が一致する場合 no-op
- `plugins.mordred_*` セクションが既に存在する場合は diff を表示し、上書きを prompt
- Existing skills without `metadata.mordred.*` are treated as `network_requirements: unknown`。Lenient mode (default for upgrade) では一回限りの warning、strict mode では block で listed in `hermes mordred policy explain`
- `~/.hermes/config.yaml` のコメントとキー順は保持される (`ruamel.yaml` 経由の round-trip writer)
- 既存 `~/.hermes/mordred/` は `--reset` 指定が無い限り保持

### Story 1.5: OpenClaw + Mordred-OpenClaw からの移行

OpenClaw 環境で旧 Mordred を使っていたユーザは以下の 3 ステップ:

1. `hermes claw migrate` — Hermes 化 (workspace, config 移行)
2. `pip install mordred-hermes` — Mordred plugin 群を入手
3. `hermes mordred upgrade` — privacy 層を有効化

`hermes mordred upgrade` は OpenClaw 時代の `~/.openclaw/mordred/` を検出した場合、policy / audit log / keyvault state を `~/.hermes/mordred/` に migrate する補助機能を持つ (詳細は PLAN.md §1.3)。

### Story 2: 新規ユーザのセットアップ

As a new user, I want `hermes mordred configure` to:

1. `hermes setup` を child-process spawn (Hermes 標準セットアップを先に実行)
2. Mordred-specific questions (network policy strict/lenient/off, local LLM endpoint, keyvault initialization opt-in) を聞く

これにより Hermes と Mordred を 1 コマンドで設定可能。Hermes core 改変なし。

### Story 3: スキル実行と自動経路選択

スキル install 時 (`hermes mordred install <skill>` ラッパ経由)、`mordred_privacy_check` が SKILL.md frontmatter の `metadata.mordred.network_requirements` を解析し user policy と照合。不適合なら install を block。Runtime では `mordred_network` が proxy 環境変数を Hermes spawn する子プロセスに inject。Active path は gateway 全体 single state (last-write-wins, audited)。

> **Note**: Hermes core に install hook が追加されたら、ラッパ CLI 廃止して直接 hook 経由に移行。それまでは ラッパ経由のみが policy enforcement 経路。

### Story 4: Local LLM enforcement (strict-mode override)

> **Phase 0.8 verify (2026-05-10) 完了 — Story 4 の機構を再定義**: Hermes v0.11.0 の `pre_llm_call` payload は `model` だけで `provider` を含まず、 戻り値は **context-injection 専用** (provider override 不可)。 `pre_api_request` には provider/model/base_url が乗るが **observer-only**。 従って **「ターン毎 `pre_llm_call` で provider redirect」 は v1 では構造的に不可能** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5)。 v1 は `on_session_start` 時の **session-scoped enforcement** に切り替える: strict policy + non-allowlisted current provider の組合せは **起動を refuse** する (v1 default、 audit `policy.strict.session_refused`)。 `register_provider` + config patch で active provider を `mordred-local` synthetic provider に swap する代替案は Codex B2 review で **v1 構造的に不可能**と確定した (Hermes は `on_session_start` 発火前に active provider を解決するため config patch は次セッションまで効かない) — v2 vendored fork (Tier B、 `[hard-lock]`) に deferred。 zero-PR commitment (`MIGRATION.md` §5) は維持。

Policy が `strict` の時、`mordred_llm_guard` は **session 開始時に** provider 設定を判定し、 `cloud_provider_allowlist` に該当しない provider が active であれば session を refuse する (v1 default)。 `mordred-local` synthetic provider への swap は Codex B2 review で v1 不可能と確定したため v2 deferred。 ターンが始まった後の provider 切替も v1 では行わない (構造的制約)。 `cloud_provider_allowlist` に該当 + `allow_cloud_llm: true` の組合せでは session 続行 (passthrough)。 詳細な audit reason code は §Audit log policy 参照 (`policy.strict.session_refused`、 および v2 deferred な `policy.strict.provider_override_at_session_start`)。

Local endpoint が unreachable な時は `MordredLocalUnreachable` を raise し、ターン abort。lenient mode では override しない。

### Story 5: Key management

`metadata.mordred.requires_keyvault: true` を declare するスキルのために、`mordred_keyvault` が `Security.framework` (pyobjc 経由) backed AES key wrapping を提供。Keyvault 初期化は Seed Phrase + Passphrase + PoW の物理的な手書き transcribe を要求し、verification-digest flow が一致しない限り finalize されない。詳細は SPEC §Plugin: `mordred_keyvault`。

### Story 6: Hermes 既存機能との共存

Mordred plugin は Hermes の memory plugin (honcho/mem0)、context engine、observability (langfuse) と同居可能。各 plugin は独立しており、Mordred の hook は他の plugin の hook と並列に呼ばれる。 **Phase 0.8 verify (2026-05-10) 完了**: Hermes v0.11.0 plugin loader の hook 順序保証は **登録順** で確定 (`PluginManager.invoke_hook` at `hermes_cli/plugins.py` L968-1002、 priority システム無し)。 Plugin 読込順は bundled → user → project → entry-point の順で、 Mordred (entry-point) は **すべての hook で最後に登録される**。 詳細は [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1。

## Scope (In) — what we build in v1

### Plugin: `mordred_network`

- **Tor connection (v1 default = official `tor` daemon)**:
  - `arti` (Rust) は v1 baseline 候補として残すが、 v1 default は `tor` daemon — v1 baseline は最も entry barrier が低く Linux/macOS でパッケージマネージャ install が確立しているため
  - **torrc isolation**: Mordred は **自前の torrc** を `~/.hermes/mordred/tor-data/torrc` に生成し、 system 全体の `/etc/tor/torrc` やユーザの Tor Browser 設定には触れない
  - **SOCKS5 listener**: 既定 `127.0.0.1:9050`。 `lsof -i :9050` で既存 listener (例: Tor Browser、 system tor service) を検出した場合、 v1 では alt port `9150` (Tor Browser default 衝突) を経て **policy.json `tor_socks_port` で明示指定** された port に shift。 衝突解決順: 9050 → 9150 → user-specified → abort with `MordredPathBringupFailed`
  - **ControlPort**: 既定 `127.0.0.1:9051` を有効化 (cookie auth)。 cookie file は `~/.hermes/mordred/tor-data/control_auth_cookie`。 `getinfo circuit-status` で M9 liveness probe を実装するため **必須**
  - **Bridge / obfs4 / Snowflake**: v1 範囲外 (検閲環境での使用は v2 `v2-N3`)。 startup banner で「censorship 環境では v1 default Tor は接続失敗する可能性」 を warn
  - **Stream isolation (per-skill SOCKS auth)**: v1 では未実装。 全 skill が同一 circuit pool を共有 (Tor 自身が circuit を rotate)。 per-skill SOCKS5 username/password で circuit 分離は v2 `v2-N1`。 **2026-06-02 追記**: per-**session** 単位の SOCKS5 isolation は landed — `proxy_env.isolation_token` (SOCKS credential) + torrc `IsolateSOCKSAuth` + `on_session_start` が Hermes `session_id` を circuit token に配線。 per-**skill** 単位は `origin_skill` (v2-H2) 待ちで据え置き
- **Mullvad VPN integration (v1 = official `mullvad` CLI)**:
  - **CLI 選択**: v1 は Mullvad **公式 client** (`mullvad` binary、 macOS は `/Applications/Mullvad VPN.app/Contents/Resources/mullvad`、 Linux は `apt install mullvad-vpn` 等のパッケージ) を使用。 自前 `wg-quick` 直接実行は v1 範囲外 (CAP_NET_ADMIN/sudo の取り扱いが OS 横断で複雑)
  - **権限**: 公式 client は背後で system service (Linux: systemd unit、 macOS: LaunchDaemon) として動作、 ユーザコマンドは IPC で daemon に依頼するため **追加 sudo 不要**
  - **Killswitch (lockdown mode)**: strict mode では `mullvad lockdown-mode set on` を bring-up 時に enforce (Mullvad CLI 2026.2 で `always-require-vpn` サブコマンドは削除され、`lockdown-mode` に統合された)。 VPN drop 時に OS が clearnet route を一切作らない。 lenient/off では user 設定を尊重 (lockdown が off なら warn のみ)
  - **DNS leak prevention**: Mullvad client が tunnel 内 resolver を強制するため v1 で DNS leak は無し (M8 IPv6 leak と異なり mitigated)
  - **Relay 選択**: 既定 `auto` (Mullvad が地理的最近 relay を選ぶ)。 user override は policy.json `mullvad_relay_country: "jp"` 等で。 multihop / wireguard-over-tor は v1 範囲外
  - **Tear-down**: `on_session_end` で `mullvad disconnect` を実行。 strict mode では同時に `mullvad lockdown-mode set off` を **行わない** (lockdown 維持)、 user は次セッション開始 or 手動 disable で抜ける
  - **Platform**: macOS Apple Silicon、 Ubuntu/Debian baseline。 Windows は v1 範囲外 (Phase 4 keyvault macOS-only と同じ platform tone)
- Clearnet (no-op path)
- **`provider_transport_flagger` v1 baseline allowlist** (Phase 0.8 で実機 verify):
  - **既知 compatible (HTTPS_PROXY + SOCKS5h 尊重)**: `anthropic` SDK (httpx)、 `openai` SDK (httpx)、 `gemini` (`google-genai` SDK、 httpx baseline — Phase 0.8 実機 verify で旧 `google-generativeai`/requests から訂正、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §Out of scope の live verify 結果)
  - **conditional**: `mordred-local` localhost provider — NO_PROXY default で proxy 経由から除外され機能、 但し SOCKS5h 関係なし
  - **既知 partial / 要監視**: `bedrock` (boto3) — HTTPS_PROXY 尊重するが botocore の DNS 解決経路に quirk あり、 strict + tor で DNS leak の可能性。 `vertex` (google-cloud SDK) — 一部 transport で HTTPS_PROXY を bypass、 strict mode で warning 後 user 判断
  - **既知 incompatible (v1 strict mode で active 時 startup abort 候補)**: 上記以外で raw socket / 独自 transport を握る provider があれば Phase 0.8 verify で列挙
  - 上記は **v1 ship 前の Phase 0.8 タスクで実機テストして確定**。 actual allowlist は plugin 同梱の Python dict (declarative module) として配布、 policy.json から user override 可能 (entry 追加のみ、 削除は不可)
- Subprocess lifecycle: `on_session_start` hook で Tor/VPN client を起動 (policy が要求する時)、`on_session_end` で teardown
- Dynamic path-switching via internal Python API (`mordred_network.api.use(path)` 等)
- Path injection: spawned child processes に `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` を設定。 **NO_PROXY default**: `localhost,127.0.0.1,::1` (Phase 2 の `mordred-local` localhost 通信を proxy 経由から除外するため必須)。 ユーザ追加 entries は policy.json `no_proxy: [...]` から append
- **Transport coverage (M8, v1)**: proxy_env が tunnel するのは **HTTP(S) traffic のみ**。 以下は v1 で防御範囲外、 SPEC §Threat Model に明記:
  - **DNS resolution**: 通常の `HTTPS_PROXY=http://...` では Python/curl 等が **system resolver で名前解決してから** proxy に接続するため、 Tor 経路でも DNS query が ISP に漏れる。 v1 強制対応: Tor 経路では `HTTPS_PROXY=socks5h://127.0.0.1:9050` を使用 (`socks5h` は server-side resolution)。 SOCKS5h を尊重しないライブラリ (一部の旧 HTTP client) は provider_transport_flagger で warning。 VPN 経路では tunnel が DNS query 自体を握るので緩和。 v2: bundled DNS-over-Tor / `mordred-dns-resolver` で完全防御
  - **IPv6 traffic**: 多くの HTTP client は IPv6 endpoint に対し proxy_env を bypass する。 v1 では provider が IPv6-only endpoint を持つ場合 traffic は **proxy を経由しない** (clearnet leak)。 strict mode では policy.json `disable_ipv6: true` (default true) で v1 baseline を IPv4 only に。 VPN 経路では tunnel が IPv6 を握るので緩和、 Tor 経路では強制 IPv4 (Tor 自体が IPv6 exit 限定的のため実害は少)
  - **Non-HTTP transport (raw TCP, UDP, QUIC, gRPC, WebSocket)**: HTTPS_PROXY が効くかは client library 次第。 SSE / standard WebSocket (WS-over-HTTP upgrade) は通常尊重するが、 raw socket を握る provider plugin は bypass。 provider_transport_flagger の static allowlist で warning、 strict mode では known-incompatible provider が active 時 startup abort
- **Path failure semantics (M9, v1)**:
  - **Bring-up failure** (Tor bootstrap timeout / VPN handshake fail): strict は session abort with `MordredPathBringupFailed`、 lenient は user-visible warning + clearnet fallback (audit `network.bringup_failed` emit)、 off は silent fallback
  - **Liveness probe**: 30s interval で `mordred_network.api.health()` を内部 worker thread が実行 (Tor: SOCKS5 reachability + circuit established check、 VPN: WireGuard handshake recency + interface up)。 連続 2 回失敗で path-dropped 判定
  - **Mid-session drop**: strict は次の `pre_tool_call` で `MordredPathDropped` を raise (tool 実行 block)、 lenient は warn + 続行 (path-dropped 状態を維持、 **clearnet 自動 fallback は行わない**。 user が `hermes mordred network use clearnet` で明示的に切り替える前提)。 audit `network.path_dropped` 必ず emit
  - **`use(path)` failure**: `MordredNetworkError` (subclasses: `BringupFailed`, `AlreadySwitching`, `UnknownPath`) を raise。 silent fallback は禁止
- **Concurrency model (v1)**:
  - Active path is **gateway-wide single state** — `mordred_network.api.use(path)` は last-write-wins、 audit-logged on switch
  - **並列 tool_call の path mismatch**: runtime での per-skill path mismatch 判定は **v1 では行わない** — Phase 0.8 verify で `pre_tool_call` payload に `origin_skill` が **無い** ことが確定したため ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)、 runtime での skill 単位の block は構造的に不可能。 per-skill enforcement は install-time (`hermes mordred install <skill>`) のみ。 path 自動切り替えも v1 では行わない (M3 transitive failure mode 回避のため)。 `origin_skill` payload 拡張が upstream に landing したら v2-H2 で runtime 判定を再検討
  - **同 path 要求の並列**: 制限なし、 通常通り並列実行
  - **異なる path 要求の並列**: serialize しない (block / warn semantics で対処)。 v2 で per-skill SOCKS5 stream isolation (Tor only) を検討
- Provider transport flagging: 起動時に Hermes provider adapter を列挙し、proxy env vars を無視するものに warning を発出 (v1 は static known-incompatible allowlist、per-provider declaration は v2)
- Strict-mode bootstrap order: `mordred_network` の `on_session_start` を `mordred_privacy_check` より先に登録することで active path 確定後に privacy-check が判定する。 **Phase 0.8 verify 完了** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1): Hermes plugin loader は **登録順** で hook callback を呼出 (priority システム無し)、 entry-point plugin (Mordred 5 個すべて) は bundled/user/project の後にロードされるため、 Mordred plugin 同士の登録順は entry-point group `hermes_agent.plugins` の declaration 順序で決まる。 plugin 内 probe wait (`wait_for(api.status().ready, timeout=5s)`) を default の bootstrap 経路として採用 — 上流側の priority 制御は無いため、 register 順依存を最小化する設計

### Plugin: `mordred_privacy_check`

- **Skill install ガード** (`hermes mordred install <skill>` ラッパ経由):
  - SKILL.md を install source path から読み、frontmatter の `metadata.mordred.network_requirements` を抽出
  - Strict + `clearnet` → block
  - Strict + missing metadata → block with `policy.strict.unknown_metadata`
  - Lenient + missing metadata → allow + warning
- `pre_tool_call` — generic per-tool allowlist (configurable)。Default strict-mode blocklist: builtin `web_fetch`, `web_search` when active network path is Clearnet。`origin_skill` が payload にあれば per-skill 判定も、無ければ tool-name allowlist のみ
- Policy state: `on_session_start` で `~/.hermes/config.yaml` の `plugins.mordred_privacy_check` から load、メモリキャッシュ。reload は `hermes mordred policy reload` で明示的に
- Audit logging: §Operational Guarantees 参照

### Plugin: `mordred_llm_guard`

- Synthetic provider `mordred-local` を `mordred_llm_guard/local_adapter.py` (plugin 同梱の adapter) として実装。Hermes provider adapter pattern を踏襲し、local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM) に delegate
- **Phase 0.8 verify (2026-05-10) 完了**: v0.11.0 の `pre_llm_call` は context-injection 専用で provider override 不可、 `pre_api_request` は observer-only ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5)。 従って enforcement は **`on_session_start` で session-scoped に確定** する (ターン毎の動的 override は v1 範囲外):
  - strict policy + current provider が `cloud_provider_allowlist` に **該当する** + `allow_cloud_llm: true` → session 続行 (passthrough)
  - strict policy + current provider が cloud_provider_allowlist に該当しない、 または `allow_cloud_llm: false` → session を refuse して exit (v1 default、 audit `policy.strict.session_refused`)。 `register_provider` + config patch で active provider を `mordred-local` に swap する代替案 (audit `policy.strict.provider_override_at_session_start`) は Codex B2 review で v1 構造的に不可能と確定したため **v2 deferred** (Tier B `[hard-lock]` vendored fork)
  - lenient/off → 何もしない
- Local-unreachable fail-fast: `mordred-local` は health-check 失敗時 `MordredLocalUnreachable` を raise
- Harness refusal: `on_session_start` で configured agents を scan、harness-based primary (Codex/Claude CLI/Cursor/ACP client) で strict mode の時は startup を abort

### Plugin: `mordred_keyvault`

#### Key hierarchy

`mordred_keyvault` protects the combination of **Seed Phrase + Passphrase + PoW**。BIP39 標準準拠、ユーザは 24-word Seed と Passphrase を物理的に手書き。

```
secret      = SeedPhrase (24 words) + Passphrase + PoW       ← protected (user transcribes by hand)
dek         = random 256-bit AES-GCM data-encryption key     ← generated by keyvault
ciphertext  = AES-GCM(secret, dek)                           ← stored on disk as backup/state
wrappingKey = Secure Enclave-backed non-exportable key       ← authorizes DEK unwrap only
wrappedDek  = wrap(dek, wrappingKey)                         ← stored next to ciphertext
```

Design decisions:

- **Withdrawn**: Secure Enclave が signing key を保持/derive する設計は v1 では採用しない
- **Adopted**: Secure Enclave は AES DEK の wrapping/unwrapping authorization 境界としてのみ使用
- `dek` は plaintext 保存しない (encryption/decryption 中のみメモリに存在)
- `Passphrase + PoW` は `secret` の一部、`dek` 派生材料ではない (Enclave 破壊時、ユーザが書き留めた secret から別 machine で再 wrap 可能)
- Biometric 認証は cryptographic operation ではなく authorization mechanism のみ

Limitations:

- Local secrets at rest 保護: disk theft, backup, accidental plaintext disclosure を防ぐ
- Compromised running gateway が unwrap 後の secret を扱う場合は保護できない
- Runtime signing isolation は v1 範囲外、 future Payment work (`v3-P1`) で扱う

#### Key generation and verification digest

Key generation は **mandatory and one-shot**。mis-transcribe を防ぐため verification digest 一致まで finalize しない。

Conceptual formula:

```
digest = hash( hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW) )
```

> **Notation note (code-reviewer LOW-1, 2026-05-14)**: the `⊕` here is shorthand for "XOR the 4 bytes of `top4(PoW)` into the **first 4 bytes** of `hash(Passphrase)`, leaving bytes `[4:32]` of `hash(Passphrase)` unchanged". Read as a full-width XOR (32-byte vs. 32-byte with zero-padding), the formula would be ambiguous and a naive implementation could end up XOR-padding `top4(PoW)` to 32 bytes. The Concrete algorithm below is canonical; the conceptual formula is for high-level intuition only.

**Concrete algorithm (canonical, Phase 4 PR2 step-0 freeze 2026-05-14)**:

```
H               := BLAKE3 (32-byte digest mode)
seed_hash       := H(SeedPhrase as UTF-8 bytes)            # 32 bytes
pass_hash       := H(Passphrase as UTF-8 bytes)            # 32 bytes
top4            := PoW_bytes[0:4]                          # PoW is a precomputed BLAKE3-based artifact;
                                                           # caller passes the raw bytes, top4 = first 4 bytes
masked_pass[0:4]  := pass_hash[0:4] XOR top4              # XOR affects ONLY the first 4 bytes
masked_pass[4:32] := pass_hash[4:32]                       # remaining 28 bytes unchanged
digest          := H(seed_hash || masked_pass)             # 32 bytes
```

Resolved ambiguities:
- `top4(PoW)` is `PoW_bytes[:4]`; PoW is NOT re-hashed inside `compute_digest` (caller is responsible for PoW computation, see §`mordred_keyvault` PoW section)
- `⊕` operates on **4 bytes only**, into the first 4 bytes of `pass_hash`. Bytes `[4:32]` of `pass_hash` pass through unchanged. (Rationale: SPEC notation explicitly says `top4`, not `pad_to_32(PoW)` — the masking is intentionally narrow so cross-machine recovery only requires transmitting the 4-byte mask, not 32 bytes.)
- Outer hash combines via byte concatenation `seed_hash || masked_pass` (64 bytes total input)
- All BLAKE3 invocations use the unkeyed, 32-byte default output (no `derive_key` / `keyed_hash` mode)
- String inputs (`SeedPhrase`, `Passphrase`) are UTF-8 encoded **as-is** at this layer. Unicode normalization is the caller's responsibility — implemented by `mordred_keyvault.api` (Phase 4 PR4). PR4 step-0 freeze (2026-05-15, codex HIGH #1) splits normalization: seed phrase uses `NFKD + casefold + whitespace-collapse` (BIP39 word-list tolerance); passphrase uses `NFKD only` (preserves case and whitespace entropy). See §"PR4 API contract" below for the exact `_normalize_seed_phrase` / `_normalize_passphrase` definitions.

**Fixed test vector** (Phase 4 PR2 baseline, BLAKE3 1.0.8):

| Field         | Value (hex unless noted)                                              |
| ------------- | --------------------------------------------------------------------- |
| `seed_phrase` | `"test seed"` (UTF-8: `746573742073656564`)                           |
| `passphrase`  | `"test pass"` (UTF-8: `746573742070617373`)                           |
| `pow_bytes`   | `deadbeef` + `00` × 28 (32 bytes total)                               |
| `seed_hash`   | `c18818fa275b46e46836d45540512fb2561a66924b2962d6675ef71c7cdcecf0`    |
| `pass_hash`   | `734cedd9a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb`    |
| `top4`        | `deadbeef`                                                            |
| `masked_pass` | `ade15336a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb`    |
| **`digest`**  | **`25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93`**|

This vector is pinned in `tests/test_keyvault_digest.py::TestSpecFixedVector` and acts as the regression anchor for the digest algorithm. Any future change that perturbs the vector requires a SPEC update + reason in the PR description.

**Operator tooling**: The standalone `scripts/keyvault_offline_digest.py` (stdlib + `blake3` only, no `mordred_hermes` import) is the canonical implementation an operator runs on the air-gapped second device. It reproduces the algorithm above plus the seed/passphrase normalization defined in §"PR4 API contract". The script's `--self-test` flag validates the same fixed vector pinned above. Operator preparation and step-by-step recipe live in `setup.md` §"Offline verification digest".

Confirmation flow (PC = Hermes process が動く machine):

| Input location                 | Input       | Output                                             |
| ------------------------------ | ----------- | -------------------------------------------------- |
| PC (Hermes process)            | SeedPhrase  | `hash(SeedPhrase)`                                 |
| Separate offline medium/device | Passphrase  | `hash(Passphrase) ⊕ top4(PoW)`                     |
| Combine                        | Both halves | verify `digest` matches the locally computed value |

- v1 default は offline/manual verification while PC is in network blackout。QR + local LAN pairing は v2 (`v2-F7`)
- PoW (BLAKE3 ベース) は real-time phishing replication を deter — 具体的アルゴリズムは次節 §"Proof-of-Work (PoW) algorithm" で freeze
- Cross-machine recovery 時は backup blob に embedded された first-generation digest と比較し mis-transcription を検出

#### Proof-of-Work (PoW) algorithm (Phase 4 PR10 step-0 freeze, 2026-05-16)

`compute_digest` の `pow_bytes` 入力は caller が用意する。PR10 で `keyvault init` がこの artifact を生成する必要が生じたため、 v1 アルゴリズムをここで freeze する。

**目的**: PoW は **seed-bound な計算成果物** であり、 init 時に一回だけ固定コストを支払わせる。 seed に bind しているため別マシンでの recovery 時に同じ seed から決定的に再計算でき、 PoW を別途手書き transcribe する必要がない (offline medium に渡すのは `top4(PoW)` の 4 byte のみ — §"Key generation and verification digest" の `⊕` narrow-mask 根拠と整合)。

**Concrete algorithm (canonical)**:

```
H                    := BLAKE3 (32-byte digest mode; unkeyed — digest.py と同一)
POW_PREFIX           := b"MRPOW\x01"          # 6 bytes: domain-separation tag ‖ version 1
POW_DIFFICULTY_BITS  := 20                     # v1 baseline (tunable; 下記 caveat 参照)

preimage(n)  := POW_PREFIX ‖ normalized_seed_utf8 ‖ n.to_bytes(8, "little")
                # normalized_seed は api._normalize_seed_phrase の出力 (NFKD + casefold
                # + whitespace-collapse)。n は 0 から始まる uint64 カウンタ
find smallest n such that leading_zero_bits(H(preimage(n))) >= POW_DIFFICULTY_BITS
pow_bytes    := H(preimage(n))                 # 32 bytes — 勝った preimage の BLAKE3 digest
```

- `top4(PoW) = pow_bytes[:4]` (digest 式と整合)。 difficulty が高いほど `top4` の先頭 bit は 0 が増えるが、 `top4` は passphrase 半分の **mis-transcription 検出**用であって security 境界ではない (digest 全 32 byte の `hmac.compare_digest` が一次検出)。
- 決定的: `pow_bytes` は normalized seed のみの関数。 recovery は transcribe された seed から同じ値を再計算する。
- `n` が `2**64` に達した場合 (天文学的に起こらない) は `PowExhausted` を raise。

**Caveat (codex step-0 review 対象)**: `POW_DIFFICULTY_BITS = 20` (≈ 1.4M BLAKE3 hashes、 最新ハードで 1 秒未満) は conservative baseline。 real-time phishing に対する厳密な difficulty 解析は v1 範囲外で、 security review / v2 に deferred。 定数は `mordred_keyvault.pow` 内 module-level で 1 箇所に集約し将来 tune 可能とする。 recovery も PoW を再計算するため difficulty 引き上げは recovery 時間にも比例して効く点に注意。

**Fixed test vectors** (BLAKE3 1.x、 `tests/test_keyvault_pow.py` に pin):

| Field                 | Value                                                              |
| --------------------- | ------------------------------------------------------------------ |
| `normalized_seed`     | `"test seed"` (UTF-8: `746573742073656564`)                        |
| `POW_PREFIX`          | `4d52504f5701` (`MRPOW` ‖ `0x01`)                                  |
| **difficulty 8** (human-checkable worked example) | `n = 519` |
| → `pow_bytes`         | `00faa270f9d4a1047cd3f00002d6bd6c3ded6d151e2542ee21742a4665b56ac2` |
| → `top4`              | `00faa270`                                                         |
| **difficulty 20** (v1 production `POW_DIFFICULTY_BITS`) | `n = 1449850` |
| → `pow_bytes`         | `00000df459e58f525449c530a547d48ba70e488f7ed15f9c810ae7a76bd0e7c9` |
| → `top4`              | `00000df4`                                                         |

difficulty 8 vector は手計算検証用 (`n = 519` で到達)、 difficulty 20 vector が v1 production の regression anchor。 いずれかが変わる変更は SPEC 更新 + PR 理由必須。

#### `keyvault init` flow (Phase 4 PR10)

`hermes mordred keyvault init` は one-shot の鍵生成 flow を以下の順で実行する:

1. **生成**: `keyvault` が 24-word BIP39 mnemonic (256-bit entropy + SHA-256 checksum) を生成、 `pow.compute_pow(normalized_seed)` で PoW を計算。 Passphrase は user が対話入力 (PC 画面に echo しない)。
2. **prepare**: `api.prepare_generate(seed, passphrase, pow_bytes)` → `(SeedDisplayHandle, expected_digest)` (in-memory のみ、 disk mutation なし)。
3. **display**: `seed_display.display_seed(handle, surface)` — network blackout assert (fail-closed) → M4/M5 banner → 60s timer 付きで **Seed のみ** を端末に表示 (Passphrase は絶対 render しない)。
4. **offline confirm**: user が seed + passphrase + `top4(PoW)` を offline medium に transcribe し digest を独立計算、 その digest を CLI に入力。
5. **finalize**: `api.confirm_generate(handle, user_digest, backend=_SecKeyBackend())` — digest 一致時のみ Secure Enclave key + `meta.json` を durable 化、 mismatch 時は state 変更ゼロで `keyvault.init_denied`。

#### Seed phrase display security

1. **Network blackout (M4 caveat)**: 表示前に `mordred_network.api.blackout_assert()` で host が disconnected であることを verify。macOS では `SCNetworkReachability` / `nw_path_monitor` (pyobjc 経由)。Linux では `ip link show` / `nmcli` で代替 (Phase 4 が macOS only なので Linux fallback は v2)
   - **Fallback**: `mordred_network` 不在時は keyvault が直接 OS API を呼ぶ薄い wrapper にフォールバック
   - **検出範囲の限界 (M4)**: `blackout_assert` は **OS の標準ネットワークスタックに見える経路** だけを検出する。 以下は検出できないため、 物理的な air-gap はユーザの責任で確保すること:
     - Bluetooth / USB tethering / personal hotspot (OS が WAN として認識しない / させていない場合)
     - 仮想マシン / コンテナの外側で動く NIC、 ホスト側 VPN、 仮想スイッチ
     - 悪意ある kernel モジュールや ring-0 ローダー (root compromise 環境)
     - Thunderbolt / DMA 経路で接続された外部 NIC が OS から hidden になっているケース
   - 表示前に `keyvault init` の startup banner で「物理的に Wi-Fi/Ethernet/Bluetooth/USB tether が切れていることを目視確認してください」 と user prompt を出す
2. **Show only the Seed on the PC**。Passphrase は PC 画面に絶対 render しない
3. **Verification は v1 では offline by default**: Passphrase 半分は別 device で入力 or 手書き
4. **Display timeout & capture caveats (M5)**: Seed は 60 秒で自動消去。 capture 関連の v1 防御範囲は以下:
   - **Screenshot 検出**: best-effort のみ (macOS `CGDisplayRegisterReconfigurationCallback` + `CGScreenIsBeingCaptured` の polling)。 検出した瞬間に Seed display を即時クリア + audit log `keyvault.seed_display_aborted_screenshot` (Phase 4 reason enum で freeze)
   - **Screen recording (M5、 v1 検出範囲外)**: macOS `screencapture -v`、 Loom、 Zoom share、 OBS、 QuickTime Player の screen recording は **検出しない**。 `CGDisplayStream` ベースの検出 API は API stability の観点で v1 採用見送り、 v2 で再評価
   - **Remote desktop (VNC / Screen Sharing / SSH X11 forwarding / `tmate` / `mosh`)**: 検出しない。 ユーザは Seed display 前に remote session を切る責任がある
   - **Camera / 物理 shoulder-surfing**: 当然検出範囲外
   - 表示前 startup banner で「ローカル機の物理画面のみで Seed を見てください。 screen recorder / 画面共有ツール / remote desktop を停止してください」 と warn
   - 60 秒タイマーは monotonic clock (`time.monotonic()`) ベース。 wall-clock 改ざんに耐性

#### Protection-tier hierarchy (fallback)

1. **TEE present (Tier 1, v1)**: Secure Enclave (`Security.framework` via pyobjc)
2. **No TEE (Tier 2, v2)**: Keychain/HSM/TPM/DPAPI
3. **Neither (Tier 3, v2)**: master-password-derived key

> **Tier 2 — Linux TPM 2.0 (v2-OS2)**: `hermes mordred keyvault enable-tpm` builds the `mordred-hermes-tpmkey` helper, which backs the wrapping key with a non-extractable TPM P-256 key + on-chip ECDH (same WMK wire format). This is **machine-binding** — a copied key-blob is useless on another host — but **NOT Touch-ID-equivalent**: the MVP has no per-use user-presence gate (no PIN/PCR prompt), unlike the Tier-1 Secure Enclave's biometric-per-decrypt. Per-use gating is a deferred follow-up. (Phase 2a/2c shipped the Rust crate + CLI; the `tss-esapi` TPM backend is Phase 2b.)

#### Implementation interface

- `pyobjc-framework-Security` を `mordred-hermes` の macOS extra に追加 (`pip install mordred-hermes[macos]`)
- `mordred_keyvault/native.py` で `Security.framework` ラッパー実装、import は lazy (Linux/WSL2 で import 時 ImportError にならないよう `_lazy_import` パターン)
- 内部 Python API (Mordred plugin 間で共有) — PR4 step-0 freeze (2026-05-15) の正準形は §"PR4 API contract & MREN envelope wire format" 参照:
  - `mordred_keyvault.api.prepare_generate(seed, passphrase, pow_bytes) -> (SeedDisplayHandle, expected_digest)` — in-memory only、 no persistence
  - `mordred_keyvault.api.confirm_generate(handle, user_confirmed_digest, *, ...) -> GenerateResult` — digest 一致時のみ Keychain + meta.json mutation; mismatch 時 rollback (codex BLOCKER #2)
  - `mordred_keyvault.api.generate(seed, passphrase, pow_bytes, expected_digest, *, ...) -> GenerateResult` — non-interactive convenience (tests / automation 用); wizard CLI は two-phase form 必須
  - `mordred_keyvault.api.encrypt(key_id, plaintext, purpose, *, ...) -> envelope_id` — managed storage; AES-GCM encrypt + persist `.gcm` envelope; envelope_id 返却
  - `mordred_keyvault.api.decrypt(key_id, envelope_id, purpose, *, ...) -> bytes` — caller-supplied `purpose` 必須 (cross-purpose replay 防御、 codex HIGH #2); unwrap authorization 後に復号
  - `mordred_keyvault.api.export_backup(key_id, passphrase, *, ...) -> bytes` — 全 ciphertext を Argon2id-KEK で再 wrap した manifest 入り MRKV blob (codex BLOCKER #1)
  - `mordred_keyvault.api.import_backup(blob, passphrase, *, seed_phrase, pow_bytes, ...) -> str` — digest 検証 → manifest 復号 → 新 Enclave key で各 DEK を再 wrap
  - `mordred_keyvault.api.verify_digest(seed, passphrase, pow_bytes, *, expected) -> None` — split normalization 適用後の digest 一致確認
- スキル opt-in: `metadata.mordred.requires_keyvault: true` を declare、`mordred_privacy_check` が install 時 enforce

#### Backup wire format versioning (Phase 4 PR2 freeze, 2026-05-14)

`mordred_keyvault.backup.export()` produces a self-describing blob with the layout

```
magic(4)="MRKV" | version(1) | kdf_id(1) | m_cost(4 BE) | t_cost(4 BE) | p_cost(4 BE)
                | salt(16) | verification_digest(32) | aes_blob_len(4 BE) | aes_blob(*)
```

with `HEADER_LEN = 70` for `version=1`. The AAD bound to the AES-GCM ciphertext is `magic ‖ version ‖ kdf_id ‖ m_cost ‖ t_cost ‖ p_cost ‖ salt ‖ verification_digest` (66 bytes). Tampered headers therefore fail `InvalidTag` at decrypt time, separately from `BackupCorrupt` structural rejects.

> **Migration policy (code-reviewer LOW-2, 2026-05-14)**: a `version=2` blob is **not** required to keep `HEADER_LEN = 70`. Decoders must read the `version` byte first and dispatch on it; `parse_header` for `version=1` raises `BackupCorrupt` on any other version (the policy in PR2). When introducing `version=2`:
>
> 1. Keep `magic = b"MRKV"` and `version` at byte offset 4 stable — these are the dispatch keys.
> 2. Bump the SPEC table above with the version-2 layout, list which fields moved, and update any consumers reading `HEADER_LEN` as a constant.
> 3. AAD construction may change but must remain field-set-deterministic so re-encrypting the same secret + parameters yields the same ciphertext under a fixed nonce.
> 4. Migration tools should detect version=1 blobs and re-export as version=2 with a fresh nonce — never silently upgrade the blob in place (preserves the original verification digest's transcription evidence).

DOS guards on parsed KDF params (Phase 4 PR2 integration finding): `parse_header` rejects `m_cost > 1 GiB`, `t_cost > 64`, or `p_cost > 16` (and any value ≤ 0). Without these caps a tampered cost-param byte can force `decrypt_body` into a multi-GiB Argon2 allocation before AAD authentication has a chance to fail. The caps must be re-evaluated when introducing a stronger KDF profile (a future "v2 profile" with `m_cost=256 MiB, t=4` for higher-security keyvaults stays within them).

#### Wrap wire format & algorithm (Phase 4 PR3 freeze, 2026-05-14)

The Secure-Enclave-backed DEK wrap is the Tier-1 protection step from the [Protection-tier hierarchy](#protection-tier-hierarchy-fallback) above. `mordred_keyvault.wrap.wrap_dek(dek, key_id)` produces a self-describing 127-byte blob:

```
magic(4)="MRKW" | version(1) | alg_suite(1) | key_id_hash(16) | ephemeral_pub(65) | wrapped_dek(40)
```

Field reference for `version = 1`:

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `MRKW`. Dispatch key, never changes across versions. |
| 4 | 1 | `version` | `1`. Dispatch key for future format bumps. |
| 5 | 1 | `alg_suite` | `1` = `(P256_ECDH_RAW, HKDF_SHA256, AES256_KW_RFC3394)`. Reserved values: `0` invalid, `2-255` future. |
| 6 | 16 | `key_id_hash` | First 16 bytes of `SHA-256(key_id_bytes)`. Used for Keychain lookup + audit log; never the cleartext `key_id`. |
| 22 | 65 | `ephemeral_pub` | SEC1 uncompressed P-256 (`0x04 ‖ X(32) ‖ Y(32)`). Freshly generated by `wrap_dek` via `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(SECP256R1())` (which itself draws from the OS RNG via OpenSSL `BN_rand_range`) — wrap is **never** deterministic and never reuses the ephemeral key. Hand-rolled scalar generation via `secrets.token_bytes` is intentionally avoided (codex review-fix-2 NIT-1) because it would require a manual modular-reduction step against the curve order. |
| 87 | 40 | `wrapped_dek` | RFC 3394 AES-KW output for a 32-byte DEK (`8 + 32 = 40` bytes; the fixed IV/AIV is internal to RFC 3394, so the blob has **no separate IV field** — codex review BLOCKER-2). |

`HEADER_LEN = 127` for `version=1`. The parser rejects any other version with `WrapParseError`.

**Algorithm — `wrap_dek(dek, key_id)`** (offline, no Enclave authorization, no user prompt):

1. Lookup the Enclave **public** key for `key_id` via `SecKeyCopyPublicKey` on a Keychain lookup (`kSecAttrApplicationTag = "mordred-hermes.wrap." + key_id_hash`).
2. Generate an ephemeral P-256 keypair in software (`cryptography` library, never persisted).
3. Raw ECDH: pass the ephemeral private key + Enclave public key to `SecKeyCopyKeyExchangeResult` with `kSecKeyAlgorithmECDHKeyExchangeStandard` (NOT `…X963SHA256` — codex review HIGH-1; we want raw ECDH output, then a single explicit HKDF, not double-derive).
4. HKDF-SHA256 derive a 32-byte AES-KEK: `salt = b""`, `info = magic || version(1) || alg_suite(1) || key_id_hash(16) || ephemeral_pub(65)` (87 bytes; binds every non-secret blob field to the KEK — codex review HIGH-2).
5. `wrapped_dek = AES-KW(KEK, dek)` per RFC 3394 (32-byte DEK → 40-byte output, integrity-protected by the AIV).
6. Emit the blob; do NOT emit an audit-log entry (wrap is unauthorized, fast, no decision boundary).

**Algorithm — `unwrap_dek(blob, key_id)`** (authorized, may prompt the user):

1. `parse_header(blob)` — reject if `len(blob) != 127`, `magic != b"MRKW"`, `version != 1`, `alg_suite != 1`, or `key_id_hash != SHA-256(key_id)[:16]`. Each rejection raises `WrapParseError`.
2. Lookup Enclave **private** key by Keychain query (same `kSecAttrApplicationTag` namespacing). Missing → `WrapKeyNotFound`.
3. Decode `ephemeral_pub` as SEC1 P-256; reject invalid curve points with `WrapParseError`.
4. Call `SecKeyCopyKeyExchangeResult(enclave_private, ECDHKeyExchangeStandard, ephemeral_pub, params)`. This triggers the access-control prompt (Touch ID / Optic ID / passcode). On `errSecUserCancelled` / `errSecAuthFailed` / `errSecInteractionNotAllowed` / `errSecAuthorizationCanceled`, emit `keyvault.unwrap_denied` with translated `native_error_code` and raise `WrapAuthCancelled` (chains the native `NSError` via `__cause__`).
5. HKDF-SHA256 with the same `info` constructed in wrap step 4 (binds blob fields to KEK; a tampered `ephemeral_pub` produces a different KEK → AES-KW unwrap fails AIV check).
6. `dek = AES-KW-Unwrap(KEK, wrapped_dek)`. AIV mismatch → `WrapIntegrityError`.
7. Emit `keyvault.unwrap_authorized` with `key_id_hash` (16-char hex prefix) and return `dek`.

**Access-control attributes for the Enclave key** (set at `generate_wrapping_key` time, persisted in the Keychain):

| Attr | Value | Rationale |
| --- | --- | --- |
| `kSecAttrKeyType` | `kSecAttrKeyTypeECSECPrimeRandom` | P-256, the only curve the Enclave supports. |
| `kSecAttrKeySizeInBits` | `256` | Required by `ECSECPrimeRandom`. |
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` | Bind the private key to the Enclave; the public key is freely exportable. |
| `kSecAttrIsPermanent` | `True` | Survives reboot — `wrap` needs to look up the public key without re-prompting. |
| `kSecAttrApplicationTag` | `b"mordred-hermes.wrap." + key_id_hash` | Namespaced lookup; avoids collision with other apps. |
| `kSecAttrLabel` | `"Mordred wrapping key " + key_id_hash[:8].hex()` | Human-readable in Keychain Access.app. |
| `kSecAttrAccessControl` | `SecAccessControlCreateWithFlags(.privateKeyUsage \| .biometryCurrentSet, accessible: .whenPasscodeSetThisDeviceOnly)` | Touch/Optic ID required — `.biometryCurrentSet` is biometry-only with no passcode fallback; an Enclave-capable Mac without enrolled biometry cannot create or use the key (codex review MEDIUM-2; reaffirmed PR9). `.biometryCurrentSet` invalidates the key if the user adds/removes biometrics — protects against the "stolen device with attacker biometric enrolled" attack. `.whenPasscodeSetThisDeviceOnly` ensures the key cannot exist on a device without a passcode and never syncs to iCloud Keychain. |

Capability detection (codex review MEDIUM-1): `is_secure_enclave_available()` does NOT check `platform.machine() == 'arm64'`. Intel Macs with the T2 chip also have a Secure Enclave reachable through the same API. Detection probes capability via a throwaway key-generate-then-delete cycle (with `.privateKeyUsage` only, no biometry, so it cannot prompt) — non-`Darwin` platforms short-circuit to `False` without touching pyobjc.

**Internal Python surface (frozen for PR4 callers — codex review LOW-2)**:

```python
class WrapError(Exception): ...                 # base; all PR3 errors derive from here
class WrapParseError(WrapError): ...            # malformed blob (length, magic, version, alg_suite, key_id_hash mismatch, invalid EC point)
class WrapIntegrityError(WrapError): ...        # AES-KW AIV check failed (tampered wrapped_dek or ephemeral_pub)
class WrapNativeUnavailable(WrapError): ...     # Security.framework not importable (non-macOS or pyobjc missing)
class WrapAuthCancelled(WrapError): ...         # user denied biometry / passcode prompt; emit keyvault.unwrap_denied
class WrapKeyNotFound(WrapError): ...           # Keychain has no item for this key_id (key revoked or wrong device)
class WrapKeyAlreadyExists(WrapKeyNotFound): ...  # duplicate key_id at generation time; WrapKeyNotFound subclass so historical `except` sites keep catching it

def generate_wrapping_key(key_id: str, *, backend: NativeBackend) -> bytes: ...     # returns SEC1 uncompressed P-256 pubkey, 65 bytes
def get_wrapping_key_public(key_id: str, *, backend: NativeBackend) -> bytes: ...   # SEC1 uncompressed P-256, 65 bytes
def delete_wrapping_key(key_id: str, *, backend: NativeBackend) -> None: ...        # removes Keychain item; idempotent
def wrap_dek(dek: bytes, key_id: str, *, backend: NativeBackend) -> bytes: ...      # offline; returns 127-byte blob
def unwrap_dek(blob: bytes, key_id: str, *, audit_sink: AuditSink, backend: NativeBackend) -> bytes: ...
```

`api.py` (Phase 4 PR4) is the only callsite — internal API contract for `mordred_keyvault.api.generate` / `encrypt` / `decrypt` / `export_backup` / `import_backup` derives from this surface.

**Migration policy** (mirrors PR2 backup wire format L428-433): a future `version=2` must keep `magic = b"MRKW"` and `version` at byte offset 4 stable as dispatch keys; bump the table above; do not silently upgrade existing blobs in place (preserves provenance evidence).

#### PR4 API contract & MREN envelope wire format (Phase 4 PR4 step-0 freeze, 2026-05-15)

The planning-stage codex review of PR4 (BLOCKER × 3 + HIGH × 5 + MEDIUM × 3 + LOW × 1) is incorporated below. The freeze covers `api.py` public surface, MREN envelope format, normalization split, two-phase generation, opaque `SeedDisplayHandle`, managed storage, file-safety semantics, and the four new audit codes.

##### Mordred normalization (split: seed phrase vs passphrase, codex HIGH #1)

The PR2 freeze (L349) said "(NFKD + casefold + single-space collapse) is the caller's responsibility". Codex pre-implementation review flagged that applying this uniformly to passphrase weakens entropy (casefold conflates distinct Unicode strings; whitespace collapse drops information). PR4 splits normalization:

```python
def _normalize_seed_phrase(s: str) -> str:
    # BIP39 + tolerance: NFKD decompose, strip Cf-category chars,
    # casefold, collapse runs of whitespace.
    # Seed phrases are word lists — casefold and whitespace tolerance are correct.
    # Cf-strip handles invisible clipboard noise (ZWSP / ZWJ / BOM / soft hyphen);
    # these are NFKD-stable and str.split() does not treat them as whitespace,
    # so without an explicit drop they survive normalization and silently
    # produce a different digest (code-reviewer MEDIUM-1, 2026-05-15).
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Cf")
    return " ".join(stripped.casefold().split())

def _normalize_passphrase(s: str) -> str:
    # BIP39 reference normalization: NFKD only. No casefold, no whitespace
    # collapse, NO Cf strip — preserves the exact entropy of the input. A user
    # who chose to embed an invisible char did so intentionally; recovery
    # requires reproducing the same bytes. The verify-digest mismatch at
    # recovery time surfaces any clipboard-injected invisible char visibly.
    return unicodedata.normalize("NFKD", s)
```

Both apply at `api.py` boundaries (`prepare_generate` / `verify_digest` / `import_backup`). `digest.compute_digest` continues to receive already-normalized UTF-8 bytes as PR2 freeze. The existing fixed test vector (L355-362) remains valid for ASCII inputs (`"test seed"` / `"test pass"` have no NFKD decomposition and no casefold delta). PR4 adds new fixed vectors covering Japanese precomposed/decomposed equivalence on the seed side and entropy preservation on the passphrase side.

##### Two-phase generate (codex BLOCKER #2)

SPEC §Key generation and verification digest mandates that key generation be "mandatory and one-shot" and finalize only after the verification digest matches. A single-call `generate(seed, passphrase, pow)` cannot enforce that — Keychain state and `meta.json` would be created before the user has confirmed via the offline channel. PR4 splits into two phases:

```python
def prepare_generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
) -> tuple[SeedDisplayHandle, bytes]:
    # In-memory only. Computes digest from normalized inputs. Returns:
    #   - handle: opaque SeedDisplayHandle for Seed display flow (PR5 will consume)
    #   - expected_digest: 32-byte digest for user to confirm via offline channel
    # NO Keychain creation, NO meta.json write, NO digests/ commit, NO audit emit.
    # Pure function with respect to disk state.
    ...

def confirm_generate(
    handle: SeedDisplayHandle,
    user_confirmed_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    # Reads the prepared digest via handle.expected_digest() — the
    #   confirm-side egress: it does NOT consume the handle (consume() is
    #   the display flow's egress, so prepare -> display-seed -> confirm
    #   works), but on an expired deadline it wipes the seed payload before
    #   raising SeedDisplayExpired.
    # Verifies user_confirmed_digest matches that digest via hmac.compare_digest.
    # On mismatch: emit keyvault.init_denied (sink failure chained as
    #   __context__), raise VerificationDigestMismatch; NO mutation. The
    #   handle is not consumed, so the caller may retry with a corrected
    #   digest on the same handle.
    # On match:
    #   0. Re-init guard: v1 keyvault is single-key (Story 5). If meta.json
    #      already has any key, raise RuntimeError. Checked once unlocked
    #      (before init_started, to avoid a dangling audit event) and again
    #      authoritatively under the lock (TOCTOU-safe).
    #   1. Emit keyvault.init_started (audit-sink failure aborts; durability barrier).
    #   2. Under one .lock hold: re-check the re-init guard, then
    #      wrap.generate_wrapping_key(key_id, backend=...) — key_id=None
    #      resolves to the "default" literal; a duplicate raise here is
    #      OUTSIDE the rollback scope so a pre-existing key is not deleted.
    #   3. Still under .lock: write digests/<key_id_hash>.commit FIRST, then
    #      meta.json LAST. meta.json is the transaction commit point —
    #      save_meta replaces it atomically. Rollback deletes the Enclave
    #      key + the orphaned commit file, and best-effort repairs the
    #      meta.json row in the rare case the atomic rename committed before
    #      a later fsync raised.
    #   4. Emit keyvault.init_completed (sink failure suppressed; init has already succeeded).
    # ``backend`` is required (no None default) — matches encrypt/decrypt;
    #   the production backend is a later step so there is no None fallback.
    ...

def generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    expected_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    # Non-interactive convenience: prepare → confirm in one call.
    # Tests and future automation use this. Wizard CLI MUST use the two-phase form.
    # Delegates fully to confirm_generate (no in-generate digest pre-check):
    # confirm_generate reads the handle's digest, compares, and emits
    # keyvault.init_denied on mismatch — so a non-interactive mismatch gets
    # the same audit trail as the interactive path.
    handle, _prepared = prepare_generate(seed_phrase, passphrase, pow_bytes)
    try:
        return confirm_generate(handle, expected_digest, key_id=key_id, backend=backend,
                                audit_sink=audit_sink, home=home)
    finally:
        # No display flow consumes the handle in the non-interactive path,
        # so generate() wipes the seed itself (consume() under the lock) on
        # both the success and the raise paths.
        with contextlib.suppress(SeedDisplayExpired):
            handle.consume()
```

##### SeedDisplayHandle (opaque, codex BLOCKER #3)

A frozen dataclass with `seed_phrase: str` would expose the seed via `repr`, equality comparison, hash-based memoization, and long-lived object retention. PR4 defines `SeedDisplayHandle` as an opaque class with:

```python
class SeedDisplayHandle:
    __slots__ = ("_payload", "_consumed", "_deadline", "_expected_digest", "_lock")

    def __init__(
        self,
        normalized_seed: str,
        deadline_monotonic: float,
        expected_digest: bytes,
    ) -> None:
        self._payload = bytearray(normalized_seed.encode("utf-8"))  # wipeable
        self._consumed = False
        self._deadline = deadline_monotonic  # time.monotonic() + 60.0 by default
        # 32-byte digest baked in by prepare_generate; confirm_generate
        # uses this as the compare target for hmac.compare_digest against
        # the user-typed value (defense-in-depth: even if the caller forgot
        # to verify before calling confirm_generate, the handle still
        # raises on mismatch). Coerced through bytes(...) and length-checked.
        self._expected_digest = bytes(expected_digest)
        self._lock = threading.Lock()  # serializes consume() across threads

    def __repr__(self) -> str:
        return "<SeedDisplayHandle redacted>"

    def __eq__(self, other: object) -> bool:
        raise TypeError("SeedDisplayHandle does not support equality (would leak via comparison oracle)")

    __hash__ = None  # unhashable: cannot land in dict/set/cache by accident

    # __copy__ / __deepcopy__ / __reduce__ / __reduce_ex__ / __getstate__
    # / __setstate__ all raise TypeError — the default object machinery
    # would otherwise duplicate or serialize the slotted _payload and leak
    # the seed (or let a duplicate consume() it after the original wiped).

    def consume(self) -> str:
        # One-shot. Returns the normalized seed string, then zero-fills internal bytes.
        # The whole body runs under self._lock so the one-shot guarantee holds
        # even if the handle is shared across threads.
        # After consume(): subsequent calls raise RuntimeError("handle already consumed").
        # If time.monotonic() > self._deadline: raise SeedDisplayExpired, wipe, do not return.
        # consume() is the DISPLAY FLOW's egress for the seed.
        ...

    def expected_digest(self) -> bytes:
        # confirm_generate's read-only egress: returns the prepared
        # verification digest WITHOUT consuming the handle. The deadline
        # guard fires only while the seed is still live (not _consumed):
        # an expired, never-consumed handle is wiped before raising
        # SeedDisplayExpired; once consume() has wiped the seed the deadline
        # is moot, so expected_digest() returns the digest even past the
        # deadline (a slow user confirming after the display window still
        # succeeds). Callable repeatedly.
        ...
```

> **Step-D extension (2026-05-15, PR4c-1)**: the original step-0 freeze
> listed 3 slots; this proved inconsistent with the `confirm_generate`
> comment "Verifies user_confirmed_digest matches handle's prepared
> digest" because the handle had no compare target. Two slots were
> appended during PR4c-1 (the first three are preserved in SPEC order):
>
> - `_expected_digest` (4th) — the BLAKE3 compare target. Coerced through
>   `bytes(...)` so a caller-passed `bytearray` / `memoryview` cannot
>   alias-mutate it post-construction, and length-validated (== 32) at
>   construction time.
> - `_lock` (5th) — a per-handle `threading.Lock` serializing `consume()`;
>   without it two threads sharing a handle could both pass the one-shot
>   guard and release the seed twice.
>
> PR4c-1 also added `__copy__` / `__deepcopy__` / `__reduce__` /
> `__reduce_ex__` / `__getstate__` / `__setstate__` guards (all raise
> `TypeError`) so the default copy / pickle / state-dump machinery
> cannot duplicate or serialize the seed payload. CPython-level
> introspection (`gc.get_referents`, `ctypes`, a debugger) remains out
> of scope — defending it would require C-level work.

Phase 4 PR7 `seed_display.py` layers the screen-blackout-assert + M4/M5 warning banner + 60s monotonic display loop + screenshot detection on top of this class. `SeedDisplayHandle` is **not** relocated — it stays in `api.py` and `seed_display.display_seed` consumes it, so api.py callers are unaffected (the original plan said "relocate", but keeping it in `api.py` keeps the contract narrow as PR4 intended). `display_seed(handle, surface, ...)`: blackout assert (`network_fallback.resolve_blackout_assert`, fail-closed) → `surface.banner(SEED_DISPLAY_BANNER)` → screenshot pre-check → `handle.consume()` → 60s `time.monotonic()` timer polling `CGScreenIsBeingCaptured` → `finally` auto-clear. A detected capture clears the surface, emits `keyvault.seed_display_aborted_screenshot`, and raises `SeedDisplayAborted`.

##### MREN envelope (managed storage, decrypt requires purpose)

```
offset  bytes  field
0       4      magic = b"MREN"
4       1      version = 1
5       16     key_id_hash = SHA-256(key_id)[:16]
21      16     purpose_hash = SHA-256(purpose)[:16]
37      127    wrapped_dek (RFC 3394 AES-KW under Enclave-derived KEK, PR3 MRKW prefix verbatim)
164     4      aes_blob_len (uint32 big-endian)
168     N      aes_blob = nonce(12) || ciphertext || tag(16)
```

AAD = bytes `[0:164]` (`magic || version || key_id_hash || purpose_hash || wrapped_dek`). Any header byte flip invalidates the GCM tag, mirroring PR2/PR3 integrity story. Total envelope size: `196 + len(plaintext)` bytes minimum (the 127-byte MRKW prefix is itself wrapped-dek-only; the +N bytes are ciphertext + tag).

API surface (managed storage — keyvault owns persistence):

```python
def encrypt(
    key_id: str,
    plaintext: bytes,
    purpose: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    # Generates fresh DEK (secrets.token_bytes(32)); offline-wraps via wrap.wrap_dek;
    # AES-GCM encrypts plaintext under DEK with AAD bound to header. Persists to
    # ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm via atomic
    # tmp+rename+fsync under .lock, file mode 0600. Returns envelope_id
    # (URL-safe base64 of 16 random bytes, ~22 chars).
    ...

def decrypt(
    key_id: str,
    envelope_id: str,
    purpose: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    # Reads envelope; verifies envelope.purpose_hash == SHA-256(purpose)[:16] via
    # hmac.compare_digest BEFORE invoking wrap.unwrap_dek. Cross-purpose attempts
    # raise WrapParseError without spending a biometric prompt or emitting audit
    # (mirrors PR3 review-fix-1 HIGH-1 "no emit for parse errors"). On purpose match:
    # unwraps DEK (PR3 wrap layer emits keyvault.unwrap_authorized or _denied via
    # codes #19/#20 — api.decrypt does NOT double-emit), then AES-GCM decrypts.
    ...
```

Per-ciphertext DEK rationale (codex OD-1 confirmed): each `encrypt` generates a fresh 32-byte DEK. AES-GCM nonce reuse across plaintexts is structurally eliminated. The 127-byte MRKW prefix per envelope is acceptable overhead; the biometric-prompt-per-decrypt UX cost is acceptable for Tier 1 posture (v2-F5 may add a configurable in-memory grace window).

##### export_backup / import_backup (ciphertext-rewrap manifest, codex BLOCKER #1)

Codex flagged that an Enclave-only DEK wrap is unrecoverable across machines (Enclave keys are non-exportable). PR4 implements full ciphertext portability via a passphrase-derived KEK manifest: each envelope is unwrapped, the AAD is rebound from the per-device MRKW prefix to a portable form, and on import the envelope is reconstructed with a fresh Enclave wrap on the destination device. The DEK travels in the manifest (encrypted-at-rest by the passphrase-derived KEK), so the destination device never needs the source device's Enclave key.

**Portable manifest AAD**: `manifest_aad = b"MRMN" || key_id_hash(16) || purpose_hash(16)` — exactly 36 bytes, fully reconstructible from `(key_id, purpose)` on the import side. It does NOT include the MRKW prefix because that prefix is per-device and changes on each machine.

```python
def export_backup(
    key_id: str,
    passphrase: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    # 1. Walk ciphertexts/<sha256(key_id)[:16].hex()>/**/*.gcm.
    # 2. For each envelope file, parse the MREN wire format (SPEC §MREN envelope above):
    #    extract wrapped_dek_blob (offset 37, 127 bytes), aes_blob (offset 168, len from
    #    aes_blob_len field), purpose_hash (offset 21, 16 bytes), envelope_id (filename
    #    minus .gcm).
    # 3. Reconstruct the envelope's original AAD = envelope_bytes[0:164]
    #    (magic || version || key_id_hash || purpose_hash || wrapped_dek_blob).
    # 4. Call wrap.unwrap_dek(wrapped_dek_blob, key_id, backend=...) to recover the 32-byte
    #    DEK (single biometric prompt covers the whole batch — SecKeyCopyKeyExchangeResult
    #    sessions amortize one user gesture across all envelopes in the same call frame;
    #    if Enclave behavior changes in a future macOS, fall back to one-prompt-per-envelope
    #    and document in PR description).
    # 5. AES-GCM-decrypt the original aes_blob under the recovered DEK with the original AAD
    #    → original_plaintext.
    # 6. Compute portable manifest_aad = b"MRMN" || key_id_hash(16) || purpose_hash(16)
    #    (36 bytes, no MRKW prefix).
    # 7. AES-GCM-re-encrypt: manifest_aes_blob = AES-GCM-encrypt(DEK, original_plaintext,
    #    aad=manifest_aad) with a fresh 96-bit nonce. Output bytes = nonce(12)||ciphertext||tag(16).
    # 8. Append a manifest entry (manifest_aad is recomputable on import from key_id +
    #    purpose, so it is NOT stored in the entry):
    #      {
    #        "purpose_hash_hex": "<32 hex chars>",
    #        "envelope_id":      "<URL-safe b64, 22 chars>",
    #        "dek_hex":          "<64 hex chars>",
    #        "manifest_aes_blob_b64": "<base64 of step-7 output>",
    #      }
    # 9. Serialize manifest as canonical JSON:
    #      manifest_json = json.dumps({
    #        "version": 1,
    #        "key_id": <plaintext key_id>,
    #        "envelopes": [<entry>, ...],
    #      }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # 10. Argon2id-derive KEK_passphrase from passphrase + fresh 16-byte salt
    #     (m=46 MiB, t=1, p=1 — same parameters as PR2 backup.export).
    # 11. manifest_body = AES-GCM-encrypt(KEK_passphrase, manifest_json,
    #     aad=PR2_backup_header_aad) (PR2 backup wire format AAD already binds salt + KDF
    #     params + verification_digest).
    # 12. Pack PR2 MRKV blob with verification_digest from digests/<sha256(key_id)[:16].hex()>.commit
    #     and manifest_body as the AES blob payload (PR2 backup.export contract).
    # 13. Emit keyvault.backup_exported (#24, fields: key_id_hash, blob_version=1,
    #     kdf_id=1, envelope_count = len(manifest.envelopes)).
    # Returns the MRKV blob bytes; file persistence is the caller's responsibility.
    ...

def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    # 1. recovery.parse_header(blob) — PR2 contract; raises BackupCorrupt on parse failure.
    # 2. Recompute verification digest from normalized (seed_phrase, passphrase, pow_bytes)
    #    using api._normalize_seed_phrase + api._normalize_passphrase + digest.compute_digest.
    #    Compare with the header's verification_digest field via 32-byte length guard +
    #    hmac.compare_digest. Mismatch → raise RecoveryDigestMismatch + emit
    #    keyvault.recovery_digest_mismatch (#17).
    # 3. Argon2id-derive KEK_passphrase from passphrase + parsed salt.
    # 4. AES-GCM-decrypt manifest_body → manifest_json. AAD = PR2 backup header AAD.
    # 5. Parse manifest JSON; validate "version" == 1.
    # 6. imported_key_id = manifest["key_id"]. backend.generate_enclave_key(imported_key_id)
    #    on this device → new Enclave wrapping key.
    # 7. For each manifest entry (in declared order):
    #    a. Recompute manifest_aad = b"MRMN" || sha256(imported_key_id)[:16] ||
    #       bytes.fromhex(entry["purpose_hash_hex"]) (36 bytes, identical to export step 6).
    #    b. plaintext = AES-GCM-decrypt(bytes.fromhex(entry["dek_hex"]),
    #                                   b64decode(entry["manifest_aes_blob_b64"]),
    #                                   aad=manifest_aad).
    #    c. new_wrapped_dek = wrap.wrap_dek(dek_bytes, imported_key_id, backend=...) — offline,
    #       produces a fresh 127-byte MRKW blob bound to THIS device's Enclave public key.
    #    d. new_key_id_hash = sha256(imported_key_id)[:16].
    #       new_envelope_aad = b"MREN" || version(1) || new_key_id_hash ||
    #                           bytes.fromhex(entry["purpose_hash_hex"]) || new_wrapped_dek
    #       (164 bytes total — identical layout to step-C MREN envelope §AAD).
    #    e. new_aes_blob = AES-GCM-encrypt(dek_bytes, plaintext, aad=new_envelope_aad) with a
    #       fresh 96-bit nonce. Output bytes = nonce(12) || ciphertext || tag(16).
    #    f. envelope_bytes = new_envelope_aad ||
    #                        len(new_aes_blob).to_bytes(4, "big") || new_aes_blob.
    #    g. Persist envelope_bytes to
    #       ciphertexts/<new_key_id_hash.hex()>/<entry["purpose_hash_hex"]>/<entry["envelope_id"]>.gcm
    #       via the step-B atomic + fsync + flock helpers.
    # 8. Write meta.json (add row for imported_key_id) and
    #    digests/<new_key_id_hash.hex()>.commit (32 bytes = recomputed verification digest)
    #    under .lock with atomic semantics.
    # 9. Return imported_key_id.
    # 10. On any mid-import failure after step 6: rmtree(home / "mordred" / "keyvault"
    #     / "ciphertexts" / new_key_id_hash.hex()) and backend.delete_enclave_key(imported_key_id),
    #     then re-raise. Steps 1-5 are pre-mutation (no rollback needed).
    ...
```

**Manifest wire format** (inside the MRKV body, after PR2 header parse + AES-GCM decrypt):

```
Mordred Manifest v1 — UTF-8 JSON with canonical separators:
{
  "version": 1,
  "key_id": "<plaintext key_id>",
  "envelopes": [
    {
      "purpose_hash_hex": "<32 hex chars = sha256(purpose)[:16].hex()>",
      "envelope_id":      "<URL-safe base64, 22 chars, no padding>",
      "dek_hex":          "<64 hex chars = 32-byte DEK>",
      "manifest_aes_blob_b64": "<base64 of nonce(12)||ciphertext||tag(16)>"
    }
  ]
}
```

`manifest_aad` is **not stored in the manifest entry** — it is recomputed deterministically on import from `(manifest["key_id"], entry["purpose_hash_hex"])` so a manifest with a tampered `key_id` or `purpose_hash_hex` fails AES-GCM tag verification on import. This is the AAD-binding integrity story: any field that participates in `manifest_aad` is implicitly authenticated; tampering one field flips the GCM tag.

**Why re-encrypt** (rather than ship the original `aes_blob` unmodified): the original envelope's AAD includes the per-device MRKW prefix (`wrapped_dek_blob`, 127 bytes). The destination device has a different Enclave key and therefore a different MRKW prefix, so the original AAD cannot be reconstructed there. AES-GCM does NOT allow rebinding AAD without re-encryption — that is by design (AAD is part of the tag computation). The export side therefore decrypts under the original AAD, the manifest side carries plaintext under a *portable* AAD (no MRKW component), and the import side re-encrypts under the new device's envelope AAD. The plaintext is exposed in memory only inside `export_backup` and `import_backup`; it never touches disk.

##### File-safety semantics (step-B foundation, codex HIGH #4)

All keyvault filesystem operations MUST:

- Open files with `os.open(path, O_NOFOLLOW)` to refuse symlink-following (symlink → `KeyvaultPermissionError`).
- Reject existing files whose mode is not `0600` and directories whose mode is not `0700` via `fstat` after open (mode mismatch → `KeyvaultPermissionError`).
- Write atomically: `<file>.tmp + fsync(tmp_fd) + os.replace(tmp, final) + fsync(parent_dir_fd)`.
- Hold an exclusive `fcntl.flock` on `~/.hermes/mordred/keyvault/.lock` (mode `0600`) for the duration of any write transaction (covers generate, encrypt, export, import).
- On `meta.json` corruption (JSON parse failure / missing required keys / `version` mismatch): raise `KeyvaultCorruptError` whose `str()` does NOT include the corrupted contents (audit-safety — corrupted JSON could include secret-shaped bytes from a partially-overwritten file).

##### Audit emissions for PR4 (4 new reason codes #21-24)

See `POLICY.md` §"Phase 4 PR4 step-0 freeze" for the full table. Summary:

| # | Code | Emit site | Decision |
| --- | --- | --- | --- |
| 21 | `keyvault.init_started` | `confirm_generate` durability barrier | `allow` |
| 22 | `keyvault.init_completed` | `confirm_generate` success | `allow` |
| 23 | `keyvault.init_denied` | `confirm_generate` digest mismatch | `block` |
| 24 | `keyvault.backup_exported` | `export_backup` success | `allow` |

`encrypt` and `decrypt` are NOT audited at the api layer (codex OD-3): `encrypt` has no auth gate (wrap is offline), and `decrypt` already inherits #19/#20 via the wrap layer.

##### Capability-probe fail-on-skip (codex HIGH #5)

`is_secure_enclave_available()` returning `False` while `MORDRED_KEYVAULT_LIVE=1` is set in the environment MUST cause the live test suite to **fail** (not skip). The integration test fixture asserts the capability and the env var consistency before any per-test skip logic.

#### Explicitly out of v1

- バイナリ/フォルダ名/ファイル名の暗号化 → `v2-F6`
- per-skill file-encryption mapping → `v2-F6`
- HSM/TPM/master-password fallback → `v2-OS2`
- Secure Enclave-backed signing isolation, Payment signing → `v3-P1`
- Session log encryption → Hermes 側に session-log writer seam が必要

### Plugin: `mordred_wizard` (CLI Extension)

`PluginContext.register_cli_command("mordred", help, setup_fn, handler_fn)` で `hermes mordred ...` サブコマンドツリーを登録。`setup_fn(subparser)` 内で argparse subparser 階層を構築。

サブコマンド:
- `hermes mordred configure` — `hermes setup` を child-process spawn し、Mordred-specific questions
- `hermes mordred upgrade` — Story 1 / 1.5 single-command migration
- `hermes mordred install <skill>` — privacy-check 経由のスキルインストール (Hermes core にスキル install hook が追加されるまでの代替)
- `hermes mordred network init` — on-demand network-privacy setup (Tor / VPN / clearnet + Mullvad); separate from `configure`, re-runnable (blank Mullvad answer keeps the current secret). `--non-interactive` is flag-driven (`--path` / `--tor-binary` / `--tor-socks-port` / `--mullvad-relay` / `--mullvad-killswitch`); `--clear-mullvad` removes the stored secret. The Mullvad secret is never accepted as a CLI flag.
- `hermes mordred network use <tor|vpn|clearnet>` — manual override
- `hermes mordred network status` — show current active path
- `hermes mordred policy show` — print effective policy
- `hermes mordred policy explain <skill-id>` — explain why a given skill is allowed/blocked
- `hermes mordred policy dry-run <skill-path>` — predict install-time decision without installing
- `hermes mordred policy reload` — invalidate in-memory policy cache
- `hermes mordred audit tail [-n N]` — print last N entries from `~/.hermes/mordred/audit.log`
- `hermes mordred audit grep <pattern>` — search audit log
- `hermes mordred keyvault init` — Seed Phrase + Passphrase + PoW generation flow
- `hermes mordred keyvault list` — list key IDs (no key material)
- `hermes mordred keyvault verify-digest` — re-display digest
- `hermes mordred keyvault recover --blob <path>` — recovery on different machine
- `hermes mordred audit decrypt --date YYYY-MM-DD` — Phase 4 以降、encrypted historical logs を Secure Enclave authorization で復号

## Operational Guarantees & Caveats

### Audit log policy

- Path: `~/.hermes/mordred/audit.log`
- File mode: `0600` (user-only)
- Format: newline-delimited JSON (NDJSON), single writer per Hermes process, append-only
- Concurrency: in-process write queue で serialize、multi-process scenario は v1 unsupported
- Rotation: daily roll to `audit.log.YYYY-MM-DD`、gzip after rotation、size cap 10 MB per current file (force-rotate)、retention 30 days
- Redaction: `reason` strings は固定 enum (free-text params / 完全な skill content は never logged)。 enum は `src/mordred_hermes/privacy_check/_audit_reasons.py` の `ReasonCode` `Literal` が型レベルの source of truth、 人間可読の canonical 一覧は [`POLICY.md`](./POLICY.md) §Audit log `reason` enum を参照。 Phase 1.1 step-0 で 12 code を freeze し、 以降 phase ごとに closed-set 拡張のみで追加 (Phase 3 PR1 で `network.*` +4 → Phase 4 PR2–§4.1 で `keyvault.*`/`policy.*` +10 → PR #39 follow-up で `mordred.degraded.audit_encryption_unavailable` +1、 **現在 27 code**)。 既存 code の削除・改名はしない
- Encryption: Phase 1–3 は plaintext NDJSON at file mode `0600`。Phase 4 以降は AES-GCM (DEK は keyvault wrapping、メモリのみ保持) で新規 entry を暗号化
- Phase staging: `audit.py` writer は swappable Writer interface を Phase 1 で freeze、Phase 4 で `EncryptedWriter` に factory swap

Audit entry シェイプ (synthetic example):

```json
{
  "ts": "2026-04-29T12:34:56.000Z",
  "event": "pre_tool_call",
  "decision": "block",
  "reason": "policy.strict.clearnet",
  "tool_name": "web_fetch",
  "skill_id": "example-skill"
}
```

フィールド: `ts` (ISO-8601 UTC), `event` (hook 名), `decision` (`allow`/`block`/`override`/`warn`), `reason` (固定 enum), `skill_id`/`tool_name`/`provider_id` (event に応じていずれか), 任意の event 固有フィールド。

#### Encrypted audit-log wire format (`MRAL` v1、 Phase 4 PR6 freeze)

Phase 4 以降、 `keyvault/log_encryption.py` の `EncryptedWriter` (Phase 1 `Writer` Protocol 実装) が新規 entry を AES-GCM で暗号化する。 ファイルは行指向 — 1 entry = 1 行で、 `O_APPEND` の whole-entry atomicity を保ちつつ全ファイル再暗号化を不要にする:

```
行 0   header   {"fmt":"MRAL","ver":1,"key_id":<str>,"wdek":<base64>}
行 1+  entry    base64( nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16) )
```

- `wdek` は audit-log DEK を `keyvault.wrap.wrap_dek` で wrap した 127-byte `MRKW` blob。 ディスクに載るのは **wrapped DEK のみ**、 平文 32-byte DEK は writer のメモリ上のみ (`close()` で参照破棄)。
- DEK は writer 生成時ではなく **最初の append 時に lazy 生成**、 file ごとに fresh。 `wrap_dek` は Enclave public key を使う offline 操作で biometric prompt 無し — **書き込みは authorization boundary を踏まない**。
- 各 entry の AES-GCM AAD = `MAGIC ‖ version ‖ SHA-256(header 行)`。 header 行は file 固有のランダム `wdek` を含むため digest が file ごとに異なり、 別 file からの entry splice / header 改竄後の replay は tag check で失敗する。
- atomicity caveat: 最大サイズ (4000 byte plaintext) の暗号化行は約 5.4 KiB で POSIX `PIPE_BUF` (4096) を超える。 multi-process 並行 writer での `O_APPEND` atomicity は保証されないが、 v1 は multi-process audit 書き込みを未サポート (§1.1 M1) のため single-process 単一 writer-lock で invariant #2 は成立。
- rotation は Phase 1 NDJSONWriter と同じ (日次 + size cap + gzip + 30 日 retention)。 rotation ごとに fresh file + DEK + header。 既存 foreign file (pre-Phase-4 plaintext log、 または DEK を prompt 無しで unwrap できない別セッションの暗号化 file) は **overwrite せず rotate aside**。
- 復号は `keyvault.log_encryption.decrypt_log_file` — `wrap.unwrap_dek` (Secure Enclave authorization boundary、 `keyvault.unwrap_authorized` を emit) 経由で DEK を unwrap し、 gzip rotated file も透過処理。 構造 / 整合性エラーは `AuditLogDecryptError`、 prompt 拒否 (`WrapAuthCancelled`) と鍵欠落 (`WrapKeyNotFound`) は CLI が区別できるよう unwrapped で propagate。
- audit-log wrapping key の Keychain key id は `mordred.audit-log` (`AUDIT_LOG_KEY_ID`)。 audit code 追加なし — unwrap の audit は `wrap.unwrap_dek` が既に emit する。

### Plugin-disable protection (plugin-side only、 zero-PR strategy)

ユーザが `hermes plugins disable mordred_privacy_check` 等を実行すると enforcement が silent disable されるリスク。

**Tier A (v1 default、 plugin-only strict-mode startup refusal、 H3)**:

MIGRATION.md §10 row 4 で **zero upstream PR** が確定したため (2026-05-07)、 v1 では plugin 側で fail-closed な startup refusal を行う。 これは「警告に留める」 のではなく `BaseException` 派生例外を raise して strict-mode のセッション開始そのものを止める防御:

1. 各 Mordred plugin の `on_session_start` 冒頭で sibling list `["mordred_network", "mordred_privacy_check", "mordred_llm_guard", "mordred_keyvault", "mordred_wizard"]` のうち disabled-plugins リスト (`hermes plugins list --disabled` 相当 — Phase 0.8 で実 API verify) に含まれるものを scan
2. policy が `strict` かつ sibling が 1 つでも disable されている場合: `MordredSiblingDisabled("Mordred strict mode requires all sibling plugins enabled; disabled: [...]. Re-enable via 'hermes plugins enable <name>' or downgrade policy to lenient.")` 相当の refusal exception (`BaseException` 直接派生 — `RuntimeError` 等の `Exception` 派生は Hermes `invoke_hook` の `except Exception:` wrapper に握り潰されセッションが止まらないため不可) を raise してセッションを abort

   > **Exception propagation contract** (2026-05-13): refusal exception は Hermes `invoke_hook` の `except Exception:` wrapper を escape する必要がある。 `privacy_check/hooks.py` は legacy で **`SystemExit` 派生**、 Phase 2 `llm_guard` 以降の新規 refusal class (`MordredHarnessRefused` / `MordredSessionRefused`) は **`BaseException` 直接派生** (cleanup-style `except SystemExit:` で policy refusal が CLI exit として誤検出されないため、 `src/mordred_hermes/llm_guard/_exceptions.py` 参照)。 後者が canonical で、 `privacy_check` は follow-up で `BaseException` 派生 (`MordredSiblingDisabled` 想定) へ統一する候補。 上記の例外名・メッセージ例は illustrative — 実装は phase ごとに上記の派生規則に従う。
3. 同時に audit log に `mordred.degraded.disable_unprotected` (decision=`block`) を記録
4. `policy=lenient` / `off` の場合は warning のみ (互換性確保)
5. `plugin.yaml` の `privacy_lock: true` は Mordred 内部 hint として保持 (sibling list の自動拡張に活用、 Hermes 上流側の意味は持たない)

**Tier B (v2 deferred、 vendored fork extra)**:

hard-enforce が真に必要になった時点で `pip install mordred-hermes[hard-lock]` extra を提供。 内容は `hermes_cli/plugins_cmd.py` のパッチ版を `vendor/hermes/<version>/` 配下に持ち、 `mordred-hermes[hard-lock]` インストール時に `pyproject.toml` の `dependencies` で Hermes 特定バージョンに pin したまま、 disable 操作そのものを core-side で refuse する。 Hermes 上流への PR は提出せず、 vendored fork として配布する。 v1 範囲外。

**重要な caveat (§Threat Model "does NOT defend against" 参照)**: Tier A は **次回セッション開始時** に block する設計。 「実行中に disable された場合の即時停止」 は v1 範囲外 (Hermes は plugin の動的 disable を session-running 中に反映しない前提、 Phase 0.8 で verify)。 セッション間で disable 編集 → 次セッション strict 起動 → block というフローで防御する。

### Policy file caching

- Loaded at `on_session_start` (Hermes session 開始時)
- Cached in-memory for the session lifetime
- Reload via `hermes mordred policy reload` (内部関数呼び出し、fs watcher は v1 で導入しない)
- 意図的 tradeoff: hot-path file reads を防ぐ、policy 編集は明示的 reload

### Plugin Versioning & Compatibility

- 5 plugin はすべて単一 pip パッケージ `mordred-hermes` に同梱、共通バージョン
- `pyproject.toml` の `[project.metadata]` で `mordred-min-hermes-version` を declare、各 plugin の `on_session_start` で Hermes version 検証
- Hermes upstream の hook payload type 変更を CI (GitHub Actions) で検知し、互換性壊れた時に issue 自動起票
- `mordred-hermes` 自身のバージョンは `docs/VERSION` で管理 (旧 SPEC 同様)

### Observability

- All hook decisions (allow / block / override) are logged via the audit log policy above
- `hermes mordred policy explain <skill-id>` gives a per-skill decision trace
- `hermes mordred policy dry-run <skill-path>` predicts install-time decision without filesystem mutation
- `hermes mordred network status` reports active path + health
- LLM Guard は startup banner で active provider override target を出力
- Hermes の observability plugin (langfuse 等) と並列に動作、衝突しない

## Scope (Out) — explicitly deferred

> Motivation, dependencies, and priorities for post-v1 work live in [`ROADMAP.md`](./ROADMAP.md). This section only enumerates what is **excluded** from v1.

- Linux / Windows native での Phase 4 keyvault (v2-OS2)
- Harness-aware LLM Guard enforcement (v2)
- GUI controls (v2)
- Payment skills using `mordred_keyvault` (v3-P1)
- Per-skill independent network paths (v2; v1 is gateway-wide single-state)
- Skill metadata signing / integrity verification (v2)
- Multi-user / multi-tenant on a single machine (v2)
- Mordred-specific telemetry or crash reporting (v2; Hermes 既存 telemetry 動作を継承)
- iOS / Android native Mordred apps (v2; Hermes Termux 対応のみ Phase 1–3 で利用可能)
- Hermes core への大規模変更 (永久 out of scope。 v1 では Hermes 上流への PR を一切提出しない zero-PR commitment、 v2 で hard-enforce が必要なら `[hard-lock]` extra に vendored fork で対応; MIGRATION.md §10 row 4)

## MVP Phasing

If full v1 scope is too large for a single milestone, ship in this order. Each phase is independently usable.

1. **Phase 1 — Privacy primitives**: `mordred_privacy_check` (with skill install wrapper) + `metadata.mordred.network_requirements` + `mordred_wizard configure/upgrade/policy`。Story 2 と Story 3 部分達成
2. **Phase 2 — LLM enforcement**: `mordred_llm_guard` + `mordred-local` synthetic provider (full Hermes adapter surface)。Story 4 達成。`pre_tool_call` generic allowlist を privacy-check に追加
3. **Phase 3 — Network paths**: `mordred_network` (Tor + VPN + Clearnet switching, on_session_start/end lifecycle, provider transport flagging)。Story 3 完了
4. **Phase 4 — Key management**: `mordred_keyvault` (Secure Enclave-backed AES key wrapping via pyobjc)。Story 5 達成。最大の engineering risk、defer 可能

User-visible MVP = Phase 1 + Phase 2。これが最小の "Hermes with Privacy" 配信。

## Operational Setup (one-time)

開発開始前に必要:

1. `Mordred-Hermes/` リポジトリ確認 (Mordred plugin 開発リポ; Hermes 本体は `pip install hermes-agent` 済み環境であること)
2. `~/.hermes/` プロファイル作成 (`hermes setup` 実行で自動)
3. 5 plugin の scaffold: `src/mordred_hermes/<name>/` ディレクトリで以下を作成
   - `plugin.yaml` — manifest (`name`, `version`, `description`, `author`, `privacy_lock`, `config_schema`)
   - `__init__.py` — entry, defines `register(ctx: PluginContext) -> None`
   - `*.py` — runtime modules (lazy import for native/heavy deps)
   - `tests/test_*.py` — pytest, colocated
   - `README.md` — Mordred-owned paths, config keys, internal API surface
4. `pyproject.toml` (`mordred-hermes` package) に entry-point `hermes_agent.plugins` を declare:
   ```toml
   [project.entry-points."hermes_agent.plugins"]
   mordred_network = "mordred_hermes.network"
   mordred_privacy_check = "mordred_hermes.privacy_check"
   mordred_llm_guard = "mordred_hermes.llm_guard"
   mordred_keyvault = "mordred_hermes.keyvault"
   mordred_wizard = "mordred_hermes.wizard"
   ```
5. CI workflow: `.github/workflows/ci.yml` (pytest + ruff + mypy)、`.github/workflows/upstream-check.yml` (Hermes hook **名** drift 検知; payload field shape の diff は v2)
6. ~~HSeam-1 PR の提出~~ → **削除**: zero-PR commitment (MIGRATION.md §10 row 4、 2026-05-07 確定) のため Hermes 上流への PR は提出しない。 disable 防御は plugin-side strict-mode startup refusal (§Plugin-disable protection Tier A) で完結。 v2 で hard-enforce が必要になれば `[hard-lock]` extra (vendored fork) を追加
