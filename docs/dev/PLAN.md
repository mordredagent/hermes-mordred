# Mordred — Implementation Plan (Hermes-base)

> **Note**: 本 PLAN は `Hermes (NousResearch/hermes-agent)` 基盤での Mordred 実装計画です。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/PLAN.md` (deprecated) に残置。

Companion to `SPEC.md`。各 phase の具体的なファイルパス、 milestone、 test approach、 acceptance criteria を定義する。 Plugin の実装は `src/mordred_hermes/<name>/` (pip 配布レイアウト) に landing し、 `pyproject.toml` の `[project.entry-points."hermes_agent.plugins"]` 経由で Hermes にロードされる。 v1 は **zero-PR commitment** (`MIGRATION.md` §5、 2026-05-07): Hermes core 改変は **plugin-only Tier A** (wrapper CLI + audit log + strict-mode startup refusal) で完結し、 hard-enforce が真に必要になった項目のみ v2 で vendored fork extra (`mordred-hermes[hard-lock]`、 Tier B) に escalate する。 詳細は SPEC §Plugin-Only Architecture 参照。

`Mordred-Hermes/` リポジトリは upstream `NousResearch/hermes-agent` の rebase 不要 (純粋な plugin 開発リポ)。配布は `pip install mordred-hermes` 単発インストール。

## Phase 0 — Operational Setup (one-time, blocking everything else)

### 0.1 Repo & venv 確認

- `Mordred-Hermes/` から Hermes が利用可能であること (`pip install hermes-agent` 済み環境、 または開発者は隣に Hermes 開発 clone を持っていても可): `python -m hermes_cli --version` 等で sanity check
- venv を有効化: `source .venv/bin/activate` (Hermes の `scripts/run_tests.sh` が probe する順序: `.venv` → `venv` → `~/.hermes/hermes-agent/venv`)
- pyproject.toml で `mordred-hermes` パッケージをローカル開発インストール準備 (Phase 0.5 で実装)

### 0.2 Hermes upstream tracking 戦略 (オプション)

- 推奨は **rebase 不要** (plugin-only 配布のため)
- 開発中に Hermes upstream の最新を追いたい場合のみ: `git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git`
- `.github/workflows/upstream-check.yml` で週次に Hermes 最新の hook **名** drift (`hermes_cli.plugins.VALID_HOOKS` membership) を検知し、 Mordred plugin が `register_hook("...")` で登録する hook 名と比較。差分発生時に issue 自動起票 (hook **payload field shape** の deep diff は v2 deferred — 本 workflow は名前 drift のみ)
- decision: 上記 workflow を v1 で導入するか、v2 まで遅延するかは Phase 0.5 で決定

### 0.3 Mordred-owned paths (PATHS.md と同期)

予約 path:
- `~/.hermes/mordred/audit.log` (Phase 1)
- `~/.hermes/mordred/policy.json` (Phase 1)
- `~/.hermes/mordred/credentials/` (Phase 3)
- `~/.hermes/mordred/keyvault/` (Phase 4)

各 plugin の `README.md` で own する path / 内部 Python API を明記。

### 0.4 Plugin scaffolding pattern

各 Mordred plugin は `src/mordred_hermes/<name>/` (pip 配布レイアウト) で以下を持つ:

- `plugin.yaml` — Hermes plugin manifest:
  ```yaml
  name: mordred_<name>
  version: 0.1.0
  description: <one-line>
  author: InternetMaximalism
  privacy_lock: true   # Mordred 内部 hint (zero-PR commitment、 Hermes 上流に PR を出さないため Hermes 本体は当該フィールドを無視)。 Tier A の sibling-disable 検出に活用。 hard-enforce は v2 `[hard-lock]` extra (vendored fork) が担う
  config_schema:
    type: object
    properties:
      ...
  ```
- `__init__.py` — entry, defines `def register(ctx: PluginContext) -> None`
- `*.py` — runtime modules
  - native / heavy deps は `_lazy_import()` で遅延読み込み (例: `mordred_keyvault.native` は macOS 以外で import error にならない)
- `tests/test_*.py` — pytest, colocated
- `README.md` — Mordred-owned paths, config keys, 内部 Python API surface
- `AGENTS.md` (オプション) — 開発時の AI agent 向けガイド

### 0.5 `mordred-hermes` パッケージ scaffold

- ルート `pyproject.toml` 例:
  ```toml
  [build-system]
  requires = ["hatchling"]
  build-backend = "hatchling.build"

  [project]
  name = "mordred-hermes"
  dynamic = ["version"]                        # docs/VERSION から読む (single source of truth、 M6)
  description = "Privacy-enhancement layer for Hermes"
  readme = "README.md"
  license = { file = "LICENSE" }
  requires-python = ">=3.10"
  dependencies = [
    "hermes-agent>=1.0",                       # H1: peer Hermes ランタイム。 install 時必須 (これが無いと entry-point が解決しない)
    "ruamel.yaml>=0.18",
  ]

  [project.optional-dependencies]
  macos = ["pyobjc-framework-Security>=10.0"]   # Phase 4 keyvault

  [project.entry-points."hermes_agent.plugins"]
  mordred_network = "mordred_hermes.network"
  mordred_privacy_check = "mordred_hermes.privacy_check"
  mordred_llm_guard = "mordred_hermes.llm_guard"
  mordred_keyvault = "mordred_hermes.keyvault"
  mordred_wizard = "mordred_hermes.wizard"

  [project.metadata]
  mordred-min-hermes-version = "1.0.0"   # 各 plugin の on_session_start で runtime version を再検証

  [tool.hatch.version]
  source = "regex"                       # default `path` source は `__version__ = "..."` パターンを期待するため、 plain-text VERSION ファイル用に regex source を明示
  path = "docs/VERSION"          # M6: VERSION ファイルが single source of truth、 pyproject にハードコードしない
  pattern = "^v?(?P<version>.+?)\\s*$"   # 先頭 `v` prefix を許容、 trailing whitespace を chomp。 抽出値は PEP 440 準拠であること (Hatch が validate)
  ```

  > **PEP 440 準拠 (Codex review 2026-05-09)**: `docs/VERSION` の中身は **PEP 440 準拠の version string** (例: `0.1.0a0` = alpha 0、 `0.1.0` = release、 `0.1.0.dev0` = dev release) であること。 v1 baseline は `0.1.0a0` (Hatch が `0.1.0-mvp.0` を reject するため)。 人間可読の spec label `v0.1.0-mvp.0` は ROADMAP / SPEC / release notes でのみ branding として使用、 packaging 上は `0.1.0a0` を first PyPI upload version とする。

- パッケージレイアウトは `src/mordred_hermes/{network,privacy_check,llm_guard,keyvault,wizard}/`
- 開発時は `pip install -e ./mordred-hermes` で editable install、Hermes が entry-point 経由でロード
- **install-time の hermes-agent 必須化** (H1): `dependencies = ["hermes-agent>=1.0", ...]` により `pip install mordred-hermes` 単体が Hermes 不在環境で fail-fast。 `[project.metadata].mordred-min-hermes-version` は runtime side の二重検証として残す (`hermes-agent` を緩く pin した環境で旧バージョンが入った場合の検出用)
- **package-name reservation** (M7): TestPyPI / PyPI 上で `mordred-hermes` 名を v1 docs 公開前に stub upload で押さえる (TODO §0.5 参照)。 Squat による supply-chain 攻撃の予防

### 0.6 CI workflow

- `.github/workflows/ci.yml`:
  - `pytest` (with `pytest-cov` でカバレッジ)
  - `ruff check src tests`
  - `ruff format --check src tests`
  - `mypy src` (strict mode)
- `.github/workflows/upstream-check.yml` (上記 0.2 のオプション workflow)
- Labeler: `.github/labeler.yml` で `mordred-*` paths にラベル付与 (旧 OpenClaw repo の慣行を踏襲)

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

> **2026-05-07 revise**: MIGRATION.md §10 row 4 / §5 で **zero upstream PR** が確定。 Hermes 上流への HSeam-1 PR は v1 で**提出しない**。 disable 防御は plugin-side strict-mode startup refusal (SPEC.md §Plugin-disable protection Tier A、 TODO.md §1.1 H3 タスク) で完結する。

v1 では Phase 0.7 タスクは以下のみ:

- [x] `plugin.yaml` の `privacy_lock: true` を Mordred 内部 hint として 5 plugin 全てで declare (Hermes 上流側に意味は持たないが、 sibling list 自動拡張に活用) — **完了**: 5 plugin (`keyvault`/`network`/`wizard`/`privacy_check`/`llm_guard`) の `src/mordred_hermes/<name>/plugin.yaml` で `privacy_lock: true` を declare 済み
- [x] H3 plugin-side strict-mode startup refusal の実装は Phase 1.1 (`mordred_privacy_check.on_session_start`) で行う — **完了**: `privacy_check/hooks.on_session_start` が `_runtime.find_disabled_siblings` で sibling-disable を検出し、 strict mode で audit + poison + `SystemExit` (H3 Path B、 SPEC.md §Plugin-disable protection Tier A)。 `privacy_check/__init__.py` で hook 登録、 `tests/test_hooks.py` でカバー

将来 (v2) に hard-enforce が必要になった場合のみ vendored fork extra を導入:

- `vendor/hermes/<version>/hermes_cli/plugins_cmd.py` に Hermes 該当バージョンのパッチ版を配置
- `pyproject.toml` に `[project.optional-dependencies]` で `hard-lock` extra を定義
- ユーザは `pip install mordred-hermes[hard-lock]` で hard-enforce 版を取得
- 詳細手順は UPSTREAM.md §Tier B 参照、 v1 範囲外

**Phase 0 acceptance**:

- `pip install -e ./mordred-hermes` 成功、 entry-point 経由で `PluginManager.discover_and_load()` が 5 つの mordred_* を検出
- ~~`hermes plugins list` で 5 つの mordred_* が表示~~ → Phase 1.3 wizard で `hermes mordred plugins list` wrapper CLI を提供 (Hermes 0.11.0 の `_discover_all_plugins()` が entry-point plugin を表示しない既知 gap、 TODO.md §Acceptance gate L126 参照)
- pytest が空でも green、 ruff/mypy も green (CI で強制、 PR #8 で landing。 詳細は `docs/dev/CI.md` §`ci.yml` 詳細)
- ~~HSeam-1 PR draft~~ → 不要 (zero-PR commitment)

---

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

最小 end-to-end スライス。Story 2 と Story 3 部分達成。Network code / native module 一切無し。

**Privacy-lock guard (Tier A、 zero-PR commitment)**: `privacy_lock: true` は all 5 plugins の `plugin.yaml` で Mordred 内部 hint として declare。 Hermes 本体は当該フィールドを無視するため、 各 plugin の `on_session_start` で sibling Mordred plugin の disable を検出した時点で strict-mode セッション起動を `RuntimeError` で abort + audit log `mordred.degraded.disable_unprotected` を記録。 v2 で hard-enforce が必要なら `[hard-lock]` extra (vendored fork) に escalate。

### 1.1 Plugin: `mordred_privacy_check`

**Files**

- `src/mordred_hermes/privacy_check/plugin.yaml`
  ```yaml
  name: mordred_privacy_check
  version: 0.1.0
  description: Privacy policy enforcement for Mordred
  author: InternetMaximalism
  privacy_lock: true
  config_schema:
    type: object
    additionalProperties: false
    properties:
      policy:
        enum: [strict, lenient, off]
        default: lenient
      allow_cloud_llm:
        type: boolean
        default: false
      cloud_provider_allowlist:
        type: array
        items: { type: string }
        default: []
      audit_log_path:
        type: string
  ```
- `src/mordred_hermes/privacy_check/__init__.py` — `register(ctx)` 関数
- `src/mordred_hermes/privacy_check/policy.py` — pure policy evaluator (no I/O)
- `src/mordred_hermes/privacy_check/skill_frontmatter.py` — SKILL.md frontmatter parser、 `metadata.mordred.*` 抽出
- `src/mordred_hermes/privacy_check/audit.py` — single-writer append-only audit logger with rotation
  - Phase 1–3: plaintext NDJSON, file mode `0600`
  - Writer interface: `class Writer(Protocol)`、 Phase 4 で `EncryptedWriter` に factory swap
- `src/mordred_hermes/privacy_check/install_wrapper.py` — `hermes mordred install <skill>` 実装 (wizard から呼ばれる)
- `tests/test_policy.py` — policy 評価の matrix (strict/lenient/off × clearnet/tor/vpn/local-only)
- `tests/test_audit.py` — rotation, file mode, single-writer concurrency
- `tests/test_install_wrapper.py` — fixture skill (clearnet/tor/missing) を install して expected outcome を assert

**Hooks to register**

Hermes hook payload shapes は `hermes_cli/plugins.py:VALID_HOOKS` で固定:

- **Skill install ガード** (Hermes core hook が無いので wrapper 経由):
  - `hermes mordred install <skill>` → `install_wrapper.run(skill_path)`
  - SKILL.md を `skill_path` から read、 frontmatter を yaml.safe_load
  - `metadata.mordred.network_requirements` を抽出
  - Strict + `clearnet` → `RuntimeError` raise + audit log `policy.strict.clearnet`
  - Strict + missing → `RuntimeError` raise + audit log `policy.strict.unknown_metadata`
  - Lenient + missing → allow + audit log `policy.lenient.unknown_metadata_warning`
  - Allow → Hermes 標準の skill install を child-process spawn (`hermes skills install <skill>`)
- `pre_tool_call` (`ctx.register_hook("pre_tool_call", _on_pre_tool_call)`)
  - payload (**Phase 0.8 verify 完了**、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4): `{tool_name, args, task_id, session_id, tool_call_id}`。 **`origin_skill` は含まれない** — per-skill ポリシーは install-time の `hermes mordred install` ラッパで判定する経路のみ
  - 汎用 per-tool allowlist (configurable)。Default strict-mode blocklist: builtin `web_fetch`, `web_search` when active network path is Clearnet
  - block 形式は `{"action": "block", "message": str}` を return (**Phase 0.8 verify 完了**、 例外 raise ではない、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)
  - **v1 は常に generic allowlist 経路** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4 で `origin_skill` payload 不在を確定)。 起動時に audit `mordred.degraded.no_origin_skill` を 1 回記録 (per-skill 経路が v1 で利用不可であることの宣言。 v2-H2 で `origin_skill` payload 拡張が landing したら本ログは抑止)
- `on_session_start` (`ctx.register_hook("on_session_start", _on_session_start)`)
  - `~/.hermes/config.yaml` の `plugins.mordred_privacy_check` から policy snapshot を load
  - メモリにキャッシュ
  - sibling Mordred plugin が disable されている場合は warning + `mordred.degraded.disable_unprotected`
  - v2 `[hard-lock]` extra (vendored fork) が install されている場合は core-side guard が一段早く防ぐため、 plugin-side の startup refusal は redundant な defense-in-depth として残す (害は無い)

**Audit log format** (newline-delimited JSON, `~/.hermes/mordred/audit.log`, 0600, daily rotation, 10 MB cap, 30-day retention, gzip after rotation, single-writer queue):

```json
{
  "ts": "2026-04-29T12:34:56.000Z",
  "event": "pre_install",
  "skill_id": "example",
  "decision": "block",
  "reason": "policy.strict.clearnet"
}
```

Fields: `ts` (ISO-8601 UTC), `event` (hook name or `pre_install`), `skill_id` / `tool_name` / `provider_id` (one of, depending on event), `decision` (`allow` | `block` | `override` | `warn`), `reason` (固定 enum、 SPEC.md §Audit log policy で freeze)。Raw `params`、 prompt content、 skill body は never logged。

### 1.2 Skill metadata namespace

- 文書化: `src/mordred_hermes/privacy_check/README.md` で:
  - `metadata.mordred.network_requirements`: enum `tor` | `vpn` | `clearnet` | `local-only`
  - `metadata.mordred.requires_keyvault`: boolean (Phase 4)
  - `metadata.mordred.outbound_endpoints`: optional `string[]` — explicit endpoint allow-list
- Hermes 標準スキルローダは `metadata.mordred.*` を解釈しない (agentskills.io 規格との衝突は無し、 Phase 1.5 で確認)
- Acceptance: fixture skill at `tests/fixtures/clearnet_skill/SKILL.md` is rejected at `hermes mordred install` under strict policy

### 1.3 Plugin: `mordred_wizard`

**Files**

- `src/mordred_hermes/wizard/plugin.yaml` — config under `plugins.mordred_wizard`
- `src/mordred_hermes/wizard/__init__.py` — `register(ctx)` で `ctx.register_cli_command("mordred", help="Mordred privacy layer", setup_fn=_setup_subparser, ...)`
- `src/mordred_hermes/wizard/cli.py` — `_setup_subparser(subparser)` で argparse subparser ツリー構築 (configure / upgrade / install / network / policy / audit / keyvault)
- `src/mordred_hermes/wizard/configure.py` — `hermes setup` を `subprocess.run` で child spawn、 後に Mordred-specific questions を `prompt_toolkit` (Hermes 既存依存) で
- `src/mordred_hermes/wizard/upgrade.py` — Story 1 / 1.5 single-command migration
  - `~/.hermes/config.yaml` を `ruamel.yaml` で round-trip (コメント・キー順保持)
  - idempotent
  - 既存 `plugins.mordred_*` 衝突時は diff + prompt
  - 既存スキルで `metadata.mordred.*` 無いものは lenient で audit-warn、 strict で block
  - **Story 1.5 (OpenClaw 移行)**: `~/.openclaw/mordred/` を検出時、 PATHS.md "OpenClaw 旧パスからの migration" 表に従って migration
- `src/mordred_hermes/wizard/policy_writer.py` — `~/.hermes/config.yaml` の `plugins.mordred_*` セクションを書き出し (`ruamel.yaml`)
- `src/mordred_hermes/wizard/policy_explainer.py` — `policy explain` / `policy dry-run` 実装
- `tests/test_upgrade.py` — fixture config を migrate して expected output 確認
- `tests/test_policy_writer.py` — JSON5/YAML round-trip の comment preservation を assert

**CLI surface (Phase 1)**

- `hermes mordred configure` — child-spawn `hermes setup`、 then Mordred prompts (policy, allow_cloud_llm, cloud_provider_allowlist, local LLM endpoint, local model id (Phase 2 fields は Phase 1 で集めても未使用))
- `hermes mordred upgrade` — Story 1 / 1.5 migration; idempotent; preserves YAML comments (`ruamel.yaml`)
- `hermes mordred install <skill>` — Phase 1 の重要エントリ。privacy-check 経由のスキル install
- `hermes mordred policy show` — print effective policy (merged from all `plugins.mordred_*`)
- `hermes mordred policy explain <skill-id>` — explain why a skill is allowed/blocked
- `hermes mordred policy dry-run <skill-path>` — predict install-time decision
- `hermes mordred policy reload` — invalidate in-memory policy cache (in-process call)
- `hermes mordred audit tail [-n N]` — print last N audit entries
- `hermes mordred audit grep <pattern>` — search audit log

### 1.4 Tests

- Unit: `test_policy.py` covers strict/lenient/off × clearnet/tor/vpn/local-only matrix
- Integration: install fixture skill via `hermes mordred install`, assert outcome
- Wizard: snapshot-test the prompt sequence (`pytest-snapshot`)
- E2E: `pytest tests/` 全体

**Phase 1 acceptance**:

- `hermes mordred configure` writes policy to `~/.hermes/config.yaml` and `policy.json`
- `hermes mordred upgrade` migrates an existing Hermes install without data loss; OpenClaw 移行も Story 1.5 通り
- `hermes mordred install <fixture-clearnet-skill>` is blocked under strict policy
- All tests pass on `pytest -q`、 ruff / mypy green
- zero-PR commitment 下でも plugin 側 Tier A guard (strict-mode startup refusal + audit log) で defense-in-depth が成立。 v2 で `[hard-lock]` extra (vendored fork) を追加すれば core-side hard-enforce にも対応可能

---

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

> **2026-05-13: Phase 2 PR1 + PR2 完了** (`main` にマージ済み、 PR #14 / #15)。 本セクションは PR1 prep findings (Codex review B1/B2/H1/H2、 TODO.md §2 L227-234) を反映した **landed design** を記述する。 履歴的な「pre_llm_call 経由の動的 provider override」 計画は Phase 0.8 verify 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5) で却下、 後段 §2.1 で landed semantics に統一。

session-scoped LLM enforcement と harness 起動 refuse。Story 4 達成。

**Hermes 機能依存** (Phase 0.8 verify 完了、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5):

- v0.11.0 の `pre_llm_call` payload は `model` のみで `provider` を含まず、 戻り値も context-injection 専用 (provider override 不可)。 `pre_api_request` には provider/model/base_url が乗るが observer-only。 v1 は **`on_session_start` + `pre_api_request` の二段で session-scoped enforcement**:
  - strict + current provider が `cloud_provider_allowlist` に該当 + `allow_cloud_llm: true` → session 続行 (passthrough、 audit `policy.strict.cloud_allowlisted`)
  - strict + 該当しない、 または `allow_cloud_llm: false` → **refuse** (`MordredSessionRefused(BaseException)` raise、 audit `policy.strict.session_refused` + classification `policy.strict.cloud_not_allowlisted`)。 **auto-swap (config patch + `register_provider`) は B2 により v1 不可** — Hermes は session 開始**前**に provider を resolve 済みのため。 v2 vendored fork (`[hard-lock]` extra、 Tier B) で復活予定 (`policy.strict.provider_override_at_session_start` enum は forward-compat reservation として既に freeze 済み、 POLICY.md row 11 参照)
- ターン毎の動的 override は v1 範囲外 (構造的不可能)

### 2.1 Plugin: `mordred_llm_guard` (landed)

**Files** (landed in `src/mordred_hermes/llm_guard/`):

- `plugin.yaml` — config under `plugins.mordred_llm_guard`、 `privacy_lock: true`
- `__init__.py` — `register(ctx)` で provider adapter (`register_mordred_local`) + 3 hooks (`on_session_start` × 2 + `pre_api_request`) を**明示登録** (Codex B1: `providers._discover_providers()` は entry-point plugin を scan しないため module-import side effect は不可)
- `local_adapter.py` — **declarative `ProviderProfile` subclass のみ** (Codex H1: PLAN 旧版が列挙していた SPI list `auth/discovery/resolve_synthetic_auth/normalize_config/prepare_dynamic_model/resolve_dynamic_model/augment_model_catalog/wrap_stream_fn/wizard` は Hermes v0.11.0 に存在せず stale)。 `name="mordred-local"` / `api_mode="chat_completions"` / `base_url` は `policy.json` から動的 read。 streaming は Hermes core (`agent/error_classifier.py`) 所有
- ~~`transport.py`~~ → **v1 範囲外** (Codex H1、 placeholder のみ残置)。 v2 で upstream に streaming hook が landed したら復活
- `health.py` — endpoint health probe (`/models` GET、 default timeout 2.0s); failure 時に `MordredLocalUnreachable` raise
- `enforce.py` (PR2) — `on_session_start` + `pre_api_request` handler、 **v1 = refuse-only** (Codex B2):
  - lenient/off → no-op (audit silent — per-session allow audit は v2 で再検討)
  - strict + active provider が `cloud_provider_allowlist` に該当 + `allow_cloud_llm: true` → passthrough、 audit `policy.strict.cloud_allowlisted`
  - strict + 該当しない、 または `allow_cloud_llm: false` → `MordredSessionRefused(BaseException)` raise、 audit `policy.strict.session_refused` + classification `policy.strict.cloud_not_allowlisted` を **2 entry で同時 emit** (Codex N1)
  - strict + provider info 無し (degraded) → refuse + audit `mordred.degraded.no_resolved_provider` (one-shot) + `policy.strict.unconditional_override`
  - strict + `mordred-local` active → health probe 成功なら allow、 失敗なら `MordredSessionRefused`（`MordredLocalUnreachable` を `__cause__` に連鎖、 Codex round-2 P2: bare `Exception` だと Hermes `invoke_hook` が swallow するため `BaseException`-derived refusal に wrap）
  - **runtime override 対応** (Codex round-3 P1): `on_session_start` は disk 解決のみで CLI `--provider` / `HERMES_INFERENCE_PROVIDER` / oneshot を取りこぼすため `pre_api_request` で `check_runtime_provider(provider=kwargs.provider)` を追加実行 (`run_agent.py:11320-11338` の resolved runtime provider を消費)
- ~~`override.py`~~ → **削除** (Codex B2 / HOOK_PAYLOADS §5: `pre_llm_call` 経由の provider override は不可能、 v2 vendored fork で再評価時に再作成)
- `harness_detect.py` — `on_session_start` handler (enforce.py より早く呼ぶ):
  - configured harness primary を `~/.hermes/config.yaml plugins.mordred_llm_guard.harness_primary` から read
  - prefix-regex allowlist: `^codex(-\d+(\.\d+)*)?$` / `^claude-cli(-\d+(\.\d+)*)?$` / `^cursor(-\d+(\.\d+)*)?$` / `^acp-[a-z][a-z0-9-]*$`
  - strict → `MordredHarnessRefused(BaseException)` raise + audit `mordred.degraded.disable_unprotected` (decision=`block`)
  - lenient → audit (decision=`warn`) + log warning + 続行 (Codex M2)
  - off → no-op
- `_exceptions.py` — `MordredLocalUnreachable(Exception)` + `MordredHarnessRefused(BaseException)` + `MordredSessionRefused(BaseException)`。 後 2 つは Hermes `invoke_hook` の `except Exception:` wrapper を escape するため `BaseException` 直接派生。 `SystemExit` 派生にしないのは cleanup-style `except SystemExit:` で policy refusal が CLI exit と誤検出されないため (vs. `privacy_check/hooks.py` は legacy で `SystemExit` 派生、 follow-up refactor で `BaseException` 派生に揃える候補)
- `_typing.py` — `PluginContext` Protocol narrow surface (`register_hook` のみ)
- `tests/test_enforce.py`、 `tests/test_enforce_audit.py`、 `tests/test_harness_detect.py`、 `tests/test_health.py`、 `tests/test_local_adapter.py`、 `tests/test_exceptions.py`、 `tests/test_llm_guard_register.py`、 `tests/test_llm_guard_typing.py`、 `tests/integration/test_llm_local.py` (`MORDRED_LIVE_LLM_TEST=1` gated)

**Provider behavior (`mordred-local`)**:

- Provider id: `mordred-local`、 declarative `ProviderProfile` (OpenAI chat-completions wire format)
- Pre-request: `health.probe(endpoint=...)` で `{endpoint}/models` GET、 failure → `MordredLocalUnreachable`
- Cloud allow-list 判定は `enforce.py` の責務 (provider 自身は cloud 知らない)

**Mid-stream local-endpoint death (M2、 v2 deferred)**:

Codex H1 で「Hermes core (`agent/error_classifier.py`) が streaming pipeline を所有しており、 plugin 側で `httpx.RemoteProtocolError` / `httpx.ReadError` を確実に capture できない」 と確定。 結果として:

- `transport.py` は placeholder のみ、 plugin 側で stream interrupt 検知は実装しない
- `MordredLocalStreamInterrupted` exception class は **意図的に未定義** (`_exceptions.py` docstring 参照)
- `policy.strict.local_stream_interrupted` audit reason は 12-code enum に freeze 済み (forward-compat reservation、 POLICY.md row 12)、 v1 では emit site なし
- v2 で upstream に streaming hook が landed した時点で class 復活 + emit site 実装 + `tests/test_enforce.py::test_mid_stream_disconnect` (現在 deleted) 再導入

### 2.2 Wizard additions (landed)

- `hermes mordred configure` に追加 (Phase 1.3 で collect、 Phase 2 PR1 で `PolicySnapshot` に wire、 旧 `phase2_fields` 別 dict は撤去):
  - local LLM endpoint URL (default `http://localhost:1234/v1`)
  - local model id
  - cloud attempt action (`always-block` / `prompt-once`)
  - harness primary declaration (PR2、 default `none`、 choices: `none` / `codex` / `claude-cli` / `cursor` / `acp-claude` / `acp-cline`)
- `PolicyWriter.write` で `~/.hermes/mordred/policy.json` + `~/.hermes/config.yaml plugins.mordred_privacy_check` (Phase 1 fields) + `plugins.mordred_llm_guard.harness_primary` (PR2) を upsert

### 2.3 Tests (landed)

- Unit: `tests/test_enforce.py` で決定 matrix の全 case (25 tests)、 `tests/test_enforce_audit.py` で reason code 同時 emit + frozen-enum membership (7 tests)
- Harness: `tests/test_harness_detect.py` で prefix-regex matrix (24 tests)
- Adapter: `tests/test_local_adapter.py` で B1 explicit-register + module-import side-effect 無し + policy.json fallback (8 tests)
- Health: `tests/test_health.py` で success / timeout / connect-refused / 500 matrix (9 tests)
- Propagation: `tests/test_exceptions.py` で `BaseException` propagation contract (7 tests)
- Registration: `tests/test_llm_guard_register.py` で provider 登録 + hook callback registration order (7 tests)
- Typing: `tests/test_llm_guard_typing.py` で `PluginContext` Protocol narrow surface (4 tests)
- Live: `tests/integration/test_llm_local.py` (`MORDRED_LIVE_LLM_TEST=1` gated): real LM Studio roundtrip + failure mode (port 1 で hermetic 実行)

**Phase 2 acceptance** (Phase 2 PR2 で全 PASS、 2026-05-13):

- strict + `mordred-local` active → health probe 成功で passthrough、 audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictLocal`)
- strict + cloud upstream in `cloud_provider_allowlist` + `allow_cloud_llm: true` → no refuse、 audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictCloudAllowlisted`)
- strict + provider info 無し (degraded) → refuse + audit `mordred.degraded.no_resolved_provider` + `policy.strict.unconditional_override` (`test_enforce.py::TestStrictDegraded`)。 ~~`mordred-local` 自動 routes~~ は v2 vendored fork で復活予定
- strict + no local endpoint reachable → `MordredSessionRefused` (`MordredLocalUnreachable` を `__cause__` に連鎖、 `tests/integration/test_llm_local.py::TestFailureMode`)
- Codex / Claude-CLI primary + strict → `MordredHarnessRefused` で起動 refuse (`test_harness_detect.py` + `test_llm_guard_register.py` で hook registration order を検証)
- Audit log records every refusal / passthrough decision (`test_enforce_audit.py::TestFrozenEnumMembership`、 5 reasons membership invariant)

---

## Phase 3 — Network Paths (`mordred_network`)

3-layer dynamic switching。Story 3 完了。

**Hermes 機能依存**:

- `subprocess` モジュールで Tor/VPN clients を起動 (`tor`/`arti` daemon、 Mullvad WireGuard CLI)
- **Phase 0.8 verify 完了** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §8 — PR #9 Codex review が修正): Hermes は subprocess の env 渡しに **2 つの異なる regime** を持つ:
  - **Regime A (blocklist-style、 default 許可)**: `tools/environments/local.py:_make_run_env`、 `tools/browser_tool.py`、 等。 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` は blocklist 外なので `os.environ.update({...})` で **後続 spawn に伝播**
  - **Regime B (allowlist-style、 default 削除)**: `tools/code_execution_tool.py` は `_SAFE_ENV_PREFIXES` のみ pass through。 proxy 変数は **silently dropped** — Mordred は **`tools.env_passthrough` registry に明示登録** が必須 (さもなくば execute_code child は Tor/VPN tunnel の外で通信)
  - 既に動いている長寿命 subprocess は spawn 時の env を凍結保持 (どちらの regime でも)。 audit `network.use` の `live_subprocess_count` field 設計 (TODO §3.1 M3) は妥当
- v1 は **全体 single-state** (Phase 0.8 verify で `origin_skill` 不在を確定、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)。 per-skill auto-path-switching は v2-H2 で `origin_skill` payload 拡張が landing した後に検討

### 3.1 Plugin: `mordred_network`

**Files**

- `src/mordred_hermes/network/plugin.yaml` — config under `plugins.mordred_network`、 `privacy_lock: true`
- `src/mordred_hermes/network/__init__.py` — `register(ctx)` で `on_session_start`/`on_session_end`/`pre_tool_call` 登録
- `src/mordred_hermes/network/paths/tor.py` — Tor daemon manager (v1 default = official `tor` binary、 `arti` は v2 で再評価):
  - **torrc 生成**: テンプレートから `~/.hermes/mordred/tor-data/torrc` を生成 (`SOCKSPort 127.0.0.1:<port>`、 `ControlPort 127.0.0.1:<port>`、 `CookieAuthentication 1`、 `DataDirectory ~/.hermes/mordred/tor-data/`)
  - **port 衝突解決**: `lsof -i :9050` 相当 (`socket.socket(AF_INET).bind(('127.0.0.1', port))` で probe) → 9150 → `tor_socks_port` user-specified → abort
  - **ControlPort client**: `stem` ライブラリ または raw TCP cookie auth で `getinfo circuit-status` を発行
  - **bootstrap progress**: `tor` の stdout を tail し `Bootstrapped 100%` を 30s 以内に検出 → 失敗で `MordredPathBringupFailed`
  - **process management**: `subprocess.Popen` で起動、 `on_session_end` で `process.terminate()` (5s grace 後に `kill()`)
- `src/mordred_hermes/network/paths/vpn.py` — Mullvad 公式 client wrapper (`subprocess`):
  - **CLI 検出**: `shutil.which("mullvad")` → fail なら macOS 既知 path `/Applications/Mullvad VPN.app/Contents/Resources/mullvad` を試行 → fail なら `MordredPathBringupFailed("mullvad client not installed")`
  - **bring-up sequence**: (strict のみ) `mullvad lockdown-mode set on` → `mullvad relay set location <country|auto>` → `mullvad connect` → `mullvad status` を 10s polling で `Connected` 到達確認 (Mullvad CLI 2026.2 で `always-require-vpn` サブコマンドは削除され、`lockdown-mode` に統合された)
  - **liveness probe**: `wg show` で latest handshake の age を確認、 < 180s で OK (Mullvad client が裏で 25-120s ごとに rekey する想定)
  - **tear-down**: `mullvad disconnect`。 strict 中は lockdown は維持
- `src/mordred_hermes/network/paths/clearnet.py` — no-op
- `src/mordred_hermes/network/proxy_env.py` — emits `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` for active path (NO_PROXY default + URL scheme は M8 §DNS / IPv6 / non-HTTP transport coverage 参照)
- `src/mordred_hermes/network/provider_transport_flagger.py` — `on_session_start` で Hermes provider adapter を列挙し proxy env vars を ignore する known provider に warning
  - **v1 baseline allowlist** (Python dict、 SPEC §Plugin: `mordred_network` v1 baseline allowlist と同期):
    ```python
    KNOWN_PROVIDERS = {
        "anthropic": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "openai": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "gemini": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "mordred-local": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True, "localhost_only": True},
        "bedrock": {"transport": "boto3", "respects_proxy": True, "respects_socks5h": False, "dns_quirk": True},
        "vertex": {"transport": "google-cloud", "respects_proxy": "partial", "respects_socks5h": False},
    }
    ```
  - **strict mode behavior**: active path = `tor` で `respects_socks5h=False` provider が enabled なら startup abort、 active path = `clearnet` (with `policy=strict + cloud_provider_allowlist`) で `respects_proxy=False` provider が enabled なら warning のみ
  - **user override**: policy.json の `provider_overrides: {"<provider>": {"respects_proxy": true}}` で entry 追加可 (削除不可、 baseline は immutable)
- `src/mordred_hermes/network/api.py` — 内部 Python API:
  - `mordred_network.api.use(path: str)` — switch active path
  - `mordred_network.api.status()` — current state
  - `mordred_network.api.health()` — probe
  - `mordred_network.api.blackout_assert()` — verify network blackout (keyvault Phase 4 が consume)
- `src/mordred_hermes/network/runtime.py` — lazy-loaded subprocess management
- `tests/test_paths.py`, `tests/test_proxy_env.py`, `tests/test_provider_transport_flagger.py`
- `tests/integration/test_tor.py` — docker-compose harness for Tor (`docker compose up tor`)

**Bootstrap order (strict mode)**

- `mordred_network` の `on_session_start` を `mordred_privacy_check` の `on_session_start` より先に登録 (**Phase 0.8 verify 完了**、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1: Hermes plugin loader は **登録順** で priority 無し、 entry-point plugin である Mordred 5 個は bundled/user/project の後にロードされる)。 plugin 内 polling fallback (`wait_for(lambda: api.status().ready, timeout=5s)`) を **default** の bootstrap 経路として採用 — register 順依存を最小化
- 強制順序が必要なら Hermes 側 PR 候補 (`register_hook(name, callback, priority=int)`)
- 上記 PR 提出までは plugin 内 polling fallback で動作

**Concurrency model**

- Active path is gateway-wide single state、 per-skill independent paths は v2
- `mordred_network.api.use(path)` is last-write-wins、 audit-logged on switch
- **Parallel tool_call の path mismatch (v1)**: per-tool-call の per-skill 判定は v1 では不可能 (Phase 0.8 verify で `origin_skill` 不在、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)。 v1 enforcement の経路:
  - **install-time**: `hermes mordred install` ラッパが SKILL.md frontmatter の `network_requirements` と active path を比較、 strict 不一致は install を block
  - **runtime**: 全体 single-state のみ。 active path が tor の状態で clearnet-only skill が実行されても block しない (per-skill 検出不能)
  - **path 自動切り替えは行わない** (M3 transitive proxy-env failure mode 回避 + per-skill 判定不能のため)
  - per-tool-call mismatch detection は v2-H2 で復活予定
- **同 path 要求の並列**: 通常通り並列実行 (新 subprocess は親 env を inherit するため active path で透過的に流れる)
- **異なる path 要求の並列**: serialize せず block/warn semantics で対処。 v2 で per-skill SOCKS5 stream isolation (Tor only) を検討 (`v2-N1`)

**Path injection into skills**

- Primary v1 mechanism: `os.environ` に proxy env vars を set on `on_session_start` so spawned child processes inherit them
- `mordred_network.api.use(path)` refreshes the in-process proxy env state and audit-logs the switch
- Per-call env injection from `pre_tool_call` は v2 unless Hermes が subprocess-env hook を expose
- Provider plugins that respect HTTP_PROXY (most do) は automatically active path 経由
- Hard-coded transport の provider plugin は startup で flagger が warning
- **NO_PROXY default**: `proxy_env.py` は active path に依らず常に `NO_PROXY` ベースに `localhost,127.0.0.1,::1` を含める (`mordred-local` localhost LLM endpoint が proxy 経由 になると Phase 2 の health-check が失敗するため)。 user-supplied entries は policy.json `no_proxy: [...]` から append、 重複排除。 IP literal だけでなく `.local` 等のドメイン suffix も append-only で受け付ける
- **`HTTPS_PROXY` URL scheme**:
  - clearnet path: 値を unset (削除)
  - vpn path: 値を unset (tunnel が全 IP traffic を握るため proxy_env 不要、 ただし `provider_transport_flagger` の non-respecting provider がある場合は VPN tunnel 自体に依存)
  - tor path: `socks5h://127.0.0.1:9050` (`socks5h` で **DNS は server-side 解決**、 leak 防止)。 SOCKS5h 非対応の library は flagger で warning

**DNS / IPv6 / non-HTTP transport coverage (M8)**

proxy_env のみで全 traffic を tunnel するのは v1 では達成できない。 以下を SPEC §Threat Model M8 と併せて文書化、 acceptance gate にも反映:

- **DNS leak (Tor 経路で最重要)**: SOCKS5h でない HTTP_PROXY URL は system resolver で名前解決を先に行う → Tor を使っていても query は ISP に到達。 v1 強制: Tor 経路は `socks5h://` URL scheme + 主要 HTTP client (urllib3 / httpx / requests[socks]) のみサポート。 SOCKS5h 非対応 client (古い `aiohttp` 旧版、 直接 socket 操作する provider) は static allowlist で startup warning、 strict mode では active 時 abort
- **IPv6 leak**: HTTPS_PROXY env を尊重しない実装が多い。 v1 default は `disable_ipv6: true` (strict)、 `false` (lenient/off) を policy.json に追加。 enforcement は `socket.has_ipv6` flag では effective でないため、 v1 は **IPv4-only resolver 設定 + IPv6 endpoint への接続は provider_transport_flagger で警告** に留める。 完全防御は v2 (`v2-N2`: bundled IPv6 firewall rule injection)
- **Non-HTTP transport (raw TCP/UDP/QUIC/gRPC native)**: provider_transport_flagger の static allowlist で v1 baseline 列挙 (Phase 0.8 verify で既存 Hermes provider を実機テスト)。 strict mode で known-incompatible provider が active 時は session abort

**Path failure & liveness (M9)**

- **Bring-up failure (path 起動時)**:
  - Tor: bootstrap timeout 30s (initial circuit established までの時間。 SOCKS5 listen open は 5s 以内)
  - VPN: WireGuard handshake timeout 10s (`wg show` で `latest handshake` が更新されるまで)
  - 失敗時: strict → `MordredPathBringupFailed` raise + session abort、 lenient → user-visible warning + clearnet fallback + audit `network.bringup_failed`、 off → silent fallback
- **Liveness probe (mid-session)**:
  - 内部 worker thread が 30s interval で `mordred_network.api.health()` を実行
  - Tor probe: SOCKS5 listener reachable AND `getinfo circuit-status` で 1 つ以上 BUILT circuit (ControlPort 経由)
  - VPN probe: WireGuard `latest handshake` が < 180s 前 AND interface state UP
  - 連続 2 回失敗で path-dropped 判定 (transient な Tor circuit rebuild を吸収)
- **Mid-session drop 検出時**:
  - strict: 次の `pre_tool_call` で `MordredPathDropped` raise (tool 実行 block)
  - lenient: warn + 続行 (注意: clearnet fallback ではなく、 path-dropped 状態を維持。 user が `hermes mordred network use clearnet` で明示的に切り替える前提)
  - 必ず audit `network.path_dropped` (decision=`block` or `warn`、 fields `path` / `consecutive_failures` / `last_health_at`)
- **`mordred_network.api.use(path)` の失敗 semantics**:
  - `MordredNetworkError` を raise (silent fallback は禁止)
  - subclasses: `BringupFailed` (path 起動失敗)、 `AlreadySwitching` (concurrent switch 試行)、 `UnknownPath` (未知の path 名)
  - audit `network.use_failed` emit (decision=`raise`、 fields `requested_path` / `error_type` / `prev_path`)

**Transitive proxy-env failure mode (M3)**

`os.environ` への proxy env vars 注入には mid-session の path switch に対する **transitive** な穴がある。 v1 で正確に把握しておくべき:

- **既に spawn 済みの subprocess は env 更新を見ない**: `mordred_network.api.use("clearnet")` を session 中に呼んだ場合、 親プロセスの `os.environ` は即時更新されるが、 **その時点で生きている子プロセス** (例: Tor daemon、 long-running tool subprocess、 Hermes が `Popen` で残している sidecar) は **古い proxy 設定** を保持し続ける。 逆も真 (`use("tor")` 後の clearnet 子プロセスは clearnet を流れ続ける)
- **特に危険なケース**: `use("tor")` → 何か実行 → `use("clearnet")` → 別の何か実行、 で前段の Tor daemon child がまだ生きていれば、 後段の clearnet 操作が Tor daemon の制御 traffic と混ざる可能性 (現実的には Tor daemon は SOCKS5 listener なので env を読まないが、 一般化された警告として記載)
- **検出**: `mordred_network.api.use(path)` 呼び出し時に audit log へ `network_use` (decision=`override`, fields `prev_path` / `new_path` / `live_subprocess_count`) を emit。 `live_subprocess_count > 0` は env 更新が transitive に効かない signal
- **暫定対応 (v1)**: `mordred_network.api.use()` の docstring に "新規 spawn 子プロセスのみ反映、 既存は再起動が必要" を明記。 wizard CLI `hermes mordred network use` も同 warning を stdout へ
- **完全解決 (v2)**: `mordred_network.api.use()` が live subprocesses を列挙して `signal.SIGTERM` で再起動を提案 (interactive prompt)、 もしくは Hermes に subprocess-env hook を追加 PR
- **混乱を避けるための運用上のおすすめ**: session lifetime の途中で path を切り替える運用は v1 で非推奨。 path は session 開始時に決め、 切り替えたい場合は session 自体を一旦 `on_session_end` させる

### 3.2 Wizard additions

- `hermes mordred network init` asks: default network path、 Tor binary path、 Mullvad アカウント番号 (on-demand、 `configure` からは分離、 再実行可能)
  - 機密情報は `~/.hermes/.env` に `MORDRED_MULLVAD_ACCOUNT=...` として書き込み、 `~/.hermes/mordred/credentials/network.json` には env var ref を記載 (PATHS.md §credentials)
  - 空入力は既存シークレットを維持 (再実行で消さない); prompt のデフォルトは on-disk の現在値を seed
- `hermes mordred network use <tor|vpn|clearnet>` — manual override
- `hermes mordred network status` — print active

### 3.3 Tests

- Unit: path manager state machine
- Integration: docker-compose with Tor container; SOCKS5 reachable assert
- Live (gated by `MORDRED_LIVE_TOR_TEST=1`): Mullvad real connection
- Privacy-check coordination: skill declaring `network_requirements: tor` auto-switches path before tool call (S2 fallback パスでは `policy explain` 経由で確認)

**Phase 3 acceptance**:

- Skill with `network_requirements: tor` auto-routes through Tor at tool-call time (origin_skill 含まれる場合)、 含まれない場合は wizard で手動 `network use tor` する流れを確認
- Manual `hermes mordred network use vpn` switches path within 2s
- `mordred_network.api.status()` returns truthful state
- All bundled provider plugins continue to function under each path

---

## Phase 4 — Key Management (`mordred_keyvault`)

最大 engineering risk。Native module (`pyobjc-framework-Security`)、 macOS Apple Silicon limited。Phase 1-3 と独立して ship 可能。v1 は Secure Enclave で AES DEK wrapping/unwrapping を authorize するのみ (signing key 保持・signing 実行はしない)。

### 4.1 Plugin: `mordred_keyvault`

**Files**

- `src/mordred_hermes/keyvault/plugin.yaml` — `privacy_lock: true`、 macOS extra に依存
- `src/mordred_hermes/keyvault/__init__.py` — `register(ctx)` で CLI 登録、 内部 API 公開
- `src/mordred_hermes/keyvault/native.py` — `Security.framework` ラッパー (pyobjc-framework-Security 経由)、 lazy import (`_lazy_import` pattern で macOS 以外で import 時 ImportError 防止)
- `src/mordred_hermes/keyvault/api.py` — 公開 Python API:
  - `generate(...)` — wrapping-key 初期化 (verification-digest flow 含む)
  - `encrypt(key_id, plaintext, purpose)` — AES-GCM encrypt
  - `decrypt(key_id, ciphertext)` — AES-GCM decrypt (unwrap authorization 後)
  - `export_backup(passphrase)` — Argon2id (m=46 MiB, t=1, p=1) wrapped backup blob
  - `import_backup(blob, passphrase)` — recovery、 digest mismatch で reject
  - `verify_digest(seed_hash, pass_hash_xor_pow)` — verification-digest match
- `src/mordred_hermes/keyvault/crypto.py` — AES-GCM encrypt/decrypt helpers (cryptography ライブラリ)
- `src/mordred_hermes/keyvault/wrap.py` — Secure Enclave-backed wrapping-key integration
- `src/mordred_hermes/keyvault/backup.py` — encrypted secret backup logic; Argon2id (`argon2-cffi` ライブラリ) `m=46 MiB, t=1, p=1`、 16-byte salt + verification digest を blob に embed
- `src/mordred_hermes/keyvault/recovery.py` — cross-machine recovery; `import_backup` で digest 再計算 + mismatch reject
- `src/mordred_hermes/keyvault/digest.py` — `digest = hash(hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW))` 計算 (BLAKE3 ベース)
- `src/mordred_hermes/keyvault/seed_display.py` — Seed display flow: blackout assert → 60-sec timer → display → auto-clear
- `src/mordred_hermes/keyvault/network_fallback.py` — `mordred_network.api.blackout_assert` 不在時に OS API (`SCNetworkReachability` / `nw_path_monitor` via pyobjc) を直接呼ぶ wrapper
- `src/mordred_hermes/keyvault/log_encryption.py` — Phase 1 audit `Writer` interface に slot-in する AES-GCM encryption layer。 audit-log DEK は keyvault wrapped、 メモリのみ保持
- Tests: native module mocked for unit; integration runs only on macOS arm64

**内部 Python API surface**

- `mordred_keyvault.api.generate()` → `(key_id, digest, display_token)`. `display_token` は UI が Seed-display を drive するための opaque handle. Internally `generate` は network-fallback で blackout assert し、 offline verification が成功した時のみ完了
- 他 plugin は `from mordred_hermes.keyvault import api` で import

**Skill opt-in**

- `metadata.mordred.requires_keyvault: true` で declare
- `mordred_privacy_check` が install 時 enforce (Phase 1 では metadata を read するが no-op、 Phase 4 で wired)

**Audit-log encryption coupling (slot into Phase 1 audit logger)**

- Phase 4 ローンチ時、 `keyvault/log_encryption.py` の `EncryptedWriter` を Phase 1 で freeze した `Writer` interface に factory swap
- Pre-Phase-4 plaintext logs は retroactively 暗号化されない。 wizard が `hermes mordred audit purge --before YYYY-MM-DD` を提供
- 復号 CLI: `hermes mordred audit decrypt --date YYYY-MM-DD` (Secure Enclave authorization 必要)
- Interface contract: Phase 1 で `class Writer(Protocol): def append(self, entry: dict) -> None: ...` を freeze、 Phase 4 で `EncryptedWriter` 実装、 factory が選ぶ
- Session log encryption は v1 out (Hermes が generic session-log writer seam を expose する必要あり)

**Network-absent fallback (`mordred_network` 不在時)**

- `on_session_start` で `mordred_network.api.blackout_assert` が import 不可なら `network_fallback.py` activate
- Fallback 実装は OS API 直接呼び出しのみ。VPN/Tor 経路状態は判定不可 (network up/down のみ)
- セキュリティ caveat: 単独 plugin 構成では keyvault が "transmitting over clearnet" を自己検出できない。Seed-display の network-blackout check は OS API のみ。`keyvault init` は startup banner で `mordred_network` ペアリングを推奨表示

### 4.2 Wizard additions

- `hermes mordred keyvault init` — Seed Phrase + Passphrase + PoW 生成 flow (network-blackout assert → Seed display → offline/manual digest match → keyvault initialize)
- `hermes mordred keyvault list` — list key IDs
- `hermes mordred keyvault verify-digest` — re-display digest for cross-checking
- `hermes mordred keyvault recover --blob <path>` — recovery on different machine
- `hermes mordred audit decrypt --date YYYY-MM-DD` — Secure Enclave authorization で復号

### 4.3 Tests

- Unit: backup/recovery roundtrip with mocked native binding
- Unit: fixed-vector tests for `digest.py` (`top4(PoW)` extraction, SPEC-example match)
- Unit: AES-GCM encrypt/decrypt roundtrip and unwrap failure handling with mocked native binding
- Integration (macOS arm64 only, gated by `MORDRED_KEYVAULT_LIVE=1`): real Secure Enclave wrapping-key create + DEK wrap/unwrap + AES-GCM roundtrip
- Integration: with `mordred_network` disabled, run `keyvault init` and confirm `network_fallback` makes the blackout decision via OS APIs
- Integration: PC↔phone pairing flow — v2-F7 deferred unless included in v1 scope late
- Cross-machine recovery: export → deliberate off-by-one Passphrase → import_backup rejects → correct entry succeeds → decrypt

**Phase 4 acceptance**:

- Skill declaring `requires_keyvault: true` blocks install if keyvault not initialized
- Keyvault-protected secret encrypts/decrypts through AES-GCM、 DEK wrapped/unwrapped through Secure Enclave authorization
- Backup → wipe → restore → decrypt roundtrip works
- Seed display always runs blackout check (RPC or fallback) first; refused on check failure
- `import_backup` does not complete unless recomputed digest equals embedded digest
- In `mordred_network`-absent envs, `keyvault init` still functions via OS API fallback
- After Phase 4 lands, audit log is AES-GCM encrypted (test by failing decryption with `openssl`)

---

## Cross-cutting concerns

### Documentation

- `docs/UPSTREAM.md` — Hermes upstream tracking 戦略 (Phase 0)
- `docs/dev/POLICY.md` — policy schema reference (Phase 1.1 / 2026-05-10 で landed; canonical な audit log reason enum + `metadata.mordred.*` spec deviation + `plugins.mordred_privacy_check` config schema + Phase 3 `disable_ipv6` 拡張を網羅)
- 各 plugin の `README.md` — own paths、 config keys、 内部 Python API surface
- Changelog: 各 PR で `### Changes` / `### Fixes` に 1-line entry + `Thanks @<author>`

### Testing posture

- pytest, colocated `tests/test_*.py`、 integration `tests/integration/test_*.py`
- mock native bindings, network paths, provider HTTP at unit level
- One integration smoke per plugin boundary
- Live tests gated by env vars (`MORDRED_LIVE_LLM_TEST=1`, `MORDRED_KEYVAULT_LIVE=1`, `MORDRED_LIVE_TOR_TEST=1`)
- Hermes の `scripts/run_tests.sh` と整合する CI 構成

### Type/build/lint posture

- Python >= 3.10、 strict typing (`mypy --strict src`)
- ruff (lint + format) — Hermes 既存依存
- circular import 防止: 各 plugin は `from mordred_hermes.<other_plugin> import api` のみ許可、 内部 module は import しない

### Boundary discipline

- Mordred plugins import from `hermes_cli.plugins.PluginContext` のみ — `hermes_cli` 他 module は触らない
- Native module loading via `_lazy_import` pattern (macOS 以外で ImportError 回避)
- Hermes core (`agent/`, `gateway/`, `model_tools.py` 等) は Mordred-owned path / module を一切参照しない
- `privacy_lock: true` は 汎用 boolean フィールド (Mordred 内部 hint)、 Mordred-specific id を含まない。 v2 vendored fork extra (`[hard-lock]`) を導入する際も同じ汎用フィールド設計を維持し、 vendored モジュールに Mordred-specific id・default・recovery policy を入れない
- Plugin-side `mordred.degraded.*` fallbacks remain in place permanently as defense in depth

### Versioning & SDK compatibility

- 5 plugin は単一 pip パッケージ `mordred-hermes` に同梱、 共通バージョン
- `pyproject.toml` の `[project.metadata]` で `mordred-min-hermes-version` declare、 各 plugin の `on_session_start` で Hermes version verify
- Mordred-as-distribution version は `docs/VERSION` で管理
- Upstream-check workflow (`.github/workflows/upstream-check.yml`) で Hermes hook **名** drift (`VALID_HOOKS` membership) を検知し issue 自動起票 (payload field shape の deep diff は v2 deferred)

### Hook payload realities (Phase 0.8 verify 完了 — 2026-05-10)

Hermes hook payload の実形状は **Phase 0.8 で source-code verify 完了** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md))。 Phase 1 / 2 / 3 の implementation はこれらの確定済み形状を前提にする:

- **`pre_tool_call`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4): `{tool_name, args, task_id, session_id, tool_call_id}`。 **`origin_skill` 不在** — per-skill ポリシーは install-time の `hermes mordred install` ラッパで判定
- **`pre_llm_call`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5): payload は `model` のみで `provider` 不在、 戻り値は context-injection 専用 (provider override 不可)。 v1 は `on_session_start` で session-scoped enforcement に切り替え
- **`pre_gateway_dispatch`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §6): `skip`/`rewrite`/`allow` action 可能。 docstring と一致、 設計変更不要
- **`pre_approval_request` / `post_approval_response`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §7): observer-only (戻り値 ignored)、 Mordred は audit log emit のみ

SPEC § "Plugin-Only Architecture" の "他に core 改修が必要になりそうな項目" は Phase 0.8 verify outcome を反映済み (TODO §0.8 acceptance gate L127 closed)。

---

## Risks and unresolved decisions

1. **Hermes hook payload shape の verify** — Phase 0 で確認、 結果次第で Phase 1.1 / Phase 2.1 の implementation 詳細が変動
2. ~~**Hermes plugin loader の hook 順序保証**~~ — **Phase 0.8 verify 完了** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1): 登録順、 priority 無し。 Phase 3 strict-mode bootstrap は plugin 内 polling fallback を採用
3. **Hermes child process spawn API** — proxy env var inheritance の機構を確認 (Phase 3)
4. ~~**HSeam-1 PR の受理タイミング**~~ → **解消 (2026-05-07 zero-PR commitment)**: Hermes 上流に PR を提出しない方針が確定したため、 受理タイミング依存は無くなる。 disable 防御は plugin-side strict-mode startup refusal (SPEC.md §Plugin-disable protection Tier A) で完結。 v2 で vendored fork extra (`[hard-lock]`) が必要かは別途判断
5. **`pyobjc-framework-Security` の API stability** — Phase 4 native binding が macOS バージョン更新で壊れる可能性。CI で macOS-latest をターゲットにし、 早期検知
6. **Story 1.5 OpenClaw 移行の動作テスト** — 実 OpenClaw + Mordred-OpenClaw 環境を再現する手段 (Docker image 推奨)

## Recommended execution order

1. **Phase 0** (1-2 日) — venv、 plugin scaffold、 pyproject.toml、 CI、 Hermes hook payload verify (zero-PR commitment 確定後は HSeam-1 PR draft 作業は不要)
2. **Phase 1** (1 週間) — privacy_check + wizard、 audit log、 install wrapper、 Story 2 + 部分 Story 3
3. **Phase 2** (4-5 日) — llm_guard + mordred-local provider、 Story 4
4. **Phase 3** (1-2 週間) — network、 Tor/VPN switching、 Story 3 完了
5. **Phase 4** (2-3 週間、 pairing v2-F7 deferred) — keyvault、 Secure Enclave native binding、 Story 5

User-visible MVP = Phase 0 + Phase 1 + Phase 2。これが最小の "Hermes with Privacy" 配信。
