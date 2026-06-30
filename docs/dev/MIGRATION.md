# Mordred — OpenClaw → Hermes 移行ガイド (叩き台 / DRAFT)

> このファイルは、`mordred-mvp-docs` を `OpenClaw` 基準から `Hermes` (NousResearch/hermes-agent) 基準へ書き換えるための **基本方針書** です。
> 用語マッピング、戦略、確定事項、未決事項を一覧化し、SPEC/PLAN/PATHS/TODO 等の本体書き換えのリファレンスとして使います。
> **Status: DECIDED — 推奨案が確定 (§10 参照)。 v1 戦略は `案 C + Vendored-fork escape hatch` (zero upstream PR)、 詳細は §5。 2026-05-07 に B+C ハイブリッドから revise。**

---

## 0. 背景と動機

旧 SPEC は `Fork OpenClaw + 5プラグイン + 3 core seams (S1–S3)` という構成。基盤が `OpenClaw` (TypeScript / Node.js) だった。

現在の作業リポジトリは `Mordred-Hermes/` で、**Hermes (Python / NousResearch)** をベースとしている。Hermes は OpenClaw からの移行を一級市民としてサポートしており (`hermes claw migrate` 既存)、エコシステムとしての成熟度・モデル選択の柔軟性・配布チャネルの広さで優位。

**目的**: Mordred のプライバシー強化レイヤを Hermes 上で再構築し、文書群をそれに整合させる。

---

## 1. アーキテクチャ差分マトリクス (検証済み)

| 領域 | OpenClaw | Hermes |
|------|----------|--------|
| 言語/ランタイム | TypeScript / Node.js (pnpm) | Python (pyproject.toml, pytest) |
| プラグイン場所 | `extensions/<name>/` | `plugins/<name>/` (bundled) または `~/.hermes/plugins/<name>/` (user) または `./.hermes/plugins/<name>/` (project) または `pip` entry-point `hermes_agent.plugins` |
| プラグイン マニフェスト | `openclaw.plugin.json` (JSON) | `plugin.yaml` (YAML) + `__init__.py` の `register(ctx)` |
| 登録 API | `api.on`, `api.registerCli`, `api.registerProvider`, `api.registerGatewayMethod` | `ctx.register_hook`, `ctx.register_cli_command`, `ctx.register_command` (スラッシュ), `ctx.register_tool`, `ctx.register_platform`, `ctx.register_context_engine`, `ctx.register_image_gen_provider`, `ctx.register_skill`, `ctx.dispatch_tool`, `ctx.inject_message` |
| ライフサイクルフック | `before_install`, `before_tool_call`, `before_model_resolve`, `gateway_start`, `gateway_stop` | `pre_tool_call`, `post_tool_call`, `pre_llm_call`, `post_llm_call`, `pre_api_request`, `post_api_request`, `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`, `pre_gateway_dispatch`, `pre_approval_request`, `post_approval_response`, `subagent_stop`, `transform_terminal_output`, `transform_tool_result` |
| ユーザーパス | `~/.openclaw/mordred/` | `~/.hermes/mordred/` |
| 設定ファイル | `~/.openclaw/openclaw.json` (JSON5) | `~/.hermes/config.yaml` (YAML) + `~/.hermes/.env` (API キーのみ) |
| CLI | `openclaw mordred ...` | `hermes mordred ...` |
| プロバイダ参照実装 | `extensions/lmstudio/` | `agent/*_adapter.py` (anthropic, bedrock, gemini_native, codex_responses, lmstudio_reasoning 等) |
| サブエージェント | `agent` 概念 | `subagent_stop` フック + delegate_task ツール |
| Secure Enclave 結合 | node-addon-api / node-gyp | pyobjc または cffi+Swift bridge または PyO3 |
| テスト | Vitest (`*.test.ts`) | pytest (`tests/test_*.py`) — `scripts/run_tests.sh` |
| フォーマッタ | oxfmt | ruff (推定) |
| 型チェック | tsgo | mypy (推定) |
| Upstream | `github.com/openclaw/openclaw` (MIT) | `github.com/NousResearch/hermes-agent` (MIT) |
| スキルレジストリ | `clawhub.ai` | Skills Hub (組み込み) + `agentskills.io` 規格、`hermes_cli/skills_hub.py` |
| 既存 OpenClaw 移行ツール | n/a | `hermes claw migrate` 既存 |

---

## 2. フックとシグナルの正確なマッピング

旧 SPEC が依存していた 3 つのフックを Hermes 等価に対応付けると以下:

| 旧フック (OpenClaw) | 新フック (Hermes) | payload 等価性 | 備考 |
|---------------------|---------------------|-----------------|------|
| `before_install` | **存在しない** | × | Hermes はスキルインストールを `hermes_cli/skills_hub.py` 経由で行うので、相当する hook ポイントを **新規追加** する必要あり ⇒ **新 Core Seam H1** 候補 |
| `before_tool_call` | `pre_tool_call` | ◯ (調査要) | payload に `originSkill` 相当が含まれるかは要 verify |
| `before_model_resolve` | `pre_llm_call` (or `pre_api_request`) | ◯ (調査要) | provider/model 情報は `pre_llm_call` の方が早い段階で見える |
| `gateway_start` / `gateway_stop` | `on_session_start` / `on_session_end` (個別セッション) | ✗ (粒度が違う) | Hermes の gateway は messaging gateway (Telegram/Discord/...) を指すので、**プロセス全体の起動/終了** に相当するフックは別に必要 ⇒ **新 Core Seam H2** 候補 (例: `on_agent_init` / `on_agent_shutdown`) |
| `before_install` (スキルメタデータ抽出) | n/a | × | Hermes に skill installer ガード機構を追加するか、CLI ラッパで実現 |

### 旧 S1–S3 を Hermes に対応付けると

| 旧 Seam | 概要 | Hermes 対応 |
|--------|------|--------------|
| S1: `pluginManifest.privacyLock?: boolean` | プラグイン disable から守る | v1 default は **plugin-side のみ** (`hermes mordred plugins disable` ラッパ CLI が `--unlock` を要求 + `mordred.degraded.disable_unprotected` audit log)。 hard-enforce が必要なら v2 で **vendored fork extra** (`pip install mordred-hermes[hard-lock]` で `hermes_cli/plugins_cmd.py` のパッチ版を再配布)。 **Hermes 上流への PR は提出しない** |
| S2: `originSkill?` を `before_tool_call` に追加 | スキル単位の per-tool ポリシー | `pre_tool_call` payload に origin skill を含める。Hermes の skill サブシステム経由で tool が呼ばれるパスがあるか要 verify。もしなければ **新 Seam H3** |
| S3: `resolvedProvider?` を `before_model_resolve` に追加 | strict mode 下でも cloud allow-list を許す | `pre_llm_call` payload には provider/model が含まれる可能性が高い (要 verify)。含まれていれば S3 は **upstream に存在する** とみなせて Mordred 側は単に消費するだけ |

→ S1–S3 を **「H1–H4」(仮)** として Hermes 用に再設計する必要あり。具体は SPEC 書き換えで詳細化。

---

## 3. プラグイン 5 種の Hermes 化マッピング

> **Note (L3、 2026-05-07 更新)**: 配布レイアウトは F4 fix で **`src/mordred_hermes/<name>/`** (pip 配布レイアウト、 entry-point `hermes_agent.plugins` 経由ロード) に統一済み。 `plugins/mordred_*/` (bundled-style、 OpenClaw 系統の旧表記) は使わない。 §0 〜 §2 の議論段階ではまだ揺れていたため記載が残っていたが、 §10 (DECIDED) と SPEC/PLAN/PATHS は `src/mordred_hermes/<name>/` で確定済み。

| 旧プラグイン | Hermes 実装パス (src layout) | 主要 register API | 備考 |
|-------------|--------------------|----------------------|------|
| `mordred-network` | `src/mordred_hermes/network/__init__.py` | `register_hook("on_session_start")`, `register_hook("pre_tool_call")`, `register_cli_command("mordred")` | サブプロセス管理 (`tor`/`arti`/Mullvad WireGuard) は Python `subprocess` モジュール。プロキシ環境変数注入は子プロセス起動箇所への配慮が必要。 mid-session の path switch は transitive な穴あり (PLAN §3.1 M3 参照) |
| `mordred-privacy-check` | `src/mordred_hermes/privacy_check/__init__.py` | `register_hook("pre_tool_call")`, `register_hook("on_session_start")`, スキルインストールフック (新規) | **既存スキルインストール経路にフックする手段が無い** ことが課題。CLI ラッパ `hermes mordred install <skill>` を提供するか、Hermes core に新フックを追加するか |
| `mordred-llm-guard` | `src/mordred_hermes/llm_guard/__init__.py` + 同 dir 内 `local_adapter.py` | `register_hook("pre_llm_call")`、 provider adapter は plugin 同梱 (Phase 0.8 verify 結果次第で `plugins/model-providers/<name>/` 系統への移設も検討) | Hermes provider adapter pattern を踏襲。 `pre_llm_call` の override semantics は Phase 0.8 で実コード verify 必要 (Story 4 caveat) |
| `mordred-keyvault` | `src/mordred_hermes/keyvault/__init__.py` (`pyobjc-framework-Security` を `[macos]` extra で同梱) | `register_cli_command("mordred")` 経由で `keyvault` サブツリー登録 | Native binding は **pyobjc** (Security.framework 直バインディング) を最有力候補に。`pip install mordred-hermes[macos]` で導入可能なため node-gyp より単純 |
| `mordred-wizard` | `src/mordred_hermes/wizard/__init__.py` | `register_cli_command("mordred", help, setup_fn, handler_fn)` | `setup_fn(subparser)` 内で `argparse` のサブパーサ階層 (`hermes mordred configure`, `hermes mordred network use ...`, `hermes mordred policy show` 等) を構築 |

---

## 4. Mordred 所有パスのマッピング

| 旧パス | 新パス | オーナー (Hermes) |
|--------|--------|--------------------|
| `~/.openclaw/mordred/audit.log` | `~/.hermes/mordred/audit.log` | `mordred_privacy_check` |
| `~/.openclaw/mordred/policy.json` | `~/.hermes/mordred/policy.json` | `mordred_privacy_check` (writer は `mordred_wizard`) |
| `~/.openclaw/mordred/keyvault/` | `~/.hermes/mordred/keyvault/` | `mordred_keyvault` (Phase 4) |
| `~/.openclaw/credentials/mordred-network.json` | `~/.hermes/mordred/credentials/network.json` または `~/.hermes/.env` の Mordred 用キー (例: `MORDRED_MULLVAD_ACCOUNT=...`) | `mordred_network` |
| `~/.openclaw/openclaw.json` の `plugins.entries.mordred-*.config` | `~/.hermes/config.yaml` の `plugins.mordred-*` セクション | wizard が JSON5 round-trip → YAML round-trip (pyyaml は roundtrip が弱いので **`ruamel.yaml`** 採用検討) |

> Hermes の `get_hermes_home()` は profile-aware (デフォルト `~/.hermes/`)。Mordred も同じ profile 解決を再利用する。

---

## 5. 戦略候補 (3案 → 確定)

### 案 A: ハードフォーク

`NousResearch/hermes-agent` をフォークし、Mordred 専用の long-lived ブランチで開発。Core 改変も自由。

- ◯ Pros: 拘束なし、UX も独自ブランディング可能
- × Cons: upstream 同期コスト最大、メンテ人員依存、Hermes 側の急速な進化に追従しにくい

### 案 B: ソフトフォーク + Hermes Core Seams (旧 SPEC と同じ思想)

`Mordred-Hermes/` をフォークとして残しつつ、core 改変は **最小・追加・汎用 (H1–H4 仮)** に限定。週次 rebase で upstream を吸収。

- ◯ Pros: 旧 SPEC と整合、Hermes 進化を吸収しやすい
- × Cons: Hermes 側に PR を出す必要があり (受理されないと永遠に fork 維持)、レビュー遅延が phase ブロッカーになりうる

### 案 C: 純プラグインバンドル + 必要時のみ patch

5プラグインを **`pip install mordred-hermes`** で配布。Hermes 本体には触れない。`hermes_agent.plugins` entry-point で自動ロード。

- ◯ Pros: Mordred-Hermes リポジトリは upstream rebase 不要、配布が極めて簡単、ユーザは `pip install mordred-hermes` だけ
- × Cons: core 側のガードが効かない (ユーザが手動で plugin disable するとセキュリティ層が消える)。core 改変が必要なシーンが将来出てきた場合の逃げ道が無い

### 確定: 案 C + Vendored-fork escape hatch [DECIDED, revised 2026-05-07]

**案 C (純プラグインバンドル) をベースに、core 改変が真に必要になった項目のみ vendored fork で対応する**。**Hermes 上流への PR は提出しない (zero-PR commitment)**。

理由:

1. Hermes 上流への PR 提出はレビュー時間と受理リスクが phase ブロッカーになり得る。Mordred は上流のスピードに依存せず単独でリリース可能であるべき
2. Plugin-only 配布で MVP (Phase 1–3) は成立する。Privacy-lock 等の "core seam" 相当は plugin-side wrapper + audit log で defense-in-depth を達成
3. それでも core 改変が真に必要になった項目 (将来の seam) は、 Hermes 上流に PR を出さず、 **vendored fork** (Hermes core モジュールのコピーを Mordred-Hermes 配下に保持し、 必要箇所のみパッチを当てた版を `mordred-hermes` 配布物として再配布) で吸収する
4. `Mordred-Hermes/` リポジトリの位置付けは「**プラグイン開発リポジトリ + (必要時に) Hermes 一部モジュールの vendored patch 保有リポ**」

**実装の含意**:

- `Mordred-Hermes/` は upstream `NousResearch/hermes-agent` の rebase 不要 (plugin 開発リポ + 一部 vendored modules)
- 5 plugin は `src/mordred_hermes/<name>/` (pip 配布レイアウト) で開発、`pip install mordred-hermes` (entry-point `hermes_agent.plugins`) で配布
- 旧 SPEC の "core seam" 相当 (旧 S1–S3) は **upstream PR を出さず**、 以下の二段構えで対処:
  - **Tier A (v1 default、 plugin-only)**: plugin-side audit log (`mordred.degraded.*` 系列) と `hermes mordred ...` ラッパ CLI で defense-in-depth
  - **Tier B (deferred、 vendored fork extra)**: 真に hard-enforce が必要な場合のみ、 `vendor/hermes/<version>/` に該当 Hermes モジュールのパッチ版を持ち、 packaging extra (`pip install mordred-hermes[hard-lock]` 等) で再配布。 Hermes 特定バージョンに pin する。 v1 リリース範囲外
- 上流の hook signature drift は CI (`upstream-check.yml`) で検知 (informational、 リリースを block しない)
- "Vendored module を持つ" ことと "上流に PR を出す" ことは別物。 後者は **行わない**

---

## 6. 命名規約

| 項目 | 旧 (OpenClaw) | 新 (Hermes) | 備考 |
|------|---------------|-----------------|------|
| 製品名 | Mordred | **Mordred** (維持) | 確定 |
| CLI | `openclaw mordred ...` | **`hermes mordred ...`** (確定) | ユーザ承認済み |
| プラグイン ID | `mordred-network` 等 (kebab-case) | `mordred_network` 等 (snake_case) ⇒ Python module 名 | Hermes プラグインは Python パッケージ名に従う必要あり |
| pip パッケージ名 | n/a | `mordred-hermes` (kebab) または `mordred-network`, `mordred-privacy-check` 個別 | バンドル戦略に依存 |
| 設定 namespace | `plugins.entries.mordred-*.config` | `plugins.mordred_*` または `mordred:` トップレベルキー | 命名は plugin 自由だが Hermes 既存 plugin に倣うのが望ましい |
| スキル frontmatter | `metadata.mordred.*` | **同じ** `metadata.mordred.*` (互換維持) | agentskills.io 規格との衝突有無を要確認 |
| Mordred-as-distribution version | `mordred-mvp-docs/VERSION` | **同じ** `docs/VERSION` | 維持 |

---

## 7. プラットフォーム対応 [DECIDED]

旧 SPEC は **macOS Apple Silicon only** (理由: Secure Enclave native addon) だったが、Hermes 化で Phase 1–3 を OS 非依存にできるため拡張する。

| Phase | プラットフォーム |
|-------|-------------------|
| Phase 1–3 | **macOS / Linux / WSL2** (Hermes が動く全環境) |
| Phase 4 (keyvault, Tier 1) | **macOS Apple Silicon only** (Secure Enclave) |
| Phase 4 (keyvault, Tier 2/3) | v2: Linux (TPM 2.0) / Windows (DPAPI) は ROADMAP `v2-OS2` 据え置き |

**根拠**:
- Phase 1–3 (network/privacy-check/llm-guard/wizard) は純 Python。Tor/Mullvad CLI は Linux でむしろ動かしやすい
- Hermes コミュニティ全体に開ける意義が大きい (Hermes は Linux/Termux/WSL2 まで支援)
- Phase 4 のみ Secure Enclave 物理制約で macOS Apple Silicon 限定 (これは旧 SPEC 同様)

---

## 8. ドキュメント書き換え フェーズ計画

| Phase | 期間 | 成果物 |
|-------|------|---------|
| **A: 用語マッピング & 意思決定** | 0.5日 | この `MIGRATION.md` (本ファイル) — 意思決定後にロック |
| **B: SPEC.md 書き換え** | 1–2日 | `SPEC.md` を Hermes 基準に全面改訂、5 plugins / H1–H4 seams を確定 |
| **C: PLAN/PATHS/TODO 書き換え** | 1–2日 | ファイルパス、Python ツール、pytest fixture、`hermes mordred ...` CLI 列挙 |
| **D: UPSTREAM/ROADMAP/CI 書き換え** | 0.5日 | `git remote add upstream https://github.com/NousResearch/hermes-agent.git`、Python CI に置換、`upstream-sync.yml` を Python ベースに |
| **(後段) F: 5プラグイン scaffolding 着手** | 別計画 | コード実装は別 PR/別計画で扱う |

合計: **4–6 日** (文書のみ、コード実装は含まない)

---

## 9. リスクと未決事項

### High

1. **Hermes に `before_install` 等価フックが無い** — スキルインストール時の policy 強制ができない可能性。回避案:
   - (a) `hermes_cli/skills_hub.py` に Mordred 用フックポイントを Hermes 側に PR
   - (b) `hermes mordred install <skill>` ラッパ CLI を Mordred wizard 経由で提供 (こちらが現実的)

2. **`pre_llm_call` payload の中身を実コードで verify** — `resolvedProvider` 相当が見えるかで S3 (cloud allow-list) の実装容易度が変わる

3. **Hermes プラグインから LLM provider を動的登録する正規 API が無い** — `agent/*_adapter.py` パターンは core 側に置く必要があり。`mordred-llm-guard` の `mordred-local` synthetic provider をどう統合するかの設計が必要

### Medium

4. **[RESOLVED 2026-05-07]** ~~**`hermes claw migrate` と `hermes mordred upgrade` の二段階移行 UX** — OpenClaw からの既存ユーザは 2 コマンド実行が必要になる。Story 1 を書き直す必要あり~~ → **解決済み (L4)**: §10 row 5 で「独立コマンド維持 + docs で 2-step フローを明記」 で確定。 SPEC.md Story 1.5 が 3 ステップ (`hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade`) を明示している。 統合 wrapper は v2 で再評価

5. **YAML round-trip writer の選択** — `ruamel.yaml` 採用が確定なら Phase 1.3 wizard 設計に影響

6. **Hermes upstream の更新頻度が高い** (rapid development) — Mordred は plugin-only 配布なので **rebase は不要**。 hook signature drift は CI で informational に検知。 vendored fork extra (Tier B) が将来 v2 で導入された場合は、 該当 Hermes バージョン pin の追従コストが発生する

### Low

7. **日本語版の用語ブレ** — 本ファイルに用語対応表 (§1) を載せたので、英→日翻訳時の参照点とする

---

## 10. 意思決定チェックリスト [全項目 DECIDED]

| # | 項目 | 確定内容 | 備考 |
|---|------|------------|------|
| 1 | 戦略 | **案 C + Vendored-fork escape hatch** (zero upstream PR) | §5 参照。`pip install mordred-hermes` 配布、 上流 PR は提出しない、 core 改変が真に必要になった項目のみ vendored fork extra で対応 (v1 範囲外) |
| 2 | プラットフォーム | **Phase 1–3 = macOS/Linux/WSL2、Phase 4 = macOS Apple Silicon** | §7 参照。Phase 4 Tier 2/3 は v2-OS2 |
| 3 | YAML writer | **`ruamel.yaml`** | round-trip でユーザのコメント・キー順を保持 (旧 SPEC の JSON5 round-trip と同等の保証) |
| 4 | Hermes 上流 PR | **提出しない (zero-PR commitment)** | 旧 S1 (privacy_lock) は plugin-side wrapper + audit log で defense-in-depth。 `H1` (before_install 等価) と `H2` (agent init/shutdown) も plugin 側 fallback (CLI ラッパ・既存 hook) で対応。 v2 で hard-enforce が必要になれば vendored fork extra に進む |
| 5 | `hermes claw migrate` との関係 | **独立コマンド維持** (`hermes mordred upgrade`)、ただし docs で 2 ステップフロー明記 | OpenClaw + Mordred 出身ユーザは `hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade` の 3 ステップ |
| 6 | 配布形態 | **単一パッケージ `mordred-hermes`** (5 plugin 同梱) | 5 plugin は密結合 (例: keyvault → network blackout assert)。版ズレ回避のため一括配布。各 plugin の有効/無効は config で個別制御可 |
| 7 | 旧 `mordred-mvp-docs/` の扱い | **deprecation marker 追加して残置** | `../../mordred/mordred-mvp-docs/README.md` を新設し移行先を明記。検索性のため削除はしない |

---

## 11. 参考: Hermes プラグイン実装の最小例

```python
# plugins/mordred_privacy_check/__init__.py
"""Mordred Privacy Check plugin — enforces network/cloud policy."""

from hermes_cli.plugins import PluginContext


def register(ctx: PluginContext) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)


def _on_pre_tool_call(tool_name: str, params: dict, **kwargs):
    # ポリシー判定。ブロックする場合は例外 or 戻り値で制御 (要 verify)
    ...


def _on_session_start(**kwargs):
    # policy snapshot を memory に load
    ...
```

```yaml
# plugins/mordred_privacy_check/plugin.yaml
name: mordred_privacy_check
version: 0.1.0
description: Privacy policy enforcement for Mordred
author: InternetMaximalism
privacy_lock: true   # ← 旧 S1 等価のフィールド。 v1 では plugin 側で参照するヒント (実 enforce は `hermes mordred plugins disable` ラッパ + audit log)。 Hermes 上流への PR は出さない。 hard-enforce は将来の `[hard-lock]` extra で vendored fork が担う
config_schema:
  type: object
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
```

---

## 付録: 検証済み Hermes API リファレンス

`hermes_cli/plugins.py` (line 78–114, 233–600+) で確認済み:

- **Plugin discovery**: 4 sources (bundled / user / project / pip entry-point `hermes_agent.plugins`)
- **Manifest**: `plugin.yaml` (YAML), `__init__.py` の `register(ctx)` 関数
- **`PluginContext` API**:
  - `register_tool(name, toolset, schema, handler, check_fn=None, requires_env=None, is_async=False, description="", emoji="")`
  - `register_hook(hook_name, callback)` — `VALID_HOOKS` のいずれか
  - `register_cli_command(name, help, setup_fn, handler_fn=None, description="")` — `hermes <name> ...` を作る
  - `register_command(name, handler, description="", args_hint="")` — スラッシュコマンド `/<name>`
  - `register_context_engine(engine)` — 単一 plugin のみ可
  - `register_image_gen_provider(provider)`
  - `register_platform(name, label, adapter_factory, check_fn, ...)` — gateway platform adapter
  - `register_skill(name, path, description="")`
  - `dispatch_tool(tool_name, args, **kwargs)`
  - `inject_message(content, role="user")`
- **`VALID_HOOKS`** (16 種):
  - tool: `pre_tool_call`, `post_tool_call`, `transform_tool_result`, `transform_terminal_output`
  - llm: `pre_llm_call`, `post_llm_call`, `pre_api_request`, `post_api_request`
  - session: `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`
  - subagent: `subagent_stop`
  - gateway: `pre_gateway_dispatch` (return `{action: skip|rewrite|allow}`)
  - approval: `pre_approval_request`, `post_approval_response` (observers only)
