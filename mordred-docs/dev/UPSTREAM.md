# Mordred — Upstream Tracking (Hermes-base)

> **Note**: 本ドキュメントは `Hermes (NousResearch/hermes-agent)` 基盤での upstream 追跡戦略を記述します。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/UPSTREAM.md` (deprecated) に残置。

戦略の確定事項は `MIGRATION.md` §5 (`案 C + Vendored-fork escape hatch`、 zero-PR commitment、 2026-05-07 revise)。本ファイルは具体的な操作手順を記録する。

## Repository position

`Mordred-Hermes/` は **Hermes plugin 開発リポジトリ** (純粋な plugin bundle) であり、 Hermes upstream のフォークではない。
配布形態は `pip install mordred-hermes` の単一パッケージ (entry-point `hermes_agent.plugins`)。

そのため:

- **Mordred 自身のコード** は `mordred-hermes/src/mordred_hermes/<plugin>/` に landing
- **Hermes upstream** は `Mordred-Hermes/` 直下のクローンとして開発時のテストに使うだけで、 Mordred 用の git remote としては optional
- 通常の Mordred 開発では Hermes upstream を **rebase する必要はない** (plugin のみ管理しているため)
- v2 で **vendored fork extra** (Tier B、 §後述) を導入する場合のみ、 該当 Hermes バージョンの一部モジュールを `vendor/hermes/<version>/` にコピー保持。 plugin 配布レイアウトには影響しない

この前提が成立する限り、 旧 OpenClaw 時代の "weekly rebase" や "manual handoff" は不要。

## Zero-PR commitment

**Mordred は `NousResearch/hermes-agent` 上流に PR を提出しない**。 理由は `MIGRATION.md` §5 を参照。

- 旧 SPEC が "core seam" としていた箇所 (旧 S1–S3) は **plugin 側で吸収** する (Tier A)
- 真に hard-enforce が必要な箇所のみ **vendored fork extra** (Tier B、 v2) で対応する
- 上流 PR の draft 作成・提出・レビュー追跡は v1 ロードマップから完全に除去

`PR ステータス: 提出待ち / submitted / accepted` のような追跡項目は不要。 上流の readme 文言や release ノートを参照する read-only 関係のみ維持する。

## Optional remote (任意)

Mordred 開発中に Hermes upstream の最新を追跡したい場合のみ:

```sh
git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git
git fetch hermes-upstream
git log --oneline hermes-upstream/main -5
```

clone を fast-forward したい場合:

```sh
git fetch hermes-upstream
git checkout main
git merge --ff-only hermes-upstream/main   # ローカル変更が無いことを前提
```

ローカルに Mordred plugin の開発ファイルがある場合、 `git stash` して `merge --ff-only` してから `git stash pop` する。

## Hook signature drift detection (informational only)

Hermes 上流の急速な進化に追従するため、 plugin が依存している hook payload (例: `pre_tool_call`、 `pre_llm_call`) の signature drift を CI で検知する。

詳細は [`CI.md`](./CI.md) の `upstream-check.yml` workflow を参照。本 workflow は週次に Hermes 最新の `hermes_cli/plugins.py:VALID_HOOKS` 列挙を fetch し、 Mordred plugin が登録している hook 名と照合する。差分発生時に GitHub issue を自動起票。

- このシグナル検知は **informational**: 上流に PR を出すためではなく、 vendored fork extra (Tier B) が必要かを判断する材料、 および Mordred plugin 側の `mordred-min-hermes-version` / `mordred-max-hermes-version` レンジを更新するためのトリガとして使う
- 検知された drift がリリースを block することは無い

## Privacy-lock guard (旧 HSeam-1 の置き換え)

旧 SPEC は `plugin.yaml` に `privacy_lock: bool` フィールドを追加し、 `hermes plugins disable` 側で `--unlock` フラグを要求する小改修を Hermes 上流に PR 提出する計画だった (旧 HSeam-1)。

revised 戦略では Hermes 上流に PR を提出せず、 以下の二段構えで privacy-lock を実現する:

### Tier A: Plugin-side guard (v1 default、 zero core change)

> **2026-05-07 確定 (H3 Path B)**: Tier A は **strict mode で fail-closed (RuntimeError raise + session abort)** がデフォルト。 audit-only な仕様ではない。 SPEC.md §Plugin-disable protection §Tier A / TODO §1.1 H3 Path B と同一定義。

- 各 Mordred plugin の `plugin.yaml` で `privacy_lock: true` を declare (Hermes 本体は当該フィールドを無視するが、 Mordred plugin 側で互いに参照する)
- `mordred_wizard` が `hermes mordred plugins disable <plugin>` ラッパ CLI を提供し、 `mordred_*` 配下の plugin は `--unlock` フラグ無しで disable しようとした時に refuse (UX 層の defense-in-depth)
- **各 Mordred plugin の `on_session_start` 冒頭で sibling list (`mordred_network` / `mordred_privacy_check` / `mordred_llm_guard` / `mordred_keyvault` / `mordred_wizard`) を scan**:
  - **`policy=strict` かつ sibling が 1 つでも disable されている場合**: `RuntimeError("Mordred strict mode requires all sibling plugins enabled; disabled: [...]. Re-enable via 'hermes plugins enable <name>' or downgrade policy to lenient.")` 相当の refusal exception を raise してセッション abort。 同時に audit log `mordred.degraded.disable_unprotected` (decision=`block`) を記録。 **派生クラスの選択は SPEC.md §Plugin-disable protection §Tier A の Exception propagation contract に従う** (`privacy_check` legacy = `SystemExit` 派生、 `llm_guard` 以降 = `BaseException` 直接派生)
  - **`policy=lenient` / `off` の場合**: warning のみ (audit `mordred.degraded.disable_unprotected` (decision=`warn`) は同様に記録、 互換性確保)
- ユーザが Hermes 標準の `hermes plugins disable mordred_*` を使えば Hermes 側の disable 自体は通るが、 **次回 strict セッション開始時に上記 fail-closed が発動して block する設計**
- **重要 caveat**: Tier A は **次回セッション開始時** に block する。 「実行中に disable された場合の即時停止」 は v1 範囲外 (Hermes は plugin の動的 disable を session-running 中に反映しない前提、 Phase 0.8 で verify)

### Tier B: Vendored fork extra (v2、 deferred)

真に hard-enforce が必要になったとき (例: Tier A の defense-in-depth では足りないと判断したとき) のみ:

- `vendor/hermes/<version>/hermes_cli/plugins_cmd.py` に Hermes 該当バージョンの `plugins_cmd.py` をコピー、 `disable` 内部関数で `privacy_lock` をチェックするパッチを当てる
- `pyproject.toml` の `[project.optional-dependencies]` に `hard-lock = ["mordred-hermes-core==<pinned>"]` 等の extra を追加 (具体的な配布形態は v2 設計時に確定)
- ユーザは `pip install mordred-hermes[hard-lock]` で hard-enforce 版を取得
- Hermes 特定バージョン (例: `hermes-agent==0.5.0`) に pin、 上流リリースの度にパッチを再適用
- v1 リリースには含まれない

## Conflict resolution (もし vendored fork で衝突したら)

通常、 plugin-only な Mordred では衝突は発生しない (Mordred は `mordred-hermes/src/mordred_hermes/*` のみ触る、 Hermes upstream は触らない)。

万一 v2 以降に vendored fork extra が導入された後に衝突した場合の方針:

- `mordred-hermes/src/mordred_hermes/*` の変更は **常に Mordred 側を保持**
- `vendor/hermes/<version>/*` の Mordred パッチは Hermes 該当バージョンに pin。 Hermes 上流の新バージョンと merge せず、 別 vendored ディレクトリ (`vendor/hermes/<new-version>/`) を新規に作って migrate
- Hermes upstream に PR を出すことは **しない** (zero-PR commitment)

## Future migration

以下の状況になった場合は、 戦略を再評価する:

- Mordred plugin の Tier A guard (CLI ラッパ + audit log) では defense-in-depth として不十分との判断 → **Tier B (vendored fork extra)** へ進む
- vendored fork が複数の Hermes モジュールに広がり、 patch carry コストが過大化 → 案 B (ソフトフォーク) または案 A (ハードフォーク) を再検討
- Mordred が独自ブランディングを強化する必要が出てきた → **案 A (ハードフォーク)** を再検討

その時 `MIGRATION.md` §5 を更新する。

## Quick reference

- Hermes upstream URL: `https://github.com/NousResearch/hermes-agent`
- Mordred plugin リポジトリ: `Mordred-Hermes/` (本リポジトリ)
- Mordred 配布パッケージ: `mordred-hermes` (PyPI 予定、 v1 は plugin-only)
- v2 候補 extra: `mordred-hermes[hard-lock]` (vendored fork、 Tier B)
- Hermes 上流 PR ステータス: **提出しない (zero-PR commitment、 §Zero-PR commitment)**
