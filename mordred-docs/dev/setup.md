# Mordred — Development Setup (Hermes-base)

> **Note**: 本ドキュメントは Mordred plugin 開発者向けのローカル環境セットアップ手順をまとめたものです。 GA (`v0.1.0-mvp.0`) 後に `dev/setup.md` へ移動予定 (`ROADMAP.md` v2-X3)。 GA 前は prefix 規則 (`DEV_*.md`) に従い `mordred-docs/` 直下に flat 配置。

本ガイドは **Mordred plugin の開発に着手する開発者** が対象。 Mordred を end-user として install したい場合は将来の package README を参照すること (Phase 0.5 完了後に追加予定)。

正式な順序・タスク内訳は `PLAN.md` Phase 0、 チェックリストは `TODO.md` §0.1–0.6 を canonical とする。 本ファイルはそれらを日常運用視点で再構成したリファレンスであり、 仕様の出典ではない。

リポジトリルートの `CONTRIBUTING.md` / `AGENTS.md` / `setup-hermes.sh` は Hermes upstream のドキュメントであり、 本ファイルとは対象 (Hermes 本体への貢献 vs Mordred plugin 開発) が異なる。

---

## 前提

- Python 3.11 以上 (`requires-python = ">=3.11"`、 `mordred-hermes/pyproject.toml` L10 + Hermes upstream root `pyproject.toml` も同 pin)。 CI matrix は 3.11 / 3.12 を両方 cover (`CI.md` §`ci.yml` 詳細)
- git 2.30+
- macOS / Linux (Phase 4 `mordred_keyvault` のみ macOS Apple Silicon 限定、 `SPEC.md` Phase 4)
- Hermes upstream のローカル利用 (`pip install hermes-agent`、 または開発時は隣接 clone を推奨)

## リポジトリ構成

`Mordred-Hermes/` (本リポジトリ) は **Hermes plugin 開発用のワーキングコピー** であり、 Hermes upstream のフォークではない (`UPSTREAM.md` §Repository position)。

```
Mordred-Hermes/
├── hermes_cli/                       # Hermes upstream の clone (テスト用、 Mordred 開発者は触らない)
├── pyproject.toml                    # Hermes 既存。 Mordred 自身の pyproject は mordred-hermes/ 内に分離
├── mordred-hermes/                   # Mordred plugin パッケージ (1 subdir = 1 package、 build root を分離)
│   ├── pyproject.toml                # Mordred package config (Phase 0.5 で landing)
│   ├── src/mordred_hermes/           # Mordred plugin の landing site (Phase 0.4 で scaffold)
│   │   ├── privacy_check/
│   │   ├── wizard/
│   │   ├── llm_guard/
│   │   ├── network/
│   │   └── keyvault/
│   └── tests/                        # Mordred 側 test (Hermes root tests/ とは分離)
├── tests/                            # Hermes upstream の test。 Mordred 側は mordred-hermes/tests/
└── mordred-docs/                     # Mordred 自身の SPEC / PLAN / TODO 等
```

> 開発用 venv は Hermes が管理する `~/.hermes/hermes-agent/venv` を使う (`hermes setup` が生成)。 リポジトリ内に自前の `.venv/` を作る必要はない (`mordred-hermes/README.md` の canonical install フロー参照)。

> **現状 (`v0.1.0-mvp.0` GA 前、 2026-05-14)**: Phase 0.4–0.5 完了済み (PR #8、 2026-05-09)。 `mordred-hermes/` subdir 一式 (`pyproject.toml` + `src/mordred_hermes/{privacy_check,wizard,llm_guard,network,keyvault}/` + `tests/`) が landing 済み。 Phase 1.1 / 1.3 / 2 / 3 PR1-PR3b / 4 PR1-PR2 まで実装済みで、 `pip install -e ./mordred-hermes` が即座に動く状態。

## 初期セットアップ

```sh
# 1. リポジトリ取得
git clone <Mordred-Hermes-repo-url> Mordred-Hermes
cd Mordred-Hermes

# 2. Hermes プロファイル作成 (~/.hermes/ と Hermes 管理 venv を生成)
hermes setup

# 3. Hermes 自体が動くか sanity check
python -m hermes_cli --version

# 4. mordred-hermes を Hermes 管理 venv に editable install
#    canonical なコマンドは mordred-hermes/README.md を参照
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e ./mordred-hermes
```

`mordred-hermes/pyproject.toml` は既に landing 済み (version `0.1.0a0`、 5 entry point) なので、 上記 install ステップは **現行かつ必須**。 自前で `.venv` を作るのではなく、 Hermes が管理する `~/.hermes/hermes-agent/venv` に対して `uv pip` で install するのが canonical なフロー (`mordred-hermes/README.md` 参照)。

### Optional extras

`mordred-hermes/pyproject.toml` の `[project.optional-dependencies]` は 5 つの extra を定義する。 開発時にどれを install するかは目的次第:

| Extra | 内容 | install すべき場面 |
|---|---|---|
| `dev` | `pytest` / `pytest-cov` / `ruff` / `mypy` | **日常コマンド (下記) を動かすために必須**。 開発者は常に install する |
| `keyvault` | cross-platform crypto stack (`cryptography` / `argon2-cffi` / `blake3`) | keyvault モジュールの型検査 / テストを Linux でも通すため。 全 platform で install 推奨 |
| `macos` | `keyvault` extra + pyobjc bridge (`Security` / `SystemConfiguration` / `Quartz`) | macOS で `mordred_keyvault` 機能を開発する場合 |
| `tor-control` | `stem` (Tor ControlPort cookie auth + liveness probe) | strict-mode の Tor liveness を開発 / テストする場合 |
| `integration` | SOCKS5h client ライブラリ + provider SDK | `pytest -m integration` の §0.8 検証スイートを動かす場合 |

```sh
# 開発者の標準セット (CI の test job と同じ — ci.yml は [dev] + [keyvault] を install)
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e "./mordred-hermes[dev]"
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e "./mordred-hermes[keyvault]"

# macOS で mordred_keyvault を開発する場合 (keyvault extra を包含)
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e "./mordred-hermes[macos]"
```

> **重要**: 下記「日常コマンド」表が参照する `pytest` / `ruff` / `mypy` は `[dev]` extra に含まれる。 `[dev]` を install していないとこれらのコマンドは動かない。

> **Discovery 確認** (Hermes 0.11.0): `hermes plugins list` は entry-point plugin を表示しない (上流の `_discover_all_plugins` が directory-based のみを scan する仕様)。 loader 側 (`PluginManager.discover_and_load`) は discover + `register()` 実行する。 確認は次の Python ワンライナー:
> ```sh
> ~/.hermes/hermes-agent/venv/bin/python3 -c "from hermes_cli.plugins import PluginManager; m=PluginManager(); m.discover_and_load(force=True); print(sorted(k for k,p in m._plugins.items() if p.manifest.source=='entrypoint'))"
> # → ['mordred_keyvault', 'mordred_llm_guard', 'mordred_network', 'mordred_privacy_check', 'mordred_wizard']
> ```
> Phase 1.3 で `hermes mordred plugins list` wrapper を提供して UX gap を埋める (TODO §1.3 / Phase 0 acceptance gate 注記参照)。

## (オプション) Hermes upstream remote

Hermes 最新を追跡したい場合のみ (`UPSTREAM.md` §Optional remote):

```sh
git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git
git fetch hermes-upstream
git log --oneline hermes-upstream/main -5
```

通常の Mordred 開発では rebase 不要 (zero-PR commitment、 `UPSTREAM.md` §Zero-PR commitment)。

## 日常コマンド

| 目的 | コマンド | 補足 |
|---|---|---|
| テスト実行 | `pytest -q` | Phase 1 以降は `pytest --cov=src/mordred_hermes` (CI と同じ; package は `src/` 配下) |
| Lint | `ruff check mordred-hermes/src mordred-hermes/tests` | `PLAN.md` §0.6 |
| Format check | `ruff format --check mordred-hermes/src mordred-hermes/tests` | CI で blocking |
| 型検査 | `mypy --strict mordred-hermes/src` | `mordred-hermes/src/mordred_hermes/` のみ対象 |
| Mordred 初期設定 | `hermes-mordred configure` | ポリシー / LLM / harness を設定。 ネットワークプライバシーは含まない (短時間で完了)。 CI/スクリプトは `--non-interactive --policy strict --harness codex ...` でフラグ駆動 (未指定フラグは既存設定を維持) |
| ネットワークプライバシー設定 | `hermes-mordred network init` | Tor / VPN / clearnet + Mullvad を必要時にオンデマンドでセットアップ。 再実行可能 (既存値を prompt のデフォルトに seed、 Mullvad 空入力で既存シークレット維持)。 CI/スクリプトは `--non-interactive --path tor --mullvad-relay jp ...` でフラグ駆動 (シークレットは CLI フラグでは渡さない)。 保存済みシークレット削除は `--clear-mullvad` |
| ネットワーク経路の切替 / 確認 | `hermes-mordred network use <tor\|vpn\|clearnet>` / `network status` | 既定経路の切替と現在状態の表示 (`network status --json` で機械可読出力) |
| 全体状態の確認 | `hermes-mordred status` | policy / network / keyvault / encryption を 1 画面で表示 (`--json` あり)。 read-only でプロンプト・Secure Enclave アクセス無し |

CI workflow の詳細は `CI.md` を参照。 `upstream-check.yml` の hook signature drift 検知は informational only (`UPSTREAM.md` §Hook signature drift detection)。

## Mordred-owned filesystem paths

開発中に手元の状態を観察する際は `~/.hermes/mordred/` 配下を見る (`PATHS.md` 参照):

- `~/.hermes/mordred/audit.log` — 全 plugin の audit log (Phase 1 owner)
- `~/.hermes/mordred/policy.json` — `mordred_wizard` が書き、 他 plugin が読む (Phase 1)
- `~/.hermes/mordred/credentials/` — `mordred_network` の Mullvad relay/killswitch 参照 (`network init` が書き込み)
- `~/.hermes/mordred/keyvault/` — `mordred_keyvault` の wrapped DEK 等 (Phase 4)

各 plugin が own する path / 内部 Python API は plugin 自身の `README.md` に記載 (`PLAN.md` §0.4)。

## Offline verification digest (`keyvault init` step 4)

`hermes-mordred keyvault init` の途中で、 operator は **air-gapped な第二デバイス** で 32-byte の verification digest を独立に再計算し、 primary machine に再入力する必要がある (SPEC §`keyvault init` flow、 step 6-7)。 そのための standalone tool を `scripts/keyvault_offline_digest.py` で提供する。

**設計上の不変条件**: この script は `mordred_hermes` パッケージに依存しない (stdlib + `blake3` のみ)。 USB / 印刷-手打ち / QR で第二デバイスへ運べる前提。 algorithm と Unicode normalization は `mordred_hermes.keyvault.{digest,api}` から逐語コピーで、 `--self-test` が SPEC fixed vector (`test_keyvault_digest.py:SPEC_*`) に対する回帰を pin する。

> **この dev チェックアウトで動作確認するだけなら**、第二デバイスの準備は不要。
> `keyvault init` が案内する `python3 scripts/keyvault_offline_digest.py` を
> リポジトリルートでそのまま実行すれば、blake3 を同梱する venv で自動的に再実行
> される (手動の `pip install` も venv のフルパスも不要)。以下は本番の air-gapped
> 運用手順。

### 第二デバイスの準備 (オンラインで実施)

1. blake3 が import 可能な Python 環境を用意:
   ```bash
   python3 -m pip install blake3
   ```
2. `scripts/keyvault_offline_digest.py` を第二デバイスにコピー (USB / scp / 印刷)
3. 動作確認:
   ```bash
   python3 keyvault_offline_digest.py --self-test
   # SPEC fixed vector digest: 25c17b1e...
   # Computed digest:          25c17b1e...
   # OK - algorithm matches SPEC.
   ```
4. 第二デバイスを完全に **air-gap** する (Wi-Fi / Ethernet / Bluetooth / VPN / tethering を全部 OFF)

### digest の計算 (オフラインで実施)

primary machine の `keyvault init` が seed 表示画面で示す 3 値:

- 24-word Seed Phrase (紙に書き写したもの)
- top4(PoW) hex (Seed 表示直前の banner — `PoW mask top4 = xxxxxxxx`)
- Passphrase (記憶)

を第二デバイスで入力:

```bash
python3 keyvault_offline_digest.py
# 24-word Seed Phrase: <紙から書き写し>
# Passphrase: <記憶から入力、 非表示>
# top4(PoW) hex (8 chars): <primary banner から>
#
# verification digest: <64-hex>
```

出力された 64 文字 hex を primary machine の `Verification digest from your offline device (hex)` プロンプトに再入力する。 mismatch なら `VerificationDigestMismatch` で reject され、 keyvault には何も書かれない (transcription error は安全に発見できる)。

### よくある落とし穴

- **blake3 wheel の有無**: ARM Mac / x86 Linux は wheel あり。 古い ARM Linux / 32-bit 端末は source build が走るので、 pip install の段階でこけたら端末を変える
- **Cf 文字の clipboard 注入**: seed phrase を OS 経由で paste すると ZWSP が混入することがある。 `_normalize_seed_phrase` が NFKD + Cf-strip で吸収するが、 手打ち推奨
- **Passphrase の case**: `_normalize_passphrase` は NFKD only。 大文字小文字とスペースはそのまま entropy なので、 primary 入力時のキーボードレイアウト (US / JIS) を第二デバイスでも一致させること

詳細な algorithm は `SPEC.md §Key generation and verification digest` を参照。

## 開発ワークフロー指針

- 1 plugin 1 PR 原則: `mordred_privacy_check` と `mordred_wizard` を同時にいじらない。 cross-plugin 変更が必要な場合は SPEC/PLAN 側を先に PR 化
- Hermes 上流に PR を出さない (zero-PR commitment、 `MIGRATION.md` §5)。 hard-enforce が必要に見える場合は v2 vendored fork extra の検討対象であり、 v1 では plugin-side で吸収
- 新規 doc を追加する場合は GA まで `mordred-docs/` 直下に `HERMES_*.md` / `DEV_*.md` prefix で配置 (post-GA で `hermes/` `dev/` subdirectory に `git mv`、 `ROADMAP.md` v2-X3)

## 次のステップ

- `PLAN.md` Phase 0 の手順を順に実行 → `TODO.md` §0.x をチェック
- 個別 plugin 実装に入る場合は `SPEC.md` の該当 phase + `PLAN.md` の plugin module レイアウトを参照
- AI agent (Claude Code 等) を併用する場合は repo ルートの `AGENTS.md` を参照 (Hermes upstream のガイドだが Mordred 開発でも有用)

---

## 関連ドキュメント

- `SPEC.md` — 何を作るか (機能仕様)
- `PLAN.md` — どう作るか (実装計画)
- `TODO.md` — タスク順序とチェックリスト
- `PATHS.md` — Mordred が触るファイルシステムパス
- `UPSTREAM.md` — Hermes upstream との関係
- `CI.md` — CI workflow 詳細
- `MIGRATION.md` — OpenClaw → Hermes 移行戦略
- `ROADMAP.md` — post-v1 計画 (本 doc の post-GA 移送先 v2-X3 を含む)
