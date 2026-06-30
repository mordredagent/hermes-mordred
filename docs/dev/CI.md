# Mordred — CI Policy (Hermes-base)

> **Note**: 本ドキュメントは Mordred plugin 開発リポジトリ (`Mordred-Hermes/`) の CI 戦略を記述します。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/CI.md` (deprecated) に残置。

旧版は OpenClaw upstream 由来の 42 個の workflow を fork で disable する複雑な構成だった。Hermes 化により Mordred は **plugin 開発リポジトリ** へ位置付けが変わったため、 CI も大幅に簡素化される。

## なぜシンプルになったか

`Mordred-Hermes/` は Hermes upstream のフォークではなく、 **Mordred plugin 専用リポジトリ**。Hermes upstream の release lane / signing keys / Blacksmith runner / CodeQL enterprise tier 等は一切持たないし、 模倣する必要もない。

CI が果たすべき責務:

1. Mordred plugin (`src/mordred_hermes/*`) のテストが green
2. Lint / format / type check が green
3. (Optional) Hermes upstream の hook signature drift 検知

それ以外は upstream の責務であり、 upstream の CI で実行される。

## Active workflows (5 個)

| Path | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | Per-PR / push: 5 job — `test` (matrix; ruff + mypy + pytest)、 `fresh-venv-resolution` (H1 fail-fast 契約)、 `integration-tor` (hermetic Tor Docker 統合テスト)、 `tpmkey-helper` (`native/tpmkey-helper` Rust crate を ubuntu+macOS で cargo fmt/clippy/test; Linux は tss-esapi backend も build)、 `tpmkey-helper-tpm` (swtpm で TPM backend を統合テスト) |
| `.github/workflows/upstream-check.yml` (optional) | 週次に Hermes 最新の hook signature drift を検知 |
| `.github/workflows/labeler.yml` | PR の path にラベル自動付与 (mordred-* paths) |
| `.github/workflows/integration-vpn.yml` | `workflow_dispatch` 限定: live Mullvad VPN 統合テスト (PR3b、 `integration-tor` job と対をなす) |
| `.github/workflows/release.yml` | `workflow_dispatch` 限定: `mordred-hermes` の PyPI publish (M7) |

## `ci.yml` 詳細

実装は `.github/workflows/ci.yml` を参照。 `ci.yml` は **5 つの job** で構成される:

1. **`test`** — matrix (OS × Python) の unit-test job。 ruff + mypy + pytest
2. **`fresh-venv-resolution`** — H1 fail-fast 契約の検証 job。 `hermes-agent` を root install せずに `mordred-hermes` を install し、 依存解決が **失敗する** ことを assert する (`hermes-agent` 未公開時に install が fail-fast する保証)
3. **`integration-tor`** — hermetic な Tor Docker 統合テスト job (Linux 限定; macOS runner に Docker がないため)
4. **`tpmkey-helper`** — `native/tpmkey-helper` Rust crate (Linux TPM 2.0 helper) を ubuntu + macOS で `cargo fmt --check` / `cargo clippy -D warnings` / `cargo test` 検証する。 純粋関数層 (wire / SEC1 codec / 32-byte ECDH-Z left-pad / blob store / neutral error taxonomy) を両 OS で build し「macOS dev host では検証できない Linux build」を実 Linux で担保する。 Linux leg は v2-OS2 Phase 2b の `tss-esapi` TPM backend (`cfg(target_os="linux")`) も build するため libtss2-dev + libclang を install する; backend の live テストは `MORDRED_TPM_TEST` で gate され job 5 で走る
5. **`tpmkey-helper-tpm`** — v2-OS2 Phase 2b。 ubuntu で `swtpm` software TPM を起動し `MORDRED_TPM_TEST=1` で `tss-esapi` backend を end-to-end 検証する (generate / public_key / delete / software P-256 との ECDH parity)。 テストは単一の swtpm command server を共有するため `--test-threads=1`

主要ポイント:

- **paths filter (trigger 種別で異なる)**:
  - `pull_request` trigger: `mordred-hermes/**`, `pyproject.toml`, `hermes_cli/**`, `.github/workflows/ci.yml`, `docs/dev/CI.md`
  - `push` (`main`) trigger: `mordred-hermes/**`, `pyproject.toml`, `hermes_cli/**`, `.github/workflows/ci.yml` のみ。 **CI.md は push trigger には含まれない** (docs-only の変更は PR で検査され、 `main` への push では再実行しない)
- **concurrency**: `ci-${{ github.ref }}` group + `cancel-in-progress: true` で同一 PR の旧 run を自動 cancel
- **`test` job — install order**: `pip install -e .` (Hermes upstream を root から install) → `pip install -e './mordred-hermes[dev]'` → `pip install -e './mordred-hermes[keyvault]'`。 Hermes upstream (`hermes-agent`) は現時点で PyPI 未公開のため root install が必須 (`hermes-agent` 自体が PyPI 公開された後に root install を削除予定)。 M7 の `release.yml` が publish するのは `mordred-hermes` であって `hermes-agent` ではない点に注意 (Mordred のマイルストーンタグ `v0.1.0-mvp.0` と `hermes-agent` のバージョンは別物 — Mordred の `hermes-agent` 依存 pin は `hermes-agent>=0.11.0`、 `pyproject.toml` 参照)
- **`keyvault` extra (全 platform)**: cross-platform な crypto スタック (`cryptography` / `argon2-cffi` / `blake3`) を全 runner で install。 keyvault モジュール群を Linux でも `mypy --strict src` / pytest が解決できるようにするため (これらの package 自体は cross-platform; keyvault *機能* の macOS 限定は下記 pyobjc bridge が gating)
- **macOS のみ**: `pip install -e './mordred-hermes[macos]'` を追加で実行 (`macos` extra = `keyvault` extra + Phase 4 keyvault 用 pyobjc bridge: `pyobjc-framework-Security` / `-SystemConfiguration` / `-Quartz`)
- **`test` job — steps**: ruff lint → ruff format check → mypy strict → pytest (coverage XML)
- **Matrix**: macOS Apple Silicon (Phase 4 keyvault 動作確認)、 Ubuntu (Phase 1-3 multi-platform 確認) × Python 3.11 / 3.12 (Hermes upstream の `requires-python = ">=3.11"` に整合、 mordred-hermes 側も同 pin)
- **`fresh-venv-resolution` job**: `needs: test`。 `pip install -e .` を意図的に skip し、 `pip install -e './mordred-hermes'` の依存解決が `hermes-agent` 不在で失敗することを検証 (単なる非ゼロ終了では不十分なので、 `install.log` に `hermes-agent` の dependency-resolution エラーが出ていることまで grep で確認)
- **`integration-tor` job**: `needs: test`。 `mordred-hermes[dev,integration]` を install し、 `tests/integration/docker/tor/` で Docker image を build、 `pytest -m integration` で Tor + SOCKS5h + provider-transport の統合テストを実行
- **coverage**: `actions/upload-artifact@v4` で `coverage-${os}-py${version}` 名のアーティファクトに保存。 Codecov 連携は別 PR (token を Repo secret に追加してから有効化)
- **Live tests** (`MORDRED_LIVE_LLM_TEST=1` / `MORDRED_KEYVAULT_LIVE=1` / `MORDRED_LIVE_TOR_TEST=1`) は default では実行しない。明示的にトリガーする workflow_dispatch を別途用意

## `integration-vpn.yml` 詳細

実装は `.github/workflows/integration-vpn.yml` を参照。 `ci.yml` の `integration-tor` job と対をなす live 統合テスト workflow で、 Tor 側が CI で常時走る (`integration-tor` job) のに対し VPN 側はこの独立 workflow に切り出されている。

- **trigger**: `workflow_dispatch` 限定 — push / PR では決して自動実行しない。 Mullvad アカウント番号は有料リソースであり、 bring-up が runner の実ネットワーク状態を mutate するため
- **input**: `mullvad_version` (Mullvad client のバージョン; semver または `latest`)
- **secrets**: `MORDRED_MULLVAD_ACCOUNT` (16 桁アカウント番号) を repo secret として要求
- **手順**: `hermes-agent` (root) + `mordred-hermes[dev]` を install → 公式 Mullvad daemon を runner に install → `MORDRED_LIVE_VPN_TEST=1` で `pytest -m integration tests/integration/test_vpn.py` を実行 → teardown で必ず `mullvad disconnect` / `account logout`

## Manual live-device validation log

- **2026-05-25**: operator により、 default PR CI から除外される hardware / network gated suite の実機検証成功が報告された:
  - `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v` — macOS Secure Enclave hardware 上で実行。
  - `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v` — real Mullvad CLI / daemon session に対して実行。

Tor path は hermetic Docker-based `integration-tor` CI job で別途カバーする。 host VPN state や Secure Enclave hardware は要求しない。

## `upstream-check.yml` 詳細

実装は `.github/workflows/upstream-check.yml` を参照 (DECIDE 0.1: v1 で導入確定、 2026-05-09)。 主要ポイント:

- **schedule**: 週次 月曜 03:00 UTC (`cron: "0 3 * * 1"`) + `workflow_dispatch`
- **permissions**: `contents: read` + `issues: write` (drift 検出時の自動 issue 起票用)
- **drift 検知**: Hermes upstream を `git clone --depth 1` した後、 `pip install -e ./hermes-upstream` で transitive deps (PyYAML 等) を確実に入れてから `hermes_cli.plugins.VALID_HOOKS` を import (sys.path hack で済ませると runner の dep 不在を `__MISSING__` と誤検出する)。 取得した hook 一覧を Mordred plugin の `register_hook("...")` grep 結果と比較
- **Phase 0 caveat**: Phase 0 plugin は no-op stub のため `register_hook` 呼出 = 0 件。 required-set が空でも fail させない (Phase 1.x で hook を呼ぶようになってから drift detection が有意義になる)
- **VALID_HOOKS が消えた場合**: Hermes upstream 側の constant rename も drift signal として `__VALID_HOOKS_REMOVED__` で issue 起票
- **issue 起票**: 差分発生時に `actionable` + `upstream-drift` ラベル付きで自動起票。 既に open な `upstream-drift` issue があれば**新規起票せず comment を追記**する dedup (週次再実行での issue 量産を防ぐ)。 payload field drift 検出時は issue 本文に per-site の欠落フィールド一覧を併記
- **payload field drift 検知 (2026-06-12 追加、 TODO L474)**: hook **名** (`VALID_HOOKS` membership) に加えて、 `tools/check_hook_payload_drift.py` が upstream ソースを pure-`ast` で走査し、 core の `invoke_hook("<name>", key=value, ...)` 全 dispatch site に Mordred が消費する payload フィールド (`tools/hook_payload_contract.json`) が渡っているかを照合する (import / install 不要)。 contract キーが plugin の `register_hook` 呼出と完全一致することは `tests/test_hook_payload_drift.py` が強制し、 同テストの canary が vendored fork (リポジトリ自身の Hermes ツリー) へ同じ照合を毎 CI 実行する

## `labeler.yml` 詳細

実装は 2 ファイル構成:

- `.github/labeler.yml` — label と path glob の対応表 (`actions/labeler@v5` schema)
- `.github/workflows/labeler.yml` — `on: pull_request_target` で `actions/labeler@v5` を駆動

label はリポジトリに事前作成しておく必要あり (one-time `gh label create`):

```sh
gh label create plugins/mordred-network        --color 1F77B4 --description "mordred_network plugin"
gh label create plugins/mordred-privacy-check  --color 1F77B4 --description "mordred_privacy_check plugin"
gh label create plugins/mordred-llm-guard      --color 1F77B4 --description "mordred_llm_guard plugin"
gh label create plugins/mordred-keyvault       --color 1F77B4 --description "mordred_keyvault plugin"
gh label create plugins/mordred-wizard         --color 1F77B4 --description "mordred_wizard plugin"
gh label create actionable                     --color D73A4A --description "Needs maintainer action"
gh label create upstream-drift                 --color FB8500 --description "Hermes upstream signature drift"
gh label create docs                           --color 0E8A16 --description "Documentation only"
gh label create ci                             --color 6F42C1 --description "CI/CD configuration"
```

`pull_request_target` を使うため、 fork からの PR でも label が付与される。 permissions は `contents: read` + `pull-requests: write` のみ (PR HEAD コードは checkout しない、 label mutation のみ)。

## `release.yml` 詳細

実装は `.github/workflows/release.yml` を参照 (M7、 TODO §0.5 L70)。 `mordred-hermes` を PyPI / TestPyPI に publish する。 **`workflow_dispatch` 限定** — PyPI publish は不可逆 (削除した version / ファイル名は二度と再アップロード不可) のため自動実行しない。

- **認証**: PyPI Trusted Publishing (OIDC)。 API トークンは一切保存しない。 `publish` job が `id-token: write` 権限で短命の OIDC トークンを取得し、 `pypa/gh-action-pypi-publish` がそれで認証する
- **`target` input**: `testpypi` / `pypi` の choice。 GitHub Environment (`testpypi` / `pypi`) で gating — `pypi` Environment に required reviewers を設定すれば本番 publish に人手承認が挟まる
- **`mode` input**:
  - `reserve` — `packaging/name-reservation/` の空 stub (`0.0.0.dev0`) を build。 v1 docs 公開前に名前を squat から守るための一度きりの予約
  - `release` — 本体 (`mordred-hermes/`、 `0.1.0a0`+) を build。 名前予約後の通常リリースで使う
- **build job の guard**: `reserve` モードは成果物が `0.0.0.dev0` であることを、 `release` モードは逆に `0.0.0.dev0` *でない* ことを検証してモード取り違えを防ぐ
- **version 順序の不変条件**: `0.0.0.dev0 < 0.1.0a0` (PEP 440)。 stub が本体より小さいことで、 予約 stub が後続の本リリースを塞がない。 `tests/test_packaging_versions.py` がこの不変条件を pin

### 初回 setup (one-time、 operator 手動)

PyPI への upload は不可逆な外部公開のため、 以下は **operator が手動で実施** する (CI 自動化対象外):

1. **PyPI 名の空き確認**: <https://pypi.org/project/mordred-hermes/> と <https://test.pypi.org/project/mordred-hermes/> が未登録であることを確認
2. **pending publisher 登録 (TestPyPI)**: TestPyPI → Account settings → Publishing → "Add a new pending publisher":
   - PyPI Project Name: `mordred-hermes`
   - Owner: `InternetMaximalism` / Repository: `Mordred-Hermes`
   - Workflow name: `release.yml` / Environment name: `testpypi`
3. **pending publisher 登録 (PyPI)**: 同様に PyPI 側で Environment name = `pypi`
4. **GitHub Environment 作成**: リポジトリ Settings → Environments で `testpypi` と `pypi` を作成。 `pypi` には required reviewers の設定を推奨
5. **name reservation 実行**: Actions → "Release (PyPI publish)" → Run workflow → `target=testpypi, mode=reserve` で検証 → 成功確認後 `target=pypi, mode=reserve` で本予約
6. 予約完了後、 `TODO.md` §0.5 L70 (M7) の checkbox を `[x]` 化

### 通常リリース

名前予約後は `target=pypi, mode=release` で本体を publish。 version bump 手順は v1 リリース時に別途追記する。

## Changelog 規約

Mordred は専用の `CHANGELOG.md` ファイルを**持たない**。変更履歴は **各 PR の説明文**に記述する (`PLAN.md` / `TODO.md` の cross-cutting 運用規律):

- 各 PR 説明に `### Changes` (機能追加・変更) / `### Fixes` (バグ修正) の見出しで **1 行ずつ** entry を書く
- 外部コントリビュータの貢献には `Thanks @<author>` を併記する
- リリース時は、 当該リリースに含まれる PR 群の `### Changes` / `### Fixes` を集約して GitHub Release / タグ注釈のリリースノートへ転記する

**共有 PR テンプレートは編集しない**: リポジトリ root の `.github/PULL_REQUEST_TEMPLATE.md` は Hermes upstream 所有でモノレポ全体に適用されるため、 Mordred 固有の見出しを注入しない (soft-fork 規律、 `ROADMAP.md` "Forever out of scope")。 本規約は Mordred PR の author が手動で踏襲する。

## Branch protection (one-time setup)

Phase 0 完了後、 `main` ブランチで以下を有効化:

- Required status checks:
  - `CI / test (ubuntu-24.04, 3.12)`
  - `CI / test (macos-latest, 3.12)`
- Require strict mode (branches must be up to date)
- Allow force pushes from maintainers (rebase workflow 用)
- Linear history は **任意** (Mordred plugin 開発では merge commit を許容する場合あり)

## Auditing

Mordred plugin リポジトリは upstream OpenClaw のような大量の workflow を持たないため、 旧版にあった `workflow-allowlist-audit` job は不要。

```sh
gh api -X GET /repos/InternetMaximalism/Mordred-Hermes/actions/workflows --paginate \
  --jq '.workflows[] | select(.state=="active") | .path' | sort
```

期待出力 (Mordred-owned 5 個):

```
.github/workflows/ci.yml
.github/workflows/integration-vpn.yml
.github/workflows/labeler.yml
.github/workflows/release.yml
.github/workflows/upstream-check.yml
```

**Hermes upstream 由来の workflow について**: 本リポジトリは Hermes (`NousResearch/hermes-agent`) フォーク派生のため、 上流由来の workflow (`tests.yml`, `osv-scanner.yml`, `nix.yml`, `docker-publish.yml`, `deploy-site.yml`, `docs-site-checks.yml`, `nix-lockfile-fix.yml`, `skills-index.yml`, `supply-chain-audit.yml`, `contributor-check.yml`) が `.github/workflows/` に共存している。 これらは **Mordred-Hermes v0.1.0-mvp.0 の本 PR では touch せず残置** し、 後続の cleanup PR で個別に評価して disable / archive する (Mordred plugin 開発に必要なら残す、 不要なら削除)。 Mordred-owned workflow と paths filter で住み分けているため、 当面の co-existence で問題はない。

## Future expansion

将来必要になった時に追加検討する workflow:

- `docs.yml` — `docs/` を Sphinx / mkdocs で公開
- `e2e.yml` — Hermes 実環境を Docker で起動して end-to-end test

これらは v1 リリース後に Phase 1 として優先度判定する。
