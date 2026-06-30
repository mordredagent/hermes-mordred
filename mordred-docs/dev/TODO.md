# Mordred — TODO (Hermes-base)

> **Note**: 本 TODO は `Hermes (NousResearch/hermes-agent)` 基盤での Mordred 実装チェックリストです。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/TODO.md` (deprecated) に残置。
>
> 旧 TODO の `[x]` 完了マーカーは OpenClaw 環境での作業履歴であり、Hermes 移行に伴い **すべて pending として再開** する。一部の概念 (例: 5 plugin scaffold) は再利用可能だが、 ファイルパス・テストランナー等は完全 rewrite が必要。

Actionable checklist derived from `mordred-docs/SPEC.md` and `mordred-docs/PLAN.md`.
Each item is a developer-pickable task. Cross-references point back to SPEC/PLAN sections rather than restating context.
Update this file whenever a task is completed (check the box) or when SPEC/PLAN evolves (add/remove tasks to match).
Phases are sequenced; do not start Phase N+1 until the Phase N acceptance gate is green.
Open decisions are surfaced as `DECIDE:` items at the top of the relevant phase.

**Plugin-Only Architecture policy (zero-PR、 2026-05-07 確定)**: ほぼすべての作業は `mordred-hermes/src/mordred_hermes/<plugin>/` に landing。 v1 では Hermes 上流への PR を一切提出しない (MIGRATION.md §10 row 4)。 disable footgun の防御は plugin-side **strict-mode startup refusal** (Phase 1.1 H3 タスク、 SPEC.md §Plugin-disable protection Tier A) と `mordred.degraded.disable_unprotected` audit log で完結。 hard-enforce が真に必要になった項目は v2 で vendored fork extra (`mordred-hermes[hard-lock]`、 Tier B、 UPSTREAM.md §Tier B) に escalate する。

---

## Phase 0 — Operational Setup (blocks all later phases)

### Open decisions

- [x] ~~DECIDE: `.github/workflows/upstream-check.yml` (Hermes hook **名** drift 検知; payload field shape は v2) を v1 で導入するか v2 まで遅延するか~~ → **v1 で導入確定** (2026-05-09、 PR #8、 週次 cron 月曜 03:00 UTC、 drift 時 `actionable` + `upstream-drift` ラベル付きで issue 自動起票)

### 0.1 Repo & venv 確認

- [x] `Mordred-Hermes/` で sanity check (Hermes 自体が動くこと) — **2026-05-16 完了**。 console-script は `hermes --version` (`python -m hermes_cli` は `__main__` 不在で不可)。 `hermes-mordred --help` の subcommand tree も動作確認済み
- [x] venv を有効化: `source .venv/bin/activate` (Hermes `scripts/run_tests.sh` の probe 順序に整合) — **2026-05-16 確認**。 `.venv` から `mordred_hermes` が editable install で import 可能
- [x] `~/.hermes/` プロファイル作成: `hermes setup` 実行で Hermes 設定完了 — **2026-05-16 確認**。 `~/.hermes/config.yaml` + `auth.json` 生成済み

### 0.2 Hermes upstream tracking 戦略 (オプション、 推奨 rebase 不要)

- [x] (オプション) `git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git` — **2026-05-16 判断: v1 では追加しない**。 Mordred-Hermes は plugin 開発リポジトリで upstream のフォークではなく rebase 不要。 必要時は `UPSTREAM.md` §Optional remote の手順でいつでも追加可能
- [x] `mordred-docs/UPSTREAM.md` に Hermes upstream 戦略の決定を記録 (Phase D で書き換え) — **完了**。 実ファイルは `mordred-docs/dev/UPSTREAM.md` (114 行): repository position / zero-PR commitment / optional remote 手順 / hook signature drift detection を記録済み

### 0.3 Mordred-owned filesystem paths を予約 (PATHS.md と同期)

- [x] `~/.hermes/mordred/audit.log` を Phase 1 owner として `mordred-docs/PATHS.md` に文書化済み (✓ 完了、 Phase C 内)
- [x] `~/.hermes/mordred/policy.json` (writer = `mordred_wizard`、 reader = privacy_check/llm_guard/network) を `mordred-docs/PATHS.md` に文書化済み (✓ 完了)
- [x] `~/.hermes/mordred/credentials/` を Phase 3 owner として `mordred-docs/PATHS.md` に文書化済み (✓ 完了)
- [x] `~/.hermes/mordred/keyvault/` を Phase 4 owner として `mordred-docs/PATHS.md` に文書化済み (✓ 完了)
- [x] 各 plugin の `README.md` (0.4 で作成) に own path を cross-reference

### 0.4 Plugin scaffolding (five plugins)

- [x] `mordred-hermes/src/mordred_hermes/privacy_check/` を scaffold: `plugin.yaml`, `__init__.py` (with `register(ctx)`), `policy.py`, `skill_frontmatter.py`, `audit.py`, `install_wrapper.py`, `README.md`, `tests/test_*.py`
- [x] `mordred-hermes/src/mordred_hermes/wizard/` を scaffold: `plugin.yaml`, `__init__.py`, `cli.py`, `configure.py`, `upgrade.py`, `policy_writer.py`, `policy_explainer.py`, `README.md`, `tests/test_*.py`
- [x] `mordred-hermes/src/mordred_hermes/llm_guard/` を scaffold: `plugin.yaml` (`privacy_lock: true`), `__init__.py`, `local_adapter.py`, `transport.py`, `health.py`, `override.py`, `harness_detect.py`, `README.md`, `tests/test_*.py`
- [x] `mordred-hermes/src/mordred_hermes/network/` を scaffold: `plugin.yaml`, `__init__.py`, `paths/{tor,vpn,clearnet}.py`, `proxy_env.py`, `provider_transport_flagger.py`, `api.py`, `runtime.py`, `README.md`, `tests/test_*.py`
- [x] `mordred-hermes/src/mordred_hermes/keyvault/` を scaffold: `plugin.yaml` (macOS extra で gating), `__init__.py`, `native.py` (lazy import), `api.py`, `crypto.py`, `wrap.py`, `backup.py`, `recovery.py`, `digest.py`, `seed_display.py`, `network_fallback.py`, `log_encryption.py`, `README.md`, `tests/test_*.py`
- [x] 各 plugin の `__init__.py` で `def register(ctx) -> None` の **stub** を定義 (Phase 0、 typing は `ctx: Any`、 中身は no-op)。 実 hook / CLI / provider / tool 登録は Phase 1.x 以降の plugin 別タスクで行う (Phase 1.1 / 1.3 / 2.1 / 3.1 / 4.1 参照)
- [x] (Phase 1.0 prep) `ctx` の typing を `TYPE_CHECKING` 経由で `hermes_cli.plugins.PluginContext` に絞るか Mordred 内 `Protocol` で代替。 Hermes hook payload drift を mypy で検知できるようにする — **2026-05-10 完了** (Phase 1.1 PR、 各 plugin に narrow `Protocol` 方式を採用。 `mordred-hermes/src/mordred_hermes/privacy_check/_typing.py:PluginContext` を参照、 他 plugin は Phase 2/3/4 で必要に応じて拡張)
- [x] 各 plugin の `plugin.yaml` で `privacy_lock: true` を Mordred 内部 hint として declare (zero-PR commitment、 Hermes 本体は当該フィールドを無視するが Mordred plugin 側で sibling-disable 検出に活用)

### 0.5 `mordred-hermes` パッケージ scaffold

- [x] `mordred-hermes/pyproject.toml` 作成 (2026-05-09、 下記 deviations あり):
  - `name = "mordred-hermes"`
  - `dynamic = ["version"]` + `[tool.hatch.version] path = "mordred-docs/VERSION"` (M6: VERSION ファイルを single source of truth に)
  - `requires-python = ">=3.10"`
  - `dependencies = ["hermes-agent>=1.0", "ruamel.yaml>=0.18"]` (H1: hermes-agent を install 時必須化、 fail-fast)
  - `[project.optional-dependencies]` で `macos = ["pyobjc-framework-Security>=10.0"]`
  - `[project.entry-points."hermes_agent.plugins"]` で 5 plugin の `register` を expose
  - `[project.metadata]` で `mordred-min-hermes-version` declare (runtime 二重検証用)
  - **Deviations from spec** (Phase 0.5 follow-ups required):
    - ~~`version = "0.1.0a0"` を直接記述 (dynamic version 未使用)~~ — **2026-06-09 完了**: static `version` を削除し `dynamic = ["version"]` + `[tool.hatch.version] path = "src/mordred_hermes/__about__.py"` へ移行。正準ソースを importable package 内 (`__about__.py`) に置くことで build isolation を回避 (docs-tree の `mordred-docs/dev/VERSION` は cross-dir のため sdist→wheel で読めない、が本 deviation の懸念だった)。`uv build` で sdist/wheel とも `0.1.0a0` 解決を検証済 (sdist は `__about__.py` を同梱)。bump は `tools/bump_version.py` が `__about__.py`(正準)/docs `VERSION`/全 `plugin.yaml` を一括更新、`tests/test_packaging_versions.py` が一致と stub < real を pin
    - `dependencies = ["hermes-agent>=0.11.0"]` (spec は `>=1.0` だが Hermes 上流の最新が 0.11.0)。 Hermes が 1.0 GA したら pin を引き上げ
    - PEP 621 が `[project.metadata]` を許容しないため `[tool.mordred] min-hermes-version = "0.11.0"` table に変更
    - Entry-point は **module のみ** を指定 (`mordred_hermes.privacy_check`、 `:register` を付けない)。 Hermes loader (`hermes_cli/plugins.py:_load_entrypoint_module` → `getattr(module, "register")`) と整合。 SPEC/PLAN/TODO の例も訂正済み
- [x] `pip install -e ./mordred-hermes` で editable install 成功確認
- [x] `hermes plugins list` で 5 つの mordred_* が表示されることを確認 — **deferred to Phase 1.3 wizard で UX gap close** (entry-point plugin は Hermes 上流 `_discover_all_plugins()` の対象外。 `hermes mordred plugins list` wrapper を `wizard/plugins_list.py` で提供、 L130 acceptance gate と同じ outcome を達成済)
- [ ] **M7: PyPI name reservation** — v1 docs を public にする前に TestPyPI / PyPI で `mordred-hermes` 名を stub upload (空の `0.0.0.dev0`) で押さえる。 squat による supply-chain 攻撃の予防。 **2026-05-18: 予約 tooling 実装済み** — stub package (`mordred-hermes/packaging/name-reservation/`、 `0.0.0.dev0`、 `uv build` + `twine check` PASS 確認) + `.github/workflows/release.yml` (PyPI Trusted Publishing OIDC、 `mode=reserve`/`release` × `target=testpypi`/`pypi`、 `workflow_dispatch` 限定) + version 不変条件 test (`tests/test_packaging_versions.py`、 `0.0.0.dev0 < 0.1.0a0` を pin)。 **残**: operator が手動で PyPI/TestPyPI に pending publisher 登録 → `release.yml` を `mode=reserve` で TestPyPI→PyPI 実行 (runbook = `CI.md` §`release.yml` 詳細)。 upload 完了後に本 checkbox を `[x]` 化
- [x] H1 検証: hermes-agent 不在環境で `pip install mordred-hermes` を実行し、 dependency resolution が hermes-agent の解決失敗で fail-fast することを確認 (CI で fresh venv test を追加) — **2026-05-17 完了** (Codex review 反映): `.github/workflows/ci.yml` に `fresh-venv-resolution` job を追加 (`needs: test`、 root `pip install -e .` を意図的に省き mordred-hermes 単独 install を実行)。 非 0 exit に加え `install.log` が `hermes-agent` の resolution failure (`No matching distribution` / `Could not find a version`) を含むことを grep 検証 — pyproject 破損や network 障害による偽陽性を防止。 検証対象 pin は現行 `hermes-agent>=0.11.0` (spec の `>=1.0` からの deviation、 §0.5 L66 参照)

### 0.6 CI workflow

- [x] `.github/workflows/ci.yml` を作成 (2026-05-09、 PR #8): pytest + pytest-cov、 ruff check / format --check、 mypy --strict、 paths-filter + concurrency cancel-in-progress、 matrix = (ubuntu-24.04 / macos-latest) × (Python 3.10 / 3.11 / 3.12)、 macOS は `[macos]` extra も install。 詳細は `mordred-docs/dev/CI.md` §`ci.yml` 詳細
- [x] `.github/workflows/upstream-check.yml` を作成 (2026-05-09、 PR #8): 週次 月曜 03:00 UTC + workflow_dispatch、 Hermes upstream `VALID_HOOKS` と Mordred plugin `register_hook("...")` 呼出を比較、 drift 時 `actionable` + `upstream-drift` label 付きで issue 自動起票。 詳細は `CI.md` §`upstream-check.yml` 詳細
- [x] `.github/labeler.yml` + `.github/workflows/labeler.yml` 作成 (2026-05-09、 PR #8): `mordred-*` paths にラベル付与、 fork PR 対応のため `pull_request_target` 採用 (permissions = `contents: read` + `pull-requests: write` のみ)、 label 一覧の one-time `gh label create` コマンドは `CI.md` §`labeler.yml` 詳細

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

> **2026-05-07 revise**: MIGRATION.md §10 row 4 / §5 で **zero upstream PR** が確定。 Hermes 上流への PR は v1 で**提出しない**。 disable 防御は plugin-side strict-mode startup refusal (Phase 1.1 H3 タスク、 SPEC.md §Plugin-disable protection Tier A) で完結。

v1 では本 0.7 セクションのタスクは以下のみ:

- [x] 5 plugin の `plugin.yaml` で `privacy_lock: true` を Mordred 内部 hint として declare (Hermes 上流側には意味を持たない hint、 sibling list 自動拡張用)
- [x] H3 plugin-side strict-mode startup refusal の実装は Phase 1.1 で行う (TODO §1.1 参照) — **2026-05-10 完了** (Phase 1.1 PR、 §1.1 H3 Path B チェック参照)

v2 escape hatch (deferred):

- [ ] (v2) `vendor/hermes/<version>/hermes_cli/plugins_cmd.py` に Hermes 該当バージョンのパッチ版を配置、 `pyproject.toml` に `[project.optional-dependencies]` `hard-lock` extra を定義。 詳細は UPSTREAM.md §Tier B 参照

### 0.8 Hermes hook payload を実コードで verify

> **L2 (Phase 0 blocker scope の拡大)**: 旧 0.8 は `pre_llm_call` の override 戻り値と `register_provider` のみを blocker 扱いしていたが、 SPEC/PLAN 全体に散らばる "要 verify" 項目 (hook 順序保証、 child-process spawn proxy 継承、 `pre_gateway_dispatch` return shape、 等) も Phase 0 で同時に verify する。 Phase 1.1 / 2.1 / 3.1 の implementation path がこれらに依存するため。
>
> **2026-05-10 source-code verify 完了** (PR `docs/mordred-hermes-phase0.8-hook-verify`): 結果は [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) に集約。 SPEC.md §Plugin-Only Architecture / §Story 4 / §Plugin: `mordred_llm_guard` / §Story 6 にも反映済み。 **MAJOR finding**: `pre_llm_call` での provider override は v0.11.0 では構造的に不可能 — Phase 2 設計を session-scoped enforcement に変更 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5 参照)。 runtime/network 実機 verify は L106-117 のとおり別 issue / PR (live verify) に deferred。

- [x] `pre_tool_call` payload の中身を `agent/run_agent.py` および `model_tools.py` で確認 (`origin_skill` が含まれるか、 hook が block する return 形式) → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4): payload は `tool_name`/`args`/`task_id`/`session_id`/`tool_call_id` のみ、 **`origin_skill` 不在**、 block 形式は `{"action": "block", "message": str}` (`hermes_cli/plugins.py:1085-1121`)
- [x] `pre_llm_call` payload の中身を `agent/run_agent.py` で確認 (`provider_id`/`model_id` が含まれるか、 override 用 return 形式) → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5): payload に `model` のみ (`provider` 不在)、 戻り値は **context-injection 専用** で provider override 不可 (`run_agent.py:10303-10313`、 `plugins.py:976-986`)
- [x] `pre_gateway_dispatch` の return action (`skip`/`rewrite`/`allow`) を `gateway/run.py` で確認 → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §6): `gateway/run.py:3573-3605` で skip/rewrite/allow セマンティクス確認、 docstring と一致
- [x] `pre_approval_request` / `post_approval_response` の payload を `tools/approval.py` で確認 → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §7): `approval.py:34-56, 1054-1209` で確認、 **observer-only** (戻り値ignored)、 `choice` は once/session/always/deny/timeout
- [x] Hermes plugin loader の hook 順序保証を `hermes_cli/plugins.py` で確認 (登録順か priority か) — **Phase 3 strict-mode bootstrap order の前提条件** → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1): **登録順** で確定 (priority システム無し、 `plugins.py:968-1002`)。 entry-point plugin (Mordred) は bundled/user/project の後にロードされるため、 hook callback も常に最後に呼ばれる
- [x] Hermes child process spawn API を確認 (`os.environ` から proxy env vars を inherit するか、 必要なら明示的注入が要るか) — **Phase 3 path injection の前提条件、 M3 transitive failure mode の影響範囲確定にも必要** → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §8)
  - [x] subprocess env が **snapshot** (`subprocess.Popen(env=os.environ.copy())` 形式 — mid-session use(path) の env 更新が live subprocess に伝播しない) か **live reference** (環境変数の参照を保持) かを実機で確認 → **snapshot per spawn** で確定 (`tools/environments/local.py:186-213` の `_make_run_env` が `dict(os.environ | env)` を毎回 fresh 構築)。 Mordred の `os.environ` mutation は **後続の spawn には伝播するが running children は frozen**
  - [x] subprocess 起動箇所を `agent/run_agent.py` / `tools/terminal.py` / 他の Popen 呼出 site で grep して列挙、 各 site で env 渡し方法を確認 → 285 サイト列挙、 **2 つの regime に分かれる** (PR #9 Codex review で発見、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §8.1):
    - **Regime A (blocklist-style)**: `tools/terminal_tool.py` / `tools/environments/{local,docker,ssh,singularity}.py` / `tools/browser_tool.py` — proxy 変数は pass through
    - **Regime B (allowlist-style、 silently drops proxy)**: `tools/code_execution_tool.py` (`_SAFE_ENV_PREFIXES` フィルタ) — Mordred は `tools.env_passthrough` registry に proxy 変数を **明示登録必須**、 さもなくば execute_code child が tunnel 外で通信
- [x] `hermes plugins list --disabled` 相当 API の存在確認 (H3 Path B `on_session_start` で sibling-disabled 検出に必要、 無ければ `~/.hermes/config.yaml` の plugins 設定を直読する fallback) → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §2): `--disabled` flag 不在、 `plugins_cmd._discover_all_plugins()` は entry-point plugin を表示しない。 **fallback 確定**: `from hermes_cli.plugins import _get_disabled_plugins` (module-level) を直接呼び出すか、 `~/.hermes/config.yaml` を `yaml.safe_load` で直読 (`plugins.disabled` list)
- [x] Hermes が動的 plugin disable を session-running 中に反映するか確認 (H3 Path B caveat: 反映しない前提で v1 設計、 反映する場合は別設計が必要) → 2026-05-10 完了 ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §3): **反映しない** (`PluginManager.discover_and_load(force=False)` が `_discovered` キャッシュで short-circuit)。 H3 Path B の refuse-at-startup-only 設計が正しいことを確定
- [x] **Network provider 実機テスト** (M8 §provider_transport_flagger v1 baseline allowlist 確定の前提) — **2026-05-17 完了** (Wireshark/live-Tor の代わりに hermetic な in-process SOCKS5 inspector で実証。 `tests/integration/test_provider_transport.py` + `_socks5_inspector.py` が各 SDK の CONNECT を RFC 1928 ATYP byte で観測。 API キー・クラウド呼出不要)。 bedrock の DNS quirk 深部 / vertex は下記の通り deferred:
  - [x] `anthropic` SDK + `HTTPS_PROXY=socks5h://...` でリクエストが proxy 経由になるか実機テスト — **完了** (`TestAnthropic`、 env-trusting httpx、 ATYP=DOMAINNAME 確認)
  - [x] `openai` SDK で同様テスト — **完了** (`TestOpenAI`、 同 httpx 経路)
  - [x] `gemini` で同様テスト — **完了** (`TestGemini`)。 **finding**: 現行 SDK は `google-genai` (httpx ベース)、 旧 `google-generativeai` (requests) ではない。 `KNOWN_PROVIDERS["gemini"].transport` を `"requests"` → `"httpx"` に訂正
  - [x] `mordred-local` (LM Studio/Ollama localhost) が NO_PROXY default で proxy 経由から除外されるか確認 — **完了** (`TestMordredLocal`、 `proxy_env.desired_env(path="tor")` の実 env で localhost が proxy bypass することを実証)
  - [ ] `bedrock` (boto3) の DNS quirk を実機検証 (DNS query が proxy bypass で OS resolver に向かうか) — **partial**: `respects_socks5h=False` は実証済 (`TestBedrock`、 botocore の urllib3 transport は SOCKS 非対応)。 DNS quirk の packet-capture 深部検証は実 AWS アカウント必須のため v2 deferred
  - [ ] `vertex` (google-cloud SDK) の partial proxy compliance を実機検証 — **deferred**: `google-cloud-aiplatform` は heavy SDK で `partial` 挙動は GCP-side。 transport 層検証の範囲外、 v2 deferred
  - [x] 各結果を `provider_transport_flagger.py` の `KNOWN_PROVIDERS` dict に書き込む — **完了** (anthropic/openai/gemini/mordred-local は `unverified_baseline=False`、 bedrock/vertex は上記理由で `True` 据置、 module docstring に検証状態を記録)
- [x] **SOCKS5h library 互換性テスト**: 主要 HTTP client の SOCKS5h URL scheme 対応を確認 — **2026-05-17 完了** (`tests/integration/test_socks5h_libs.py`、 in-process SOCKS5 inspector で ATYP=DOMAINNAME を実証。 `proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` 全 4 entry の `unverified_baseline` を `False` に flip、 `notes` を実証値で書換)
  - [x] `httpx` (anthropic/openai/mordred-local 採用): `socks5h://` 対応バージョン要件を確定 — **完了** (httpx 0.28.1 + socksio 1.0.0、 socks5:// / socks5h:// 両方で DNS を proxy に委譲 = scheme 区別なし・安全側)
  - [x] `urllib3` / `requests[socks]`: same — **完了** (urllib3 2.7.0 + PySocks 1.7.1、 requests 2.33.1。 requests/urllib3 は scheme 区別を honor — socks5:// = local DNS)
  - [x] `aiohttp` 旧版で SOCKS5h 非対応のバージョン境界を確定 (allowlist の判定根拠) — **完了** (aiohttp 3.13.5 + aiohttp-socks 0.11.0)。 **finding**: `python-socks` (aiohttp-socks エンジン) は `socks5h://` URL scheme を `ValueError` で**拒否** — remote DNS は `socks5://` + 明示 `rdns=True` が必要。 `notes` に caveat 記録
- [x] verify 結果を `mordred-docs/SPEC.md` § "Plugin-Only Architecture" の "他に core 改修が必要になりそうな項目" にフィードバック → 2026-05-10 完了 (SPEC.md L100-107 を更新、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) を canonical reference として cross-link)

### Acceptance gate (Phase 0)

- [x] `pip install -e ./mordred-hermes` 成功 (2026-05-09 実行確認)
- [x] entry-point 経由で 5 plugin が `PluginManager.discover_and_load()` に検出され、 `register()` が呼ばれる (2026-05-09 実行確認)
- [x] ~~`hermes plugins list` で 5 つの mordred_* が表示~~ → **closed by Phase 1.3 wizard**: Hermes 上流の `hermes_cli/plugins_cmd.py:_discover_all_plugins()` は bundled (`<repo>/plugins/`) と user (`~/.hermes/plugins/`) directory のみを scan し、 entry-point plugin を表示しない (Hermes 0.11.0 確認)。 Tier A discovery (loader) は機能するため Phase 0 acceptance としては passing 扱い。 **2026-05-13 完了**: `hermes mordred plugins list` (`mordred-hermes/src/mordred_hermes/wizard/plugins_list.py`) で UX gap を埋めた — `PluginManager` を直接 query し `mordred_*` prefix で filter、 ImportError 時は `~/.hermes/config.yaml` `plugins.enabled` への fallback あり
- [x] `pytest -q` が空でも green、 `ruff check`/`mypy --strict` も green (2026-05-09 ローカル確認 + CI 強制、 PR #8。 7 tests passed、 ruff lint/format clean、 mypy strict 0 errors。 baseline で `mypy --strict` が既に green のため TODO §0.4 L52 ctx typing 改善は本 PR で scope-out、 Phase 1.0 prep に残置)
- [x] ~~HSeam-1 PR draft 作成済み~~ → 不要 (zero-PR commitment 2026-05-07 確定。 2026-05-17 棚卸し: struck-through の disposition 確定済み、 L131 と整合させ checkbox を `[x]` に補正)
- [x] 0.8 verify 結果が SPEC.md に反映済み (2026-05-10 完了、 source-code 部分のみ。 runtime / network 実機 verify は別 issue で trace、 Phase 2/3 で `MORDRED_LIVE_*=1` integration test gate 配下に置く)

---

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

### Open decisions

- [x] DECIDE: audit log `reason` enum の最終固定。SPEC.md §Audit log policy に列挙されているコード (`policy.strict.clearnet` 等 9 個) を Phase 1 step 0 で freeze。 **2026-05-07 追記 (M2)**: `policy.strict.local_stream_interrupted` (Phase 2 mid-stream local-endpoint death) を 10 個目として追加、 同時 freeze → **2026-05-10 完了**: 12-code freeze (9 + M2 + Phase 2 forward-compat の `policy.strict.session_refused` / `policy.strict.provider_override_at_session_start` 2 個 — SPEC/PLAN で既に referenced されていたため同時に enum 化)。 `mordred-hermes/src/mordred_hermes/privacy_check/_audit_reasons.py:ReasonCode` (typed `Literal`) と `mordred-docs/dev/POLICY.md §Audit log reason enum (frozen)` が canonical
- [x] DECIDE: agentskills.io 規格との `metadata.mordred.*` 衝突有無。同名キーが標準にないことを spec 文書で確認 → **2026-05-10 完了**: agentskills.io v1 spec (`https://agentskills.io/specification`) は `metadata` を flat string→string map と定義、 vendor namespacing を明示推奨 (`We recommend making your key names reasonably unique to avoid accidental conflicts`)。 衝突キー無し。 ただし Mordred は **nested object + non-string types** で deviation あり (`requires_keyvault: bool`, `outbound_endpoints: list[str]`)。 `skills-ref validate` が Mordred-flavoured skill を reject する可能性あるが、 v1 では `hermes mordred install` ラッパが authoritative validator なので許容。 詳細 `POLICY.md §agentskills.io deviation` 参照

### 1.1 `mordred_privacy_check` plugin

> **2026-05-10 Phase 1.1 PR 完了**: 全 sub-task を `mordred-hermes/src/mordred_hermes/privacy_check/` に landing。 105 テスト green、 ruff/mypy strict clean。 詳細は `mordred-docs/dev/POLICY.md` を参照。

- [x] `plugin.yaml` に `config_schema` (policy/allow_cloud_llm/cloud_provider_allowlist/audit_log_path) を実装 (PLAN §1.1)
- [x] `policy.py` で pure policy evaluator を実装 (no I/O)
- [x] `skill_frontmatter.py` で SKILL.md frontmatter を yaml.safe_load し `metadata.mordred.*` を抽出 (ruamel.yaml safe loader 採用、 nested object form は agentskills.io spec 偏差として POLICY.md §SKILL.md `metadata.mordred.*` に文書化)
- [x] `audit.py` で single-writer NDJSON logger を実装 (rotation, gzip, 30-day retention, file mode 0600)
  - [x] `class Writer(Protocol): def append(self, entry: dict) -> None: ...` interface を Phase 1 で freeze (Phase 4 で `EncryptedWriter` に factory swap)
  - [x] in-process write queue で serialize、 multi-process は v1 unsupported
  - [x] **M1 (multi-process write contention)**: 各 writer が `os.O_APPEND` mode で open + 1 line ごとに `write()` 1 回 (POSIX `O_APPEND` の atomic guarantee に依存、 PIPE_BUF 4 KiB 以下なら interleave しない、 entry size cap = 4000 bytes)。 PATHS.md §Multi-process write contention 参照。 v2 で Unix domain socket 経由 daemon writer または `fcntl.flock` 排他に upgrade
- [x] `install_wrapper.py` で `hermes mordred install <skill>` を実装:
  - [x] SKILL.md を read、 frontmatter parse
  - [x] strict + clearnet → block + audit `policy.strict.clearnet`
  - [x] strict + missing → block + audit `policy.strict.unknown_metadata`
  - [x] lenient + missing → allow + audit `policy.lenient.unknown_metadata_warning`
  - [x] allow → `subprocess.run(["hermes", "skills", "install", skill])` (runner は test injectable)
- [x] `pre_tool_call` hook 実装: **generic tool-name allowlist のみ** (Phase 0.8 verify で `origin_skill` が payload にないことが確定、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)。 strict mode default blocklist: `web_fetch`, `web_search` on Clearnet。 per-skill enforcement は install-time wrapper (`hermes mordred install`) でのみ実装、 runtime hook では行わない
- [x] `on_session_start` hook で policy snapshot を `~/.hermes/config.yaml` の `plugins.mordred_privacy_check` から load + sibling Mordred plugin disable 検出 (zero-PR commitment 下で常時必要、 v2 で `[hard-lock]` extra が install されている場合も defense-in-depth として残す)
- [x] **H3 Path B (strict-mode startup refusal)**: `on_session_start` 冒頭で sibling list `["mordred_network", "mordred_llm_guard", "mordred_keyvault", "mordred_wizard"]` を scan、 `policy=strict` かつ 1 つでも disable されている場合は `SystemExit` を raise してセッション abort (`RuntimeError` から `SystemExit` に変更 — Hermes `invoke_hook` が `except Exception:` で wrap するため `BaseException` 派生が必要、 詳細 hooks.py docstring 参照)。 audit `mordred.degraded.disable_unprotected` 同時記録 + 防御 in 深い `_runtime.poison()` flag セット。 lenient/off では warning のみ。 SPEC.md §Plugin-disable protection の Path B を参照

### 1.2 Skill metadata namespace

- [x] `mordred-hermes/src/mordred_hermes/privacy_check/README.md` で `metadata.mordred.*` フィールド (network_requirements / requires_keyvault / outbound_endpoints) を文書化 (2026-05-10 Phase 1.1 PR、 `POLICY.md §SKILL.md \`metadata.mordred.*\` extension` も参照)
- [x] Fixture skill 作成: `tests/fixtures/clearnet_skill/SKILL.md`, `tests/fixtures/tor_skill/SKILL.md`, `tests/fixtures/missing_metadata_skill/SKILL.md`

### 1.3 `mordred_wizard` plugin

> **2026-05-13 Phase 1.3 完了** (PR1 = configure + explainer、 PR2 = upgrade + install_dispatch + audit_cli + plugins_list + docs)。 282 tests green、 ruff/mypy strict clean。 `hermes-mordred {configure,upgrade,install,policy,audit,plugins} ...` が動作 — `hermes mordred ...` も Hermes 0.12+ で自動的に動く構造。

- [x] `__init__.py` で `ctx.register_cli_command("mordred", help, setup_fn=_setup_subparser, ...)` を実装
- [x] `cli.py` で argparse subparser ツリー (configure / upgrade / install / network / policy / audit / keyvault / plugins) を構築
- [x] `configure.py` で `subprocess.run(["hermes", "setup"])` の child spawn → Mordred-specific prompts (`prompt_toolkit` 経由)
- [x] `upgrade.py` で Story 1 / Story 1.5 migration を実装:
  - [x] `~/.hermes/config.yaml` を `ruamel.yaml` round-trip で編集 (コメント・キー順保持)
  - [x] idempotent (state 一致時 no-op)
  - [x] 既存 `plugins.mordred_*` 衝突時は diff + prompt
  - [x] `~/.openclaw/mordred/` を検出時、 PATHS.md "OpenClaw 旧パスからの migration" 表に従う
  - [x] **H5 conflict resolution semantics**: PATHS.md §OpenClaw 旧パスからの migration 表で確定した per-row policy を実装:
    - audit.log は append-by-timestamp-window、 overlap 時は abort + `--audit-merge=skip\|append-all\|abort` を要求
    - keyvault / credentials は `never overwrite`、 既存時は abort (content-identical なら idempotent noop)
    - policy.json / `plugins.mordred_*` は diff + prompt (interactive)、 batch では `--policy-conflict=keep-existing\|overwrite\|abort`
  - [x] **H5 idempotency marker**: 1 回目の audit migration 完了時に `~/.hermes/mordred/.audit-migrated-from-openclaw` (内容: ISO-8601 UTC timestamp 1 行) を書き出し、 2 回目以降は marker 存在なら audit migration を skip
  - [x] `--reset` フラグで全 conflict-policy を `overwrite` 強制、 `--non-interactive` で interactive prompt を抑止し未指定 policy は fail-fast
- [x] `policy_writer.py` で `~/.hermes/config.yaml` の `plugins.mordred_*` セクションを書き出し
- [x] `policy_explainer.py` で `policy explain <skill-id>` / `policy dry-run <skill-path>` を実装
- [x] **PR2 追加**: `install_dispatch.py` (privacy_check.install_wrapper への adapter)、 `audit_cli.py` (tail/grep)、 `plugins_list.py` (§0.5 L128 UX gap close)

### 1.4 Tests (Phase 1)

- [x] `tests/test_policy.py`: strict/lenient/off × clearnet/tor/vpn/local-only matrix を網羅 (2026-05-10 Phase 1.1 PR)
- [x] `tests/test_audit.py`: rotation, file mode 0600, single-writer concurrency (2026-05-10 Phase 1.1 PR)
- [x] `tests/test_install_wrapper.py`: fixture skills の install 結果を assert (2026-05-10 Phase 1.1 PR)
- [x] `tests/test_skill_frontmatter.py` 追加: SKILL.md frontmatter parser の matrix (2026-05-10 Phase 1.1 PR、 当初 PLAN にはなかったが skill_frontmatter.py の独立検証として追加)
- [x] `tests/test_hooks.py` 追加: `on_session_start` / `pre_tool_call` hook handler の matrix、 `SystemExit` 経路、 poison flag、 sibling-disable detection (2026-05-10 Phase 1.1 PR)
- [x] `tests/test_upgrade.py`: fixture config を migrate して expected output 確認 (Phase 1.3 wizard PR2 / 2026-05-11)
- [x] `tests/test_policy_writer.py`: `ruamel.yaml` round-trip の comment preservation を assert (Phase 1.3 wizard PR1 / 2026-05-10)
- [x] ~~`tests/test_wizard_prompts.py` (snapshot test、 `pytest-snapshot` 利用)~~ → **Phase 1.3 で不採用 (2026-05-13)**: 実装した `configure.py` は `PromptIO` Protocol を介して prompt 文字列を直接構築するため、 `tests/test_configure.py` で各 prompt の label / default を一発で assert できる (実 prompt_toolkit 出力に依存しない)。 snapshot test の必要性が消えたので `pytest-snapshot` dep も追加していない

### 1.5 Docs and bookkeeping (Phase 1)

- [x] `mordred-docs/POLICY.md` を新規作成 (policy schema reference、 全 enum 値、 例) — 2026-05-10 Phase 1.1 PR、 12-code freeze (Phase 1 9 codes + Phase 2 forward-compat 3 codes) を `_audit_reasons.py:ReasonCode` の typed `Literal` でも宣言
- [x] `mordred-docs/VERSION` を `0.1.0a0` (PEP 440 alpha 0) で初期化。 人間可読 spec label `v0.1.0-mvp.0` は ROADMAP/SPEC/release notes 用 branding として別管理 (Codex review 2026-05-09 で確定、 PLAN §0.5 PEP 440 準拠 caveat 参照)
- [x] 各 plugin `README.md` で own path / config / 内部 API を記述 (privacy_check / wizard 完了 2026-05-13、 残り network / llm_guard / keyvault は対応 Phase 着手時)
- [x] **L1 (bilingual track retired)**: 日本語版 (`*.ja.md`) docs は廃止・削除済み (2026-06-25)。 以降ドキュメントは英語版 (`*.md`) のみを単一の正とする

### Acceptance gate (Phase 1)

- [x] `hermes mordred configure` が `~/.hermes/config.yaml` と `policy.json` を書き込む (PR1 完了、 `tests/test_configure.py`)
- [x] `hermes mordred upgrade` が既存 Hermes install を破壊せず migrate (OpenClaw 移行 Story 1.5 も成功) (PR2 Phase E 完了、 `tests/test_upgrade.py` + `tests/test_openclaw_migration.py`)
- [x] `hermes mordred install <fixture-clearnet-skill>` が strict policy で block (PR2 Phase F-1 完了、 `tests/test_install_dispatch.py::TestRunBlock`)
- [x] `pytest -q` 全 green、 `ruff check` / `mypy --strict mordred-hermes/src` green (2026-05-13: 282 tests passed)
- [x] zero-PR commitment 下で plugin Tier A guard (strict-mode startup refusal + audit log) のみで Phase 1 acceptance gate を通過することを確認 (v2 `[hard-lock]` extra に依存しない) — Phase 1.1 で landed、 wizard 追加でも変わらず

---

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

> **Phase 2 PR2 完了** (2026-05-13、 TDD redo): PR1 (`local_adapter` + `harness_detect` + PolicySnapshot Phase 2 fields) は #14 で main にマージ済み。 PR2 で `enforce.py` (session-scoped, refuse-only)、 wizard `harness_primary` prompt、 PR1 self-review からの M1/M2/L1 follow-up を入れて Phase 2 完了。 386 tests passed / 4 skipped (live LLM gated)、 ruff + ruff format + mypy --strict すべて green。 strict RED→GREEN→REFACTOR で書き直し済み。

### Open decisions

- [x] ~~DECIDE: `pre_llm_call` payload に provider/model 含まれる場合の cloud passthrough 有効化~~ → **closed stale** (Phase 0.8 verify で v0.11.0 に `provider` 不在 + 戻り値 context-injection 専用を確定済み、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5)。 v1 は常に session-scoped enforcement (Phase 2 PR2 `enforce.py`)
- [x] DECIDE: harness primary 検出時の挙動 — strict mode で startup を完全 abort vs warn + degrade → **strict=abort / lenient=warn+audit / off=noop** (Codex D2、 SPEC.md L143 と整合)。 実装: `harness_detect.check_harness_primary` (Phase 2 PR1)。 strict 時 `MordredHarnessRefused(BaseException)` raise

### PR1 prep findings (Codex review 2026-05-13)

- **B1 (BLOCKER)**: `providers._discover_providers()` は `<repo>/plugins/model-providers/*` + `$HERMES_HOME/plugins/model-providers/*` のみ scan、 entry-point plugin を見ない → `register_mordred_local()` を `register(ctx)` 内で**明示呼出**。 module-import side effect は禁止
- **B2 (BLOCKER)**: `~/.hermes/config.yaml` の active provider を `on_session_start` で patch しても、 `HermesCLI/AIAgent` は session 開始**前**に `self.provider`/`base_url`/`model` を resolve 済み → **auto-swap は v1 不可**。 PR2 enforce は **refuse 一本化** (D3 = refuse-only)。 `register_provider` + config patch による (b) パスは v2 vendored fork まで延期
- **H1 (HIGH)**: PLAN.md L299 の SPI list (`wrap_stream_fn` / `auth` / `discovery` / `resolve_synthetic_auth` / `normalize_config` / `prepare_dynamic_model` / `resolve_dynamic_model` / `augment_model_catalog` / `wizard`) は **現 Hermes に存在せず stale**。 `ProviderProfile` は declarative only。 streaming は Hermes core (`agent/error_classifier.py`) 所有 → **`transport.py` と M2 `MordredLocalStreamInterrupted` は PR1 から drop、 v2 deferred**。 `policy.strict.local_stream_interrupted` は freeze enum に残置 (raise する class が無い状態)、 POLICY.md で deferred を明示
- **H2 (HIGH)**: strict 時の refusal は `SystemExit` ではなく `BaseException` 派生の custom class (`MordredHarnessRefused` / `MordredSessionRefused`)。 cleanup-style `except SystemExit:` で誤検出されない。 `privacy_check/hooks.py` の `SystemExit` は別 PR で refactor 候補 (`privacy_check_systemexit_refactor` follow-up)
- **M3 (MEDIUM)**: `PolicySnapshot` Phase 2 fields (`local_llm_endpoint` / `local_llm_model_id` / `cloud_attempt_action`) を PR1 へ前倒し。 PR2 enforce が PolicySnapshot を input surface として直接読めるように。 wizard `configure.py` も同 PR で snapshot に wire (現状 `phase2_fields` 別 dict に collect → discard だった経路を撤去)
- **N1 (NIT)**: 12-code freeze の `policy.strict.cloud_not_allowlisted` は classification reason、 final action は `policy.strict.session_refused` (default refuse) または `policy.strict.provider_override_at_session_start` (v2 auto-swap)。 POLICY.md §Audit log reason enum (frozen) で明示

### 2.1 `mordred_llm_guard` plugin

- [x] `local_adapter.py` で `mordred-local` synthetic provider を実装 — **declarative `ProviderProfile` のみ** (Phase 2 PR1、 SPI list は H1 で stale 確定。 `name="mordred-local"` / `api_mode="chat_completions"` / `base_url` は `policy.json` から動的 read)。 `register_mordred_local()` を `register(ctx)` 内で明示呼出 (B1 fix)
- [x] ~~`transport.py` で local OpenAI-compatible endpoint の HTTPX クライアント~~ → **v1 drop** (H1: streaming は Hermes core 所有、 plugin transport は noop。 v2 で upstream に streaming hook が landed したら復活。 2026-05-17 棚卸し: v1-drop 確定済み、 checkbox を `[x]` に補正)
- [x] `health.py` で endpoint health probe; failure 時に `MordredLocalUnreachable` raise (Phase 2 PR1)
- [x] ~~`override.py` で `pre_llm_call` handler~~ → **v1 drop** (B2 / HOOK_PAYLOADS §5: `pre_llm_call` は provider override 不可)。 代替: `enforce.py` で `on_session_start` session-scoped enforcement (PR2 で実装。 2026-05-17 棚卸し: v1-drop 確定済み、 checkbox を `[x]` に補正)
- [x] **`enforce.py` (PR2、 v1 = refuse-only)** で `on_session_start` handler (Phase 2 PR2 完了):
  - [x] lenient/off → no-op (v1 は silent — per-session allow audit は v2 で再検討)
  - [x] strict + active provider が `cloud_provider_allowlist` に該当 + `allow_cloud_llm: true` → passthrough、 audit `policy.strict.cloud_allowlisted`
  - [x] strict + 該当しない、 または `allow_cloud_llm: false` → **refuse** (`MordredSessionRefused` raise)、 audit `policy.strict.session_refused` (classification reason `policy.strict.cloud_not_allowlisted` も同時 emit、 Codex N1)
  - [x] strict + provider info 無し (degraded `no_resolved_provider`) → refuse + audit `mordred.degraded.no_resolved_provider` (one-shot) + `policy.strict.unconditional_override`
  - [x] strict + `mordred-local` → health probe → 成功なら audit allow、 失敗なら `MordredSessionRefused` (`MordredLocalUnreachable` を `__cause__` に連鎖。 Codex review P2 round 2: bare `Exception` だと Hermes `invoke_hook` が swallow するため `_probe_local` で `BaseException`-derived refusal に wrap) (Phase 2 acceptance gate row 4)
  - [ ] (b) auto-swap `register_provider` + config patch は **v1 範囲外** (B2: live runtime mutate 不可)、 v2 vendored fork で再評価
  - [x] **runtime override 対応** (Codex review P1 round 3): `on_session_start` は disk-based 解決のみで CLI `--provider` / `HERMES_INFERENCE_PROVIDER` / oneshot 切り替えを取りこぼすため、 `pre_api_request` hook で `check_runtime_provider(provider=kwargs.provider)` を追加実行 (`run_agent.py:11320-11338` 経由で resolved runtime provider が来る)。 strict + cloud not allowlisted → `MordredSessionRefused` で `run_agent.py:11337` の `except Exception: pass` を `BaseException` 経由で escape
- [x] **`harness_detect.py`** で `on_session_start` handler (Phase 2 PR1 完了):
  - [x] configured harness primary を `~/.hermes/config.yaml plugins.mordred_llm_guard.harness_primary` から read
  - [x] prefix-regex allowlist: `^codex(-\d+(\.\d+)*)?$` / `^claude-cli(-\d+(\.\d+)*)?$` / `^cursor(-\d+(\.\d+)*)?$` / `^acp-[a-z][a-z0-9-]*$`
  - [x] strict → `MordredHarnessRefused(BaseException)` raise + audit `mordred.degraded.disable_unprotected` (decision=block)
  - [x] lenient → audit (decision=warn) + log warning + 続行 (Codex M2)
  - [x] off → no-op

### 2.2 Wizard additions (Phase 2)

- [x] `hermes mordred configure` に local LLM endpoint URL (default `http://localhost:1234/v1`)、 local model id、 cloud attempt action (always-block / prompt-once) prompt を追加 — **Phase 1.3 で既に collect。 Phase 2 PR1 で `PolicySnapshot` に wire (Codex M3 反映、 旧 `phase2_fields` 別 dict は撤去)**
- [x] `hermes mordred configure` に harness primary declaration prompt を追加 (Phase 2 PR2 完了、 default `none`、 choices: `none`/`codex`/`claude-cli`/`cursor`/`acp-claude`/`acp-cline`)。 PolicySnapshot に `harness_primary` 追加 + `PolicyWriter.write` で `config.yaml plugins.mordred_llm_guard.harness_primary` を upsert

### 2.3 Tests (Phase 2)

- [x] `tests/test_enforce.py`: 決定 matrix の全 case (Phase 2 PR2 完了、 25 tests green。 旧 `tests/test_override.py` から rename — Codex L2)
- [x] `tests/test_enforce_audit.py`: 各 path で正しい reason code emit (Phase 2 PR2 完了、 7 tests green、 frozen-enum membership 含む)
- [x] `tests/test_harness_detect.py`: harness primary 検出 matrix (Phase 2 PR1 完了、 24 tests green)
- [x] `tests/test_health.py`: health probe success / timeout / connect-refused / 500 matrix (Phase 2 PR1 完了、 9 tests green)
- [x] `tests/test_local_adapter.py`: B1 explicit-register + module-import-no-side-effect + policy.json fallback (Phase 2 PR1 完了、 8 tests green)
- [x] `tests/test_exceptions.py`: `BaseException` propagation contract (Phase 2 PR1 完了、 7 tests green)
- [x] `tests/test_llm_guard_register.py`: `register(ctx)` wires provider + `on_session_start` (Phase 2 PR1 完了、 PR2 で 2-callback registration order test を追加、 7 tests green)
- [x] `tests/test_llm_guard_typing.py`: `PluginContext` Protocol narrow surface (Phase 2 PR1 完了、 4 tests green)
- [x] `tests/integration/test_llm_local.py` (gated by `MORDRED_LIVE_LLM_TEST=1`): real LM Studio endpoint roundtrip (Phase 2 PR2 完了、 5 tests; 3 live-gated を skip)
- [x] Failure mode テスト: lmstudio down → `MordredSessionRefused` (`MordredLocalUnreachable` を `__cause__` に連鎖、 Codex review P2 round 2 後の wrap 経由)。 Phase 2 PR2 完了、 `tests/integration/test_llm_local.py::TestFailureMode`、 port 1 で hermetic 実行
- [x] ~~**M2 (mid-stream local-endpoint death)**: `tests/test_enforce.py::test_mid_stream_disconnect`~~ → **v2 deferred** (H1: Hermes core が streaming を所有、 plugin から `MordredLocalStreamInterrupted` を確実に raise できない。 v2 で upstream に streaming hook が landed したら復活。 2026-05-17 棚卸し: v2-deferral 確定済み、 checkbox を `[x]` に補正)

### Acceptance gate (Phase 2)

- [x] strict policy 下のターン → v1 refuse-only (B2: live runtime mutate 不可なので auto-swap deferred)。 `mordred-local` がすでに active な場合は health probe 後に passthrough、 audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictLocal`)
- [x] (provider info 含まれる場合) strict + cloud upstream in `cloud_provider_allowlist` + `allow_cloud_llm: true` → no refuse、 audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictCloudAllowlisted`)
- [x] (provider info 無い場合 / degraded) v1 では refuse + audit `mordred.degraded.no_resolved_provider` (one-shot) + `policy.strict.unconditional_override` (action)。 routes to `mordred-local` 自体は v2 vendored fork で復活予定 (`test_enforce.py::TestStrictDegraded`)
- [x] strict + no local endpoint reachable → fails fast with `MordredSessionRefused` (`MordredLocalUnreachable` を `__cause__` に連鎖、 Codex review P2 round 2 で wrap)。 `tests/integration/test_llm_local.py::TestFailureMode`
- [x] Codex/Claude-CLI primary + strict → `hermes mordred` 起動 refuse (`harness_detect` PR1 + PR2 で hook registration order を `test_llm_guard_register.py` で検証)
- [x] Audit log records every override decision (`test_enforce_audit.py::TestFrozenEnumMembership`、 frozen 5 reasons membership invariant 含む)

---

## Phase 3 — Network Paths (`mordred_network`)

> **Phase 3 PR1 完了** (2026-05-13): primitives 着地 (paths/* / proxy_env / provider_transport_flagger / api / _exceptions / 16-code freeze)。 514 tests passed / 4 skipped、 ruff + format + mypy --strict すべて green。 `register(ctx)` は no-op のまま、 hooks + runtime + wizard CLI は PR2 で landing 予定。 real-traffic verify (TODO §0.8 L110-117 含む) は PR3 で実施。 詳細は `mordred-hermes/src/mordred_hermes/network/README.md` 参照。
>
> **Phase 3 PR2 完了** (2026-05-14): `runtime.py` (state machine + M9 liveness worker + M3 `live_subprocess_count` + env snapshot/restore)、 `hooks.py` (`on_session_start` / `on_session_end` / `pre_tool_call` + `wait_until_ready` polling fallback)、 `__init__.register(ctx)` (runtime singleton + 3 hook callbacks)、 wizard `network_cli.py` (`network use` / `network status` の NotImplementedError stub を real handler に置換) を landing。 583 tests passed / 4 skipped (PR1 比 +69 tests: runtime 33 / hooks 23 / wizard_network_cli 12 + 1 stub-defers test 削除)、 ruff + format + mypy --strict すべて green。 real-traffic provider verify、 SOCKS5h library 互換性、 control-port circuit-status liveness probe (`stem`)、 docker-compose integration tests は **PR3 deferred**。 詳細は `mordred-hermes/src/mordred_hermes/network/README.md` (PR2 status table) 参照。
>
> **Phase 3 PR3b 完了** (2026-05-14): `tests/integration/_docker.py` (compose v2 lifecycle helper + 3-tier skip guard) + `tests/integration/docker/tor/{Dockerfile,torrc,docker-compose.yml}` (alpine + tor + loopback-only port binding + RFC1918 SocksPolicy) + `tests/integration/test_tor.py` (SOCKS5 handshake / socks5h DNS roundtrip / proxy_env HTTPS_PROXY round-trip) + `tests/integration/test_vpn.py` (MORDRED_LIVE_VPN_TEST=1 + MORDRED_MULLVAD_ACCOUNT gated: roundtrip / lockdown rollback / handshake freshness)。 `.github/workflows/ci.yml` に `integration-tor` job (ubuntu-only、 `needs: test`) + `.github/workflows/integration-vpn.yml` (workflow_dispatch only) を追加。 paths/tor seam は不要 (`_ProcessLike` Protocol + `TorHandle` dataclass で既に満たされていたため production code は無変更)。 741 tests passed + 10 skipped、 ruff + format + mypy --strict すべて green。 Real-traffic provider verify (§0.8 L110-117) と stem-against-real-Tor deep probe は **PR3c deferred**。 詳細は `mordred-hermes/src/mordred_hermes/network/README.md` (PR3b status section) 参照。

### Open decisions (resolved 2026-05-09 / 2026-05-13)

- [x] ~~DECIDE: Tor binary 推奨を `arti` vs `tor` のどちらにするか~~ → **v1 default = official `tor` daemon** (SPEC §Plugin: `mordred_network` Tor connection 確定。 `arti` は v2 で再評価)
- [x] ~~DECIDE: Mullvad CLI dependency を v1 で要求するか~~ → **v1 = Mullvad 公式 `mullvad` client 必須** (自前 `wg-quick` 直接実行は v1 範囲外。 SPEC §Plugin: `mordred_network` Mullvad VPN integration 確定)
- [x] ~~DECIDE: Hermes plugin loader が hook 順序保証しない場合、 polling fallback (Phase 3 strict-mode bootstrap order) で進めるか~~ → **polling fallback で確定** (2026-05-13)。 Phase 0.8 §1 verify で **登録順** で確定済みだが entry-point plugin は bundled/user/project の **後** にロードされるため、 PR2 で `on_session_start` 内に `wait_for(lambda: api.status().ready, timeout=5s)` の polling fallback を実装する

### 3.1 `mordred_network` plugin

- [x] `paths/tor.py` (v1 default = official `tor` daemon) を `subprocess` で実装 (PR1 / 2026-05-13):
  - [x] **torrc 生成**: `render_torrc(socks_port, control_port, data_dir)` 実装 (`SOCKSPort 127.0.0.1:<port>`、 `ControlPort 127.0.0.1:<port>`、 `CookieAuthentication 1`、 `DataDirectory`) — PR2 が `~/.hermes/mordred/tor-data/torrc` に persist
  - [x] **port 衝突解決**: `pick_free_port(candidates)` で `socket.bind` probe (default 9050 → 9150)、 全滅時 `BringupFailed` raise (strict hook 経由で `MordredPathBringupFailed` に変換)
  - [x] **ControlPort cookie auth**: `<data_dir>/control_auth_cookie` を読み、 `GETINFO circuit-status` で M9 liveness probe を実装 — **PR3a Task #5 完了 (2026-05-14)**: `mordred_hermes.network.paths.tor.circuit_status_health(handle, *, controller_factory=...)`、 BUILT 回線が 1 本でもあれば True。 `stem>=1.8.0,<2` は **optional extra `[tor-control]`** (`pip install mordred-hermes[tor-control]`)。 stem 最終リリース 2021-12 の supply-chain 懸念に配慮、 import 失敗時 / cookie 不在時は shallow `process.poll()` fallback。 strict mode の deep liveness は runtime の `tor_health` injection 経由で opt-in
  - [x] **bootstrap timeout**: `wait_for_bootstrap(process, timeout=30s)` で stdout を tail、 `Bootstrapped 100%` を 30s 以内に検出 (M9)
  - [x] **process management**: `start_process(binary, torrc)` で `subprocess.Popen`、 `stop(handle, grace_seconds=5)` で terminate + grace + kill (PR2 の `on_session_end` から呼ばれる)
  - [x] **caveat 文書化**: bridge / obfs4 / Snowflake は v1 範囲外 — `network/README.md` に明記、 startup banner は PR2
  - [ ] Stream isolation (per-skill SOCKS auth) は v2-N1。 **2026-06-02: per-session foundation landed** — `proxy_env.desired_env(isolation_token=...)` が SOCKS5 credential を注入 (>255 octet は sha256 で RFC 1929 制限回避)、 torrc は `IsolateSOCKSAuth` 明示 (PR #76)、 後続で `on_session_start` が `session_id` を per-session circuit token として `Runtime.set_isolation_token` 経由で配線。 **per-skill** 単位は `pre_tool_call` payload の `origin_skill` (v2-H2) 待ちで未実装
- [x] `paths/vpn.py` (v1 = Mullvad 公式 `mullvad` client) を `subprocess` で実装 (PR1 / 2026-05-13):
  - [x] **CLI 検出**: `detect_cli(which)` で `shutil.which("mullvad")` → fail で `/Applications/Mullvad VPN.app/Contents/Resources/mullvad` fallback → 両方 fail で `BringupFailed` raise (PR2 hook が `MordredPathBringupFailed` に escalate)
  - [x] **bring-up sequence**: `bring_up(cli_path, region, policy_mode, runner)` で strict 時 `lockdown-mode set on`、 lenient/off は user 設定尊重 (Mullvad CLI 2026.2 で `always-require-vpn` は削除され、`lockdown-mode` に統合)
  - [x] `mullvad relay set location <country|auto>` で region 設定 — `bring_up` で実装、 default `auto` は wizard 側で確定 (PR2)
  - [x] `mullvad connect` → `wait_connected(cli_path, runner, timeout=10s, poll_interval=0.5s)` で polling (M9 bring-up timeout 10s)
  - [x] **liveness probe**: `health(handle, runner, max_handshake_age_seconds=180)` で `wg show` parse、 `parse_handshake_age` で seconds/minutes/hours/days 加算 (M9)
  - [x] **tear-down**: `disconnect(handle, preserve_lockdown=True)` 実装。 `preserve_lockdown=False` で lockdown 解除 (strict 中は default 維持)
  - [x] **DNS leak**: Mullvad client が tunnel 内 resolver を強制 — `README.md` で文書化、 v1 で leak 無し
  - [x] **Platform**: macOS Apple Silicon + Ubuntu/Debian baseline、 Windows は v1 範囲外 — `vpn.py` docstring に明記
- [x] `paths/clearnet.py` で no-op (PR1 / 2026-05-13、 `start()` / `stop()` / `health()`)
- [x] `proxy_env.py` で active path 用の `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` を計算 (PR1 / 2026-05-13、 pure function — actual `os.environ` 反映は PR2 runtime):
  - [x] **NO_PROXY default**: `localhost,127.0.0.1,::1` を active path に依らず常に含める、 user extras append + 重複排除 + 順序保持
  - [x] **HTTPS_PROXY URL scheme**: clearnet/vpn では keys 不在、 tor では `socks5h://127.0.0.1:<port>` (DNS server-side 解決で leak 防止)。 plain `http://` は **使わない**
- [x] `provider_transport_flagger.py` で v1 baseline allowlist 実装 (PR1 / 2026-05-13):
  - [x] **v1 baseline `KNOWN_PROVIDERS` Python dict を実装** (6 entries、 全 entry `unverified_baseline=True` フラグ付き):
    - `anthropic` / `openai` (httpx baseline、 `respects_proxy=True`、 `respects_socks5h=True`)
    - `gemini` (requests baseline、 `respects_proxy=True`、 `respects_socks5h=True`)
    - `mordred-local` (httpx baseline、 `localhost_only=True`、 NO_PROXY default で proxy 経由除外)
    - `bedrock` (boto3、 `respects_proxy=True`、 `respects_socks5h=False`、 `dns_quirk=True` — strict + tor で DNS leak risk)
    - `vertex` (google-cloud SDK、 `respects_proxy="partial"`、 `respects_socks5h=False`)
  - [x] Phase 0.8 verify で各 provider の HTTPS_PROXY 尊重・SOCKS5h 対応を実機テストし、 dict 値を確定 — **2026-05-17 完了** (§0.8 L110-117 参照)。 anthropic/openai/gemini/mordred-local は `tests/integration/test_provider_transport.py` で実証し `unverified_baseline=False` に flip。 bedrock は `respects_socks5h=False` のみ実証 (DNS quirk 深部は v2 deferred)、 vertex は heavy SDK のため deferred — 両者 `True` 据置
  - [x] **strict mode behavior**: `evaluate(active_path, providers, policy_mode)` で active path = `tor` + `respects_socks5h=False` → severity=`abort` Flag、 active path = `clearnet` + `respects_proxy=False` → severity=`warning`、 lenient で `abort` → `warning` downgrade、 off で no flags
  - [x] **user override**: `overrides` arg で entry 追加可。 baseline と衝突する override は `ValueError` で reject (silent strict-mode bypass 防止)
  - [x] `tests/test_provider_transport_flagger.py`: `KNOWN_PROVIDERS` dict + policy override + strict / lenient / off matrix 網羅 (18 tests)
- [x] `api.py` で内部 Python API (`use(path)`, `status()`, `health()`, `blackout_assert()`) を実装 (PR1 / 2026-05-13):
  - [x] `Runtime` Protocol 定義、 module-level `_RUNTIME` で singleton 管理 (PR2 が `set_runtime()` で wire)
  - [x] `use(path)` 失敗時は `MordredNetworkError` (subclasses: `BringupFailed`, `AlreadySwitching`, `UnknownPath`) を raise — silent fallback 禁止。 audit `network.use_failed` emit は **PR2 runtime** が orchestrate (PR1 は raise contract のみ)
  - [x] `blackout_assert(probe)` 実装、 default probe = UDP connect to 1.1.1.1:53 (connectionless)。 reachable 時 `BlackoutNotAsserted(MordredNetworkError)` raise — Phase 4 `keyvault.seed_display` consumer
- [x] **M3 (transitive proxy-env failure mode)** — PR2 / 2026-05-14: `mordred_network.api.use(path)` 経由で runtime が audit log に `network.use` (decision=`override`, fields `prev_path` / `new_path` / `live_subprocess_count`) を emit。 `live_subprocess_count` は best-effort `pgrep -P <pid>` based (Linux + macOS; Windows は 0 + 文書化)。 docstring に「新規 spawn 子プロセスのみ反映」 を明記、 README §M3 で Regime A / B 分岐も文書化。 wizard CLI 側の stdout warning は live runtime ありの場合 path 切替メッセージで間接的に user に visible
- [x] **M8 (transport coverage)** — PR3a / 2026-05-14:
  - [x] DNS leak 防御: Tor 経路で `socks5h://` 強制 (PR1 既存) + SOCKS5h 非対応 library に対する static allowlist warning — `mordred_hermes.network.proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` + `evaluate_library_compatibility(active_path, declared_libs)` (PR3a Task #4、 httpx / urllib3 / requests / aiohttp baseline、 全 entry `unverified_baseline=True` until PR3c)
  - [x] IPv6 caveat: `policy.json disable_ipv6: bool` (strict default `true`、 lenient/off default `false`) を schema に追加 — reader = `mordred_hermes.network._resolve_disable_ipv6` (Task #2)、 writer = `PolicySnapshot.disable_ipv6` (Task #7)。 v1 enforcement = IPv4-only resolver hint + `provider_transport_flagger._flag_for_ipv6` (Task #3) で IPv6 endpoint 接続時の flagger warning。 完全 kernel-level firewall 防御は v2-N2 deferred
  - [x] non-HTTP transport: `provider_transport_flagger.ProviderEntry.transport_class: Literal["http","tcp","udp","quic","grpc","websocket"]` + `_flag_for_non_http` 分岐 (PR3a Task #3、 strict + tor + non-http → abort、 clearnet → warning)。 v1 baseline は全 `transport_class="http"`、 v2 で raw TCP/UDP/QUIC/gRPC を握る provider が現れた際に override 経由で追加
- [x] **M9 (path failure & liveness)** — PR2 / 2026-05-14:
  - [x] Bring-up timeout: Tor 30s、 VPN 10s。 strict は `MordredPathBringupFailed` raise + abort (hooks 層 `on_session_start`)、 lenient は warn + clearnet fallback + audit `network.bringup_failed` (runtime 内)、 off は silent
  - [x] Liveness probe: 内部 worker thread (30s default interval、 `RuntimeConfig.liveness_interval_seconds`) で `health()` 実行、 連続 2 回失敗で `_dropped` flag flip (`RuntimeConfig.liveness_failure_threshold`)
  - [x] Mid-session drop: strict は次の `pre_tool_call` で `MordredPathDropped` raise (block)、 lenient は warn + 続行。 必ず audit `network.path_dropped` (fields `path` / `consecutive_failures`、 `last_health_at` は v2 で追加)。 control-port version probe は PR3 で `stem` と同時
- [x] `runtime.py` で lazy-loaded subprocess management — PR2 / 2026-05-14 (`Runtime` class、 `RuntimeConfig`、 `State` enum、 `_default_subprocess_counter`)
- [x] `pre_tool_call` hook (v1: tool-name allowlist のみ、 [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4 で `origin_skill` 不在を確定) — PR2 / 2026-05-14:
  - [x] **path 自動切り替えは行わない (v1)** — runtime は state machine だけで auto-switch なし
  - [x] 全体 single-state 判定のみ — `api.is_dropped()` を `hooks.pre_tool_call` が読んで strict mode で refusal
  - [x] strict mode で active path = clearnet 時の per-skill block は **install-time** (Phase 1 install_wrapper) で処理済み — runtime mismatch 検出は v1 範囲外、 lenient/off では tool は実行される
- [x] `on_session_start` で path bring-up、 `on_session_end` で path tear-down (liveness worker thread も同期 stop) — PR2 / 2026-05-14 (`hooks.on_session_start` / `hooks.on_session_end`、 `Runtime.stop()` が worker join + env restore)
- [x] Bootstrap order: polling fallback (`hooks.wait_until_ready(timeout=5s)`) を public helper として export、 他 plugin が利用可能 — PR2 / 2026-05-14

### 3.2 Wizard additions (Phase 3)

- [x] `hermes mordred configure` に prompt を追加 — **PR3a / 2026-05-14 (Task #6)**:
  - [x] default network path (`tor` / `vpn` / `clearnet`、 default `clearnet`)
  - [x] Tor binary path (default `tor`、 配置 path / collision-aware `tor_socks_port` も `ask_text` で同時収集)
  - [x] Mullvad アカウント番号 — `PromptIO.ask_password` (新規、 prompt_toolkit `is_password=True`) で shell history 漏れ防止。 secret は `~/.hermes/.env` に直接書き出され `ConfigureResult` 経由 caller には漏れない (`test_secret_does_not_appear_in_returned_result` で dataclass tree walk による不在保証)
  - [x] Mullvad relay 地域 (default `auto`、 2-letter code もサポート)
  - [x] Mullvad killswitch (lockdown-mode、 strict mode default `on`、 lenient default `off`)
- [x] 機密情報は `~/.hermes/.env` に `MORDRED_MULLVAD_ACCOUNT=...` として書き込み — `wizard/env_file_writer.py::DotEnvFileWriter` (mode 0600、 親 dir 0700、 upsert idempotent、 empty value → 行削除、 newline / 非 POSIX env name は ValueError で reject)。 `~/.hermes/mordred/credentials/network.json` には env-var REFERENCE のみを記載 — `wizard/credentials_writer.py::JSONCredentialsWriter` (dir 0700、 file 0600、 atomic write、 secret-shape 値は ValueError で reject)
- [x] `hermes mordred network use <tor|vpn|clearnet>` 実装 (manual override) — PR2 / 2026-05-14 (`wizard/network_cli.py::handle_use`、 disk persist + live runtime drive when registered)
- [x] `hermes mordred network status` 実装 (active path / health / liveness 最終結果 / lockdown 状態を表示) — PR2 / 2026-05-14 (`wizard/network_cli.py::handle_status`、 runtime ありで live state、 なしで disk config fallback。 lockdown 状態は v2 で追加)

### 3.3 Tests (Phase 3)

- [x] `tests/test_paths.py`: path manager state machine — landed として `tests/test_network_runtime.py` (PR2 / 2026-05-14、 33 tests、 state machine / env snapshot / liveness worker / audit / api integration)
- [x] `tests/test_proxy_env.py`: env vars が正しく set される — PR1 (2026-05-13)
- [x] `tests/integration/test_tor.py` (docker-compose with Tor container; SOCKS5 reachable assert) — **PR3b 完了 (2026-05-14)**: 3 tests (SOCKS5 handshake / socks5h DNS roundtrip via check.torproject.org / proxy_env HTTPS_PROXY round-trip via httpx)。 alpine + tor + loopback-only port binding + RFC1918 SocksPolicy。 3-tier skip guard (env opt-out / OS / binary + daemon probe) で dev box / macOS runner / no-docker CI で自動 skip。 `.github/workflows/ci.yml` `integration-tor` job が ubuntu-24.04 で run by default
- [x] `tests/integration/test_vpn.py` (gated by `MORDRED_LIVE_VPN_TEST=1`): Mullvad real connection — **PR3b 完了 (2026-05-14)**: 3 tests (bring-up roundtrip / lockdown rollback when `lockdown_applied_by_us` / wg show handshake freshness under 180s)。 `MORDRED_LIVE_VPN_TEST=1` + `MORDRED_MULLVAD_ACCOUNT` (16-digit account number from repo secret) 両方が要件。 workflow_dispatch only — `.github/workflows/integration-vpn.yml` で operator が手動 trigger
- [x] Privacy-check coordination (v1): skill declaring `network_requirements: tor` の **install-time** 経路 (`hermes mordred install` ラッパ) を end-to-end でテスト — **2026-05-17 棚卸し完了**: install-time coordination の E2E は `tests/test_install_dispatch.py::TestRunBlock` (clearnet → block + audit) + `TestRunAllow::test_tor_skill_in_strict_mode` (`tests/fixtures/tor_skill/SKILL.md` の `metadata.mordred.network_requirements: tor` → allow) で covered。 実機 wireshark live verify は v1 範囲外 (auto-routing 不在のため不要)。 ~~runtime auto-switch~~ は v1 範囲外 (origin_skill 不在のため、 v2-H2 待ち)。 user は `hermes mordred network use tor` で手動切替する想定 — `policy explain` で確認

### Acceptance gate (Phase 3)

> **PR2 (2026-05-14) status**: code path 全て in place、 unit tests green。 live verification (real Tor circuit、 real Mullvad tunnel、 each bundled provider through HTTPS_PROXY) は PR3 で実機実施 — その時点で本 4 項目を check off。

- [x] Skill with `network_requirements: tor` が **manual switch** (`hermes mordred network use tor`) 後に Tor 経由で動作することを確認 — **2026-05-17 完了** (方式C): Hermes に skill invoke API が無い (skill は Markdown 指示書であり callable code ではない、 `tools/skills_tool.py` は SKILL.md 文字列を返すのみ) ため、 `tests/fixtures/tor_skill/` に SKILL.md の executable counterpart `network_probe.py` を同梱。 `tests/integration/test_tor.py::TestTorSkillEndToEnd` が `network use tor` の env (`proxy_env.desired_env`) 適用後に probe を実行し `IsTor=True` を assert (`integration-tor` CI job で live verify)。 CLI/runtime の switch 機構 (`network_cli.handle_use` → `Runtime.use("tor")` → `os.environ` mutation) 自体は `test_wizard_network_cli.py` / `test_network_runtime.py` で別途カバー — 本テストは適用後の proxy env を起点に skill 側を検証する。 hermetic な response-handling は `tests/test_tor_skill_fixture.py` (6 tests、 httpx MockTransport) でカバー。 ~~auto-routing at tool-call time~~ は v1 範囲外 (Phase 0.8 verify で `origin_skill` 不在を確定、 v2-H2 で復活予定)
- [ ] **[infra-blocked]** Manual `hermes mordred network use vpn` switches path within 2s — **PR3 live verify deferred**。 code path: live runtime ありの場合 `api.use("vpn")` is synchronous; `paths/vpn.wait_connected` の default timeout 10s + polling 0.5s。 unit test (`tests/test_wizard_network_cli.py::TestNetworkUseLive`) で synchronous behaviour 確認済み。 2026-05-17 棚卸し: dev box に `mullvad` CLI 不在のため `tests/integration/test_vpn.py` は `MORDRED_LIVE_VPN_TEST=1` gated 据置、 実機 verify は operator が手動 workflow_dispatch
- [x] `mordred_network.api.status()` returns truthful state — **code complete** (`tests/test_network_runtime.py::TestInitialState` / `TestTorUse::test_status_reports_tor_active` 他多数で truthfulness asserted)。 **2026-05-17 棚卸し完了**: code-complete を実コード照合済み、 `status()` は純粋な state reader のため別途 live verify 不要 (transport の live verify は §0.8 L110-117 = PR #41 で別途完了)
- [x] All bundled provider plugins continue to function under each path — **2026-05-17 完了** (§0.8 L110-117 が PR #41 で landing、 `tests/integration/test_provider_transport.py` が anthropic / openai / gemini / mordred-local の HTTPS_PROXY 経由 transport を in-process SOCKS5 inspector で実証、 `unverified_baseline=False` に flip 済み)。 bedrock / vertex の深部 verify は v2-deferred (理由は §0.8 L115-116 参照)

---

## Phase 4 — Key Management (`mordred_keyvault`)

### Open decisions

- [x] **[DECIDE 確定]** DECIDE: PC↔phone pairing flow (QR + mDNS + self-signed-TLS) を v1 で実装するか v2-F7 まで遅延するか — **2026-06-03 確定: v2-F7 据え置き** (operator 承認)。 phone-side UI 選定込みで約 1 週間の追加実装ゆえ v1 スコープ外、 v1 GA はブロックしない。 v1 は degraded flow (両 half を PC 表示) を SPEC 通り維持 (UX-level safety 約束は弱まるため v2-F7 は早期昇格候補)。 詳細は ROADMAP.md §v2-F7
- [x] DECIDE: Pre-Phase-4 plaintext audit log の取扱 — manual purge (`hermes mordred audit purge --before YYYY-MM-DD`) を提供する → **2026-05-17 確定・実装済み** (`audit purge` CLI は Phase 4 PR8 で landed、 §4.2 L443 参照。 決定の disposition が実装で充足済みのため checkbox を `[x]` に補正)

### 4.1 `mordred_keyvault` plugin

> **Phase 4 PR2 完了** (2026-05-14): pure-Python primitives `digest.py` / `backup.py` / `recovery.py` が landing。 Codex review (12 件: BLOCKER×1 + HIGH×3 + MEDIUM×5 + LOW×2 + NIT×1) を取り込み: SPEC.md digest formula の擬似コード + 固定 vector freeze (BLOCKER #1)、 backup wire format に `b"MRKV"` magic + version + KDF params + AAD bind (#2, #3)、 recovery は verify-before-decrypt 順 (#4)、 BackupCorrupt vs InvalidTag 分離 (#5)、 digest length-confusion guard (#6)、 reason enum freeze は PR2 emit site があるもの 2 codes のみに限定 (#8)、 audit sink shape は POLICY.md §Audit entry shape 準拠の `Callable[[dict], None]` (#9)、 salt freshness は RNG monkeypatch で deterministic check (#11)。 統合テストで発見した KDF cost-param DOS (`m_cost` MSB flip → 16 GiB allocation 要求) を parse_header で reject。 70 backup + recovery tests passed in <2s、 全 819 mordred-hermes tests green。 Phase 4 acceptance gate は **未達** (api.py / native.py / wrap.py / seed_display / log_encryption はまだ stub、 後続 PR3/PR4 で連結)。

> **Phase 4 PR4 step-0 doc freeze** (2026-05-15): `api.py` public Python surface の pre-implementation codex review (BLOCKER × 3 + HIGH × 5 + MEDIUM × 3 + LOW × 1) を反映した contract を SPEC.md §"PR4 API contract & MREN envelope wire format" / POLICY.md §"Phase 4 PR4 step-0 freeze" / PATHS.md §"Expected substructure" で freeze。 主要決定 (codex-corrected): (a) `generate` は **two-phase** 化 — `prepare_generate(seed, passphrase, pow) -> (SeedDisplayHandle, expected_digest)` で in-memory digest 計算のみ、 user が offline channel で confirm 後に `confirm_generate(handle, user_digest)` で初めて Keychain + meta.json mutation、 mismatch 時は state 変更ゼロで `keyvault.init_denied` emit (BLOCKER #2 fix)。 (b) `SeedDisplayHandle` は opaque class、 `__repr__` redacted / `__eq__` 禁止 / `__hash__=None` / `consume()` で internal bytearray を zero-fill (BLOCKER #3 fix)。 (c) normalization は **split** — `_normalize_seed_phrase = NFKD + casefold + whitespace-collapse` (BIP39 word-list)、 `_normalize_passphrase = NFKD only` (entropy 保存; BIP39 reference) (HIGH #1 fix)。 (d) `decrypt(key_id, envelope_id, purpose)` で caller-supplied `purpose` を要求、 envelope の `purpose_hash` と `hmac.compare_digest` (cross-purpose replay 防御、 HIGH #2 fix)。 (e) storage は **managed** — `encrypt` は `envelope_id` 返却、 `.gcm` ファイルを `os.open(O_NOFOLLOW) + tmp+fsync+rename+fsync(parent_dir)` + `fcntl.flock(.lock)` で persist、 mode `0600`/`0700` を fstat で検証 (HIGH #3/#4 fix)。 (f) `export_backup` / `import_backup` は full **ciphertext-rewrap manifest** — 各 DEK を Argon2id-KEK で再 wrap して MRKV blob 内 manifest に格納、 復旧時は新 Enclave key で各 DEK を再 wrap (BLOCKER #1 fix で acceptance gate L437 を満たす)。 (g) 4 新 audit code (`keyvault.init_started` #21 / `init_completed` #22 / `init_denied` #23 / `backup_exported` #24) を POLICY.md で freeze、 `_audit_reasons.py:ReasonCode` への追加は step-D で landing。 (h) `is_secure_enclave_available()` probe が False を返した時 `MORDRED_KEYVAULT_LIVE=1` 環境では live test を **fail** させる (HIGH #5、 silent-skip 防止)。 (i) MREN envelope wire format (196+N bytes、 AAD = `magic ‖ version ‖ key_id_hash ‖ purpose_hash ‖ wrapped_dek` 164 bytes) を SPEC で freeze。 (j) SPEC L501-505 の wrap surface drift (`generate_wrapping_key` から `audit_sink` 削除、 全関数に `backend` 追加) を同時に修正 (MEDIUM #1)。 step-0 は docs only commit、 後続 step-A/B/C/D/E/F/G で実装 (PR4 全体は ~32-42h core dev + codex review iterations、 5-8 working days 想定)。 PR4 は Phase 4 acceptance gate のうち L436 (encrypt/decrypt roundtrip) / L437 (backup → wipe → restore → decrypt roundtrip) / L439 (digest mismatch reject) を満たすが、 L435 (`requires_keyvault` install block) / L438 (Seed display blackout check) / L440 (`mordred_network`-absent fallback) / L441 (audit log encryption) は PR5 以降に残存 — Phase 4 全体完了は PR4 単独では未達 (codex LOW #1)。

> **Phase 4 PR3 完了** (2026-05-14): Secure-Enclave wrap/unwrap の seam (`native.py` + `wrap.py` + `_exceptions.py`) が landing。 Codex review (2 BLOCKER + 4 HIGH + 4 MEDIUM + 2 LOW + 1 NIT) を取り込み: 監査コードは `keyvault.unwrap_authorized` / `keyvault.unwrap_denied` の 2 個に変更 (BLOCKER #1: 認可境界は **unwrap のみ**、 wrap は Enclave **public** key + software ephemeral private で動く offline 操作)、 wire format から `kw_iv(8)` 削除し 127 bytes 確定 (BLOCKER #2: RFC 3394 AES-KW は 32 byte input → 40 byte output、 別 IV 不要)、 KDF は raw P-256 ECDH + HKDF-SHA256 で 1 段のみ (HIGH #1)、 HKDF `info` に `magic ‖ version ‖ alg_suite ‖ key_id_hash ‖ ephemeral_pub` を bind して AAD 相当の integrity を獲得 (HIGH #2)、 CI は biometric prompt を満たせないので live test は dev-only に固定 (HIGH #4)、 Apple Silicon 限定の仮定を撤回し capability probe で T2 Intel Mac もカバー (MEDIUM #1)、 `.biometryCurrentSet | .privateKeyUsage` + `.whenPasscodeSetThisDeviceOnly` で access control 固定 (MEDIUM #2)、 NativeBackend Protocol は Keychain/SecKey 操作のみ抽象化し HKDF/AES-KW/wire parse は real crypto で test (MEDIUM #4)、 例外は `WrapError` + 5 sibling subclass に分離 (NIT #1)、 PR4 が呼ぶ内部 surface を SPEC freeze (LOW #2)。 native (11 tests) + wrap (50 tests; FakeBackend = software P-256 keypair) で 61 tests passed、 全 891 mordred-hermes tests green、 ruff + format + mypy --strict すべて clean。 production `_SecKeyBackend` (pyobjc bridge) と live integration test (`tests/integration/test_keyvault_macos.py`) は **PR4 deferred** (api.py と同 PR で landing; PR3 は contract + Fake-tested surface のみ)。

> **Phase 4 PR4 完了** (2026-05-15〜16): `api.py` public surface (`prepare_generate` / `confirm_generate` / `generate` / `encrypt` / `decrypt` / `verify_digest` / `SeedDisplayHandle`) + `_storage.py` managed storage layer が 4 本の sub-PR (#26 pr4-api-and-seckey / #27 pr4b-storage-envelope / #28 pr4c-generate-backup / #29 pr3-review-low3) で landing。 codex pre-merge review を複数 round 取り込み (`confirm_generate` の pure-reader 化 + transaction reorder、 `expected_digest` expiry semantics、 generate handle wipe、 `consume()` thread-safety、 `__getstate__/__setstate__` seed leak block、 digest byte-length post-coercion 等)。 全 1211 mordred-hermes tests green、 ruff + format + mypy --strict clean。 **未達**: `api.export_backup` / `import_backup` の api.py 配線 (下位 primitive は PR2 で landing 済み)、 `seed_display.py` / `network_fallback.py` / `log_encryption.py` (まだ stub)、 §4.2 wizard CLI、 §4.3 integration tests、 Phase 4 acceptance gate L436-443。

> **Phase 4 PR4 step-E 完了** (2026-05-16): `api.export_backup` / `api.import_backup` (ciphertext-rewrap manifest) が landing — Phase 4 acceptance gate L437 (backup → wipe → restore → decrypt roundtrip) / L439 (digest mismatch reject) を満たす。 Enclave wrapping key は non-exportable なので cross-machine recovery は不可能 (Codex BLOCKER #1) — そのため export は各 envelope の DEK を unwrap し、 plaintext を **portable** manifest AAD (`MRMN ‖ key_id_hash ‖ purpose_hash`、 per-device MRKW prefix を含まない) で再暗号化、 DEK + portable ciphertext を canonical-JSON manifest に pack、 PR2 MRKV blob (Argon2id-KEK が manifest を at-rest 保護、 verification digest を embed) で wrap。 import は verify-before-decrypt (recomputed digest ≠ embedded digest → `RecoveryDigestMismatch`、 Enclave key 生成前) 後に新デバイスの Enclave key を生成し各 DEK を再 wrap → MREN envelope を再構築、 失敗時は ciphertexts tree + Enclave key + meta row を rollback。 内部の `_encode_envelope` / `_parse_envelope` を hash-input core (`_encode_envelope_from_hashes` / `_split_envelope`) に分割し import path で再利用 (cleartext purpose は stored envelope から復元不能、 purpose_hash のみ)。 audit code #24 `keyvault.backup_exported` を ReasonCode freeze に追加 (event `keyvault.backup_export`、 success-path emit は `contextlib.suppress`、 freeze count 24)。 16 backup tests + 全 1226 mordred-hermes tests green、 ruff + format + `mypy --strict src` すべて clean。 production `_SecKeyBackend` (pyobjc) と live integration test は引き続き後続、 `seed_display.py` / `log_encryption.py` / `network_fallback.py` の stub は未着手。

> **Phase 4 PR5 完了** (2026-05-16): `network_fallback.py` が landing — `keyvault.seed_display` (PR7) の network-blackout 前提条件。 SPEC.md §Seed phrase display security の **fallback** path を実装: `mordred_network` 不在時に keyvault が macOS `SCNetworkReachability` (pyobjc) で reachability を直接 probe。 `resolve_blackout_assert()` が single entry point — `mordred_network` import 可能時は `network.api.blackout_assert` に委譲し例外を keyvault-owned `BlackoutNotAsserted` に翻訳、 不在時は OS-API `blackout_assert` を返す。 `blackout_assert` は **fail-closed**: probe 実行不可 (非 macOS / pyobjc 不在 → `NetworkFallbackUnavailable`) 時に `BlackoutNotAsserted` を raise して Seed display を拒否 (un-probeable host で表示を通さない)。 module は全 platform で importable (pyobjc は call-time lazy import、 `keyvault.native` と同 contract)。 `_interpret_reachability_flags` は標準 Apple 解釈 (`Reachable` set かつ `ConnectionRequired` clear)。 `pyproject.toml [macos]` extra に `pyobjc-framework-SystemConfiguration>=10.0` を追加。 audit code 追加なし (blackout 判定の audit は呼び出し側 seed_display が PR7 で行う)。 27 network_fallback tests + 全 1253 mordred-hermes tests green、 ruff + format + `mypy --strict` clean。 Phase 4 acceptance gate L454 (`mordred_network`-absent env での fallback) を**部分達成** — seed_display 結線と `keyvault init` CLI は PR7/PR8。

> **Phase 4 PR6 完了** (2026-05-16): `log_encryption.py` が landing — Phase 1 で freeze した audit `Writer` Protocol に slot-in する AES-GCM encryption layer。 SPEC.md §Audit-log encryption coupling の `EncryptedWriter` 実装。 行指向 `MRAL` v1 wire format (行 0 = JSON header `{"fmt","ver","key_id","wdek"}`、 行 1+ = `base64(nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16))`) — 1 entry = 1 行で `O_APPEND` の whole-entry atomicity (Writer invariant #2) を保ちつつ全ファイル再暗号化を回避。 audit-log DEK は `wrap.wrap_dek` (offline、 Enclave public key、 prompt 無し) で wrap した 127-byte `MRKW` blob として header の `wdek` に格納 — **ディスクに載るのは wrapped DEK のみ**、 平文 32-byte DEK は writer メモリ上のみで `close()` で参照破棄。 DEK は最初の append 時に lazy 生成 (file ごとに fresh)。 per-entry AES-GCM AAD = `MAGIC ‖ version ‖ SHA-256(header 行)` で各 entry を file header に bind — 別 file からの entry splice / header 改竄後の replay は tag check で失敗。 `decrypt_log_file` は `wrap.unwrap_dek` (Secure Enclave authorization boundary、 `keyvault.unwrap_authorized` emit) で DEK を unwrap、 gzip rotated file も透過処理、 構造/整合性エラーは `AuditLogDecryptError`、 `WrapAuthCancelled`/`WrapKeyNotFound` は CLI が区別できるよう propagate。 rotation は Phase 1 NDJSONWriter と同じ (日次 + size cap + gzip + 30 日 retention、 rotation ごとに fresh file+DEK+header)、 既存 foreign file (pre-Phase-4 plaintext log 等) は overwrite せず rotate aside。 `ts` ミリ秒精度注入 + `0600`/`0700` mode で Writer invariant #1/#3 準拠、 `TYPE_CHECKING` conformance shim で Writer Protocol drift を mypy 検知。 audit code 追加なし (unwrap audit は `wrap.unwrap_dek` が emit)。 24 log_encryption tests + 全 1279 mordred-hermes tests green、 ruff + format + `mypy --strict src` clean。 Phase 4 acceptance gate L457 (audit log AES-GCM 暗号化) を**部分達成** — privacy_check の factory swap 結線と `hermes mordred audit decrypt` CLI は PR8。

> **Phase 4 PR7 完了** (2026-05-16): `seed_display.py` が landing — Seed phrase display flow の orchestrator。 SPEC.md §Seed phrase display security を実装。 `display_seed(handle, surface, ...)` が 6 ステップを実行: (1) network blackout assert (`network_fallback.resolve_blackout_assert`、 **fail-closed** — host reachable なら banner すら出さず raise)、 (2) M4/M5 warning banner (`SEED_DISPLAY_BANNER` — Wi-Fi/Ethernet/Bluetooth/USB tether/hotspot の物理切断、 screen recorder/remote desktop の停止を明示)、 (3) screenshot pre-check、 (4) `SeedDisplayHandle.consume()` で seed を one-shot 取得 (`SeedDisplayExpired` は propagate)、 (5) `time.monotonic()` ベース 60s timer + capture polling、 (6) `finally` で auto-clear (全 exit path で surface clear)。 screenshot 検出 (M5) は best-effort: `_default_capture_probe` が macOS Quartz `CGScreenIsBeingCaptured` を probe、 検出時は surface 即時 clear → audit `keyvault.seed_display_aborted_screenshot` emit → `SeedDisplayAborted` raise (`detector` 属性付き、 audit-sink 失敗は `__context__` に chain)。 probe は **fail-open** (非 macOS / pyobjc 不在 / bridge error は `None` — blackout assert の fail-closed と対照的、 screenshot 検出は advisory で banner が主防御)。 `SeedDisplaySurface` Protocol (banner/show/clear) で rendering を抽象化し、 PR8 の `keyvault init` CLI が surface 実装を供給する。 `SeedDisplayHandle` は api.py に据え置き (relocate せず、 api.py consumer 非破壊)、 Quartz bridge は call-time lazy import で module は全 platform で importable。 audit code 追加なし (`keyvault.seed_display_aborted_screenshot` は PR2 step-0 ReasonCode freeze 済み)。 `pyproject.toml [macos]` extra に `pyobjc-framework-Quartz>=10.0` を追加。 code-review (M1/L1/L2/L3) を取り込み: `poll_interval <= 0` を `ValueError` で fail-fast、 pre-display abort 時に handle を consume して seed payload を zero-fill、 main-display probe の限界と TTL 定数の独立性を docstring 明文化。 22 seed_display tests + 全 1277 mordred-hermes tests green、 ruff + format + `mypy --strict src` clean。 `keyvault init` CLI からの結線は PR8。

> **Phase 4 PR9 完了** (2026-05-16): production `_SecKeyBackend` (pyobjc Secure-Enclave バックエンド) が `keyvault/_seckey_backend.py` に landing — PR3 で freeze した `NativeBackend` Protocol の本番実装。 設計は `native.py` の narrow-boundary 流儀に倣い 2 層: (1) `_SecKeyOps` Protocol = 最小の pyobjc-touching surface (create / copy-public / delete / ECDH)、 各メソッドは plain `bytes` を返すか translated `OSStatus`/`LAError` を載せた `_OpsError` を raise — `Security.framework` 型は境界を越えない。 (2) `_SecKeyBackend` = flow + error-translation ロジック (`kSecAttrApplicationTag = b"mordred-hermes.wrap." + key_id_hash` 構築、 `_OpsError` を frozen `WrapError`/`NativeBackendError` taxonomy に map)。 production ops (`_PyobjcSecKeyOps`) は `SecKeyCreateRandomKey` (token=SecureEnclave、 access control `.privateKeyUsage | .biometryCurrentSet` + `.whenPasscodeSetThisDeviceOnly`、 SPEC.md §Wrap §Access-control attributes 準拠) / `SecItemCopyMatching` / `SecItemDelete` (errSecItemNotFound=success で冪等) / `SecKeyCopyKeyExchangeResult` (`ECDHKeyExchangeStandard`、 唯一の認可境界) を呼ぶ。 OSStatus/LAError → 5-code frozen set 翻訳テーブル (`_translate_error`、 未知コードは保守的に `auth_failed`)。 `native._probe_secure_enclave_capability` の stub `return False` を `_seckey_backend.probe_capability()` (`.privateKeyUsage`-only generate-then-delete、 prompt 無し) に差し替え。 cross-platform unit test は software-crypto `_FakeOps` (real `cryptography` P-256) を `_SecKeyOps` に注入し flow + 翻訳 + wrap/unwrap roundtrip を網羅 (39 tests)。 live `tests/integration/test_keyvault_macos.py` (`MORDRED_KEYVAULT_LIVE=1` gate、 §4.3 L451) は実 Secure Enclave で generate→wrap→unwrap (biometric prompt)→delete を verify、 gate ON かつ Enclave 不在時は skip せず fail (SPEC HIGH-5)。 1381 tests passed / 7 skipped、 ruff + format + `mypy --strict src` clean。 **deferred to PR10**: §4.2 の `keyvault init` / `recover` / `audit decrypt` CLI 結線 (本番 backend を api/log_encryption に注入)、 Phase 4 acceptance gate L458-462。

> **Phase 4 PR10 完了** (2026-05-16): PR9 が deferred した 3 つの backend-coupled CLI コマンド (`keyvault init` / `keyvault recover` / `audit decrypt`) + L465 暗号化監査ログ factory swap が landing。 step-0 (docs): SPEC.md に PoW アルゴリズム (seed-bound leading-zero-bits BLAKE3 counter search、 `MRPOW\x01` prefix、 `POW_DIFFICULTY_BITS=20` baseline、 固定 vector 2 本) と `keyvault init` flow を freeze。 step-A: `keyvault/pow.py` (`compute_pow`) + `keyvault/_bip39.py` (24-word BIP39、 256-bit only、 checksum 検証) + 公式 BIP39 英語 wordlist を vendoring (`_bip39_wordlist.txt`、 SHA-256 `2f5eed53…dbda`)。 step-B: `audit_cli.decrypt` — rotated `audit.log.<date>[.N][.gz]` + 当日 active log を `log_encryption.decrypt_log_file` 経由で復号、 denied prompt / missing key / corrupt を区別。 step-C: `keyvault_cli.recover` — blob 読取 + Seed/Passphrase prompt + BIP39 checksum 先行検証 + seed-bound PoW 再計算 + `api.import_backup`。 step-D: `keyvault_cli.init_keyvault` + `TerminalSeedSurface` — re-init guard / 二重 Passphrase prompt / BIP39 生成 / PoW / `prepare_generate` → `display_seed` (network blackout) → offline digest 確認 → `confirm_generate`。 step-E (L465): `privacy_check.audit.make_audit_writer` — keyvault 初期化済み + audit-log wrapping key 使用可能なら `EncryptedWriter`、 それ以外は `NDJSONWriter` に fail-open。 `_runtime._load_state` が factory 経由に。 `init_keyvault` は `mordred.audit-log` wrapping key も provision。 step-F: integration test L453 (`test_keyvault_macos.py` に AES-GCM encrypt/decrypt roundtrip) + L454 (`tests/integration/test_network_fallback.py`)。 cli.py の 3 stub (`NotImplementedError`) を実 handler に置換、 旧 `test_wizard_cli` stub-deferral test は削除。 全 mordred-hermes tests green、 ruff + format + `mypy --strict src` (64 files) clean。 Phase 4 acceptance gate L460 (encrypt/decrypt through Enclave) / L461 (backup roundtrip) / L463 (digest mismatch reject) / L464 (network-absent fallback) / L465 (audit log 暗号化) を達成。

- [x] `pyproject.toml` の `[project.optional-dependencies]` に `macos = ["pyobjc-framework-Security>=10.0", "argon2-cffi>=23", "cryptography>=42", "blake3>=0.4"]` を追加 — PR1 (#21) の前後で完了
- [x] `native.py` で `Security.framework` ラッパー (lazy import、 macOS 以外で ImportError 防止) — Phase 4 PR3 (本 PR) で landed。 `_lazy_import_security()` は cached、 non-Darwin は `WrapNativeUnavailable` を short-circuit raise、 macOS+pyobjc 不在は `ImportError` を `__cause__` chain。 `is_secure_enclave_available()` は capability probe (try-generate-and-delete) で T2 Intel Mac も含めて判定、 `platform.machine()` には依存しない (Codex MEDIUM #1)。 production `_SecKeyBackend` (実 pyobjc 呼び出し) は PR4 で api.py と同時着地
- [x] `api.py` 鍵生成サーフェス: two-phase `prepare_generate` / `confirm_generate` + 互換 `generate`、 opaque `SeedDisplayHandle` (`__repr__` redacted / `__eq__` 禁止 / `consume()` で internal bytearray を zero-fill)、 `verify_digest`、 BIP39 Unicode normalization split (`_normalize_seed_phrase` = NFKD+casefold+whitespace-collapse / `_normalize_passphrase` = NFKD only) — Phase 4 PR4 step-A/D (PR #26, #28) で landed
- [x] `api.py` envelope サーフェス: `encrypt` (`envelope_id` 返却) / `decrypt` (caller-supplied `purpose` を envelope の `purpose_hash` と `hmac.compare_digest`、 cross-purpose replay 防御) — Phase 4 PR4 step-B/C (PR #26, #27) で landed。 PR3 で内部 surface (`generate_wrapping_key` / `get_wrapping_key_public` / `delete_wrapping_key` / `wrap_dek` / `unwrap_dek` + `WrapError` 6-class taxonomy) は freeze 済み (Codex LOW #2)
- [x] `_storage.py` で managed storage layer: `ensure_layout` / `atomic_write` (`os.open(O_NOFOLLOW)` + tmp+fsync+rename+fsync(parent_dir)) / `safe_read` / `keyvault_lock` (`fcntl.flock`) / `load_meta` / `save_meta`、 mode `0600`/`0700` を fstat 検証 — Phase 4 PR4 step-B (PR #27) で landed (HIGH #3/#4 fix)
- [x] `api.py` の `export_backup` / `import_backup` (api-level ciphertext-rewrap manifest) を実装 — Phase 4 PR4 step-E で landed。 export は各 envelope の DEK を unwrap → portable manifest AAD (`MRMN ‖ key_id_hash ‖ purpose_hash`、 per-device MRKW prefix 無し) で再暗号化 → PR2 MRKV blob (Argon2id-KEK) に manifest を pack、 import は verify-before-decrypt 後に新 Enclave key で各 DEK を再 wrap → MREN envelope を再構築。 audit code `keyvault.backup_exported` (#24) を ReasonCode freeze に追加 (count 24)。 下位 primitive (`backup.py` / `recovery.import_backup`) は PR2 で landing 済み
- [x] `crypto.py` で AES-GCM encrypt/decrypt (cryptography ライブラリ) — Phase 4 PR1 (#21) で landed、 AES-128/192/256 対応、 nonce は `secrets.token_bytes(12)`
- [x] `wrap.py` で Secure Enclave-backed wrapping-key integration — Phase 4 PR3 (本 PR) で landed。 127-byte blob (`MRKW(4)|version(1)|alg_suite(1)|key_id_hash(16)|ephemeral_pub(65)|wrapped_dek(40)`)、 raw P-256 ECDH (`SecKeyCopyKeyExchangeResult` with `kSecKeyAlgorithmECDHKeyExchangeStandard`) + HKDF-SHA256 (`info` binds non-secret fields → AAD-equivalent integrity, Codex HIGH #2) + AES-KW (RFC 3394、 内蔵 AIV のみ; `kw_iv` field は廃止、 Codex BLOCKER #2)。 wrap は offline (Enclave public key 経由、 prompt 無し、 audit 無し); unwrap は authorized (`enclave_ecdh` が `SecKeyCopyKeyExchangeResult` 経由で biometric prompt、 `keyvault.unwrap_authorized` / `keyvault.unwrap_denied` を emit、 `native_error_code` は `user_cancelled` / `auth_failed` / `biometry_lockout` / `passcode_not_set` / `key_not_found` に translate、 raw `OSStatus` は audit に出さない)。 audit-sink exception chaining は PR2 `recovery._emit_mismatch` パターン踏襲 (`except Exception`、 sink_exc を `__context__` に attach、 raise は `except` block 外で行い Python の暗黙 `__context__` 上書きを避ける)。 NativeBackend Protocol は Keychain/SecKey 操作のみ抽象化 (Codex MEDIUM #4); FakeBackend (software P-256 via `cryptography`) で 50 tests を real crypto で exercise
- [x] `backup.py` で Argon2id (`m=46 MiB, t=1, p=1`) wrapped backup blob、 16-byte salt + verification digest を blob に embed — Phase 4 PR2 (本 PR) で landed。 wire format: `b"MRKV"` magic + version(1) + kdf_id(Argon2id) + m/t/p_cost (uint32 BE) + salt(16) + digest(32) + aes_blob_len(4 BE) + aes_blob。 AAD = magic ‖ version ‖ kdf_id ‖ KDF params ‖ salt ‖ digest (66 bytes)。 parse_header に DOS guard (m_cost ≤ 1 GiB / t_cost ≤ 64 / p_cost ≤ 16) を追加
- [x] `recovery.py` で `import_backup` の digest 再計算 + mismatch reject — Phase 4 PR2 (本 PR) で landed。 verify-before-decrypt 順 (parse_header → 32-byte length guard → `hmac.compare_digest` → decrypt_body)。 `audit_sink: Callable[[dict], None]` で POLICY.md `keyvault.recovery_digest_mismatch` を emit
- [x] `digest.py` で `digest = hash(hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW))` (BLAKE3 ベース) — Phase 4 PR2 (本 PR) で landed。 SPEC.md §Key generation and verification digest に擬似コード + 固定 vector を追加 (Codex BLOCKER #1)。 top4(PoW) は `PoW_bytes[:4]`、 XOR は `pass_hash[:4]` のみ、 残り 28 byte は pass-through。 `verify_digest` は `hmac.compare_digest` ベースの timing-safe compare + 32-byte length-confusion guard
- [x] `seed_display.py` で Seed display flow (blackout assert → 60-sec timer (`time.monotonic()` ベース) → display → auto-clear) — Phase 4 PR7 で landed。 `display_seed(handle, surface, ...)` が orchestrator: blackout assert (`network_fallback.resolve_blackout_assert`、 fail-closed) → M4 banner → screenshot pre-check → `SeedDisplayHandle.consume()` で seed 取得 → 60s monotonic timer + capture polling → `finally` で auto-clear。 `SeedDisplaySurface` Protocol (banner/show/clear) で rendering を抽象化、 PR8 の `keyvault init` CLI が surface を供給
- [x] **M5 (capture caveats)**: `seed_display.py` に macOS `CGDisplayRegisterReconfigurationCallback` + `CGScreenIsBeingCaptured` polling を実装、 検出時に Seed display を即時 clear + audit `keyvault.seed_display_aborted_screenshot` (Phase 4 reason enum freeze で同時追加)。 screen recording / VNC / Loom 検出は v1 範囲外、 startup banner で warn のみ — Phase 4 PR7 で landed。 v1 detector は `CGScreenIsBeingCaptured` polling (`_default_capture_probe`、 detector 値 `cg_screen_is_being_captured`)。 検出時は surface を即時 clear → audit emit (`event=keyvault.seed_display` / `decision=block` / `detector` field) → `SeedDisplayAborted` raise。 probe は **fail-open** (非 macOS / pyobjc 不在 / bridge error は `None`、 screenshot 検出は best-effort のため — blackout assert の fail-closed とは逆)。 `CGDisplayRegisterReconfigurationCallback` callback 方式は v1 未採用 (polling 方式を採用)、 audit `detector` enum は将来用に `cg_display_reconfiguration` も許容
- [x] **M4 (blackout caveat)**: `seed_display.py` の表示前 banner で 「Bluetooth / USB tether / hotspot を切ってください、 `blackout_assert()` は OS 標準スタックのみ検出」 とユーザに明示 — Phase 4 PR7 で landed (`SEED_DISPLAY_BANNER` 定数、 display 前に `surface.banner()` で表示。 物理 air-gap / screen recorder / remote desktop 停止も併せて warn)
- [x] `network_fallback.py` で `mordred_network.api.blackout_assert` 不在時の OS API 直接呼び出し fallback — Phase 4 PR5 で landed。 `resolve_blackout_assert()` が single entry point: `mordred_network` import 可能時は `network.api.blackout_assert` に委譲 (例外を keyvault-owned `BlackoutNotAsserted` に翻訳)、 不在時は macOS `SCNetworkReachability` (pyobjc 経由、 lazy import で module は全 platform で importable) の OS-API probe にフォールバック。 `blackout_assert` は **fail-closed** — probe 実行不可 (非 macOS / pyobjc 不在) 時は `BlackoutNotAsserted` を raise して Seed display を拒否。 `pyproject.toml [macos]` extra に `pyobjc-framework-SystemConfiguration>=10.0` を追加。 27 network_fallback tests + 全 1253 mordred-hermes tests green、 ruff + format + `mypy --strict` clean。 seed_display (PR7) からの結線は後続
- [x] `log_encryption.py` で Phase 1 audit `Writer` interface に slot-in する AES-GCM encryption layer — Phase 4 PR6 で landed。 `EncryptedWriter` (Phase 1 `Writer` Protocol 実装) が新規 entry を行指向 AES-GCM (`MRAL` v1 wire format、 1 entry = 1 base64 行) で暗号化、 audit-log DEK は `wrap.wrap_dek` で wrap して header の `wdek` に格納 (平文 DEK はメモリのみ)。 per-entry AAD が header の SHA-256 を bind し cross-file splice を阻止。 `decrypt_log_file` は `wrap.unwrap_dek` (Secure Enclave authorization、 `keyvault.unwrap_authorized` emit) 経由で復号、 gzip rotated file も透過。 SPEC.md §"Encrypted audit-log wire format (`MRAL` v1)" で freeze。 24 log_encryption tests + 全 1279 mordred-hermes tests green、 ruff + format + `mypy --strict src` clean。 audit code 追加なし。 privacy_check の factory swap 結線と `audit decrypt` CLI は後続 (PR8)
- [x] Skill opt-in enforcement: Phase 1 で metadata read no-op だった `requires_keyvault: true` を Phase 4 で wired — **2026-05-16 完了** (§4.1)。 `evaluate_install` に `requires_keyvault` / `keyvault_initialized` 引数を追加 (strict=block `policy.strict.keyvault_uninitialized` / lenient=warn `policy.lenient.keyvault_uninitialized_warning` / off=allow)。 keyvault 初期化判定は backend-free probe `privacy_check/_keyvault_probe.py` (`meta.json` read のみ、 `keyvault._storage` を lazy import、 全 platform) で、 `install_wrapper.run` の `keyvault_probe` 経由で結線。 `requires_keyvault` 未宣言スキルでは probe を一切呼ばない。 network-level block は keyvault check より先に short-circuit。 reason enum freeze は 24→26 (POLICY.md §"Phase 4 §4.1 freeze")。 `policy_explainer` も同引数に対応。 1338 tests green、 ruff + format + `mypy --strict src` clean

### 4.2 Wizard additions (Phase 4)

> **Phase 4 PR8 完了** (2026-05-16): backend 不要の 3 CLI コマンドが landing。`hermes mordred {keyvault list, keyvault verify-digest, audit purge}` を実装。新規 `wizard/keyvault_cli.py` (`list_keys` / `verify_digest` + `cli_*` adapter) は `keyvault._storage` (pure stdlib) のみ import し `cryptography` / `NativeBackend` 非依存 — 全 platform で importable。`audit_cli.py` に `purge` を追加。残り 3 コマンド (`keyvault init` / `keyvault recover` / `audit decrypt`) は本番 Secure-Enclave `NativeBackend` (`_SecKeyBackend`) が未実装のため別 PR に deferred — stub handler は `NativeBackend` blocker を明記して `NotImplementedError` を raise。16 CLI tests + 全 1314 mordred-hermes tests green、ruff + `mypy --strict src` clean。

- [x] `hermes mordred keyvault init` (Seed Phrase + Passphrase + PoW 生成 flow、 network blackout assert → Seed display → offline/manual digest match) — **Phase 4 PR10 step-D 完了**。 `keyvault_cli.init_keyvault` + `TerminalSeedSurface`: re-init guard / 二重 Passphrase prompt / BIP39 生成 / seed-bound PoW / `prepare_generate` → `display_seed` → offline digest 確認 → `confirm_generate(*, backend=_SecKeyBackend())`。 audit-log wrapping key も provision (L465)
- [x] `hermes mordred keyvault list` (key IDs のみ、 key material 表示しない) — Phase 4 PR8 で landed。`keyvault_cli.list_keys` が `meta.json` の各 key の cleartext id / on-disk hash / `created_at` を表示、verification digest (key material) は出さない。空 / 未初期化 keyvault は rc 0
- [x] `hermes mordred keyvault verify-digest` — Phase 4 PR8 で landed。`keyvault_cli.verify_digest` が各 key の完全な 32-byte verification digest を hex 表示 (offline cross-check 用)。空 vault / `digests/<hash>.commit` 読取不可は rc 1
- [x] `hermes mordred keyvault recover --blob <path>` — **Phase 4 PR10 step-C 完了**。 `keyvault_cli.recover`: blob 読取 + Seed/Passphrase prompt + BIP39 checksum 先行検証 + seed-bound PoW 再計算 + `api.import_backup(*, backend=_SecKeyBackend())`。 `RecoveryDigestMismatch` / `BackupCorrupt` / `WrapError` を区別
- [x] `hermes mordred audit decrypt --date YYYY-MM-DD` (Secure Enclave authorization 必要) — **Phase 4 PR10 step-B 完了**。 `audit_cli.decrypt`: rotated `audit.log.<date>[.N][.gz]` + 当日 active log を `log_encryption.decrypt_log_file` → `unwrap_dek` → `backend.enclave_ecdh` で復号、 denied prompt / missing wrapping key / corrupt file を区別
- [x] `hermes mordred audit purge --before YYYY-MM-DD` (pre-Phase-4 plaintext log の手動削除; PATHS.md §Consumer CLI、 PLAN.md §Audit-log encryption coupling 参照) — Phase 4 PR8 で landed。`audit_cli.purge` が rotated `audit.log.<date>[.N][.gz]` のうち cutoff より厳密に前の日付のものを削除、active `audit.log` は touch しない、非日付 rotation file は無視、不正日付は rc 2

### 4.3 Tests (Phase 4)

- [x] `tests/test_digest.py`: fixed-vector tests for `top4(PoW)` extraction、 SPEC-example match — Phase 4 PR2 で `tests/test_keyvault_digest.py` として実装 (現状 20 tests passed)。 SPEC.md の固定 vector が canonical regression anchor、 XOR width / length confusion / constant-time compare 含む
- [x] `tests/test_backup.py`: backup/recovery roundtrip with mocked native binding — Phase 4 PR2 で `tests/test_keyvault_backup.py` (現状 43 tests) + `tests/test_keyvault_recovery.py` (現状 17 tests) として実装。 mocked native binding 部分は Phase 4 PR3 で `tests/test_keyvault_wrap.py` (FakeBackend) として landed
- [x] `tests/test_crypto.py`: AES-GCM encrypt/decrypt roundtrip + (GCM-layer) tag-verification failure — `tests/test_keyvault_crypto.py` で実装 (Phase 4 PR1 #21、 AES-128/192/256 roundtrip 網羅、 現状 16 tests)。 Secure Enclave wrap/unwrap failure は Phase 4 PR3 の `tests/test_keyvault_wrap.py` で別途カバー
- [x] `tests/test_keyvault_api_lifecycle.py` (現状 127 tests): `prepare_generate` / `confirm_generate` / `generate` lifecycle、 `SeedDisplayHandle` consume/wipe、 `keyvault.init_*` audit emit — Phase 4 PR4 (PR #26, #28) で landed
- [x] `tests/test_keyvault_api_envelope.py` (現状 67 tests): MREN envelope wire format encode/parse + cross-purpose replay 防御 — Phase 4 PR4 (PR #26) で landed
- [x] `tests/test_keyvault_api_storage.py` (現状 50 tests): managed storage の atomic write / `flock` / mode 検証 / meta roundtrip — Phase 4 PR4 (PR #27) で landed
- [x] `tests/test_keyvault_api_normalization.py` (現状 56 tests): BIP39 NFKD / casefold / whitespace normalization split — Phase 4 PR4 (PR #26) で landed
- [x] `tests/test_keyvault_wrap.py` (現状 67 tests) + `tests/test_keyvault_native.py` (現状 11 tests): Secure Enclave wrap/unwrap (FakeBackend = software P-256) + native capability probe — Phase 4 PR3 (PR #25) で landed
- [x] `tests/integration/test_keyvault_macos.py` (gated by `MORDRED_KEYVAULT_LIVE=1`、 macOS arm64/T2 only) — **PR9 + PR10 step-F 完了**: real Secure Enclave wrapping-key generate + DEK wrap/unwrap roundtrip + capability probe + idempotent delete を verify (gate ON かつ Enclave 不在時は fail、 SPEC HIGH-5)。 AES-GCM (`api.encrypt`/`decrypt`) roundtrip は **Phase 4 PR10 step-F で追加** (`test_encrypt_decrypt_roundtrip_through_real_enclave`、 generate → encrypt → decrypt を実 Enclave authorization 経由で verify)
- [x] `tests/integration/test_network_fallback.py`: `mordred_network` 不在時に `network_fallback` が OS API でblackout 判定 — **Phase 4 PR10 step-F 完了**。 `_import_network_api` seam を ImportError で差し替え、 OS-API fallback の isolated/reachable/fail-closed 経路 + network 存在時の delegation を verify
- [x] Cross-machine recovery test: export → off-by-one Passphrase → import_backup rejects → correct entry succeeds → decrypt — Phase 4 PR4 step-E `tests/test_keyvault_api_backup.py` で実装 (2 FakeBackend device + 2 home root で cross-machine roundtrip、 wrong-passphrase / wrong-seed は `RecoveryDigestMismatch`、 corrupt blob は `BackupCorrupt`、 digest mismatch は Enclave key 生成前に reject)

### Acceptance gate (Phase 4)

- [x] Skill declaring `requires_keyvault: true` blocks install if keyvault not initialized — **2026-05-16 完了** (§4.1)。 strict policy で keyvault 未初期化なら `install_wrapper.run` が `InstallBlocked` (`policy.strict.keyvault_uninitialized`) を raise、 audit entry を先に記録。 `tests/test_install_wrapper.py::TestRequiresKeyvault` + `tests/test_policy.py::TestEvaluateInstallKeyvault` で検証。 lenient=warn / off=allow も同時にカバー
- [x] Keyvault-protected secret encrypts/decrypts through AES-GCM、 DEK wrapped/unwrapped through Secure Enclave authorization — **PR10 完了**: `api.encrypt`/`decrypt` は PR4 で landing 済み、 PR10 step-F の `test_keyvault_macos.py::test_encrypt_decrypt_roundtrip_through_real_enclave` (`MORDRED_KEYVAULT_LIVE=1` gate) が実 Secure Enclave authorization 経由の roundtrip を verify
- [x] Backup → wipe → restore → decrypt roundtrip works — **PR4 step-E + PR10 step-C 完了**: api-level は `test_keyvault_api_backup.py` の cross-machine roundtrip、 CLI 結線は `keyvault_cli.recover` (`test_wizard_keyvault_cli.py::TestRecover::test_recover_roundtrip`)
- [x] Seed display always runs blackout check (api or fallback) first; refused on check failure — **PR7 + PR10 完了**: `display_seed` が `network_fallback.resolve_blackout_assert` を最初に呼び fail-closed で abort、 `keyvault init` CLI (`init_keyvault`) が `display_seed` を `BlackoutNotAsserted` 経路ごと wire (`TestInit::test_blackout_failure_returns_1`)
- [x] `import_backup` does not complete unless recomputed digest equals embedded digest — **PR4 + PR10 完了**: verify-before-decrypt は `recovery.import_backup`、 CLI 経路は `keyvault_cli.recover` が `RecoveryDigestMismatch` を rc 1 で surface (`TestRecover::test_wrong_passphrase_returns_1`)
- [x] In `mordred_network`-absent envs, `keyvault init` still functions via OS API fallback — **PR5 + PR10 完了**: `network_fallback.resolve_blackout_assert` の OS-API fallback、 `tests/integration/test_network_fallback.py` が `mordred_network` 不在を simulate して isolated/reachable/fail-closed を verify
- [x] After Phase 4 lands, audit log is AES-GCM encrypted (test by failing decryption with `openssl`) — **PR6 + PR10 step-E 完了**: `EncryptedWriter` / `decrypt_log_file` (`MRAL` v1) に加え、 `privacy_check.audit.make_audit_writer` factory が keyvault 初期化後に `EncryptedWriter` を選択 (`_runtime._load_state` 経由)。 `test_audit_factory.py` で初期化済み→暗号化 / 未初期化→NDJSON fail-open を verify

---

## Cross-cutting (運用フェーズで継続)

- [ ] Changelog: 各 PR で `### Changes` / `### Fixes` に 1-line entry + `Thanks @<author>`
- [x] ~~(v2) Hermes upstream の hook **payload field shape** drift を CI で監視~~ → **2026-06-12 実装済**: `mordred-hermes/tools/check_hook_payload_drift.py` (pure-`ast` で upstream の `invoke_hook("<name>", key=value, ...)` 全 dispatch site を走査、 import/install 不要) + 消費フィールド契約 `tools/hook_payload_contract.json` + `upstream-check.yml` の `Check hook payload field drift` step (drift 時は issue 本文に per-site 欠落フィールドを併記)。 `tests/test_hook_payload_drift.py` が contract キー ⇔ `register_hook` 呼出の完全一致を強制し、 canary が vendored fork へ同じ照合を毎 CI 実行
- [ ] (v2 検討) `[hard-lock]` extra (vendored fork、 Tier B) を導入する場合、 `mordred.degraded.disable_unprotected` 発生条件を再評価 (vendored fork が core-side で `--unlock` フラグを要求するため、 plugin-side fallback は redundant になる)
- [ ] リリース時に version bump — `python mordred-hermes/tools/bump_version.py <new>` で `__about__.py`(正準) + `mordred-docs/dev/VERSION` + 全 `plugin.yaml` を一括更新 (`0.1.0a0` → `0.1.0a1`/`0.1.0b0`/`0.1.0rc0` → `0.1.0` v1 GA 時 → `0.1.1` patch、 等。 すべて PEP 440 準拠)。`tests/test_packaging_versions.py` が 7 surface の一致と stub < real を CI で保証。pyproject に static `version` を手で戻さないこと (dynamic source が唯一の正準)
- [x] 旧 `mordred-mvp-docs/` (OpenClaw 基準) に deprecation marker を追加 (Phase E 完了後の cleanup task) — **2026-05-17 完了**: `../../mordred/mordred-mvp-docs/README.md` (本リポジトリ外、 L3 と同じ旧 docs ツリー) を新規作成 + 同ディレクトリ 12 個の `.md` (CI/PATHS/PLAN/ROADMAP/SPEC/TODO の md+ja.md、 UPSTREAM.md) 冒頭に deprecation note を挿入。 別ツリーのため本 PR の diff には現れない。 Phase E (upgrade Story 1.5) は L211 で完了済み
- [ ] (post-GA) `mordred-docs/` を topic 別 subdirectory (`strategy/` `spec/` `ops/` `hermes/` `dev/`) に再構成。 GA 前に追加する新規 doc は `HERMES_*.md` / `DEV_*.md` prefix で flat に配置し、 移行 PR で `git mv` + cross-reference 一括書き換え。 詳細は `ROADMAP.md` v2-X3
