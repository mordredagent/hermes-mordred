# Mordred Roadmap (post-v1, Hermes-base)

> **Note**: 本 ROADMAP は `Hermes (NousResearch/hermes-agent)` 基盤での post-v1 ワークを記述します。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/ROADMAP.md` (deprecated) に残置。

このドキュメントは **MVP (v1) の外** にある仕事を記述する。`SPEC.md` と `PLAN.md` が v1 のロックされたスコープを定義する。本ファイルは「v1 から繰り延べた事項」と「明示的に永久に行わない事項」を集約する。

SPEC/PLAN より頻繁に更新される想定。優先順位と順序は流動的。

## Legend

- **Priority**: H = v1 ship 直後に着手 / M = ユーザフィードバック後に判断 / L = 長期
- **Depends on**: 必要な Hermes hook seam、 OS API、 外部ライブラリ
- **Risk**: エンジニアリングまたは契約上の懸念

---

## Known gap: Browser-extension gateway counterpart (deferred)

- **Background**: while still part of `Mordred-Hermes-monorepo`, #204 (`feat(mordred): browser-extension WebSocket API + localhost web app`) shipped `gateway/extension_api.py` / `extension_pairing.py` / `extension_crypto.py` / `extension_chat.py` / `extension_rpc.py` / `extension_history.py` (a repo-root top-level `gateway/` package on the Hermes-fork side — a core change) together with `src/mordred_hermes/keyvault/extension_sign.py` / `wizard/extension_pair_cli.py` (the plugin side). The 2026-06-30/07-01 standalone-repo split left the `gateway/` side in the monorepo; only the two plugin-side files came to this repo
- **Current state**: `hermes mordred extension pair` fails closed (exit code 2, clear stderr message) because `gateway.extension_pairing` can't be imported. `keyvault/extension_sign.py` doesn't depend on `gateway` so it imports fine, but its caller (the gateway-side WebSocket server) isn't in this repo's dependency closure, so it's unreachable. The original commit's "36 tests" weren't copied into this repo either
- **Plan going forward**: the `gateway/`-side implementation (including starting the WebSocket server) is **planned to be added later** (confirmed with the operator, 2026-07-01). Until then, the two plugin-side files stay "unused but fail safely"
- **Checklist for when work resumes**:
  - Decide how `gateway/extension_*.py` will be distributed (a separate repo declared as an explicit `pip install` dependency / folded into a vendored-fork `[hard-lock]`-style extra / other). Re-check alignment with the zero-PR/plugin-only principle (`PLAN.md` §Boundary discipline)
  - Decide whether to port the 36 tests from `tests/extension/` into this repo or keep them in whichever repo hosts the dependency
  - Confirm the `ethereum` / `messaging` extras in `pyproject.toml` (already extended on 2026-07-01 with `eth-account`/`rlp`/`qrcode`) are still sufficient once implementation resumes
- **Priority**: M (explicitly deferred pending the operator's own timeline; until then, only the fail-closed behavior needs to be maintained)

---

## v2 candidates: Hermes hook 拡張 (PR 候補)

旧 SPEC が "Core minimal seams" として列挙していた項目を、 Hermes での拡張ポイントとして再評価。`MIGRATION.md` §2 のマッピング表に対応。

### v2-H1: Skill install hook

- **Motivation**: v1 では `hermes mordred install <skill>` ラッパ CLI 経由でしか policy 強制できない。ユーザが直接 `hermes skills install <skill>` を実行すると bypass される
- **Depends on**: Hermes core の `hermes_cli/skills_hub.py` に `pre_skill_install` / `post_skill_install` hook を新設する PR
- **Scope**: Mordred plugin が install hook で frontmatter parse → policy 評価 → block/allow を return
- **Risk**: PR レビュー遅延が plugin の install path 統一を遅らせる
- **Priority**: H (v1 で wrapper 経由が判明している UX gap を埋める)

### v2-H2: `pre_tool_call` payload に `origin_skill` 追加

- **Motivation**: v1 の `pre_tool_call` payload に skill 所有者情報が無く、 per-skill 単位の tool 制御ができない (generic tool-name allowlist のみ)
- **Depends on**: Hermes core で skill 経由の tool dispatch path を辿り `origin_skill` を payload に追加する PR
- **Scope**: Mordred `mordred_privacy_check` が per-skill ポリシーを実装可能に
- **Risk**: skill から外で発火する tool call (例: gateway 直接) では `origin_skill=None` のまま
- **Priority**: M

### v2-H3: `pre_llm_call` payload に `provider_id` / `model_id` 追加

- **Motivation**: v1 の `pre_llm_call` payload に provider/model 情報が含まれていない場合、 strict mode は unconditional override にしかならない (cloud allow-list passthrough 不可)
- **Depends on**: Hermes Phase 0.8 verify で「既に payload に含まれている」確認済み or PR が必要、 のいずれか
- **Scope**: cloud allow-list passthrough を degraded mode から normal mode に格上げ
- **Priority**: H (privacy 製品としての中核機能)

### v2-H4: Plugin loader の hook priority 制御

- **Motivation**: v1 strict-mode bootstrap order (network → privacy_check) を保証するため、 plugin 内で polling fallback を使っている。理想的には登録時に priority を declare したい
- **Depends on**: Hermes `register_hook(name, callback, priority: int = 0)` API 拡張 PR
- **Scope**: Mordred plugin が priority=100 / priority=50 で順序を保証
- **Priority**: M

---

## v2 candidates: OS integration (largest defense expansion)

Plugin SDK では到達できない領域。Native binding / OS-level 統合が必要。

### v2-OS1: Local malware / co-resident process mitigations

- **Motivation**: v1 threat model から明示的に除外した最大の gap。`HTTPS_PROXY` injection は同 machine の任意 process が direct `connect()` で bypass 可能
- **Depends on**: macOS — `sandbox-exec` profiles / Endpoint Security Framework。Linux — `seccomp` / `landlock`. Windows — AppContainer
- **Scope**: Hermes が spawn する skill 子プロセスを OS sandbox 配下で実行。Network / file / process spawn を制限
- **Risk**: 不適切な profile で legitimate skill が壊れる。Apple Endpoint Security は entitlement review 必要
- **Priority**: H (privacy ツールとしての credibility に直接結びつく)

### v2-OS2: Linux / Windows / Intel-Mac での keyvault

- **Motivation**: v1 Phase 4 は Apple Silicon + Secure Enclave 限定 (macOS only)
- **Depends on**:
  - Linux: `libsecret` / GNOME Keyring / KWallet backend, または HSM (TPM 2.0)
  - Windows: DPAPI / TPM、 または WSL 内実行
  - Intel-Mac: Keychain (no Secure Enclave) fallback
- **Scope**: `mordred_keyvault` backend abstraction、 OS-specific Tor/VPN client implementations for `mordred_network`
- **Priority**: M (macOS で価値を validate してから判断)
- **Status (2026-06-09)**: Linux TPM 2.0 = **MVP 完了**。 Phase 1 (platform-neutral seam) + Phase 2a (`native/tpmkey-helper` Rust crate 純粋層) + Phase 2b (`src/tpm.rs` の `tss-esapi` バックエンド: deterministic ECC P-256 storage primary が ECDH 子鍵を wrap、 `ECDH_ZGen` で on-chip 鍵共有、 `swtpm` で検証する `tpmkey-helper-tpm` CI job、 software P-256 との ECDH parity テストで `wrap.py` HKDF 互換を実証) + Phase 2c (`keyvault enable-tpm` CLI + wheel packaging) すべて landed。 Tier 2 = machine-bound、 Touch ID 非等価で per-use presence gate 無し (PIN/PCR prompt は deferred follow-up; SPEC §Protection-tier hierarchy 参照)

---

## v2 candidates: feature expansion

既存 plugin の粒度・カバレッジを増やす。

### v2-F1: Per-skill independent network paths

- **Motivation**: v1 は gateway 全体 single state (last-write-wins)。並行する skill が意図しない path で request を出す
- **Depends on**: v2-H2 (`origin_skill` in `pre_tool_call`) + Hermes child process spawn API で per-subprocess proxy env vars 注入
- **Scope**: `mordred_network` が skill 毎に path 切替、 skill metadata 宣言通りに enforce
- **Priority**: M

### v2-F2: Skill metadata signing / integrity verification

- **Motivation**: v1 は「メタデータが嘘をつく skill」を防御できない (threat model から除外)
- **Depends on**: agentskills.io / Skills Hub 側の signing chain、 ローカル公開鍵管理、 Hermes core に signature-verification hook を追加する PR (永久 out-of-scope ライン近接につき要レビュー)
- **Scope**: skill `frontmatter` のハッシュ + publisher signature; `mordred_privacy_check` が install 時に検証
- **Risk**: mandatory signing は core loader 改変寄りで永久 out-of-scope ラインに近接。**Plugin SDK 内に収める設計を維持**
- **Priority**: M

### v2-F3: GUI controls

- **Motivation**: v1 は CLI のみ。policy 切替・path status・audit log review の UX が弱い
- **Depends on**: 特に無し (Tauri / Electron / SwiftUI 選択)
- **Scope**: status-bar app または専用 GUI; gateway 内部 RPC over thin client
- **Priority**: L

### v2-F4: Tamper-resistant audit logs

- **Motivation**: v1 audit logs は plaintext file; local malware threat 下で改竄可能
- **Depends on**: 特に無し (plugin 内完結)
- **Scope**: hash chain (各 entry が前 entry の hash を含む) または append-only file format
- **Priority**: M

### v2-F5: Multi-user / multi-tenant

- **Motivation**: v1 は単一 user / 単一 machine 想定
- **Depends on**: 設定スキーマの大幅拡張、 keyvault user isolation
- **Priority**: L (個人開発者ターゲットには不要)

### v2-F6: Trace-minimization layer (binary / folder / file-name encryption)

- **Motivation**: 法的・フォレンジック耐性のため、 「ユーザがいつ何の skill を実行したか」の plaintext 痕跡をディスクに残さない。Phase 4 audit-log encryption は audit log の **内容** のみ保護、 file 名・folder 構造・binary は plaintext のまま
- **Depends on**: `mordred_keyvault` Tier 1 完了; plugin-owned overlay で実装可能か、 Hermes に additive seam が必要かの調査
- **Scope**:
  - skill artifact (binaries, subdirectories) を keyvault-wrapped DEK で file/folder 名レベルで暗号化、 利用時のみ decrypt + mount (Plugin SDK が許す範囲で)
  - `mordred_keyvault` が per-skill file-encryption mapping table を own
  - decrypted path はメモリのみ; cleartext form をファイルシステムに書き戻さない (FUSE-T or macOS FileProvider を検討)
- **Risk**: loader-level 改変寄り、 永久 out-of-scope ライン近接。Plugin SDK 内設計または明示的なソフトフォーク戦略レビュー後に着手。OS-level transparent-FS facility (FileProvider, FUSE-T 等) の選定が必要
- **Priority**: M (脅威モデルが要求すれば H へ昇格 — 例: ジャーナリスト / アクティビスト用途が具体化)

### v2-F7: Seed-display PC↔phone pairing UI

- **Motivation**: v1 `mordred_keyvault` は Passphrase entry を phone 経由 (QR + mDNS + self-signed-TLS localhost pairing) で分離する設計。これは設計レベルの safety 要件だが、 実装が Phase 4 budget を約 1 週間圧迫するため defer
- **Depends on**: `mordred_keyvault` Tier 1 完了; phone-side UI (PWA / native SwiftUI / Android Compose) 選定
- **Scope**:
  - PC 側: localhost HTTPS server (self-signed TLS、 mDNS advertisement、 LAN-only listener)
  - Phone 側: QR scan → Passphrase 入力 → digest half submit
  - Pairing session は single-use & 5-minute timeout
- **Risk**: phone 側 self-signed TLS UX (Safari/Chrome cert warning); mDNS name collision; LAN 内 MITM 防御 (PoW + pairing-ID confirmation)
- **Priority**: M (v1 degraded flow は両 half を PC 表示するため UX-level safety 約束を弱める; 早期昇格候補)

### v2-F8: `config.yaml` at-rest 透過復号

- **Motivation**: `~/.hermes/config.yaml` を vault に格納し起動時に透過復号する (at-rest 暗号化を `.env` / agent memory と同列に config へ拡張)。 `.env` 面 (`keyvault/_runtime_env.py`) と agent memory 面 (`vault set-memory-key`) は v1 で完了済み — config.yaml 面も **PR #86 で着地 (opt-in、 2026-06-03)**。
- **v1 で延期した理由**:
  - **低価値**: 秘密は環境変数経由 (`.env` → `os.environ`、 `hermes_cli.config.get_env_value`) で供給される設計で、 `config.yaml` は**設定専用**。 各 provider の `api_key` 既定は `""` で、 未設定なら `OPENAI_API_KEY` 等の env var にフォールバックする (`hermes_cli/config.py`)。 実機の `config.yaml` にも秘密は無い。 守る対象が薄い。
  - **構造的ブロッカー (高コスト)**: `config.yaml` は単一の正規ローダ `hermes_cli/config.py:load_config()` (mtime/size キャッシュ付き) を持つが、 `cli.py` (module import 時 `CLI_CONFIG = load_cli_config()`) / `hermes_logging.py` / `hermes_time.py` / `rl_cli.py` が **import 時 (= plugin ロード前) に直接 `yaml.safe_load`** で読む。 plugin の `register()` はこれらの後に走り、 **pre-config-load hook も存在しない**。 よって `.env` のような register() 時点の shim では透過復号が間に合わない (`.env` は遅延消費なので間に合う)。
- **Depends on**: 次のいずれか —
  - (a) Hermes core に pre-config-load の復号 seam を追加 (vendored fork **Tier B**、 `UPSTREAM.md §Tier B`)。 **zero-PR / plugin-only commitment を破る**。
  - (b) interpreter 起動時に割り込む `sitecustomize` / `.pth` 機構。 plugin-only を保てるが起動経路への侵襲が大きく、 想定外の副作用リスクが高い。
- **Risk**: (a) は plugin-only 方針を破る意思決定が必要。 (b) は heavy・surprising な機構で全 interpreter 起動に影響。
- **Priority**: L → **着地済み (opt-in、 デフォルト有効化はしないと決定)**。 秘密は env / vault `.env` 側で既にカバー済みのため defense-in-depth。 デフォルト有効化の判断は 2026-06-03 にクローズ — opt-in (`enable-config-decrypt`) を恒久設計とする (下記 Decision 参照)。
- **Status (2026-06-03): mechanism (b) を作り直して着地 — PR #86 マージ済み (commit `a16e97102`)**。 初版 PR #85 はレビューでクローズしたが、 ガードを入れた改訂版を **PR #86 でマージ**。 `.pth` 起動フック (`keyvault/_config_bootstrap.py` / `_pth_bootstrap.py` / `wizard/config_decrypt_cli.py`) が import 時 eager read の**前**に走り、 #85 の各ブロッカーを解消:
  - **narrow engage / supply-chain**: site-packages root に force-include する `.pth` は 1 行のインラインガードを持ち、 `hermes` / `hermes-mordred` の console script 起動 (または `MORDRED_CONFIG_DECRYPT=1`) の時**だけ** `_pth_bootstrap` を import する。 pytest / pip / 素の REPL / 名前が "hermes" なだけの venv は一切触らず、 device 鍵ストアも probe しない。
  - **`python -m hermes_cli`**: **site 初期化時は非対応** — `.pth` が走る時点で `sys.argv[0]` はまだ `'-m'` (runpy の解決はその後) なので `_looks_like_hermes` は false を返し engage しない。 console script で起動するか、 `-m` 起動には `MORDRED_CONFIG_DECRYPT=1` を使う。 (`/hermes_cli/` パス分岐は実 `-m` 起動では生成されず、明示的に argv を渡した時だけ一致。)
  - **profile**: home は `hermes_home()` で解決され、 尊重するのは `HERMES_HOME` **のみ** (非デフォルトの sticky な `active_profile` は警告を出すだけで `~/.hermes` を返す; 一過性の `-p/--profile` も site 初期化時に不可視)。 opt-in marker は home 毎なので未管理 home は clean な no-op — 非デフォルト profile の `config.yaml` をフック対象にするには `HERMES_HOME` を export する。
  - **同時実行**: `reseal_config` は `unlink(missing_ok=True)` で slow-open の TOCTOU 窓を塞ぎ、 vault open 失敗時は平文を残す。 次回 `materialize_config` が残った平文を再同期して self-heal (disk-wins)。
  - **fail-closed**: engage した Hermes プロセスは復号エラー時にデフォルト/古い config で起動せず `SystemExit(1)` で中断。 manifest が残るのに anchor 不在ならアンカー削除とみなし拒否。
  - **opt-in ライフサイクル** (console script は現状 `hermes-mordred …`; `hermes mordred …` は Hermes 0.12+ の entry-point CLI 配線後に動く): `hermes-mordred vault enable-config-decrypt` が `<home>/config.yaml` を enroll し、 clean enroll 後にのみ marker (`<home>/mordred/config-vault.marker`) を書く。 `disable-config-decrypt` は marker を消し可読な平文を保証 (封印されていれば vault コピーを復元)。 リカバリ脱出ハッチ: `MORDRED_CONFIG_DECRYPT=0 hermes-mordred vault disable-config-decrypt` でフックを bypass (disable が自分の外そうとするフックにブロックされない)。
  - **トレードオフ**: 管理下プロセス稼働中は平文 `config.yaml` がディスク上に存在 (mode `0o600`、 `.env` のメモリのみ注入より弱い) — Hermes core 改変なしで eager direct reader を支える代償。 そもそも `config.yaml` は設計上 secret を持たない (`api_key` 既定 `""` → `.env` フォールバック) ため defense-in-depth。
  - **Decision (2026-06-03): デフォルト有効化はしない — opt-in を恒久設計とする**。 根拠の非対称性: `config.yaml` は設計上 secret を持たず (`api_key` 既定 `""` → `.env` フォールバック)、 load-bearing な at-rest 面 (`.env` / agent memory) は既に暗号化済み。 一方デフォルト ON は「復号失敗時の `SystemExit(1)` 起動中止 + 管理中のディスク平文 + auto-exec `.pth` の supply-chain surprise (PR #85 でスキャナが flag した懸念)」を、 暗号化を要求していない**全ユーザ**に課す。 secret の無いファイルのためにこの代償は見合わない。 よって `hermes-mordred vault enable-config-decrypt` での明示 opt-in を維持する。 高脅威ユーザ向けの「痕跡を残さない」要求は v2-F6 (trace-minimization) で別途扱う方が筋が良い。
  - **e2e 済み (2026-06-03) → v2-F8 完了**: Apple Silicon SE 実機で config.yaml ライフサイクル (init→enable→reseal→materialize→disable + fail-closed) を実 Enclave 経由で通し検証。 `tests/integration/test_keyvault_macos.py` に live ゲートテスト 2 本追加 (`MORDRED_KEYVAULT_LIVE=1`、 `MORDRED_SEKEY_UNATTENDED=1` で Touch ID なし、 4/4 pass)。 現状 opt-in (dev venv では未有効)、 カバレッジ 98%。

---

## v3+ candidates: Payment layer

Mordred 存在理由のもう半分。v2 安定後に着手する大型作業。

### v3-P1: Payment skills

- **Motivation**: v1 `mordred_keyvault` は seed/payment secrets を Enclave-authorized AES key wrapping で at-rest 保護する。Crypto-payment や smart-contract skill が安全に提供されるには、 runtime signing isolation が追加で必要
- **Depends on**: v1 Phase 4 (`mordred_keyvault`) 完了、 v2-OS1 (process sandbox) 完了、 dedicated signing backend 設計。3 つすべてが揃わないと「ローカルで decrypt するが silently cloud 送信」path が空く
- **Scope**: signing JSON-RPC、 transaction assembly、 gas estimation、 pre-signature preview UI、 transaction safeguard policy
- **Risk**: Web3 skill 開発者が大事故を起こす可能性。Spec で fund 誤送信時の責任分界を明示する必要
- **Priority**: H (Mordred の差別化要因)

### v3-P2: x402 / agent payment protocol integration

- **Motivation**: AI agent が API charge を直接精算する path。Mordred keyvault と自然にペア
- **Depends on**: v3-P1
- **Priority**: M

---

## v2+ candidates: miscellaneous

### v2-X1: Mordred-branded mobile apps

- **Motivation**: Hermes は Termux 対応のみ; Mordred のための専用 mobile UI 無し
- **Scope**: PWA または native iOS/Android (Phase 4 keyvault との連携前提なら macOS Apple Silicon limited のままになる)
- **Priority**: L

### v2-X2: Mordred-specific telemetry / crash reporting

- **Motivation**: v1 は Hermes 既存 telemetry 動作を継承
- **Risk**: privacy ツールが telemetry を送るのは矛盾。**送信先と収集フィールドを完全にユーザ制御下に置く**
- **Priority**: L (議論優先)

### v2-X3: Documentation reorganization — DONE (2026-06-25, ahead of GA)

- **Status**: 完了。当初は GA 後に予定していたが、`.ja.md` companion track 廃止に合わせて前倒しで実施。
- **Motivation**: `docs/` が flat に肥大化。 docs を読者別に再構成したい。
- **実施した形 (当初案から変更)**: topic 別 (`strategy/` / `spec/` / `ops/`) ではなく **読者別の2分割**を採用 —
  - [`user/`](../user/): 運用者向け (QUICKSTART, USAGE)
  - [`dev/`](./): 開発者・プロジェクト docs (SPEC, KEYVAULT_BACKENDS, SECRETS_ENV_ENCRYPTION, PLAN, TODO, PATHS, POLICY, HARNESS_PRIVACY, HOOK_PAYLOADS, MIGRATION, UPSTREAM, CI, ROADMAP, setup, VERSION)
  - [`dev/hermes/`](./hermes/): Hermes upstream リファレンス (DESIGN, STRUCTURE)
- **移行**: 全ファイルを `git mv` で移送 (履歴保持)、 リポジトリ全体の cross-reference (~50 箇所: src docstring / tests / CI path-trigger / 各 README / `pyproject.toml` Documentation URL) を一括更新、 `docs/README.md` 索引を user/dev 構成へ書き換え。
- **Priority**: L (non-functional) — 完了済み。

---

## Forever out of scope

Mordred が **行わない** 項目。soft-fork / plugin-only 戦略を破壊するため。

- **Hermes core への大規模変更 + Hermes 上流への PR**
  zero-PR commitment (`MIGRATION.md` §5、 2026-05-07): Hermes 上流への PR は **一切提出しない**。 v1 default は plugin-only (Tier A、 wrapper CLI + audit log + strict-mode startup refusal)、 hard-enforce が真に必要になった項目のみ v2 で vendored fork extra (`mordred-hermes[hard-lock]`、 Tier B) で対応。 Mordred-specific id・default・recovery policy は core (vendored モジュール含む) に入れず、 plugin 側で保持する
- **Loader / registry 動作変更**
  - 強制 skill signing (loader-enforced)
  - Hermes-specific id (`mordred-*`) への core からの参照
  - Top-level `mordred:` 設定キー (Hermes config に top-level セクション追加しない)
  - Provider-resolution pipeline の rewrite (v2-H3 は payload 拡張のみ)
- **CLI 名の変更**
  `hermes mordred ...` を維持。`hermes-mordred` のような独立 CLI を作らない (Hermes ユーザの操作慣習を壊さない)
- **Metadata namespace の競合**
  `metadata.mordred.*` のみ使用; `metadata.hermes.*` や agentskills.io 標準キーを書き換えない
- **OpenClaw upstream への follow-up**
  OpenClaw からは完全に分離 (`hermes claw migrate` 経由で Hermes に来たユーザ向けにのみ Story 1.5 で migration 補助を提供するが、 OpenClaw 自体への PR / 同期は行わない)

---

## Update rules for this document

- v1 ship 前: SPEC/PLAN finalize 時に「defer」と判断された項目をここに移す
- v1 ship 後: ユーザフィードバックを元に priority (H/M/L) を再評価
- v2 着手時: ROADMAP 項目を SPEC/PLAN に promote
- "forever out of scope" に項目を追加する時: 理由を本文に必ず含める (「やらない」だけでは不十分)
