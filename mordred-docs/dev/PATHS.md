# Mordred-Owned Filesystem Paths (Hermes-base)

> **Note**: 本ドキュメントは `Hermes` 基盤での Mordred 所有パスを定義します。OpenClaw 基準の旧版は `../../mordred/mordred-mvp-docs/PATHS.md` (deprecated) に残置。

All filesystem paths read or written by the Mordred distribution are isolated
under `~/.hermes/mordred/` (Hermes の `get_hermes_home()` 経由で profile-aware に解決)。
各 path には単一の owning plugin が存在し、他 plugin は内部 Python API か共有ファイル契約経由でのみアクセスする。

This document is the primary reference per TODO.md §0.3. After plugin
scaffolding (TODO.md §0.4), a summary of each entry is also duplicated into
the owning plugin's `README.md`.

## Overview

| Path                                  | Owner (phase)                     | Writer                        | Reader                            |
| ------------------------------------- | --------------------------------- | ----------------------------- | --------------------------------- |
| `~/.hermes/mordred/audit.log`         | `mordred_privacy_check` (Phase 1) | privacy_check (single writer) | wizard (`audit tail/grep`)        |
| `~/.hermes/mordred/policy.json`       | `mordred_privacy_check` (Phase 1) | `mordred_wizard`              | privacy_check, llm_guard, network |
| `~/.hermes/mordred/credentials/`      | `mordred_network` (Phase 3)       | `mordred_wizard`              | (現状なし — write-only)             |
| `~/.hermes/mordred/tor-data/`         | `mordred_network` (Phase 3)       | bundled `tor` process         | bundled `tor` process             |
| `~/.hermes/mordred/keyvault/`         | `mordred_keyvault` (Phase 4)      | keyvault (single writer)      | keyvault のみ                       |

Hermes config integration:

- `~/.hermes/config.yaml` の `plugins.mordred_*` セクションが canonical な policy 入力 (wizard が編集)
- `~/.hermes/.env` に Mordred 用の API キーを置く場合は `MORDRED_*` プレフィックスで統一

---

## `~/.hermes/mordred/audit.log`

**Owning plugin**: `mordred_privacy_check` (Phase 1)
**Purpose**: Access-controlled (mode `0600`)、 append-only auditable record of policy decisions, network-path switches, and keyvault operations.

> **H4 caveat**: v1 は **tamper-evident ではない**。 file mode `0600` は access control であって tamper detection ではない。 同一 UID で動く任意のプロセスが log を書き換えても痕跡は残らない。 tamper evidence (per-entry HMAC chain、 chain-key を keyvault DEK で wrap) は v2 で導入予定 (下記 §Tamper detection roadmap、 SPEC.md §Threat Model "does NOT defend against" 参照)。

### File contract

- **Format**: newline-delimited JSON (NDJSON). One line = one entry.
- **File mode**: `0600` (owner read/write only).
- **Rotation**:
  - Daily at UTC midnight to `audit.log.YYYY-MM-DD`.
  - Forced rotation when the current file reaches 10 MB.
  - Gzip-compressed after rotation (`audit.log.YYYY-MM-DD.gz`).
  - Deleted after 30 days.
- **Write exclusivity**: single-writer queue (in the Hermes process). Multi-process
  concurrency is explicitly out of scope for v1.
- **Encryption**:
  - Phase 1-3: plaintext (file mode `0600` is the only protection).
  - Post-Phase-4 new entries: AES-GCM encrypted with a keyvault-wrapped DEK,
    unwrapped via Secure Enclave authorization.
  - Existing logs written before Phase 4 stay plaintext until the user manually
    purges or re-encrypts (see TODO.md §4 DECIDE block and
    `hermes mordred audit purge --before YYYY-MM-DD`).

### Entry contract

Audit entries carry the following fields:

- `ts`: ISO 8601 UTC timestamp (例: `2026-04-29T12:34:56.000Z`)
- `event`: hook name (`pre_install` ラッパ呼び出し時 / `pre_tool_call` /
  `pre_llm_call` / `network_use` / `keyvault_*` / ...)
- `decision`: `allow` | `block` | `override` | `warn`
- `reason`: 固定 enum コード — canonical な完全リストは
  [`POLICY.md` §Audit log `reason` enum (frozen)](./POLICY.md) と
  `mordred-hermes/src/mordred_hermes/privacy_check/_audit_reasons.py:ReasonCode`
  (typed `Literal`、 mypy で drift 検知)。 Phase 1 step-0 freeze 以降、 Phase 2
  PR2 / Phase 3 PR1 / Phase 4 PR2 で incremental に追加 (16 codes Phase 1-3 +
  Phase 4 PR2 `keyvault.recovery_digest_mismatch` /
  `keyvault.seed_display_aborted_screenshot` を含む)
- `origin_skill?`: `{ id, version? }` — Hermes `pre_tool_call` payload に含まれている場合のみ
- arbitrary event-specific fields (`tool_name`, `provider_override`, `path`, ...)

### Writer layer

- Single-writer 実装は `plugins/mordred_privacy_check/audit.py` (Python)
- Writer 抽象は `class Writer(Protocol): def append(self, entry: dict) -> None: ...`
  - Phase 1: identity Writer (plaintext NDJSON)
  - Phase 4: factory swap to AES-GCM Writer in
    `plugins/mordred_keyvault/log_encryption.py`

### Consumer CLI

- `hermes mordred audit tail [-n N]` — show last N entries
- `hermes mordred audit grep <pattern>` — pattern match
- `hermes mordred audit decrypt --date YYYY-MM-DD` — Phase 4+, decrypts encrypted logs (Secure Enclave authorization required)
- `hermes mordred audit purge --before YYYY-MM-DD` — manual purge path for plaintext logs

### Tamper detection roadmap (v2)

v1 は tamper-evident ではない (上記 H4 caveat 参照)。 v2 で以下を追加予定:

- **Per-entry HMAC chain**: 各 NDJSON entry に `hmac` field を追加。 `hmac_n = HMAC-SHA256(chain_key, hmac_{n-1} || entry_n_canonical_json)`。 entry を後から書き換えると以降の HMAC が検証不能になる
- **Chain key の保護**: `chain_key` は Phase 4 keyvault の DEK で wrap し `~/.hermes/mordred/audit.chain.wrap` に保存。 Hermes process 起動時に Secure Enclave authorization で unwrap、 メモリ常駐
- **検証 CLI**: `hermes mordred audit verify [--from YYYY-MM-DD] [--to YYYY-MM-DD]` で chain を re-walk し anomaly を report
- **Phase 4 dependency**: chain_key の安全な保管が前提。 Phase 4 keyvault が macOS-only である間、 Linux/WSL2 ユーザは tamper-detection も get できない (master-password Tier 3 が来る `v2-OS2` まで)

実装は v2 で着手。 v1 では `0600` access control + Phase 4 audit log encryption (rewrite を 1 entry 単位で困難化) が暫定的な防御。

### Multi-process write contention (v1 limitation, M1)

`hermes mordred install <skill>` は wizard-CLI として **session process とは別プロセス** で audit entry を書く設計。 v1 は単一プロセスの in-process queue で serialize する前提なので、 別プロセスの write が並行した場合 NDJSON の interleave / 部分書き込みが起こりうる。

- **検出**: `hermes mordred audit verify` (v2) で line ごとの JSON parse を試み、 失敗行を `corrupted=true` で report
- **暫定対応 (v1)**: 各 writer が `os.O_APPEND` mode で open + 1 line ごとに `write()` 1 回 (POSIX `O_APPEND` の atomic guarantee に依存、 PIPE_BUF 4 KiB 以下なら interleave しない)。 entry が PIPE_BUF を超える稀ケースでは破損リスク残る
- **完全解決 (v2)**: Unix domain socket 経由の単一 daemon writer、 または `fcntl.flock` による排他ロック。 v2 で再評価
- **運用上の注意**: `hermes mordred install` 実行中は session process で並行 audit-emitting 動作 (大量の `pre_tool_call` 等) を避ける。 install は単発 / 短時間 op なので衝突確率は実用上低い

### Cross-references

- SPEC.md §Audit log policy
- PLAN.md §1.1 audit log format

---

## `~/.hermes/mordred/policy.json`

**Owning plugin**: `mordred_privacy_check` (Phase 1)
**Writer**: `mordred_wizard` (`hermes mordred configure` / `upgrade`)
**Readers**: `mordred_privacy_check` (cached in memory at `on_session_start`),
`mordred_llm_guard` (Phase 2), `mordred_network` (Phase 3)

### Purpose

Effective merged policy snapshot。canonical source は
`~/.hermes/config.yaml` の `plugins.mordred_*` セクション。
`policy.json` は wizard が書き出す debugable な mirror で一貫した shape を持つ。

### File contract

- **Format**: JSON (UTF-8, 2-space indent)。Not YAML (人手編集を想定しない、これは mirror 出力)
- **File mode**: `0600`
- **Write exclusivity**: wizard が単独 writer。privacy_check は read-only
- **Reload**: `hermes mordred policy reload` (内部関数呼び出し、 fs watcher は v1 で導入しない)
- **設定の正本**: `~/.hermes/config.yaml` の `plugins.mordred_*` セクションを wizard が `ruamel.yaml` round-trip で編集 (コメント・キー順を保持)。`policy.json` はその scrubbed snapshot

### Schema sketch (Phase 1)

```json
{
  "policy": "strict | lenient | off",
  "allow_cloud_llm": false,
  "cloud_provider_allowlist": [],
  "audit_log_path": "~/.hermes/mordred/audit.log",
  "local_llm_endpoint": "http://localhost:1234/v1",
  "local_llm_model_id": "...",
  "default_network_path": "tor | vpn | clearnet",
  "tor_binary_path": "...",
  "tor_socks_port": 9050,
  "tor_control_port": 9051,
  "mullvad_account_id_ref": "MORDRED_MULLVAD_ACCOUNT (env var ref, 値は ~/.hermes/.env から)",
  "mullvad_killswitch": true,
  "mullvad_relay_country": "auto",
  "no_proxy": ["localhost", "127.0.0.1", "::1"],
  "disable_ipv6": true,
  "provider_overrides": {}
}
```

Full schema reference は [`POLICY.md §\`plugins.mordred_privacy_check\` config schema`](./POLICY.md) を canonical source とする (Phase 1.1 / 2026-05-10 で landed)。 Phase 3 `disable_ipv6` 拡張 (2026-05-14) も同 doc §`policy.json` Phase 3 fields に追記済み。

### Defaults

- 新規 `configure` および既存環境 `upgrade` の default は `policy=lenient` (SPEC story 1; PLAN §1.1 configSchema)

### Consumer CLI

- `hermes mordred configure` / `upgrade` — writes
- `hermes mordred policy show` — display current values
- `hermes mordred policy explain <skill-id>` — explain decision for a skill
- `hermes mordred policy dry-run <skill-path>` — pre-install decision simulation
- `hermes mordred policy reload` — triggers in-process reload

### Cross-references

- PLAN.md §1.1 policy.json
- TODO.md §1.3 wizard plugin

---

## `~/.hermes/mordred/credentials/`

**Owning plugin**: `mordred_network` (Phase 3)
**Writer**: `mordred_wizard` (`hermes mordred configure` Phase 3 質問時)
**Readers**: 現状なし — このファイルは **write-only**。 `mordred_wizard` が書き出すが、 `network/` 配下のどのモジュールも `credentials/network.json` を読まない (`mordred_network` は Mullvad 設定を `policy.json` から読む — `network/__init__.py:270-276`)。 runtime reader は未実装で、 将来の Phase で wire される。

### Purpose

Phase 3 で必要な Mullvad アカウント番号、Tor binary path、 等の機密情報を保管。Phase 4 が利用可能になったら `mordred_keyvault` 経由で AES-GCM 暗号化に移行可能 (interface は `Writer` 抽象と類似のもの)。

### File contract

- **Directory mode**: `0700`
- **File mode**: `0600`
- **Phase 3**: plaintext JSON `~/.hermes/mordred/credentials/network.json`
- **Phase 4**: 同 path で encrypted (DEK は keyvault wrapping)
- **Alternative**: シンプルな機密 (例: Mullvad アカウント番号) は `~/.hermes/.env` に `MORDRED_MULLVAD_ACCOUNT=...` として置き、`policy.json` から env var ref で参照

### Schema sketch (v1、 Phase 3 PR3a / 2026-05-14 で確定)

実装は `wizard/credentials_writer.py::JSONCredentialsWriter` (canonical) — env-var REFERENCES only:

```json
{
  "mullvad": {
    "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
    "relay_country": "auto",
    "killswitch": true
  }
}
```

- 実 secret (16 桁アカウント番号) は `~/.hermes/.env` の `MORDRED_MULLVAD_ACCOUNT=...` (`wizard/env_file_writer.py::DotEnvFileWriter` が単独 writer、 mode `0600` / parent dir `0700`)
- `credentials/network.json` は env-var 参照のみ保持 (POLICY.md §Mullvad credential indirection 参照)。 secret 形 (大文字英数字 etc.) の値が書かれた場合 `JSONCredentialsWriter` が `ValueError` で reject
- Tor 関連の **設定値** (binary path、 SOCKS port、 control port) は **`policy.json`** 側に置き、 本 credentials/ には含めない (Phase 3 PR3a)。 Tor の data directory については、 *path 値* が config から参照されることはあっても、 ディレクトリ実体は Mordred 所有のファイルシステム位置であり、 本 doc の §`~/.hermes/mordred/tor-data/` に独立した owned path として記載する
- Phase 4 で `mordred_keyvault` 経由の AES-GCM 暗号化に移行可能だが、 上記 v1 fields は env-var ref / advisory 設定のみで secret material を含まないため、 移行優先度は低い

### Cross-references

- SPEC.md §Plugin: `mordred_network`
- POLICY.md §Mullvad credential indirection
- PLAN.md §3.2 wizard additions

---

## `~/.hermes/mordred/tor-data/`

**Owning plugin**: `mordred_network` (Phase 3)
**Writer**: bundled `tor` プロセス (Mordred が spawn する Tor サブプロセス)
**Readers**: bundled `tor` プロセス

### Purpose

`mordred_network` が起動する bundled Tor プロセスの DataDirectory。 Tor の `torrc` の `DataDirectory` ディレクティブにこのパスが渡され、 Tor 自身が consensus キャッシュ・鍵・状態ファイルをここに書き出す。 Mordred のコードはこのディレクトリの中身を直接 read/write しない — 所有はするが、 操作するのは Tor プロセスのみ。

### File contract

- **Path 値**: `RuntimeConfig.tor_data_dir`。 `network/__init__.py:130` で `HERMES_BASE / "mordred" / "tor-data"` として解決され (`network/runtime.py:99` が `RuntimeConfig` の default を定義)、 path bring-up 時に `network/runtime.py:441,468,480` で `render_torrc` / `TorHandle` に渡される
- **Created**: `mordred_network` が初めて Tor path を bring-up した時に Tor プロセスが作成する
- **Lifecycle**: Tor プロセスが管理。 Mordred は path 値の供給のみ担当

### Cross-references

- SPEC.md §Plugin: `mordred_network`
- PLAN.md §3.1 plugin: `mordred_network`

---

## `~/.hermes/mordred/keyvault/`

**Owning plugin**: `mordred_keyvault` (Phase 4)
**Writer**: keyvault plugin only (single writer)
**Readers**: keyvault plugin only。他 plugin は内部 Python API
`mordred_keyvault.api.{generate,encrypt,decrypt,export_backup,import_backup,verify_digest}`
経由でアクセス。

### Purpose

Local persistence of keyvault state:

- wrapping-key identifiers (handles into Secure Enclave)
- wrapped DEK ciphertext
- metadata (key-ID list, generation timestamps, initial digest commitment)
- backup export 用の temporary file (作成直後に削除)

**Important**: plaintext Seed Phrase / Passphrase / PoW / unwrapped DEK は
**never** disk persisted。memory のみ (Seed display は 60 秒で自動消去)。

### File contract

- **Directory mode**: `0700` (owner-only access)
- **Subordinate file mode**: `0600`
- **Created**: `mordred_keyvault.api.generate` 初回呼び出し時
- **Deleted**: ユーザが明示的に `hermes mordred keyvault reset` (TBD) を実行した時のみ
- **Encryption**: ディレクトリ内の wrapped DEK は Secure-Enclave-backed wrapping key で保護。Unwrap は `Security.framework` 経由のみ可能

### Expected substructure (Phase 4 PR4 step-0 freeze, 2026-05-15 — codex H3 / H4 corrected)

```
~/.hermes/mordred/keyvault/
├── .lock                                  # fcntl.flock target for write-side mutex (file mode 0600)
├── meta.json                              # {"version": 1, "keys": {"<key_id>": {...}}}
├── digests/
│   └── <key_id_hash_hex>.commit           # 32 bytes raw verification digest (mis-record evidence)
└── ciphertexts/
    └── <key_id_hash_hex>/
        └── <purpose_hash_hex>/
            └── <envelope_id>.gcm           # MREN envelope: 196+N bytes (per-ciphertext DEK)
```

- `key_id_hash_hex` = first 16 bytes of `SHA-256(key_id)` rendered as hex (32 chars). The cleartext `key_id` lives only inside `meta.json`, never as a path component (POLICY.md #19 "never the cleartext id" rule).
- `purpose_hash_hex` = first 16 bytes of `SHA-256(purpose)` rendered as hex.
- `envelope_id` = URL-safe base64 of 16 cryptographically-random bytes (~22 chars, no `/`, no `=`).
- File mode `0600` and directory mode `0700` are enforced on open via `os.open(path, O_NOFOLLOW)` + `fstat` mode check (symlink follow refused; mode mismatch raises `KeyvaultPermissionError`).
- All writes use atomic `<file>.tmp + fsync(tmp_fd) + os.replace + fsync(parent_dir_fd)` under `fcntl.flock(.lock)`.
- The pre-PR4 draft showed `keys/<keyId>.wrap`; that was the long-lived-DEK sketch. PR4 step-0 freezes the per-ciphertext DEK model (codex OD-1A) — each `.gcm` envelope embeds its own 127-byte MRKW wrap prefix. No standalone `keys/` directory in v1.

### Internal Python API (Phase 4 PR4 step-0 freeze, 2026-05-15)

Authoritative definitions live in SPEC.md §"PR4 API contract & MREN envelope wire format". Summary:

- `mordred_keyvault.api.prepare_generate(seed_phrase, passphrase, pow_bytes) -> (SeedDisplayHandle, expected_digest)` — in-memory only, no persistence
- `mordred_keyvault.api.confirm_generate(handle, user_confirmed_digest, *, key_id=None, ...) -> GenerateResult` — durable phase, rollback on failure (codex BLOCKER #2)
- `mordred_keyvault.api.generate(seed, passphrase, pow_bytes, expected_digest, *, ...) -> GenerateResult` — non-interactive convenience (tests / automation)
- `mordred_keyvault.api.encrypt(key_id, plaintext, purpose, *, ...) -> envelope_id` — managed storage; persists `.gcm` file
- `mordred_keyvault.api.decrypt(key_id, envelope_id, purpose, *, ...) -> bytes` — caller-supplied `purpose` required (cross-purpose replay defense, codex HIGH #2)
- `mordred_keyvault.api.export_backup(key_id, passphrase, *, ...) -> bytes` — full ciphertext-rewrap manifest (codex BLOCKER #1)
- `mordred_keyvault.api.import_backup(blob, passphrase, *, seed_phrase, pow_bytes, ...) -> str` — verify digest → decrypt manifest → re-wrap each DEK
- `mordred_keyvault.api.verify_digest(seed, passphrase, pow_bytes, *, expected) -> None` — split normalization applied

### Consumer CLI

- `hermes mordred keyvault init` / `list` / `verify-digest` / `recover --blob <path>`

### Pre-Phase-4 behavior

- Phase 1-3 では `~/.hermes/mordred/keyvault/` は **作成されない**
- `mordred_privacy_check` の skill install ガードは Phase 1 で `metadata.mordred.requires_keyvault: true` を decision record にパースするが、enforcement は Phase 4 で wired (TODO.md §1.1)

### Cross-references

- SPEC.md §Plugin: `mordred_keyvault`
- PLAN.md §4.1 plugin: `mordred_keyvault`
- TODO.md §4.1 `mordred_keyvault` plugin

---

## OpenClaw 旧パスからの migration

`hermes mordred upgrade` は OpenClaw 時代の `~/.openclaw/mordred/` を検出した場合、以下のように移行する (Story 1.5)。 各エントリは衝突解決ポリシー (H5) を明示する:

| 旧パス (OpenClaw) | 新パス (Hermes) | 処理 | 衝突時の動作 (H5) |
|-------------------|-------------------|------|-------------------|
| `~/.openclaw/mordred/audit.log` | `~/.hermes/mordred/audit.log` | append (旧 entries → 新 file 末尾)、 旧パスは保持しユーザが手動削除 | **append-by-timestamp-window**: 新 file が空 or 最古 `ts` が旧 file の最新 `ts` より新しい場合のみ append、 範囲が overlap する場合は abort し `--audit-merge=skip\|append-all\|abort` の明示指定を要求。 default は abort (再度 upgrade を防ぐため、 idempotent rerun は marker file `~/.hermes/mordred/.audit-migrated-from-openclaw` で skip 判定) |
| `~/.openclaw/mordred/policy.json` | `~/.hermes/mordred/policy.json` + `~/.hermes/config.yaml` の `plugins.mordred_*` | 値を re-shape して書き込み | **diff + prompt** (Story 1 と同じ)、 `--reset` で強制上書き、 batch / CI 環境では `--policy-conflict=keep-existing\|overwrite\|abort` を明示指定 (default abort) |
| `~/.openclaw/mordred/keyvault/` | `~/.hermes/mordred/keyvault/` | コピー (Phase 4 のみ。Secure Enclave wrapping key は同 machine ならそのまま使える、別 machine の場合は `import_backup` 経由) | **never overwrite**: 新 path が既に存在する場合は abort (key material の上書きは破壊的)、 ユーザが手動で旧 key の `export_backup` → 新 machine `import_backup` フローを取る必要あり |
| `~/.openclaw/credentials/mordred-network.json` | `~/.hermes/mordred/credentials/network.json` | コピー、必要に応じて env var 参照に分解 | **never overwrite**: 新 path 既存時は abort、 マニュアル merge を要求 |
| `~/.openclaw/openclaw.json` の `plugins.entries.mordred-*.config` | `~/.hermes/config.yaml` の `plugins.mordred_*` | JSON5→YAML 変換、コメント保持 (`ruamel.yaml`) | **diff + prompt** (Story 1 と同じ)、 `--reset` で強制上書き、 batch では `--policy-conflict` フラグ |

**Idempotency contract (H5)**: `hermes mordred upgrade` を 2 回目に実行した時、 marker file `~/.hermes/mordred/.audit-migrated-from-openclaw` (1 回目に書かれる) が存在する場合は audit migration を skip する (no-op)。 これで同じ entries の重複 append を防ぐ。 ユーザが意図的に再実行したい場合は marker を削除するか `--reset --audit-merge=append-all` を指定。

`--reset` フラグはすべての conflict-policy を `overwrite` で強制上書き (破壊的、 旧データは削除される)。 CI / 自動化環境では interactive prompt が出ない非対話モードを `--non-interactive` で要求し、 conflict-policy フラグが未指定なら fail-fast。

---

## Access boundary discipline

- Mordred plugins は他の plugin が own する path を **直接 read/write しない**。常に内部 Python API (`mordred_network.api.*`, `mordred_keyvault.api.*` 等) または共有ファイル契約 (例: wizard が audit.log を `audit tail` 経由で読む、書いているのは privacy_check) を経由する
- Hermes core (`agent/`, `hermes_cli/`, `gateway/` 等) は Mordred-owned path を一切参照しない (zero-PR commitment、 `MIGRATION.md` §5)。 v2 で hard-enforce が必要になり vendored fork extra (`mordred-hermes[hard-lock]`、 `vendor/hermes/<version>/`) を導入した場合でも、 patch 範囲は Hermes 既存モジュールの局所変更にとどめ、 Mordred-specific id・default・recovery policy は core (vendored モジュール含む) に入れず plugin 側に保持する
- 各 plugin の `README.md` で own する path / 内部 API を明記する責務がある (TODO.md §0.4 plugin scaffold)
