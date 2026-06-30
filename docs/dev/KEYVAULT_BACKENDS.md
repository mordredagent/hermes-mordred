# Mordred — Keyvault バックエンド設計と Secure Enclave 署名制約 (Hermes-base)

> **Note**: 本ドキュメントは `mordred_keyvault` の **鍵保護バックエンド** の設計検討と、 macOS Secure Enclave (SE) の **コード署名要件に関する実機検証結果** を記録する。 専門用語 (entitlement・`kSec*`・OSStatus・CLI) は英語、 説明は日本語の構成。
>
> 関連: [`SPEC.md`](./SPEC.md) §Platform Support / §Threat Model、 [`ROADMAP.md`](./ROADMAP.md) v2-OS2、 keyvault 実装は `src/mordred_hermes/keyvault/`。

---

> **⚠️ 訂正 (2026-06-01) — 「SE には有料 Developer ID が必須」という本ドキュメントの結論は _Keychain 永続化_ 経路に限った話で、 出荷した live 経路では超克済み**:
>
> §2–§4 / §7 の検証と結論はすべて **SE 鍵を Keychain に永続化する** 経路 (`SecKeyCreateRandomKey` + `kSecAttrIsPermanent`、 `keychain-access-groups` entitlement) を対象にしたもので、 この経路は **放棄** した。 出荷した live SE 経路は Keychain を一切使わず、 helper `mordred-hermes-sekey` が **CryptoKit `SecureEnclave.P256` の `dataRepresentation` blob を平文ファイルに保存** する。 そのため **ad-hoc `codesign --sign -` だけで本物のハードウェア SE が動く — entitlement・provisioning profile・有料 Apple Developer Program すべて不要** (`dataRepresentation` blob はデバイス束縛で他マシンでは無意味)。
>
> **有効化は 1 コマンド**: `hermes mordred keyvault enable-se` が `native/sekey-helper/build.sh` を呼んで build → ad-hoc 署名 → `~/.local/bin` install → SE probe を実行し、 成功すると keyvault の wrapping key を software P-256 fallback から **ハードウェア SE** に昇格させる (Python 側 `_seckey_helper._find_helper()` が自動検出)。 **fail-safe**: platform guard / build / probe いずれか失敗時は software fallback のまま (at-rest 保証は決して劣化しない、 rc 1)。 詳細は [`SECRETS_ENV_ENCRYPTION.md`](./SECRETS_ENV_ENCRYPTION.md) §7、 実装は `keyvault/_seckey_helper.py` / `keyvault/_seckey_backend.py` / `wizard/keyvault_cli.py:enable_se`。
>
> 以下 §2–§8 は **Keychain 経路の調査記録** として歴史的に保全する (レイヤード backend 設計 §5 や Linux/Windows TPM の検討は引き続き有効)。

---

## 0. TL;DR

- **鍵管理のロジックは健全**。 keyvault ユニットテストは **735 passed / 4 skipped** (4 skip は live SE 統合テスト)。 暗号 (AES-GCM / P-256 ECDH / HKDF / AES-KW / Argon2id) は実暗号で検証済み。 **ただし注意**: テストは `NativeBackend` を fake で注入しており、 本番 `_SecKeyBackend` の実 SE 呼び出しは 4 skip の live 統合テストでしか実行されず **CI 未カバー** —「735 pass = SE が動く」ではない (§2 が示すとおり実 SE は別問題)。
- **macOS の SE 実機ラウンドトリップだけが動かない**。 原因は鍵管理コードのバグではなく、 **SE 鍵を keychain に永続化するにはコード署名 + provisioning-profile 承認の `keychain-access-groups` entitlement が必須** という macOS の制約。
- **自己署名 (self-signed) では SE を使えないことを実機で確定** (§2 のマトリクス)。 無料の Apple Development 証明書でも不可。 動かすには有料の **Developer ID + entitlement + 正式署名済みバイナリ + notarization** のフルセットが要る。
- **macOS SE だけが特殊**。 Linux (TPM 2.0) / Windows (TPM via CNG) / 外部トークン (YubiKey/PKCS#11) は **コード署名不要** (権限と PIN でゲート)。
- **副産物 (要修正)**: Phase 4 の commit `25e048ab6` ("switch keyvault keychain from DPK to legacy macOS") の前提 — 「legacy keychain なら entitlement 不要」 — は **実機で偽**。 正しく Apple-Dev 署名したインタプリタでも legacy 経路で `-34018` になる (§3)。
- **推奨**: レイヤード backend (§5)。 **既定 = SoftwareBackend (passphrase + Argon2id、 全 OS、 署名不要)**、 ハード保護は **外部トークン (E)** を任意上乗せ、 SE (A) / TPM は環境が許す場合の任意オプション。 CLI ツールである Mordred には SE は構造的に不向き (§4.3)。

## 1. 現状 (v1) の要約

- `mordred_keyvault` は **macOS Apple Silicon 限定** ([`SPEC.md`](./SPEC.md) §Platform Support)。 `crypto.py` は Linux/WSL2 での import を禁止し `[macos]` extras でゲート。
- 鍵階層: 実データを **DEK (AES-256-GCM)** で暗号化 → DEK を **wrapping key (P-256)** で wrap。 wrapping key の private 部分が SE に存在。 wrap はオフライン (公開鍵 + software ephemeral)、 unwrap のみ SE 認可 (`SecKeyCopyKeyExchangeResult` → Touch ID)。
- バックエンドは **`NativeBackend` Protocol** (`wrap.py`) で抽象化済み (4 メソッド: `generate_enclave_key` / `get_enclave_public_key` / `delete_enclave_key` / `enclave_ecdh`)。 本番実装は `_SecKeyBackend` (pyobjc + ctypes 経由の `Security.framework`)。
- この Protocol が **本ドキュメントのバックエンド差し替え設計の接合点**。

## 2. 実機検証: 自己署名で SE は動くか (2026-05-25, Apple Silicon)

`/tmp` に隔離コピーした uv CPython 3.13 を、 署名と entitlement を変えて SE 鍵永続化 (`SecKeyCreateRandomKey` + `kSecAttrIsPermanent`、 biometry=False プローブ) を実測。 共有ストアは未変更。

| # | 署名 | entitlement | プロセス起動 | SE 永続化 |
| --- | --- | --- | --- | --- |
| 0 | adhoc (baseline) | — | OK | ❌ `-34018` |
| 1 | self-signed (openssl, チーム無) | なし | OK | ❌ `-34018` |
| 2 | self-signed + `keychain-access-groups` | あり | ❌ **SIGKILL (137)** | — |
| 3 | Apple Development cert (実チーム) | なし | OK | ❌ `-34018` |
| 4 | Apple Dev + team-prefixed `keychain-access-groups` (profile 無) | あり | ❌ **SIGKILL (137)** | — |

- `-34018` = `errSecMissingEntitlement`。 SE 鍵自体は生成される (`SecKeyRef:('com.apple.setoken')`) が、 keychain への **add** で失敗。
- `keychain-access-groups` は **restricted entitlement**。 provisioning profile (または Developer ID の team 承認) が無いと AMFI がプロセスを起動時に kill (137)。
- **結論**: 「codesign でインタプリタを自己署名する」程度では、 無料でも有料でも SE は通らない。 安定運用には provisioning 済みの正式署名済みバイナリが必須。

### 後始末 (検証で作った一時物)
検証で使った 一時 keychain・自己署名証明書のユーザー信頼設定・keychain 検索リスト変更・`/tmp` 作業ファイルはすべて **元の状態に復元・削除済み**。 共有インタプリタは adhoc のまま未変更。

## 3. 重要な発見: Phase 4 legacy-keychain 修正の前提崩れ

commit `25e048ab6` ("fix(mordred-hermes): switch keyvault keychain from DPK to legacy macOS (Phase 4)") のコード comment は次を前提にしている:

> Data Protection Keychain (`kSecUseDataProtectionKeychain=True`) は `keychain-access-groups` entitlement を要求し、 未署名のローカル Python は持てない → legacy keychain に切替えれば entitlement 不要で書ける。

しかし §2 の #3 が示すとおり、 **正しく Apple-Dev 署名したインタプリタでも legacy keychain 経路で `-34018`**。 つまり legacy への切替えは entitlement 要件を回避できておらず、 **現状の keyvault は provisioning 済み entitlement を持つプロセス以外から SE 鍵を永続化できない**。 pip/uv/Homebrew の Python で動かす限り、 誰の環境でも SE 経路は通らない見込み。

→ **対応案**: legacy-keychain 路線を破棄し、 Data Protection Keychain + access group + 正式署名済みヘルパー (§4.2) へ作り直す。 詳細は Issue 化を推奨。

## 4. macOS SE の署名要件の本質

### 4.1 「証明書さえあれば」ではない
SE 永続化に必要なフルセット:
1. **正しい種類の証明書** — 無料の "Apple Development" では不可 (§2 #3/#4)。 **"Developer ID Application" (有料 Apple Developer Program、 年 $99) が必要**。
2. **`keychain-access-groups` entitlement** (team-prefixed) を署名に埋め込む。
3. **それを載せる正式な署名済みバイナリ** — restricted entitlement なので provisioning profile か Developer ID の team 承認が要る。
4. **notarization** — 配布時に Gatekeeper を通すため。

### 4.2 配布モデル (証明書は配らない)
- 配るのは **署名済みバイナリ** のみ。 証明書の **private key は intmax が厳重保管し配布しない** (漏洩すると intmax を騙る署名が可能になる、 単一障害点)。
- 各ユーザーの **SE 鍵 (Mordred の wrapping key) はユーザー端末の SE 内で生成され、 端末外に出ない**。 intmax の署名鍵とは別物。
- Apple はこの証明書を **遠隔失効** でき、 配布済みを一斉無効化できる (検閲・強制の経路、 privacy ツールとしての弱点)。 notarization は初回オンライン検証 (OCSP) を伴う。

### 4.3 Mordred は CLI ツール — SE と相性が悪い
- Mordred-Hermes は **`hermes` コマンド (Python CLI、 pip/uv/Homebrew 配布)**。 GUI `.app` ではない。
- SE を使うには「SE 操作だけを行う小さなコンパイル済みヘルパー (Swift/C/Rust)」を別途作って署名・同梱し、 Python から IPC で呼ぶ必要がある (signed-helper パターン、 例: Secretive)。
- pip wheel に Developer ID 署名 + notarize 済み Mach-O ヘルパーを同梱して配るのは **非常に異例で扱いづらい**。 「CLI である」事実が SE 路線をさらに不向きにする。

## 5. 提案アーキテクチャ: レイヤード backend ("G")

`NativeBackend` Protocol を共通の差込口とし、 鍵保護の実体を環境とポリシーで差し替える。

```
        api.py  (generate / encrypt / decrypt / export_backup / import_backup)
            |   ← 暗号ロジックは不変
        wrap.py (ECDH + HKDF + AES-KW、 pure-Python、 既存)
            |  uses
   +--------+----------  NativeBackend (Protocol: 4 methods)  ← 既存の seam
   |
   +- SoftwareBackend       … passphrase + Argon2id でファイル暗号化 (全 OS・既定)
   +- SecureEnclaveBackend  … 既存 _SecKeyBackend (署名済み macOS のみ)
   +- HardwareTokenBackend  … YubiKey/PIV/FIDO2/PKCS#11 (全 OS・任意)
   +- TpmBackend            … Linux: tpm2-tss / Windows: CNG Platform Crypto Provider
            ^
   resolve_backend(policy, key_id)  ← 新規: backend 選択器 + keystore 索引
```

### 5.1 backend 一覧と署名要件

| backend | private key 置き場所 | unwrap 認可 | 動作条件 | コード署名 |
| --- | --- | --- | --- | --- |
| **SoftwareBackend** (C) | Argon2id+AES-GCM 暗号化ファイル | passphrase | 全 OS | 不要 |
| **HardwareTokenBackend** (E) | トークン内 | PIN + touch | 全 OS (USB) | 不要 |
| **TpmBackend** | TPM 内 | PIN/policy | Linux/Windows | 不要 |
| **SecureEnclaveBackend** (A) | Secure Enclave | Touch ID/passcode | 署名済み macOS | **必須 (§4)** |

→ **コード署名が必須なのは macOS SE のみ**。 他は権限と PIN でゲート。

### 5.2 選択器と「鍵 ⇄ backend 束縛」(最重要の不変条件)
- `policy.keyvault.backend = auto | software | secure_enclave | token | tpm`。 `auto` は能力プローブ順 (token > OS ハード > software) で決定し、 **選択結果をユーザーに明示・記録**する。
- **鍵は生成時の backend に束縛される**。 SE で wrap した DEK は software では解けない (鍵素材が別物)。 `~/.hermes/mordred/keyvault/` に小さな **keystore 索引** (`key_id → {backend, pubkey, created_at}`) を持ち、 unwrap は正しい backend へルーティング。 wire format (MRKW blob) は変更不要。
- **黙ってのフォールバック禁止**。 SE 生成済みの鍵を署名なし環境で開こうとしたら、 静かに software に落とさず **明示的にエラー** (保護レベルの劣化を隠さない)。

### 5.3 マイグレーション (任意)
backend 間移行 = 新 backend で wrapping key 生成 → 各 DEK を {旧で unwrap(認可) → 新の公開鍵で wrap(オフライン)} → 索引更新 → 旧鍵削除。 既存 `api.py` の `import_backup` 再ラップフローを流用可能。

### 5.4 フェーズ
| フェーズ | 内容 | 効果 |
| --- | --- | --- |
| **P1 (最優先)** | `SoftwareBackend` + 選択器 + keystore 索引 + `register()` 配線 | **全 OS で keyvault が動く** (現状 macOS 限定を解消) |
| P2 | `auto` で署名済み macOS なら `SecureEnclaveBackend` (§4.2 のヘルパー前提) | Mac でハード保護を任意提供 |
| P3 | `HardwareTokenBackend` (PKCS#11) + `TpmBackend` + マイグレーション | Apple 非依存のハード保護 |

`crypto.py` の "Tier 2/3 fallback (TPM/DPAPI) は v2-OS2" コメントおよび [`ROADMAP.md`](./ROADMAP.md) v2-OS2 (backend abstraction) と整合。 P1 はそのロードマップの前倒し。

## 6. セキュリティ評価 (脅威別)

| 脅威 | SoftwareBackend (passphrase) | SE / Token / TPM |
| --- | --- | --- |
| 端末の紛失・盗難 (電源オフ) | ✅ 高 (Argon2id) | ✅ 高 |
| 鍵ファイル/バックアップ流出 | ✅ 高 (ファイル単体では解けない) | ✅ 高 |
| 暗号の正しさ・改ざん検知 | ✅ 高 (AEAD・検証済み) | ✅ 高 |
| 稼働中端末のマルウェア (使用中) | ⚠️ 弱 (鍵/passphrase が RAM に存在) | ✅ 強 (鍵が出ない) |
| ハードのレート制限/ロックアウト | ⚠️ なし (Argon2id コストのみ) | ✅ あり |
| 脅し・フィッシング・覗き見 | ⚠️ なし | ⚠️ 限定的 (押させられる) |

- **「絶対安全」は存在しない** (SE も含む)。
- SoftwareBackend は **紛失/盗難/流出/at-rest という “多くの人が実際に直面する脅威” に対して `age`・パスワードマネージャ・FileVault と同等水準で高セキュリティ**。 弱点は「稼働中端末のマルウェア」と「弱い passphrase」の 2 軸。
- 安全性の linchpin は **(1) 強い passphrase の強制 (2) 端末の非汚染**。 ハードニング: Argon2id を強化 (例 256 MiB / t≥3)、 復号鍵の `mlock` + zeroize、 unwrap レート制限 + 監査、 任意で OS keychain を第二の層に。

## 7. 推奨と意思決定

1. **P1 (SoftwareBackend) を既定にする** — SE が直るか否かに関係なく「全 OS で今すぐ動く」価値が出る。 CLI ツールに最も自然。
2. ハード保護が欲しい層には **E (外部トークン)** — Apple も profile も署名も不要、 全 OS、 反監視の観点で最良。
3. **SE (A) は任意オプション** — 実需が確認できたら、 有料 Developer ID 前提で signed-helper を作る。 それまで無理に直さない。 Apple 依存 (非匿名化・失効スイッチ・notarization) のコストを承知の上で。
4. Linux/Windows は **TPM** で署名なしにハード保護可能 (要実装)。 macOS SE のような署名地獄は無い。

## 8. 未確認事項 / 次アクション

> 冒頭の **訂正 (2026-06-01)** のとおり、 hardware SE は CryptoKit file-store helper (`keyvault enable-se`) として **出荷済み**。 以下のうち Keychain 永続化を前提にした項目は超克・完了した。

- ~~**未検証**: "Developer ID Application" (有料) + entitlement で profile 無しに SE 永続化 + ECDH が通るか~~ — **超克 (2026-06-01)**: 有料 Developer ID は **不要** だった。 出荷した live 経路は Keychain を使わない file-store helper で、 ad-hoc 署名のみで実 SE の generate / ECDH / unwrap が動くことを実機確認済み。 有料証明書が要るのは「ビルド済みバイナリを DL 配布する際の Gatekeeper 信頼」だけで、 SE 利用自体には不要。
- ~~**Issue 化推奨**: §3 の Phase 4 SE 永続化不全 (実証マトリクス付き、 「DPK + signed-helper へ作り直し」提案)~~ — **完了 (2026-06-01)**: signed-helper への作り直しは実装・出荷済み。 ただし採用したのは DPK-Keychain ではなく **CryptoKit `dataRepresentation` file-store** helper (`native/sekey-helper`)。 Keychain 永続化そのものを回避したため §3 の前提崩れは無効化された。
- **doc 同期** (継続): [`SPEC.md`](./SPEC.md) §Platform Support / §Threat Model と [`ROADMAP.md`](./ROADMAP.md) v2-OS2 に、 本ドキュメントおよび出荷済み `enable-se` 経路への相互参照を追加。
