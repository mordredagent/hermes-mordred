# Hermes ⇄ Slack E2E 暗号化 設計（双方向）

Mordred ブラウザ拡張と Hermes の間で、Slack を**ゼロ知識の伝送路**として使うための
Hermes 側設計。拡張側の仕様は `Mordred-Extension/SPEC.ja.md` §3・§4・§10.3 を正とし、
本書はそれに整合する **Hermes 側の受信復号（実装済み）と送信暗号化（新規）** を定義する。

- フォーマット: `🔒ENC:v1:{nonce_b64url}:{ciphertext_b64url}`（AES-256-GCM、拡張と同一）
- 共有鍵: ペアリングで確立した `Pairing.aes_key`（`gateway/extension_pairing.load_pairing()`）
- プリミティブ: `gateway/extension_crypto.py` の `encrypt_message` / `decrypt_message` / `is_encrypted`

## 0. 確定した方針（2026-06-30）

| 論点 | 決定 |
|------|------|
| 返信を暗号化する条件 | **Reply-in-kind**：受信が暗号化されていたスレッドでは返信も暗号化、平文なら平文 |
| 暗号化できない時 | **Fail-closed**：平文は絶対に送らない（鍵無し・暗号化失敗ならエラー通知のみ） |
| 暗号化する範囲 | **本文のみ／先頭メンションは平文**（拡張 §4.6 と対称。`<@U…>` 等は平文で残す） |

## 1. 現状（gap）

- **受信復号**: 実装済み。`gateway/platforms/slack.py::_extension_decrypt_inbound` が
  受信テキストの `🔒ENC:v1:` を `Pairing.aes_key` で復号し、エージェントに渡す前に差し替え
  （fail-open）。呼び出しは受信ハンドラ内（メッセージ処理の先頭付近）。
- **送信暗号化**: **未実装**（SPEC にも無い新機能）。Hermes の返信は常に平文で投稿される。
- **バージョン分裂**: この機能群は拡張ブランチ（`feat/mordred-extension-api`）にあるが、
  ユーザーが常用する本体は新しい系列（例: 0.17.x）で、これらが**移植されていない**ため、
  常用環境では受信復号も効いていない。→ 本設計の実装と合わせて移植が前提。

## 2. 受信復号（formalize：既存を踏襲）

```
Slack 受信 → text 取得
  ↓ is_encrypted(text)?
  ↓ YES → load_pairing().aes_key で decrypt_message → 復号文に差し替え
  ↓        さらに「このスレッドは暗号化文脈」と記録（§3 reply-in-kind 用）
  ↓ NO  → そのまま（平文）
エージェントへ
```

- **fail-open のまま**（受信は読めなくてもメッセージ処理を止めない）。ただし復号成功時に
  限り、スレッドを「暗号化文脈」として登録する（送信暗号化の判定に使う）。
- チャンネル絞りは行わない（拡張側 §4.6 が送信元を限定するため、受信は来たものを復号）。

## 3. 送信暗号化（新規）

### 3.1 Reply-in-kind の判定

「暗号化スレッド・レジストリ」を導入する（in-memory、プロセス内）。

- キー: `(chat_id, thread_ts)`（スレッド単位。スレッド外 DM/チャンネルは `(chat_id, None)`）。
- 受信復号が**成功**したら、そのキーを `encrypted_threads` に登録（TTL 付き、例: 24h）。
- 送信時（§3.3）に、宛先キーが登録済みなら返信を暗号化する。

> 利点: Hermes 側に対象チャンネル設定を持たせず、ユーザー（＝拡張）の意図に自動追従。
> 平文で来たスレッドには平文で返す。

### 3.2 暗号化範囲（本文のみ／先頭メンション平文）

返信テキスト `content` を「先頭メンション接頭辞」と「本文」に分割する。

- 接頭辞 = 先頭から連続する Slack 制御トークンと空白：
  `<@U…>`（ユーザー）, `<!here>` / `<!channel>` / `<!subteam^…>`, `<#C…|…>`（チャンネル）。
- 接頭辞は**平文のまま**、本文だけ `encrypt_message(aes_key, body)` で `🔒ENC:v1:` 化。
- 結果: `"<@U123> 🔒ENC:v1:…"`。Slack 通知（メンション）は機能し、本文は不可読。

### 3.3 送信フック

中心の送信経路 `SlackAdapter.send(chat_id, content, reply_to, metadata)` に適用する
（`chat_postMessage` 直前）。`reply_to`（thread_ts）と `chat_id` から §3.1 のキーを作り、
暗号化対象なら `content` を §3.2 で変換してから投稿する。

- **書式の喪失**: 暗号化すると Slack 側はマークダウン/blocks を解釈できない。暗号化時は
  blocks を使わず**プレーン文字列のみ**送る。拡張側は復号して平文表示する（§10.3）。
- **長文分割**: Slack は 1 メッセージ約 40k 文字上限。暗号文は base64 で約 1.33 倍に膨らむため、
  **平文を安全長で分割 → 各チャンク個別に `encrypt_message`**（各々が独立した `🔒ENC:v1:` blob）。
  分割は本文側のみ。先頭メンションは最初のチャンクにのみ付与。
- **ストリーミング/複数送信**: 送信単位（投稿される 1 メッセージ）ごとに暗号化する。

### 3.4 Fail-closed

暗号化すべき文脈（宛先が暗号化スレッド）なのに暗号化できない場合：

- 条件: `load_pairing()` が None（未ペアリング）、`aes_key` 不正、`encrypt_message` 例外。
- 挙動: **平文は投稿しない**。代わりに最小限の通知のみ投稿：
  `🔒 (暗号化できないため本文を送信できませんでした)` あるいは ephemeral 通知。
- ログに理由を記録。受信側 fail-open とは非対称（送信は漏洩を防ぐため厳格）。

## 4. 鍵管理

- 単一ペアリングの `Pairing.aes_key` を受信・送信で共用。
- 複数拡張のペアリングは現状非対応（将来: 鍵リング。受信は総当たり復号、送信は… 要設計）。
- 鍵は keyvault/ペアリングストア（`~/.hermes/extension/`）に既存。SE/keyvault 初期化は
  ペアリング済みなら不要（共有鍵は AES の対称鍵で、Ethereum 署名鍵とは別物）。

## 5. エッジケース / 非対象

- **混在**: 同一チャンネルの他者の平文や過去ログは復号しない（拡張 §4.5/§4.3 と同じ）。
- **編集/削除**: 既存通り無視（`message_changed`/`message_deleted`）。
- **スレッド外の単発**: `(chat_id, None)` で扱う。最初の暗号化受信で登録。
- **レジストリ揮発**: プロセス再起動で `encrypted_threads` は消える → 次の暗号化受信で再登録。
  恒久化は任意（将来 `~/.hermes/extension/` に保存可）。
- **cron/cross-platform 配信**: home channel への自動配信は当面**平文のまま**（暗号化対象外）。
  必要なら別途設計。

## 6. 実装タッチポイント（A→B 段階導入）

- **A. 受信（移植 + reply-in-kind 記録）**
  - `gateway/platforms/slack.py`: `_extension_decrypt_inbound`（移植済みなら再利用）。
    復号成功時に `encrypted_threads` 登録を追加。
- **B. 送信暗号化（新規）**
  - `gateway/platforms/slack.py::SlackAdapter.send`: 宛先が暗号化スレッドなら §3.2/§3.3 を適用。
  - 分割ヘルパー（平文分割→各チャンク暗号化）。
  - Fail-closed 通知ヘルパー。
  - `encrypted_threads` レジストリ（TTL 付き dict、`(chat_id, thread_ts)` キー）。
- **共通**: `gateway/extension_crypto.py`（`encrypt_message`/`is_encrypted`）、
  `gateway/extension_pairing.py`（`load_pairing`）はそのまま利用。

## 7. テスト観点

- 受信: `🔒ENC:v1:` → 復号文がエージェントに渡る／鍵無しで fail-open。
- 送信: 暗号化スレッドで返信が `🔒ENC:v1:`、本文だけ暗号化・先頭 `<@U…>` 平文。
- Reply-in-kind: 平文スレッドの返信は平文、暗号スレッドは暗号。
- Fail-closed: 鍵無し時に平文が投稿されないこと（通知のみ）。
- 長文: 分割後も各チャンクが拡張側で復号・連結できること。
- ラウンドトリップ: 拡張で暗号化送信 → Hermes 復号 → Hermes 暗号化返信 → 拡張で復号表示。

## 8. 未決事項（TBD）

- 複数ペアリング（鍵リング）対応の要否と方式。
- `encrypted_threads` の恒久化（再起動耐性）の要否。
- cron/home channel 配信を暗号化対象にするか。
- 分割時の本文境界（マルチバイト安全な分割長の確定）。
