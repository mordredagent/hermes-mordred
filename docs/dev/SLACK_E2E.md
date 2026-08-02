# Hermes ⇄ gateway E2E 暗号化

Mordred ブラウザ拡張と Hermes の間で Slack / Discord を暗号文の伝送路として
使うための、Hermes 側の受信・返信仕様です。ゲートウェイ経由の agent command は
`ENC:v3` のみを受理します。WebSocket API、履歴、`K_extchat` の v1/v2 ヘルパーは
別プロトコルであり、互換性のためそのまま残します。

> **移行上の注意:** v3 は意図的な breaking wire change です。外部の Mordred
> Extension が v3 の AAD と方向を実装する前にこの版のゲートウェイを配備すると、
> 旧 v1/v2 クライアントは gateway command と reply の両方を利用できません。
> Hermes と Extension を同時に更新してください。旧 command を暗黙に許可する
> downgrade はありません。

## 1. v3 wire

1件のプラットフォーム投稿は、許可された先頭メンション、1個のv3 token、末尾空白
だけで構成します。

```text
[mention-prefix] 🔒ENC:v3:{kid}:{message_id}:{seq}:{total}:{nonce}:{ciphertext}
```

- `kid`: `base64url(SHA-256(K_chan)[0:6])`（8文字）
- `message_id`: 送信前に生成する128-bitランダム値（base64url、22文字）。Slack /
  Discord が投稿後に付与する message ID とは別物
- 現行プロファイルは常に `seq=0,total=1`
- `nonce`: 96-bit AES-GCM nonce
- `ciphertext`: UTF-8本文のAES-256-GCM ciphertext + 16-byte tag
- base64urlはpaddingなしのcanonical表現

Slack が Unicode の鍵絵文字を `:lock:` に正規化する場合に限り、
`:lock:ENC:v3:…` も同一のcanonical aliasとして受理します。鍵絵文字なしも既存の
renderer互換として受理します。未知version、複数token、平文prefix/suffix、
非canonical encoding、改ざんは投稿全体を拒否します。

## 2. AADと宛先束縛

AES-GCM AAD は次の順序のfieldを結合します。各文字列fieldはUTF-8化し、
`uint32_be(length) || bytes` として曖昧性なく符号化し、最後に
`uint16_be(seq) || uint16_be(total)` を付けます。

```text
"mordred-e2e-v3"
direction          # "command" または "reply"
platform.lower()   # "slack" / "discord"
chat_id
thread_root        # None は空文字
message_id
seq
total
```

Hermes受信は `direction="command"`、返信は `direction="reply"` 固定です。このため
返信暗号文をagent命令へ反射できません。`platform/chat_id/thread_root` が変わる
cross-channel / cross-thread replayも認証に失敗します。

Discordのauto-threadでは、Extensionがcommandを暗号化する時点では新しいthread IDが
まだ存在しません。そのcommand AADは投稿元の `(parent_chat_id, thread_root=None)` を
canonical値とします。Hermes 0.19の `auto_thread_created` と、0.13/0.19で保持される
`raw_message.channel.id` を照合してからこの変換を行います。返信registryとreply AADは
作成後の `(thread_id, thread_id)` を使います。marker・親・raw channelが矛盾する場合や、
旧版イベントでauto-threadか既存threadか判定できない場合は推測せず拒否します。

Slackのchannel top levelにも鏡写しの問題があります。Slack adapterのデフォルト
(`reply_in_thread`)はsession keyingのため、top-level messageの `thread_id` に
そのmessage自身の `ts` を合成thread rootとして与えます(`thread_ts == ts`)。
この `ts` は送信後にSlackが採番する値でExtensionは暗号化時点で知り得ないため、
routed thread rootがcommand自身の `message_id` と一致する場合に限り、command AADは
`thread_root=None` をcanonical値とします。本物のthread replyは `thread_ts != ts`
で届くので実rootのまま認証され、top-level tokenを既存threadへ貼り直すreplayは
今まで通り拒否されます。返信routingは合成threadを使い続けます。

`kid` を全channel共通indexから引くことはしません。イベントの `chat_id`、または
Discord threadの認証済み `parent_chat_id` に登録された `K_chan` だけを候補にし、
そのfingerprintが `kid` と一致する場合に限って復号します。

## 3. Replay防止とplaintext release

認証成功時に、domain-separated SHA-256で次の2つのidentityを作ります。

- `(kid, message_id)`
- `(kid, nonce)`

生のIDやnonceは保存しません。identityはprivateな
`~/.hermes/extension/state.json` に、30日TTL・固定上限付きでatomicに保存します。
したがってgateway再起動後も同じcommandはfreshになりません。message IDの使い回し
とAES-GCM nonceの使い回しをそれぞれ拒否します。

commit順序は次の通りです。

1. wire grammarとAES-GCMを認証
2. 対象profileのlive outbound adapterがfail-closed wrapper済みか確認
3. `(platform, chat_id, thread_root, kid)` をreply-in-kind registryへ記録
4. replay identityをatomicにcheck-and-store
5. 初めてplaintextをagentへrelease

adapter不調などで手順2/3に失敗した正当な投稿はreplay cacheへ消費しません。
replay storeの読書き失敗はfail-closedです。

## 4. 返信

暗号化commandを受けたconversationは24時間のin-memory registryへ記録し、返信本文を
同じchannel keyで `direction="reply"` のv3 tokenへ暗号化します。長文は投稿単位に
分割し、各投稿を独立した `seq=0,total=1` messageとして新しいmessage ID / nonceで
暗号化します。

Slack / Discordのrouting mentionは先頭に平文で残せますが、Slack channel/subteamの
表示labelとTeamsの表示名はagent promptへ入れず、自由文を除去します。暗号化対象か
どうかの判定、thread解決、key lookup、暗号化のいずれかが失敗した場合、元のplaintext
sendへは委譲しません。Slackは最小限のlocked noticeを出せますが、本文は送りません。

Hermes multiplex gatewayでは `event.source.profile` に対応する
`gateway._profile_adapters[profile]` をwrap・検証・notice送信に使います。default
profileの同platform adapterがwrap済みでも、secondary profileの未保護adapterを
代用しません。古いHermesの `gateway.adapters` 経路も維持します。

## 5. Mandatory E2E

Slack / Discordでは暗号化されていない受信をagentへ渡しません。設定案内を
best-effortで送り、dispatchをskipします。Teams等はplaintext自体を禁止しませんが、
`ENC`を名乗ったwireは同じv3検証に合格しない限りfail-closedです。

**空 `text` も「未暗号化受信」として拒否します。** Slack adapterはbot mentionを
strip（`text.replace(f"<@{bot_uid}>", "").strip()`）し、添付は `media_urls` に
載せるため、`@Hermes` + 画像 / 音声クリップ / mentionのみは `text == ""` で
hookに到達します。v3 tokenが空textに同伴することは有り得ないので、mandatory
platformでは他の平文と同様にskip + 設定案内とします（2026-08-02のsecurity
reviewで、この経路がgateを迂回しagentの応答が平文で流出し得ることが判明）。

## 6. テスト要件

- Unicode鍵、鍵なし、Slack `:lock:` aliasのcanonical v3
- platform / chat / thread / directionを1項目ずつ変えたAAD失敗
- 異なるchannelにだけ登録されたkeyの拒否
- v1/v2 gateway command、複数token、平文混在、改ざんの拒否
- replay、message ID再利用、nonce再利用を再起動相当の永続stateでも拒否
- replay commitがoutbound保護確認より後であること
- default / secondary profile adapterを取り違えないこと
- 暗号化判定例外時にplaintext `orig_send` を呼ばないこと
- 空 / 欠落 `text`（画像・音声添付、mentionのみ）をmandatory platformで拒否し、
  他platformでは従来どおり通常dispatchすること
