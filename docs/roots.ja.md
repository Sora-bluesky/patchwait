[English](roots.md) | [日本語](roots.ja.md)

# 信頼を外されたルートを探す

アプリや Windows に残る証明書を調べる人向けに、`roots` の使い方を説明します。

ブラウザが信頼を外した証明書も、OS やアプリの信頼するルートの中には残ることがあります。

## 対象の範囲

`roots` は証明書を探すだけで、ストアや束を書き換えません。
検出しても、プログラムがその場所を実際に使うことまでは示しません。

## できること

- 渡された証明書や識別子を照合します。
- PEM・DER・バイナリ・Java キーストアを読みます。
- Windows の信頼と不信頼の一覧・ストアを調べます。

## 必要なもの

チェックアウトから使う場合は、[入門手順](getting-started.ja.md)で Python の検索先を設定してください。
以下の Bash 形式の例は `PYTHONPATH=src` をコマンドごとに指定しています。

- Python 3.11 以上。
外部パッケージは不要です。
- `--windows` には Windows が必要です。
- `--distrust-pem` または `--distrust` で比較材料を渡します。

## ルートの照合を実行する

```bash
PYTHONPATH=src python -m patchwait.cli roots \
  --distrust-pem distrust.pem \
  --pem-root Apps \
  --binary Apps/ExampleSync/bin/sync.exe
```

出力（縮めたもの）:

```json
{
  "tool": "patchwait",
  "schema": 1,
  "generated": "2026-10-25T00:45:23+09:00",
  "check": "roots",
  "distrust": [{"label": "Example Distrusted Root", "sha256": "bf183a79...", "sha1": "1b03c7ee...", "spki_sha256": "2f49c5c1...", "signature_hash": "0e9bd4c2...", "public_key_md5": "a9417e2b...", "raw_der": true}],
  "counts": {"items": 3, "trust": {"found": 2, "not_found": 1, "undetermined": 0}, "distrust": {"found": 0, "not_found": 0, "undetermined": 0}},
  "items": [
    {
      "location": "Apps\\ExampleEditor\\certs\\cacert.pem",
      "location_kind": "pem",
      "role": "trust",
      "distrust": "Example Distrusted Root",
      "verdict": {"result": "found", "value": ["sha1", "sha256", "spki_sha256"]},
      "matches": [{"matched_by": "sha256", "cert_sha256": "bf183a79...", "subject_cn": "Example Distrusted Root"}],
      "details": {"pem_blocks": 2, "certs": 2, "malformed": 0}
    }
  ]
}
```

全体の出力では、`Apps\ExampleSync\certs.pem` は `not_found`、バイナリの `sync.exe` は `found` です。
各項目の `matches` には、一致したものがすべて並びます（`matched_by`、証明書の指紋、サブジェクト名、バイナリなら位置、ROOT と Disallowed の証明書ストアなら `cert_sha1` と `registry_keys`）。

## 信頼を外した証明書の識別子を選ぶ

PEM は証明書を文字列で持つ形式で、DER はバイト列で符号化する形式です。
SPKI（SubjectPublicKeyInfo）は、証明書の公開鍵を表す構造です。

- `--distrust-pem FILE` には、信頼を外された証明書そのものを渡します。
patchwait は証明書の SHA-256 と SHA-1、公開鍵（SPKI）の SHA-256 を導きます。
SPKI だけが一致して証明書の指紋が違う場合は、同じ鍵で再発行された証明書か、相互署名の証明書です。
さらに Windows の Disallowed の一覧用に、下で説明する `signature_hash`（署名のダイジェストがわかる場合）と `public_key_md5` を導きます。
最上位の `distrust` の各項目に、これらを hex で出し、計算できないものは `null` にします。

- `--distrust FILE` には、代わりにテキストの一覧を渡します。
1行1件で、`sha256:<hex>`・`sha1:<hex>`・`spki:<hex>`、または 64 桁の SHA-256 だけを書き、続けてラベルを書けます（省略可）。
hex の中のコロンは受け付け、空行と `#` の行は飛ばします。
64 桁にラベルを付けた形は [trust-store-audit](https://github.com/globe-teck/trust-store-audit) の preset と同じ形式です。
同じラベルの行は1件にまとめ、2つのオプションは一緒に使えます。

## PEM の束とバイナリを読む

- `--pem FILE` と `--pem-root DIR` は、PEM の束か、DER の証明書1枚を読みます。
`--pem-root` は `*.pem`・`*.crt`・`*.cer`・`cacert*`・`roots.pem`・`ca-bundle*` を探して歩きます。
根より下のディレクトリへのシンボリックリンクと junction はたどらず、`skipped_reparse_points` に数えます。
歩いて見つけたファイルのうち、PEM の中身が証明書以外（鍵や CRL）だけのものは飛ばします。
飛ばした数は、そのディレクトリの `pem_root` の項目に出します。

- `--binary FILE` は、PEM の文字列と生の DER として組み込まれたルートを探します。
生の DER の証明書は、外側の SEQUENCE の長さが2バイト（およそ 260 バイトから 64 KiB）で、中の tbsCertificate が 128 バイト以上のものを認識します。
最後まで解析できたものだけを数え、証明書の先頭に似ているだけのバイト列はまったく数えません。
これより小さい証明書が生の DER で入っていても認識しませんが、`--distrust-pem` で渡したときは、下の生の DER の検索で見つかります。
どちらも SHA-256・SHA-1・SPKI で照合するので、`--distrust` の一覧でも見つかります。
一覧を `--distrust-pem` で渡したときは、各証明書と公開鍵の生の DER も探します（`matched_by` は `raw_der` と `raw_spki`）。
同じ項目にすでに一致した DER の証明書の内側で見つかったものは、二重には出しません。
ファイルは少しずつ読むので、大きなバイナリでも扱えます。

- PEM の `BEGIN CERTIFICATE` と `END CERTIFICATE` の組で、印のあいだに空白・NUL・文字列リテラルの書き方のエスケープ（`\n`・`\r`・`\t`。
バックスラッシュと英字の2文字）しかないものは、書式文字列などのひな形で、壊れた証明書ではありません。
`malformed` には数えず、`details.ignored_pem_blocks` に位置と `reason: empty_pem_block` を残します。
並べるのは 20 件までで、それより多いときは `details.ignored_pem_blocks_total` に全体の数を出します。

- バイナリの `details` は、`pem_blocks`（見つけた PEM の証明書の印）、`certs`（PEM から解析した証明書）、`der_certs`（生の DER から解析した証明書）、`malformed`（解析できなかった PEM の組）、`ignored_pem_blocks` です。
束も同じですが `der_certs` は無く、`ignored_pem_blocks` は該当があるときだけ出します。

## Java キーストアを読む

`--keystore FILE` は、ファイル名ではなく中身から形式を判別します。
典型的な入力は Java の `cacerts` です。
複数のファイルには `--keystore` を繰り返します。

```bash
PYTHONPATH=src python -m patchwait.cli roots --distrust-pem synthetic-distrusted.pem --keystore 'C:\Java\jdk\lib\security\cacerts'
```

| 形式 | 対応するバージョンと内容 |
|---|---|
| PKCS12（PFX） | version 3。平文の `data` ContentInfo にある X.509 の `certBag` を、入れ子の `safeContentsBag` も含めて読みます。 |
| JKS | version 1・2。信頼する証明書と、秘密鍵エントリに付属する証明書チェーンを読みます。秘密鍵は読み飛ばして数えます。 |
| JCEKS | version 1・2。平文の trusted-certificate エントリだけに対応します。秘密鍵・共通鍵エントリで列挙を止めます。 |

PKCS12 の `keyBag`・`pkcs8ShroudedKeyBag`・`crlBag`・`secretBag` は、数だけを取ります。
その中の証明書らしいバイト列は探しません。
暗号化された `encryptedData`・`envelopedData` ContentInfo と、未知の構造は読めません。

`MAX_KEYSTORE_FILE`（16 MiB）を超えるファイルは、中身を読む前に拒否します。
確認中にファイルが大きくなる場合も、読み込み量に上限を設けます。

項目は `location_kind: java_keystore`、`role: trust` です。
判定と一致情報は束と同じ形で、SHA-256・SHA-1・SPKI で照合します。

| 条件 | 判定 |
|---|---|
| 一致がある | 別の部分が読めなくても `found` |
| 一致がなく、すべて列挙できた | `not_found`。完全に読める空のキーストアも含む |
| 証明書を含む可能性のある暗号化・未対応の部分がある | `undetermined` / `keystore_unreadable` |
| 形式不明・構造不正 | `undetermined` / `malformed_keystore` |
| 証明書を解析できない | `undetermined` / `malformed_cert` |
| ファイルがない | `target_missing` |
| 読取不能・サイズ上限超過 | `file_unreadable` |

証明書を1枚も読めなかった場合も、これらの不確実さは残ります。

| `details` の欄 | 意味 |
|---|---|
| `format`, `version` | 検出した形式とバージョン |
| `certs`, `malformed` | 解析した証明書数と、解析できない証明書数 |
| `bags`, `entries` | 種類別の数 |
| `content_infos` | content type 別の数 |
| `declared_entries` | JKS/JCEKS のヘッダーに書かれた数 |
| `encrypted_content_infos`, `unreadable_parts` | 暗号化 ContentInfo と読めない部分の数 |
| `mac_data` | MAC の有無。検証結果ではありません |

取得不能・該当しないバージョン、ヘッダーの数、MAC の有無は `null` です。
使わない種類別の数は空のオブジェクトです。
`undetermined` の detail は、何を読めなかったかを説明します。
`ledger` と `waitlist record --from` は、これらの欄を検査します。
台帳には数も出し、`--brief` で `not_found` をまとめてもキーストアごとの数の行は残します。
`--binary` 走査も使えますが、その件数ではキーストア全体の列挙を証明できません。

## Windows の一覧とストアを読む

`--windows` は AuthRoot と Disallowed の一覧をレジストリから読みます。
ROOT と Disallowed の証明書ストアは `ssl.enum_certificates` で列挙します。
証明書の信頼リストを CTL と呼びます。
`certutil` は呼びません。
レジストリのキーはすべて読み取り専用で開き、書き込みません。

ROOT と Disallowed のストアの一致には、`matches[].cert_sha1` と `matches[].registry_keys` を付けます。
前者は証明書の SHA-1、後者はその SHA-1 を名前に持つキーの `{key, last_write}` の並びです。

| ストア | 探すキー |
|---|---|
| ROOT | HKLM・HKCU の `SOFTWARE\Microsoft\SystemCertificates` と `SOFTWARE\Policies\Microsoft\SystemCertificates` にある `ROOT`・`AuthRoot` |
| Disallowed | 同じ HKLM・HKCU の場所にある `Disallowed` |
| ROOT の企業用ストア | HKLM の `SOFTWARE\Microsoft\EnterpriseCertificates` の `ROOT` のみ（`root_store`） |
| Disallowed の企業用ストア | HKLM の `SOFTWARE\Microsoft\EnterpriseCertificates` の `Disallowed` のみ（`disallowed_store`） |

| 時刻・注記 | 意味 |
|---|---|
| `last_write` | キーの最終更新時刻（UTC）。証明書のプロパティ変更でも変わるため、追加時刻とは限りません。 |
| `last_write_note` | 時刻が 0・範囲外・整数でない場合、`last_write` を `null` にして理由を示します。 |
| `registry_keys_note` | 調べた場所にキーがなければ、空の `registry_keys` とともに説明を出します。 |
| `registry_keys_errors` | 読めなかったキーとエラーの種類です。 |
| `details.last_sync` | Windows が一覧を最後に同期した時刻です。AuthRoot の `LastSyncTime`、Disallowed の `DisallowedCertLastSyncTime` を読みます。 |
| `details.last_sync_note` | 同期時刻がないか不正なら、`details.last_sync` を `null` にして説明を出します。 |

ROOT の論理ストアには、サービスやほかのユーザーのストアなど、patchwait が読まない場所も含まれ得ます。
そこから来た証明書でも、キーの並びは空で注記を付けます。
時刻は推測で埋めません。
Windows 以外ではこれらの欄はなく、Windows の項目は `undetermined` / `not_windows` です。

## 結果を読む

- `found` の意味は `role` で変わります。
`trust` 側（AuthRoot・ROOT・束・バイナリ）の `found` は悪い結果で、信頼するルートを並べる場所に、その証明書か鍵が入っています。
ただし、あるプログラムがその場所を実際に使っていることまでは示しません。
`distrust` 側（Disallowed）の `found` は良い結果です。
この側の `not_found` は、比較できたうえで一覧に載っていないという意味です。

- AuthRoot の項目に Microsoft の「無効にした日時」の属性があれば、`trust` 側では `not_found` にして、日時を `matches[].disallowed` に載せます。
「NotBefore」の制限は `found` のまま、制限を `matches[].not_before` に載せます。

- 一致がないとき、一部の証明書が読めなかった束・バイナリ・証明書ストアは `undetermined`（`malformed_cert`）、PEM からも生の DER からも証明書を1枚も認識できなかった束・バイナリは `undetermined`（`no_certs_recognised`）です。
数えなかった空の PEM の組は、どちらにも含めません。
一致があれば必ず `found` で、証明書を1枚も解析できなかったバイナリでも、生のバイト列で一致すれば `found` です。

- バイナリの `not_found` は「patchwait が中で認識できた証明書の中には無い」という意味です。
圧縮など patchwait が読めない形でもルートを持つバイナリには、その証明書が入っている可能性があります。

## Windows の Disallowed の照合

SubjectAlgorithm が `1.3.6.1.4.1.311.10.11.15` の一覧は、署名ハッシュか公開鍵 MD5 で照合します。
識別子の長さではなく OID で判別します。

| 識別子 | 計算方法と対応範囲 |
|---|---|
| 署名ハッシュ | 証明書の外側の署名アルゴリズムでダイジェストを選び、タグと長さを含む TBSCertificate の DER 全体をハッシュにします。 |
| 対応するダイジェスト | RSA PKCS#1 v1.5 と対応する ECDSA の、MD5・SHA-1・SHA-224・SHA-256・SHA-384・SHA-512 です。 |
| RSASSA-PSS | パラメーターに対応するハッシュが明示されている場合だけです。 |
| 公開鍵 MD5 | subjectPublicKey の BIT STRING の値から、先頭の未使用ビット数の1バイトを除いて計算します。 |

| 条件 | 結果 |
|---|---|
| 一致した | `matched_by: signature_hash` または `public_key_md5` と、識別子の hex を出します。 |
| 両方を計算でき、どちらも一致しない | `not_found` |
| 署名ハッシュが不明で、公開鍵 MD5 も一致しない | 署名アルゴリズムを示した `undetermined` / `no_usable_identifier` |
| テキストの `--distrust` だけを渡した | これらのハッシュを計算できず、`undetermined` のまま |

通常のマシンには、この一覧に一致する証明書はないと予想されます。
`distrust` 側の `not_found` は、比較できたうえで一覧に載っていないという意味です。

## うまくいかないとき

> Q. 読めない証明書がある場合、見つからなかったと判定しますか。
> A. 一致があれば `found` です。一致がなく、一部の証明書が読めない束・バイナリ・証明書ストアは `undetermined` / `malformed_cert` です。

> Q. 証明書を1枚も認識できない場合はどうなりますか。
> A. PEM でも生の DER でも認識できない束・バイナリは `undetermined` / `no_certs_recognised` です。空の PEM ひな形は数えません。バイナリの生のバイト列で一致すれば、解析した証明書がなくても `found` です。

> Q. バイナリの `not_found` は、証明書が絶対にないという意味ですか。
> A. 認識できた証明書の中にない、という範囲です。圧縮データなど、読めない形で残っている可能性があります。

## セキュリティ上の注意

- パスワードは求めません。
- PKCS12 の MAC と JKS/JCEKS の完全性ハッシュは検証しません。
- 証明書の署名と信頼チェーンも検証しません。
- 完全性の検証用バイトが改変されていても、構造を読めるキーストアは `not_found` になり得ます。

## 出力を保存して終了コードを読む

`roots` は JSON 文書を1つ標準出力に出します。
`--out FILE` を付けると、一時ファイルを使って出力先を1回で置き換えます。
終了コードと判定不能の件数は [README](../README.ja.md#scan-と-roots-の終了コード)を参照してください。

## 関連ドキュメント

- [概要とコマンド一覧](../README.ja.md)
- [使い始める](getting-started.ja.md)
- [ランタイムを走査する](scan.ja.md)
- [台帳と修正待ち一覧を使う](ledger-and-waitlist.ja.md)
- [`undetermined` の理由](undetermined-reasons.ja.md)
