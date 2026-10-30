[English](README.md) | [日本語](README.ja.md)

# patchwait

patchwait は、アプリ提供元の修正を待つ人向けに、Windows PC の同梱 Node.js・Python のバージョンと、信頼を外されたルート証明書を調べるツールです。

デスクトップアプリの多くは、自前の `node.exe` や `python.exe` を同梱しています。
これらが新しくなるのは、アプリの更新に合わせてです。
ブラウザが信頼を外したルート認証局（CA）も、Windows の AuthRoot の一覧、アプリの `cacert.pem`、コンパイルされたルートストアには残ることがあります。
patchwait はバージョンを読み、渡された証明書をこれらの場所で探します。

`scan` と `roots` は、各項目に次のいずれかの結果を返します。

| 結果 | 意味 |
|---|---|
| `found` | 指定した最低版より古いランタイムがある、または証明書か鍵が一致しました。ルートでは項目の `role` も見てください。 |
| `not_found` | 照合した範囲で、最低版より古いランタイムや、一致する証明書・鍵が見つかりませんでした。各照合の制限が適用されます。例外として、Microsoft の「無効にした日時」の属性を持つ AuthRoot の項目は、一致していても `not_found` です（[roots](docs/roots.ja.md) を参照）。 |
| `undetermined` | ファイルを読めない、バージョンを解析できない、使える比較材料がないなどのため判定できません。項目に理由を付けます。 |

`version-of` はファイルを1つ読み、[独自の終了コード](docs/scan.ja.md#version-of-の終了コード)を使います。

## しないこと

- バージョンと脆弱性データベースを照合しません。最低の修正版は、たとえば Node.js のセキュリティリリースを基に使う側が決め、`--min` で渡します。
- バージョンから CVE を推測しません。`waitlist show --intel-store` は、明示された脆弱性の識別子（CVE ID）だけを、CISA の Known Exploited Vulnerabilities（KEV）カタログと、JVN の最近の更新を収めた RSS の写しに照合します。
- リポジトリの lockfile は調べません。パッケージやバイナリを OSV と照合する場合は [osv-scanner](https://github.com/google/osv-scanner) を使ってください。
- 前回からの「新規」を判定しません。毎回すべての結果を出し、状態は呼ぶ側で持ちます。
- 調べる実行ファイルを実行せず、証明書ストアや証明書の束も書き換えません。

patchwait はネットワークに接続せず、調べるファイルを実行しません。
書き込むのは、`--out` で指定した結果のファイルと、`waitlist record` に渡した台帳のファイルだけです。

状態: 初期段階（0.2.0）。PyPI には公開していません。

## できること

PE（Portable Executable）は、patchwait がバージョンリソースを読む実行ファイルの形式です。

- PE のバージョンリソースを読み、呼び出し側が渡した最低の修正版と比べます。
- 渡された証明書を、Windows の一覧・ストア、PEM の束、バイナリ、Java キーストアで探します。
- 保存した結果から、記録用の台帳に貼る Markdown を作ります。
- 提供元の修正待ち項目を手元の台帳に持ち、確認していない日数を示します。
- 明示された CVE ID を、ScanMux が保存した KEV・JVN 情報と照合します。

## 必要なもの

- Python 3.11 以上。外部パッケージは不要です。
- `roots --windows` には Windows が必要です。試験は Windows でのみ実行しています。
- Python の補完処理の参照先と、省略可能な ScanMux ストアには、Windows のローカル固定ドライブか RAM ドライブが必要です。

Windows では、次の照合で読み取り専用の API を使います。

| コマンド・処理 | Windows から読むもの |
|---|---|
| `roots --windows` | `winreg` でレジストリの値とキーの情報、`ssl.enum_certificates` で証明書ストアを読みます。 |
| ディレクトリを一覧取得できないときの `scan --root` | `winreg` で Appx の `PackageRoot` と、その根に対する現在の利用者のパッケージ登録を読みます。`GetDriveTypeW` で設定された根のドライブ種別を確認し、`PackageRoot` を特定できた場合、それ以外のディレクトリで一覧取得が拒否されると `GetFileSecurityW` で権限情報を読みます。 |
| `scan --kind python` と `version-of --kind python` の補完処理、`waitlist show --intel-store` | ローカルパスの確認に `GetDriveTypeW` と `GetFileAttributesW` を使います。 |

これらの照合は、レジストリ、権限、証明書ストア、調べるファイルに書き込みません。
書くのは、指定された結果の出力と、`waitlist record` に渡したファイルだけです。
それぞれのパスに適用する確認は、各ガイドを参照してください。

## 使い始める

チェックアウトから、[使い始める](docs/getting-started.ja.md)の手順を進めてください。
合成の `Apps/` フォルダを使い、`version-of` と `scan` を1回ずつ実行します。
例には、試験が作るものと同じ種類の偽のファイルを使います。

最低版は、信頼する修正情報を基に選んでください。
例のバージョンは、比較の動作を示すためのものです。

## コマンド

| コマンド | 読むもの | 書くもの | ガイド |
|---|---|---|---|
| `version-of` | 実行ファイル1つと、該当する場合は Python の補完用ファイル | 標準出力への JSON | [ランタイムの走査](docs/scan.ja.md) |
| `scan` | 指定したファイル、JSON の対象一覧、またはディレクトリ | 標準出力か `--out FILE` への JSON | [ランタイムの走査](docs/scan.ja.md) |
| `roots` | 信頼を外した証明書の識別子と、指定した証明書の場所 | 標準出力か `--out FILE` への JSON | [ルートの照合](docs/roots.ja.md) |
| `ledger` | 保存した `scan` または `roots` の文書1つ以上 | 標準出力か `--out FILE` への Markdown | [台帳と修正待ち一覧](docs/ledger-and-waitlist.ja.md) |
| `waitlist show` | 台帳と、指定した場合は ScanMux の保存済みストア | 標準出力への JSON または Markdown | [台帳と修正待ち一覧](docs/ledger-and-waitlist.ja.md) |
| `waitlist record` | 台帳と、`--from` の場合は保存した結果 | 指定した台帳ファイルと、標準出力への JSON | [台帳と修正待ち一覧](docs/ledger-and-waitlist.ja.md) |

`scan` と `roots` は JSON 文書を1つ出します。
`--out FILE` を付けると、一時ファイルに書いてから出力先を1回で置き換えます。
`ledger` の `--out` も原子的に書き込みます。

## `scan` と `roots` の終了コード

| コード | `scan` | `roots` |
|---|---|---|
| 0 | 最低版より古いものが見つからなかった | `trust` 側に信頼を外されたルートが見つからなかった |
| 10 | `found` が1件以上 | `trust` 側に `found` が1件以上 |
| 2 | 引数の誤りか内部エラー | 引数の誤りか内部エラー |

`undetermined` は、この2つのコマンドの終了コードを変えません。
判定できなかった件数も必ず見てください。

| コマンド | 確認する欄 |
|---|---|
| `scan` | `counts.undetermined` と、調べていない場所を示す [`walk` の情報](docs/ledger-and-waitlist.ja.md#走査の範囲を読む) |
| `roots` | `counts.trust.undetermined`、`counts.distrust.undetermined` |

`undetermined` があって終了コードが 0 なら、調べられた範囲には悪いものが見つからなかったという意味です。

ルートの `trust` 側で `found` なら、信頼するルートを並べる場所に、その証明書か鍵が残っています。
プログラムがその場所を実際に使うことまでは示しません。
`distrust` 側（Disallowed）の `found` は良い結果です。
この側の `not_found` は、比較できたうえで一覧に載っていないという意味です。

## わかっている制限

venv は Python の仮想環境です。

- PE のバージョンリソースがない venv で、`home` が読めず、`version_info` が major.minor だけなら `undetermined` のままです。
- Python の `home` と alias の参照先は読み取りの前後で確認しますが、同時に書き込むプロセスは確認と open の間にリンクを差し替えられます。
- 読めない形でルートを持つ実行ファイルは、`malformed_cert`、`no_certs_recognised`、または別の証明書が読める場合は `not_found` になり得ます。
- 設定された Store パッケージの根を一覧取得できない場合、`scan --root` が歩くのは現在の利用者に登録されたパッケージだけです。インストール済みの全 Store パッケージを網羅しません。
- Appx の `PackageRoot` や現在の利用者のパッケージ登録を読めない場合、読めない根は `undetermined` のまま残し、`walk[].package_root_error` に理由を示します。
- `PackageRoot` を特定できた場合、それ以外のディレクトリで一覧取得と所有者・DACL の読み取りの両方が拒否されると、`items` や `counts.undetermined` に含めず、`skipped_protected` に記録します。これらのフォルダーの中は調べていません。対応が必要かどうかは管理者による確認が必要です。
- Windows の Disallowed の一覧では、一部の項目に署名ハッシュか公開鍵 MD5 が必要です。テキストの識別子だけでは計算できません。

補完処理の順序とパスの制限は、[Python の仮想環境](docs/scan.ja.md#python-の仮想環境)を参照してください。
対応するハッシュと正確な判定条件は、[Windows の Disallowed の照合](docs/roots.ja.md#windows-の-disallowed-の照合)を参照してください。
バイナリの `not_found` が示す範囲は、patchwait が認識できた証明書だけです。ほかのルートが圧縮されている場合も同じです。

## セキュリティ上の注意

- 証明書の一致は、その場所をプログラムが使うことの証明にはなりません。
- Java キーストアの完全性、証明書の署名、信頼チェーンは検証しません。
- 保存済みの ScanMux ストアでは ACL を検査しません。書き込める人は、写しとハッシュを差し替えられます。
- 保存済み情報の経過日数には、既定の鮮度の閾値がありません。古い写しを最新とは呼びません。

## 関連ドキュメント

| ガイド | 読む場面 |
|---|---|
| [使い始める](docs/getting-started.ja.md) | チェックアウトから実行し、例の出力を読みたいとき |
| [ランタイムを走査する](docs/scan.ja.md) | 最低版、対象の選択、Python の venv、インストールマネージャーの alias を調べるとき |
| [信頼を外されたルートを探す](docs/roots.ja.md) | 証明書の識別子、Windows ストア、束、バイナリ、Java キーストアを調べるとき |
| [台帳と修正待ち一覧を使う](docs/ledger-and-waitlist.ja.md) | Markdown、提供元の修正待ち、保存済みの KEV・JVN 情報を使うとき |
| [`undetermined` の理由](docs/undetermined-reasons.ja.md) | 判定できなかった理由コードを調べるとき |

## 開発

```bash
python -m unittest discover -s tests -t .
pyright src tests tools
```

試験は、合成の PE ファイル・証明書・証明書の信頼リストを実行時に作ります。
本物のバイナリや証明書はリポジトリに入れていません。

`.githooks/` と `tools/publish_check.py` は、メンテナが公開前に使うローカルの検査です。
パスの公開対象リストを調べ、目印を走査します。
patchwait を使うだけなら不要です。
上の試験では、これらも検査します。

## ライセンス

[MIT](LICENSE)
