[English](scan.md) | [日本語](scan.ja.md)

# ランタイムを走査する

アプリに同梱された Node.js・Python を調べる人向けに、`version-of` と `scan` の使い方を説明します。

アプリごとにランタイムの更新時期が違うため、ファイルのバージョンを読んで、指定した最低の修正版と比べます。

## 対象の範囲

PE（Portable Executable）は、ここでバージョンリソースを読む実行ファイルの形式です。

調べる実行ファイルは起動しません。
Windows では、根の走査はレジストリと権限情報も読み、Python の補完処理は読み取り専用のパス確認 API を使います。
照合のために、調べるファイル、レジストリ、権限を書き換えることはありません。
脆弱性データベースとの照合はせず、最低版は `--min` で渡します。

## できること

- ファイル1つからバージョンを読みます。
- 指定ファイルとディレクトリを走査します。
- Python の venv とインストールマネージャーの参照先からバージョンを補います。

## 必要なもの

チェックアウトから使う場合は、[入門手順](getting-started.ja.md)で Python の検索先を設定してください。
以下の Bash 形式の例は `PYTHONPATH=src` をコマンドごとに指定しています。

- Python 3.11 以上。
外部パッケージは不要です。
- Python の `home` と alias の参照先には、Windows のローカル固定ドライブか RAM ディスクが必要です。

## `version-of` でファイル1つを読む

```bash
PYTHONPATH=src python -m patchwait.cli version-of Apps/ExampleEditor/resources/node.exe --kind node
```

```json
{"result": "found", "value": {"kind": "node", "location": "Apps/ExampleEditor/resources/node.exe", "version": {"result": "found", "value": "24.19.0"}, "evidence": "pe-version-resource"}}
```

`--kind` は必須です。
版は文字列表の `ProductVersion` から取り、`ProductVersion` が無ければ `FileVersion` から取ります。
先頭が ASCII の数字で書いた `N.N.N` の形でなければなりません（アラビア・インド数字や全角数字で書いた版は、理由 `malformed_version_resource` の `undetermined` にします）。
固定情報（VS_FIXEDFILEINFO）とは major.minor が一致することを確かめます。
python.exe は文字列表に `3.14.6`、固定情報に `3.14.6150.1013` を持つので、major.minor だけを比べます。

版のリソースを持たない `python.exe` では、`--kind python` のときだけ、`scan` と同じく venv の `pyvenv.cfg` を使います。
そこから版を取得したときは、最上位の `version_source` に、取得元に応じて `pyvenv-home-pe-version-resource` か `pyvenv-cfg-version-info` が入ります。

`--kind python` でファイル自体の版が不明、かつ適用される `pyvenv.cfg` が無い場合は、後述のインストールマネージャーの alias 用の処理で `<exact file name>.__target__` も読みます。
参照先の Python PE から版が取れたときは、`version_source: install-manager-target-pe-version-resource` になります。
ファイル自体から取れた版は常に優先し、sidecar が無いときの出力と終了コードは変わりません。

## `version-of` の終了コード

| コード | 意味 |
|---|---|
| 0 | ファイルとバージョンが読めた |
| 1 | パスが存在しない（`not_found`） |
| 3 | 結果またはバージョンが `undetermined` |
| 2 | 引数の誤りか内部エラー |

## `scan` でランタイムを比べる

```bash
PYTHONPATH=src python -m patchwait.cli scan --kind node \
  --min node=24.22.1 \
  --source node=https://nodejs.org/en/blog/vulnerability \
  --root Apps
```

出力（件数と1件だけに縮めたもの）:

```json
{
  "tool": "patchwait",
  "schema": 1,
  "generated": "2026-10-25T00:45:23+09:00",
  "kind": "node",
  "baselines": {"node": {"minimums": ["24.22.1"], "source": "https://nodejs.org/en/blog/vulnerability"}},
  "counts": {"targets": 3, "found": 1, "not_found": 1, "undetermined": 1},
  "walk": [{"root": "Apps", "matched_files": 3, "unreadable_dirs": 0, "skipped_reparse_points": 0, "excluded_dirs": 0}],
  "items": [
    {
      "path": "Apps\\ExampleEditor\\resources\\node.exe",
      "location_kind": "file",
      "product": {"name": "unknown", "inferred": true},
      "product_version": "24.19.0",
      "checked_against": {"minimum": "24.22.1", "source": "https://nodejs.org/en/blog/vulnerability"},
      "verdict": {"result": "found", "value": "24.19.0"}
    }
  ]
}
```

全体の出力では、残りの2つは `24.22.1`（`not_found`）と `20.1.0` です。
`20.1.0` は 20.x 系列の最低版を渡していないので、理由 `no_baseline` の `undetermined` になります。

- `found` は、その系列の最低版より古い版がある、という意味です。

- `--kind` は `node`（既定）か `python` です。
`--min` には系列ごとに最低版を1つずつ渡します。
系列は、node なら major、python なら major.minor です（例: `--min node=20.20.2,22.23.4,24.22.1`）。
最低版は ASCII の数字（`0`〜`9`）だけで書きます。
全角数字などほかの数字は使い方の誤りになります。
比べるには `N.N.N` ちょうどの版が要るので、`3.14.0rc1` のような接尾辞つきの版は `undetermined` にして、「修正済み」とは判定しません。

- `--source` の URL は各項目にそのまま載ります。
何を基準に比べたかを後から確かめられます。

## ファイルとディレクトリを選ぶ

| オプション | 対象の選び方 |
|---|---|
| `--path FILE` | ファイルを直接指定します。繰り返し指定できます。 |
| `--targets FILE` | `{"path": ..., "product": ...}` の JSON 配列を読みます。 |
| `--root DIR` | `--kind` に応じて `node.exe` または `python.exe` を探して歩きます。繰り返し指定できます。 |
| `--exclude TEXT` | パスに TEXT を含むサブディレクトリを飛ばします。大文字小文字と `/`・`\` の違いは区別しません。根自体は飛ばしません。 |

- 歩いている途中のシンボリックリンクと junction はたどらず、`skipped_reparse_points` に数えます。
- 指定した根自体には、リンクでも入ります。
- 読めなかったディレクトリは、下記のWindows向けの2つの例外を除き、それ自体を `undetermined` の項目にし、`counts.undetermined` に数えます。
- `--root` で見つけたファイルが `--path`・`--targets` の指定や先に歩いた根と重複すれば、1回だけ調べます。
- 製品名は明示した項目のものを使います。
`walk[].matched_files` は重複をまとめる前の数です。
- 同じ `--path` を繰り返した指定は、そのまま残します。
- 既知の一部のアプリでは、製品名をパスから推定します。
自分で指定する場合は `--targets` を使ってください。

Windowsでは、ディレクトリを一覧取得できないとき、走査のたびに `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx` の `PackageRoot` を読み、そのパスと比較します。必要に応じてレジストリ文字列を展開し、`GetDriveTypeW` でドライブ種別を調べ、ローカル固定ドライブかRAMディスクの絶対パスであることを確認します。相対パス、UNC、デバイスパス、ネットワークドライブは拒否します。Store向けの処理を使うのは、この設定値と一致する根だけです。一覧取得できない根の代わりに、`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages` のサブキー名を読み、存在する `<PackageRoot>\<PackageFullName>` を歩きます。`PackageRootFolder` は使わず、PowerShellもアプリも実行しません。ファイル名の照合、種類の判定、順序、除外、リパースポイント、重複の扱いは通常の走査と同じです。

区切り文字、`..`、ドライブ、使えないファイル名文字、予約デバイス名、末尾のドット、255文字を超える名前は、パスに結合する前に拒否します。読めないパッケージディレクトリは、詳細にパッケージ名を示す `undetermined` の項目として残します。存在しないものは `absent` に数えます。**歩けるのは現在の利用者に登録されたStoreパッケージだけです。** 別の利用者のパッケージや、インストール済みの全Storeパッケージを網羅するものではありません。一覧取得できないStoreの根自体は、追加の `undetermined` ではなく `package_root` に記録します。現在の利用者の登録が空でも同じです。

ファイルと標準出力はUTF-8です。ファイルシステムのパスに孤立サロゲートが含まれる場合は、出力時にエスケープします。保存したJSONを読むと元のパスに戻り、ほかの検出結果の出力を妨げません。通常のUnicode文字はUTF-8のまま出力します。

PackageRootの値や登録先のキーを読めない場合、または値が不正な場合は、従来の読取不能項目・判定・件数を保ち、`walk[].package_root_error` に理由を示します。PackageRootを特定できないときは、どのディレクトリがStoreの根か確かめられないため、読取不能なディレクトリを保守的に `undetermined` のまま残します。これらの追加フィールドは、該当しない走査では省略します。

それ以外のディレクトリで一覧取得が `PermissionError` になったときは、読み取り専用のWindows API `GetFileSecurityW` で所有者とDACLを読みます。この読取も `ERROR_ACCESS_DENIED` になった場合だけ、`walk[].skipped_protected` に `[{"path": "Apps/Locked", "reason": "listing_and_permissions_denied"}]` の形で記録し、`skipped_protected_count` に数えます。項目や `counts.undetermined` には含めません。権限情報が読めた場合、別のエラー、APIを使えない場合、Windows以外では従来の読取不能項目を残します。ディレクトリ名による判定はしません。**これらのフォルダーの中は調べていません。対応が必要かどうかは管理者による確認が必要です。** 脆弱なランタイムがないと確認できたわけではありません。Store向けの処理を先に適用し、読めない登録パッケージディレクトリは未確定のまま残します。

走査フィールドと、調べていない場所の件数の扱いは、[走査の範囲を読む](ledger-and-waitlist.ja.md#走査の範囲を読む)を参照してください。

## Python の仮想環境

仮想環境（venv）の `python.exe` には、バージョンリソースがないことがよくあります。
uv が `<venv>\Scripts` に置く trampoline もその例です。
`scan` は、リソースがない `python.exe` の隣、なければ1つ上の `pyvenv.cfg` を読みます。
`python.exe` の大文字小文字は問いません。
ほかの名前では、後述の alias の補完処理が適用されない限り `no_version_resource` のままです。
場所の確認には、読み取り専用の Windows API `GetDriveTypeW` と `GetFileAttributesW` を使います。
実行ファイルは起動しません。

バージョンは次の順に選びます。

1. `home` にある、venv が起動する `<home>\python.exe` のバージョンリソースを読みます。
`ProductName` が `Python` の場合だけ使い、`home` 側の `pyvenv.cfg` はたどりません。
2. 下の表で許す場合に限り、`version_info` を使います。
`N.N.N` ちょうどが必要です。
3. 取得できなければ `undetermined` / `no_version_resource` のままにし、何が足りないかを detail に出します。

| `home` と `version_info` の状態 | 動作 |
|---|---|
| `version_info` もあり、home のバージョンと major.minor が違う | `undetermined` / `version_mismatch`。バージョンは取得せず、`version_info` でも補いません |
| `version_info` が `N.N` でも `N.N.N` でもない | `malformed_version_resource`。バージョンは取得せず、`version_info` でも補いません |
| home のリソースが読めるが、壊れているか内部で不一致 | その理由を使います。例は `VS_FIXEDFILEINFO` の署名不正です。detail は `home python.exe: ` で始まり、`version_info` は使いません |
| home のファイルがない・読めない・PE でない・リソースがない・別の製品名 | `version_info` を使えるのは、これらの場合だけです |
| `version_info` が `3.12` のような major.minor だけ | それだけでは `3.12.14` のような修正版と比べられません。uv はこの形をよく使います |

不足を示す detail の例は `pyvenv.cfg version_info is 3.12 (major.minor only) and home python.exe is missing (...)` です。
`pyvenv.cfg` を読んだ項目には、`version_source` が付きます。

```json
"version_source": {"evidence": "pyvenv-home-pe-version-resource", "pyvenv_cfg": "C:\\Apps\\proj\\.venv\\pyvenv.cfg", "home": "C:\\Python\\cpython-3.12-windows-x86_64-none", "version_info": "3.12"}
```

| 欄 | 意味 |
|---|---|
| `evidence` | `pyvenv-home-pe-version-resource`、`pyvenv-cfg-version-info`、または `null`（取得なし） |
| `pyvenv_cfg` | 読んだファイルの絶対パス |
| `home`, `version_info` | `pyvenv.cfg` の値、または `null` |

インストールマネージャーの alias は後述の別形式を使います。
それ以外の項目に `version_source` はありません。

## `pyvenv.cfg` を読み取る

| 条件 | 読み取り規則 |
|---|---|
| サイズと形式 | 64 KiB を超えるファイルと、通常のファイルでないものは読みません。シンボリックリンク、junction などの reparse point も拒否します。 |
| 行の区切り | LF だけで区切り、直前の CR は取り除きます。ほかの Unicode 改行文字は値の中に残します。 |
| キーの重複 | 大文字小文字を区別せず、2回以上なら `undetermined` / `duplicate_key` にして、どちらの値も使いません。 |
| `home` に見える行 | 大文字小文字を問わず、`#`・`;` で始まるコメント行も数えます。2行以上なら `duplicate_key` です。 |
| `home` が1行だけの場合 | 小文字の `home = ...` の形が必要です。`HOME = ...` や `# home = ...` も `duplicate_key` にし、値を使いません。 |
| キーと値の前後 | ASCII の空白とタブだけを取り除きます。それ以外の空白文字が前後にあると `undetermined` / `malformed_version_resource` です。 |
| バージョンの形 | `N.N` または `N.N.N` ちょうどで、各部分は9桁以下です。`3.12.`・`3.12.not-a-version`・長すぎる数字は `undetermined` / `malformed_version_resource` です。 |

## Python の home パスを確かめる

`home` の下を開く前に、`<home>\python.exe` の場所を確かめます。
ローカルの固定ドライブか RAM ディスク上の、`X:\` から始まるパスだけを受け付けます。

| 確認するもの | 規則 |
|---|---|
| ドライブの種類 | `GetDriveTypeW` にドライブの根だけを渡します。Windows が回答のためにボリュームに触れるかは文書化されていません。 |
| 拒否する場所 | UNC（`\\host\share`・`//host/share`）、デバイスや拡張パス（`\\.\`・`\\?\`）、ドライブのないルートからのパス（`\x`）、ネットワーク・リムーバブル・CD-ROM ドライブです。`\\?\` の拒否は `home` 自体に適用します。 |
| 書き換えられる名前 | 末尾が点か空白の部分（`.` と `..` を除く）、ドライブより後ろに `:` がある部分は拒否します。Windows が開く前に名前を書き換えるためです。 |
| 予約デバイス名 | `CON`・`PRN`・`AUX`・`NUL`・`COM1`-`COM9`・`LPT1`-`LPT9`・`COM¹`-`COM³`・`LPT¹`-`LPT³` を拒否します。大文字小文字を問わず、拡張子があっても同じです。末尾の空白と点を除いて比べます。例は `nul.txt` と `Com1 .log` です。 |
| パスの存在 | すべての部分が存在する必要があります。欠けた部分があれば何も開かず、前述の条件で `version_info` を使うことがあります。 |
| 各部分の確認 | `lstat` と `GetFileAttributesW` を使います。後者は、`lstat` が黙ってたどる reparse point も報告します。 |
| リンク | シンボリックリンクと junction の参照先を開かずに読み、同じ確認を繰り返します。16リンクまでで、ループは拒否します。相対パスはリンクのディレクトリから解決します。 |
| NT 名前空間の参照先 | `\Device\`・`\??\`・`\GLOBAL??\`・`\DosDevices\`・`\\?\UNC\`・`\\.\` とドライブのないルートからの参照先は、その場で拒否します。例外の `\??\X:\...` と `\\?\X:\...` だけは `X:\...` に外し、ドライブとパスを通常どおり確認します。 |
| その他の属性 | クラウドのプレースホルダーなどの reparse point と、オフライン・アクセス時に呼び戻す印の付いた部分は拒否します。 |
| 読み取り後 | 同じ場所確認を繰り返し、ボリュームとファイルインデックスを比べます。たどったリンクかファイルが変わると `undetermined` / `no_version_resource` にし、detail に `home changed while it was read` と出します。 |

予約デバイス名は、`home` とすべてのリンク先に適用します。
Windows 10 以前では、これらの名前でファイルの代わりにデバイスを開きます。
新しいビルドでは、`nul.txt` や `COM1 .log` などを普通のファイルとして扱う場合があります。
この違いがあるため、patchwait はすべての版で拒否します。

拒否した `home` は `undetermined` / `no_version_resource` です。
detail に `pyvenv.cfg home is not a local fixed-drive path` を含めます。
`home` の下を開かず、`version_info` も使いません。
存在していても、相対パス、`C:py` のようなドライブ相対パス、空の値、NUL を含む値は同じ扱いです。
この確認は Windows 専用です。
ほかの OS では、すべての `home` を拒否します。

## Python インストールマネージャーの alias

`python.exe`・`python3.exe`・`python3.14.exe`・`pythonw.exe`・`pip.exe` などの alias は、ランタイムのバージョンではなく `ProductName: manage` を持つことがあります。
`scan` と `version-of` は、同じ補完処理を使います。

| 条件 | 動作 |
|---|---|
| ファイル自体のバージョンを使える | 常にそれを優先します。 |
| 適用する `pyvenv.cfg` がある | 使えない cfg も含め、venv の処理を優先します。 |
| ファイル自体のバージョンが不明で、適用する cfg がない | 同じディレクトリの `<exact file name>.__target__` を読みます。 |
| sidecar がない | 元の出力と終了コードを変えません。 |

sidecar は、alias の隣にある参照先を記したファイルです。

| sidecar と参照先の条件 | 規則 |
|---|---|
| ファイルの種類 | 通常のファイルだけです。リンク、reparse point、オフライン・アクセス時に呼び戻すファイルは拒否します。 |
| サイズ | 4096バイト以下です。 |
| 内容 | 厳密な UTF-8 の絶対パス1つだけです。空、BOM、NUL、CR、LF は拒否し、末尾の改行も許しません。 |
| 参照先の場所 | `home` と同じローカル固定・RAM ドライブ、名前、リンクごとの確認を適用します。読み取り後も場所とファイルの変更を再確認します。 |
| バージョンの取得元 | 参照先の PE バージョンリソースだけです。`ProductName: Python` と、文字列・固定情報の通常の一致が必要です。 |
| たどらないもの | 参照先の sidecar と `pyvenv.cfg` は読みません。文字列のバージョン情報では補いません。 |
| 不正・欠落・読取不能・別製品の参照先 | `undetermined` のままです。detail は `__target__` の経路を示します。 |

`scan` の取得元とパスの例です。

```json
"version_source": {"evidence": "install-manager-target-pe-version-resource", "target_file": "C:\\Apps\\Python\\bin\\python.exe.__target__", "target": "C:\\Python\\pythoncore-3.14-64\\python.exe"}
```

| 欄 | 意味 |
|---|---|
| `target_file` | sidecar の絶対パス |
| `target` | 復号した内容。下の条件に該当する場合だけ `null` |
| `evidence` | `install-manager-target-pe-version-resource`、またはバージョンを取得しなかった場合は `null` |

`target` が `null` になるのは、sidecar の読み取りを拒否・失敗した場合（サイズ・変更確認を含む）、BOM 付き・不正な UTF-8、空・空白だけの内容の場合に限ります。
それ以外の内容は、あとで参照先のパスとして拒否しても残します。
`version-of` の `version_source` は、venv と同じく取得元の文字列です。
何も実行しません。
場所の確認と open は別々にパスを解決するため、`home` と同じ競合の制限が残ります。

## 出力を保存して終了コードを読む

`scan` は JSON 文書を1つ標準出力に出します。
`--out FILE` を付けると、一時ファイルを使って出力先を1回で置き換えます。
終了コードと判定不能の件数は [README](../README.ja.md#scan-と-roots-の終了コード)を参照してください。

## うまくいかないとき

> Q. venv が `undetermined` のままなのはなぜですか。
> A. `home` を読めず、`version_info` が `3.12` のような major.minor だけなら、`3.12.14` のような修正版と比べられません。detail を見てください。

> Q. alias の detail が `__target__ route:` で始まるのはなぜですか。
> A. その理由は sidecar または参照先についてのものです。PE に関する理由は参照先の PE を指します。

## セキュリティ上の注意

- 調べる実行ファイルは起動せず、レジストリや権限情報も読み取り専用で扱います。
- `home` の場所確認と open は、それぞれ別にパスを解決します。
読み取り後の再確認は隙間を狭めますが、閉じません。
- 調べているツリーに同時に書き込めるプロセスは、確認と open の間にリンクを差し替えられます。
alias の参照先にも同じ制限があります。

## 関連ドキュメント

- [概要とコマンド一覧](../README.ja.md)
- [使い始める](getting-started.ja.md)
- [信頼を外されたルートを探す](roots.ja.md)
- [台帳と修正待ち一覧を使う](ledger-and-waitlist.ja.md)
- [`undetermined` の理由](undetermined-reasons.ja.md)
