[English](ledger-and-waitlist.md) | [日本語](ledger-and-waitlist.ja.md)

# 台帳と修正待ち一覧を使う

結果を記録して提供元の修正を追う人向けに、`ledger` と `waitlist` の使い方を説明します。

結果を Markdown に変換して記録し、待っている項目の最終確認日と再確認コマンドを手元に残せます。

## 対象の範囲

`ledger` は状態を持たず、前回と比べません。
`waitlist` の再確認コマンドは表示するだけで実行しません。
保存済み情報を読む場合もネットワークに接続しません。

## できること

- 保存した結果を Markdown に変換します。
- 修正待ち項目を表示し、確認日と結果を記録します。
- 明示された CVE ID を ScanMux の保存済み KEV・JVN 情報と照合します。

## 必要なもの

チェックアウトから使う場合は、[入門手順](getting-started.ja.md)で Python の検索先を設定してください。
以下の Bash 形式の例は `PYTHONPATH=src` をコマンドごとに指定しています。

- Python 3.11 以上。
外部パッケージは不要です。
- `ledger` と `record --from` には、保存した `scan` または `roots` の文書が必要です。
- 台帳は手元の JSON ファイルで持ち、リポジトリに入れないでください。
- `--intel-store` には、Windows のローカル固定ドライブか RAM ドライブ上にある ScanMux ストアが必要です。

## 台帳用の Markdown を出す

```bash
PYTHONPATH=src python -m patchwait.cli ledger --brief scan.json
```

`ledger` は `scan --out` か `roots --out` が書いた文書を1つ以上読み、Markdown を出します。
文書ごとに1つのまとまりを、渡した順に並べます:

```markdown
10-25: patchwait scan node: found 1 / not_found 1 / undetermined 2 (file_unreadable 1, no_baseline 1); not walked: skipped_reparse_points 1, excluded_dirs 0

- found: `Apps\ExampleEditor\resources\node.exe` — `24.19.0` < `24.22.1`, product `unknown` (inferred)
- undetermined: `Apps\ExampleTool\node.exe` — no_baseline: `no --min for node series 20`
- undetermined: `Apps\Locked` (directory) — file_unreadable: `PermissionError`
- not_found: 1 items
```

- 1行目は台帳に貼るための要約です。
日付は文書の `generated` の現地日付で、今日の日付ではありません。
`roots` では `trust found N / not_found N / undetermined N; distrust found N / ...` の形です。

- `undetermined` の理由は、件数の多い順に括弧の中で数えます。

- `scan` の `--root` の走査で、リパースポイント、除外したディレクトリ、保護フォルダー、または存在しない・読めない・名前を拒否したパッケージがあれば、要約の末尾に `; not walked: skipped_reparse_points N, excluded_dirs N` を付けます。
見ていない場所が分かるようにするためです。
該当する場合は `skipped_protected` と、0でない `package_absent`・`package_unreadable`・`package_refused` も表示します。別の行に、保護フォルダーの各パスと管理者確認の注意、`package_root` の全件数と現在の利用者に限る旨、拒否した名前、`package_root_error` の理由を表示します。`ledger` と `waitlist record --from` は追加フィールドの形を厳密に検査し、配列と件数の一致や、登録パッケージの全件数の内訳も確かめます。不正なら終了コード2です。
`roots` でも、`--pem-root` のディレクトリでリパースポイントか鍵だけの PEM ファイルを飛ばしたときは、その行に `skipped_reparse_points N` と `skipped_key_only N` を出し、要約の末尾に `; not walked: skipped_reparse_points N, skipped_key_only N` を付けます（ディレクトリごとに1回だけ数えます）。
`--brief` でも要約と走査の根拠は残るので、この件数は消えません。

- `found` と `undetermined` の項目は、必ず1件ずつ1行で出します。
`not_found` の項目も1件ずつ出しますが、`--brief` のときだけ件数1行にまとめます。
`scan` では `- not_found: N items`、`roots` では `- not_found: N items (trust N, distrust N)` です。
`undetermined` はまとめません。

- 項目は `found`・`undetermined`・`not_found` の順にまとめ、それぞれの中では文書の順のままです。
`--root` をたどった場合、その根のディレクトリの項目（根が無い、読めないディレクトリ）はファイルの項目のあとに来ます。

- 語は JSON の値（`found`・`not_found`・`undetermined` と理由の名前）をそのまま使い、言い換えません。

- `ledger` は状態を持たず、前回の結果とも比べません。

## 走査の範囲を読む

`scan` 文書の `walk` には、`--root` ごとに1つの項目が入ります。

| 欄 | 意味 |
|---|---|
| `root` | 指定された根のパスです。 |
| `matched_files` | 重複をまとめる前の、名前が一致したファイル数です。 |
| `unreadable_dirs` | 解消できず、ディレクトリの項目として残した走査時の読取失敗数です。`package_root` に記録した Store の根と、`skipped_protected` の保護フォルダーは含みません。 |
| `skipped_reparse_points`、`excluded_dirs` | 走査で飛ばした場所の件数です。`package_root` 内の対応する件数も含むので、足し直しません。 |
| `package_root` | Store 向けの補完処理を使った場合の情報です。欄は下記のとおりです。 |
| `package_root_error` | レジストリを読めない、または値を検査できない場合の理由です。元の読取不能項目を残します。同じ項目に `package_root` と同時には入りません。 |
| `skipped_protected`、`skipped_protected_count` | `{path, reason}` の配列とその長さです。理由は `listing_and_permissions_denied` です。両方の欄を一緒に出します。 |

`walk[].package_root` には、`path`、`packages_registered`、`walked`（一覧取得できたパッケージディレクトリ数）、`unreadable`、`absent`、`excluded`、`skipped_reparse_points`、`refused`（危険なサブキー名を、引用符付きのASCII JSON文字列として記録した配列）、`note` を記録します。たとえば、空の名前は `""`、空白1文字の名前は `" "` という文字列で残します。エスケープによってすべての文字を保持し、`ledger` と `waitlist record --from` でも読めるようにします。`packages_registered` は `walked + unreadable + absent + excluded + skipped_reparse_points + len(refused)` と一致します。

`walked` は、そのパッケージディレクトリ自体を一覧取得できた数です。サブディレクトリをすべて調べた証明にはなりません。
`counts.targets` と各判定の件数は、`items` だけを数えます。
読めない登録パッケージディレクトリは `undetermined` の項目になり、`unreadable_dirs` にも数えます。`package_root.unreadable` は同じ失敗を示すので、両者を足しません。
`package_root` に記録した一覧取得できない Store の根、保護フォルダー、存在しないパッケージ、除外したパッケージ、リパースポイントのパッケージ、名前を拒否したパッケージは、項目や `counts.undetermined` を増やしません。
Windows 向けの処理と制限は、[走査ガイド](scan.ja.md)を参照してください。

## ランタイムの取得元を読む

`scan` の `version_source` は、[走査ガイド](scan.ja.md)で説明するバージョンの取得元です。
venv の項目では、`` version from `<evidence>` `` または `no version taken` に続けて、`pyvenv.cfg`・`home`・`version_info` を、値がある場合に出します。
`undetermined` の行では、これらを理由の前に置きます。
alias の場合は、sidecar と参照先のパスを出します。

| 形式 | 検査する条件 |
|---|---|
| venv | キーは `{evidence, pyvenv_cfg, home, version_info}` の4つちょうどで、`file` の項目だけに付けられます。 |
| venv の `evidence` | `pyvenv-home-pe-version-resource`、`pyvenv-cfg-version-info`、または `null` です。`null` は `undetermined` のときだけです。 |
| home からの取得 | `pyvenv-home-pe-version-resource` では `home` が必要です。 |
| cfg からの取得 | `pyvenv-cfg-version-info` では、`version_info` が `product_version` と同じである必要があります。 |
| alias | キーは `{evidence, target_file, target}` の3つちょうどで、`file` の項目だけに付けられます。 |
| alias の `evidence` | `install-manager-target-pe-version-resource` なら `target` は `null` 以外です。`evidence` が `null` なのは、判定が `undetermined` のときだけです。 |

## ルートの照合情報を読む

`roots` の各行は、`role`・`location_kind`・信頼を外した証明書のラベルを示します。
`found` には `matched_by` も出します。
AuthRoot と Disallowed の一覧には `this_update` と `last_sync` を出します。

ROOT と Disallowed のストアでは、キーごとに最終更新時刻を出します。
表示例は `` registry `HKLM\...\Certificates\<SHA-1>` last write `2026-10-22T04:36:15Z` `` です。
時刻が `null` なら `unknown` と注記、キーがなければその注記、読めないキーがあればその情報を出します。
1項目に2つ以上の証明書の一致があるときは、各部分の先頭に、その証明書の SHA-1 の先頭12桁を付けます。

| 欄・値 | 検査する条件 |
|---|---|
| 時刻 | `YYYY-MM-DDTHH:MM:SSZ`、または注記付きの `null` |
| レジストリのキー | 各オブジェクトに `key` と `last_write` の両方が必要 |
| `cert_sha1` | 16進40桁 |
| キーとエラー | オブジェクトの配列 |
| `registry_*`, `cert_sha1` | ROOT と Disallowed のストアの一致だけに付けられる |
| `last_sync` | AuthRoot と Disallowed の一覧だけに付けられる |
| `der_certs N` | バイナリの行で、解析した生の DER の数を示す。0以上の整数が必要 |
| `ignored_pem_blocks N` | バイナリと束で、無視した空の PEM の組の総数を示す。0以上の整数が必要 |
| `ignored_pem_blocks` | `reason: empty_pem_block` の `{offset, reason}` の配列 |
| `ignored_pem_blocks_total` | 指定した場合、列挙した組はちょうど20件であること |

同じ文書内で、同じ証明書が Disallowed にもあると示せる場合、信頼側の `found` の行に次の注記を付けます。
`note: Disallowed also lists this certificate; Windows does not trust it while it is in Disallowed`

- 同じラベルが Disallowed ストア（`cert-store:Disallowed`）で `found` であることが必要です。
- ROOT ストアか AuthRoot の一覧の `found` の一致に、Disallowed ストアの一致と同じ証明書 SHA-256 が必要です。
- 鍵だけが一致した別の証明書や、証明書 SHA-256 がない一致には付けません。
- 件数と終了コードは変わりません。
束とバイナリには付けません。

## 文字列を安全に表示する

文書から取った文字列は、コードスパンの中に書きます。
パス・場所・ラベル・バージョン・製品名・detail・`matched_by` が対象です。
細工したパスやバージョンで、Markdown や HTML を差し込めないようにします。

| 文字・値 | 表示 |
|---|---|
| 制御文字・書式文字 | `\uXXXX`。U+FFFF より上は `\UXXXXXXXX` |
| 対象となる文字の例 | 改行、タブ、U+2028、U+2029、双方向の制御文字、幅のない文字 |
| エスケープの先頭に見えるバックスラッシュ | `\u005c`。文字列 `\u000a` を含むパスと、改行を含むパスを区別します |
| 空白 | Unicode の空白も含めて、そのまま残します |
| パスや場所の区切り内のメールアドレス | `<email>`。例は `...\legacy_credentials\<email>\...` です |
| 後ろに文字が付くメールアドレス | `first.last@example.com (1)` は `<email> (1)` になります |
| メールとみなすドメイン | ドット、英字のトップレベルドメイン、その前の英字が必要です。`pkg@1.0.0.tgz` は変えません |

パスの残りの部分はそのままです。

## 台帳の入力検査と終了コード

件数は、項目から数え直します。
次の入力は終了コード 2 で拒否し、何も出さず、`--out` にも書きません。

| 拒否する入力 | 条件 |
|---|---|
| 文書と読み取り | 読めないファイル、不正な JSON、patchwait の文書でないもの |
| 件数 | `counts` と項目が一致しない |
| `scan` の `found` | バージョンがない、または `product_version` と違う |
| `roots` の `found` | `matched_by` がない |
| `scan` の場所 | `location_kind` が `file` でも `directory` でもない |
| `roots` の場所 | `location_kind` が未知、または `role` がその場所に合わない |

| コード | 条件 |
|---|---|
| 10 | いずれかの文書に、`scan` または `roots` が終了コード 10 を返す `found` がある |
| 0 | そのような `found` がない |
| 2 | 入力が不正、または出力先が入力文書と同じファイル |

`--out FILE` を付けると、標準出力の代わりに Markdown を原子的に書きます。
入力と同じパスや、別の名前で同じファイルを指定すると、終了コード 2 で何も書きません。

## 修正待ち一覧のファイルを書く

`waitlist` は、修正を待っている項目を手元の JSON ファイル（リポジトリには入れないでください）で持ちます。
項目ごとに id・件名・状態・再確認コマンド・最終確認日・最終結果があります:

```json
{
  "tool": "patchwait",
  "schema": 1,
  "kind": "waitlist",
  "items": [
    {
      "id": "editor-node",
      "title": "ExampleEditor bundles node 24.19.0",
      "status": {"state": "waiting_on_vendor", "vendor": "Example Vendor"},
      "recheck_command": "patchwait version-of Apps/ExampleEditor/resources/node.exe --kind node",
      "last_checked": "2026-10-01",
      "last_result": {"result": "found", "value": "24.19.0"}
    },
    {
      "id": "tool-root",
      "title": "Old root in ExampleTool cacert.pem",
      "status": {"state": "done", "resolution": "ExampleTool 3.2 removed it"},
      "recheck_command": "patchwait roots --distrust distrust.txt --pem Apps/ExampleTool/cacert.pem",
      "last_checked": "2026-09-15",
      "last_result": {"result": "not_found"}
    }
  ]
}
```

`status` は、次のいずれかの形です。

| 状態 | 必要な形 |
|---|---|
| 提供元の対応待ち | `{"state": "waiting_on_vendor", "vendor": ...}` |
| 対応中 | `{"state": "in_progress", "owner": ...}` |
| 判断待ち | `{"state": "awaiting_decision", "question": ...}` |
| 完了 | `{"state": "done", "resolution": ...}` |

- `last_result` は `{"result": "found", "value": ...}`・`{"result": "not_found"}`・`{"result": "undetermined", "reason": ..., "detail": ...}` のどれかで、理由は[理由の一覧](undetermined-reasons.ja.md)にある名前です。

- 項目には `result_link` を付けることもできます。
保存した `scan` や `roots` の結果のうち、どの行を追うかを示します（下の `record --from` を参照）。
付けていない項目は、書き換えた後も付きません。

- 省略可能な `cves` 配列には、大文字の ASCII で CVE ID をそのまま書きます。
例: `"cves": ["CVE-2026-0001", "CVE-2026-9999"]`。
各 ID は `CVE-YYYY-` の後に4桁以上の数字が続く形で、全体で64文字以内です。
空配列・重複・空白・小文字は拒否します。
`cves` が無い項目には、`record` や `record --from` がファイルを書き換えるときも追加しません。

- ファイルは厳しく検査します。
キーの不足や余分、空の文字列、未知の状態や理由、`YYYY-MM-DD` でない日付、今日より後の `last_checked`、重複した id、重複した JSON のキーは、終了コード 2 で、stderr にエラーを出し、stdout には何も出しません。

## 修正待ち項目を表示する

```bash
PYTHONPATH=src python -m patchwait.cli waitlist show waitlist.json --stale-days 14 --format markdown
```

`show` は項目ごとに、状態・最終確認からの日数・最終結果・再確認コマンドを出します。
コマンドは文字列として出すだけで、実行しません。

```markdown
2026-10-26: patchwait waitlist: 2 items (waiting_on_vendor 1, in_progress 0, awaiting_decision 0, done 1); stale 1 (more than 14 days, not done)

- waiting_on_vendor: `editor-node` `ExampleEditor bundles node 24.19.0` — vendor `Example Vendor` — last checked 2026-10-01 (25 days) — stale — last result found `24.19.0` — recheck `patchwait version-of Apps/ExampleEditor/resources/node.exe --kind node`
- done: `tool-root` `Old root in ExampleTool cacert.pem` — resolution `ExampleTool 3.2 removed it` — last checked 2026-09-15 (41 days) — last result not_found — recheck `patchwait roots --distrust distrust.txt --pem Apps/ExampleTool/cacert.pem`
```

- `--format markdown` を付けなければ JSON を出します。
キーは `tool`・`schema`・`generated`・`today`・`stale_days`・`counts`（`items`・`state`・`last_result`、`--stale-days` があるときは `stale` も）・`items` で、各項目はファイルと同じ形に `days_since_check` を足したものです。

- 日数は `--today YYYY-MM-DD` から、無ければ現地の日付から数えます。

- 既定の閾値はありません。
`--stale-days N` を渡したときだけ、`done` 以外で最終確認から N 日を超えた項目に stale の印（JSON では `"stale": true`、ほかは `false`）を付け、1件でもあれば終了コードは 10 です。
渡さなければ印は付かず、終了コードは 0 です。
`done` の項目に印は付きません。

- Markdown では、自由に書ける値（id・件名・vendor・owner・question・resolution・value・detail・コマンド）を、`ledger` と同じエスケープでコードスパンの中に書きます。

## 確認結果を1件記録する

```bash
PYTHONPATH=src python -m patchwait.cli waitlist record waitlist.json --id editor-node --result found --value 24.22.1
```

`record` は1つの項目の最終確認日と最終結果を書き換えます。
ファイル全体を一時ファイルに書いてから1回で置き換え、更新した項目を1行の JSON で出します。

| 結果の指定 | 併せて渡すもの |
|---|---|
| `--result found` | `--value` |
| `--result undetermined` | `--reason`（理由の名前）と `--detail` |
| `--result not_found` | どちらも付けません |

それ以外の組み合わせは終了コード 2 です。

- `--date YYYY-MM-DD` は確認した日付です。
既定は現地の日付で、未来の日付も、その項目のいまの `last_checked` より前の日付も受け付けません。
前の日付は終了コード 2 で、ファイルは変わりません。
同じ日付と後の日付は記録します。

- 他の項目とその順番、その項目の状態・件名・コマンドはそのままです。
未知の id や不正なファイルは終了コード 2 で、ファイルは変わりません。
`record` が書くのは、渡したファイルだけです。

- `record` は読んだ項目からファイル全体を書き直します。
そのため、手で編集したあとのファイルでも、改行は LF に、字下げは空白2つに、キーの順は patchwait の順にそろいます。

## 保存した結果を記録する

```bash
PYTHONPATH=src python -m patchwait.cli scan --kind node --min node=24.22.1 --root Apps --out scan.json
PYTHONPATH=src python -m patchwait.cli waitlist record waitlist.json --from scan.json
```

`record --from FILE` は、`scan --out` か `roots --out` で書いた結果を読み、`result_link` のある項目をすべて更新します。
`--id ID`（複数回指定できます）を付けると、その項目だけを更新します。
結果は `ledger` と同じ厳しさで検査します。
台帳のファイル、別のツールの文書、その他の形のものは終了コード 2 で、ファイルは変わりません。

保存した走査にStoreや保護フォルダーの根拠がある場合は、このコマンドのJSON応答にも `walk` を載せ、調べていない場所が分かるようにします。この情報はwaitlistのファイルには書かず、飛ばしたフォルダーの結果にも変換しません。追加フィールドがない従来の文書では、応答の形を変えません。

項目がどの行を追うかは `result_link` に書きます。
値は結果からそのまま写してください。
比べるときは文字列が完全に一致するかだけを見ます。
大文字と小文字、`/` と `\` の違いも含め、パスを正規化しないので、推測で結び付けることはありません。

```json
"result_link": {"check": "scan", "kind": "node", "path": "Apps\\ExampleEditor\\resources\\node.exe"}
```

```json
"result_link": {"check": "roots", "location_kind": "pem", "location": "Apps\\ExampleEditor\\certs\\cacert.pem", "distrust": "Example Distrusted Root"}
```

- `scan` では文書の `kind` と項目の `path`、`roots` では項目の `location_kind`・`location`・`distrust` のラベルで結び付けます。

- 最終結果には、その行の `verdict` をそのまま入れます。
`found`、`not_found`、または理由と詳細つきの `undetermined` です。
`undetermined` の行は `undetermined` のままです。
`roots` の `found` の値は、`matched_by` の一覧を `, ` でつないだもの（例: `sha1, sha256`）です。
`found` の意味は結果と同じなので、`distrust` 側（Disallowed）では、`roots` と同じく良い結果です。

- 最終確認日は、今日ではなく、結果の `generated` の日付（そこに書かれたオフセットでの日付）です。
今日より後の日付の結果は終了コード 2 です。

変更しない項目は `unchanged` に並べ、`why` に理由を付けます。

| `why` | 変更しない条件 |
|---|---|
| `no_result_link` | 項目に `result_link` がない |
| `not_found_in_result` | 一致する行がない。もう一方のコマンド用のリンクは一致しません |
| `ambiguous_in_result` | 同じリンクの行が2つ以上あり、判定が違う。同じ判定の行は1つと数えます。繰り返した `--path` も同じです |
| `checked_after_result` | 項目の `last_checked` が結果の日付より後。古い結果で新しい確認を置き換えません |

- `--from` には `--result`・`--value`・`--reason`・`--detail`・`--date` を付けられません。
`--from` を付けないときは、`--id` をちょうど1つ渡します。
ファイルに無い `--id` は終了コード 2 です。

- 出力は1つの JSON 文書で、キーは `tool`・`schema`・`from`・`check`（`scan` か `roots`）・`checked`（使った日付）・`counts`（`updated`・`changed`・`unchanged`）・`updated`（書いた形の各項目に `changed` を足したもの）・`unchanged` で、保存した走査に Store や保護フォルダーの情報がある場合は `walk` も付けます。
書き換えなかった項目があっても終了コードは 0 なので、`counts.unchanged` を見てください。

- ファイルは `record` と同じく、一時ファイルに書いてから1回で置き換えます。
書くのは、変わった項目があるときだけです。
同じコマンドをもう一度実行しても何も変わりません。
結果のファイルは読むだけで、再確認コマンドも実行しません。

## ScanMux が保存した KEV・JVN 情報を読む

`waitlist show FILE --intel-store DIR` は、別ツール ScanMux の `intel-refresh` がディスクに保存した CISA Known Exploited Vulnerabilities（KEV）カタログを読みます。
patchwait 自身は取得せず、そのストアにも書き込みません。
同じストアに保存された JVN の更新 RSS（`https://jvn.jp/rss/jvn.rdf`）も読みます。
この RSS には直近の更新が20件ほどしか入っていないので、CVE が最近の JVN の更新に出たことは示せても、JVN にその CVE の情報が無いことは示せません。
`--intel-store` が無ければ、既存項目の出力はバイト単位で従来どおりです。

## ストアを指定する

`DIR` には、次の条件を満たすストアを指定します。

| 確認するもの | 規則 |
|---|---|
| パス | 正規化済みの絶対ディレクトリです。Windows のローカル固定ドライブか RAM ドライブ上で、既存の場所確認を通る必要があります。ドライブの根は指定できません。 |
| 構成 | `attempts/` と `blobs/` の2ディレクトリだけを含みます。 |
| リンク | ストア、両子ディレクトリ、取得記録、本体ファイルは元のパスにある必要があります。シンボリックリンク、junction、その他の reparse point は経由できません。 |
| ストア側の失敗 | ストアや子ディレクトリの拒否、ストアの欠落、ディレクトリでない場所、その他の構成は終了コード 2 です。stdout には何も出しません。 |
| ファイル側の失敗 | 拒否した取得記録や本体ファイルは、使えないものとして数えます。 |
| URL | フィードの識別用です。接続しません。 |

## KEV の取得情報と結果を読む

JSON の先頭には `intel` を置き、`store` に指定したパスを入れます。
`intel.kev` は次の欄を持ちます。

| 欄 | 意味 |
|---|---|
| `catalogVersion`, `dateReleased` | 選んだカタログのバージョンと公開日時 |
| `completedAt` | 選んだ写しの取得完了時刻 |
| `days_since_fetch` | 取得から経過した24時間単位の整数日数 |
| `latest_attempt` | `stored`・`failed`・`none` |
| `invalid_attempts` | 不正な取得記録や、選択前に検査して使えなかった写しの数 |

使える写しがなければ、バージョン・公開日時・取得完了時刻・経過日数は `null` です。
`intel.kev` に `result: undetermined`・`reason`・`detail` も付けます。
`--today` は台帳の経過日数だけに使います。
KEV の時刻は現在の時計で検査します。

`cves` のある項目には、CVE ID をキーにした `kev` も付きます。

| 結果 | 値の形 |
|---|---|
| 掲載あり | `{"result": "listed", "dateAdded": ..., "dueDate": ..., "knownRansomwareCampaignUse": ...}` |
| この写しにない | `{"result": "not_listed"}` |
| 判定不能 | `{"result": "undetermined", "reason": ..., "detail": ...}` |

ランサムウェア欄が省略されていれば `null` にします。
`cves` のない項目には、`cves` も `kev` も追加しません。
Markdown も同じ取得情報と CVE ごとの結果を、エスケープしたコードスパンで出します。
KEV の結果は終了コードを変えません。
`--stale-days` は項目の最終確認日だけに適用します。

## KEV の写しを選んで検査する

取得記録と KEV 本体は、ScanMux と同じ規則で読みます。

| 確認するもの | 規則 |
|---|---|
| 取得記録の読み取り | ファイル名が規則に合うものを、64 KiB まで読みます。キーの過不足を拒否し、フィード URL とミリ秒付き UTC 時刻を検査します。 |
| JSON の文字列 | 厳密な UTF-8 で読み、先頭の BOM を1つ取り除きます。重複キーは最後の値を採用し、孤立サロゲートを受け入れます。 |
| JSON の数値 | JavaScript と同じ倍精度浮動小数点数として読みます。NaN と Infinity のトークンは拒否します。 |
| 出力する文字列 | 孤立サロゲートは U+FFFD に置換します。判定は変えません。 |
| 取得記録の順序 | 有効な KEV 記録を完了時刻の新しい順に並べ、同時刻なら失敗を先にします。 |
| 新しい失敗 | `latest_attempt: failed` と表示し、以前の使える写しを使います。 |
| 未来の記録 | 不正として数え、使いません。 |
| 未知の schema | 規則に合うファイル名の記録を JSON オブジェクトとして解析でき、`schema` が未知なら、KEV 照合全体を `source_malformed` にします。古い schema の写しへ戻りません。 |
| 本体を解析する前 | 宣言されたサイズと SHA-256 を確かめます。上限は 16 MiB です。 |
| KEV の内容 | 件数、正確な CVE ID、必須の文章、実在する日付、重複 CVE の一致を含む、ScanMux の規則で解析します。 |
| 取得元との一致 | カタログの版と公開日時が、取得記録の `source` と一致する必要があります。キーが `version`・`date` の順であることも含みます。 |
| 不正件数 | 不正な記録と、選択が成立するまでに検査して使えなかった保存済みの写しを `invalid_attempts` に数えます。 |
| 古い写しへの切り替え | 本体の破損、解析規則との不一致、source の不一致では、以前の有効な写しを試します。 |
| JSON の深さの上限 | 取得記録やカタログが Python の解析の深さを超えると、照合を `source_malformed` にします。ScanMux なら受け入れる可能性を detail に示し、古い写しには戻りません。 |

使える写しがない場合の理由は、次のとおりです。

| 条件 | 理由 |
|---|---|
| KEV の記録がない、または失敗記録だけ | `source_missing` |
| 壊れた KEV 記録、フィード不明の記録、不正な KEV 時刻、壊れた KEV 本体、解析規則との不一致 | `source_malformed` |

壊れた JVN・JVNDB 記録も `invalid_attempts` には数えますが、KEV の理由は決めません。
ただし、未知の schema の規則は常に適用します。
どちらの理由も `not_listed` にはしません。

## JVN の取得情報と結果を読む

JVN も KEV と同じ方法で写しを選びます。
`jvn` の保存済み取得記録から、次の条件を満たす最も新しい写しを使います。

- 本体のサイズと SHA-256 が記録と一致すること。
上限は 1 MiB です。
- 解析でき、取得記録の `source` と一致すること。
JVN の形は `{"version": null, "date": <channel time>}` です。

| `intel.jvn` の欄 | 意味 |
|---|---|
| `modified` | channel の `dcterms:modified`、それがなければ `dc:date`。選んだ値がないか不正な時刻なら `null` |
| `oldest`, `newest` | item の最も古い時刻と最も新しい時刻 |
| `items` | item の数 |
| `completedAt`, `days_since_fetch`, `latest_attempt`, `invalid_attempts` | `intel.kev` と同じ欄 |

使える写しがなければ、`modified`・`oldest`・`newest`・`items`・`completedAt`・`days_since_fetch` は `null` です。
`intel.jvn` に `result: undetermined`・`reason`・`detail` も付けます。
`invalid_attempts` は、全フィードの不正な記録と、このフィードの使えなかった写しの合計です。
そのため KEV と JVN の数は違うことがあります。
壊れた記録が KEV や JVNDB を名乗っていても、JVN の理由は `source_malformed` になりません。
前節で説明した、未知の schema と解析の深さの制限は JVN にも適用します。

`cves` のある項目には、CVE ID をキーにした `jvn` も付きます。

| 結果 | 値の形 |
|---|---|
| 直近の更新に出た | `{"result": "observed", "items": [{"identifier": ..., "link": ..., "modified": ...}]}`。CVE を含む RSS の item をすべて並べます |
| この範囲にない | `{"result": "not_observed_in_window", "oldest": ..., "newest": ..., "items": N}` |
| 判定不能 | `{"result": "undetermined", "reason": ..., "detail": ...}` |

`not_observed_in_window` は、写した範囲にないという意味だけです。
Markdown は、各 CVE の `kev` の下に `jvn` の行を出します。
JVN の結果は終了コードを変えません。

## JVN RSS を検査する

RSS は ScanMux と同じ規則で読みます。

| 確認するもの | 規則 |
|---|---|
| 文字コード | 厳密な UTF-8 で読み、先頭の BOM を1つ取り除きます。XML で使える文字だけを受け付けます。 |
| 宣言 | 処理命令は XML 宣言だけで、先頭にだけ置けます。DOCTYPE と ENTITY の宣言は拒否します。 |
| コメントと CDATA | コメントを読み飛ばします。コメント内の item は数えません。CDATA は要素の中だけで使えます。 |
| 根と入れ子 | 閉じた `rdf:RDF` の根1つの下に、正しく入れ子にします。根の外はコメントと、JavaScript の trim が取り除く空白だけです。U+FEFF も含みます。 |
| 実体参照 | 定義済みの5つと数値文字参照だけを、本文と属性値で受け付けます。 |
| 属性 | 同じ要素で同じ属性を繰り返せません。 |
| item の数と場所 | `item` 要素は1〜1000個で、すべて根の直下です。 |
| item の欄 | `title`・`link`・`description`・`dc:identifier`・`dc:date`・`dcterms:issued`・`dcterms:modified` は、それぞれ1回までで子要素なしです。 |
| 識別子 | `JVN…#…` の形が必要です。 |
| リンク | `https://jvn.jp/` の後に、`!` から `~` の ASCII 文字が1〜500字続く形です。空白は含めません。 |
| title と時刻 | title は必須です。時刻は `dcterms:modified` を使い、それがなければ `dc:date` を使います。 |
| 時刻の形式 | `YYYY-MM-DDThh:mm[:ss[.fraction]]` で、小数は9桁までです。後ろに `Z` または `+hh:mm`・`-hh:mm` が必要です。 |
| 時刻の値 | 実在する日付で、時は23まで、分と秒は59までです。時差にも同じ制限を適用します。 |
| channel の欄 | `channel` の同じ欄に、1回まで・子要素なしの規則を適用します。 |
| CVE の抽出元 | title と description の独立した語だけから取ります。前後が ASCII 英字・数字・`_`・`-` なら取りません。 |
| CVE の表記 | 大文字小文字を区別せず探し、大文字で出します。64字を超える語は捨てます。 |

## うまくいかないとき

> Q. `ledger` が終了コード 2 で何も出さないのはなぜですか。
> A. 読取不能、不正な JSON、patchwait 以外の文書、項目と件数の不一致、または必要な欄の不正を拒否します。`--out` にも書きません。入力と同じパスや、別名の同じファイルを出力先にすることも拒否します。

> Q. 古い項目が stale にならないのはなぜですか。
> A. 既定の閾値はありません。`--stale-days N` を渡したときだけ、`done` 以外で最終確認から N 日を超えた項目に印を付けます。

> Q. `record --from` の終了コードが 0 でも、変わらない項目があるのはなぜですか。
> A. `counts.unchanged` と、各項目の `why` を見てください。結果が古い場合や、リンクがない・一致しない・曖昧な場合は書き換えません。

> Q. JVN の `not_observed_in_window` は、JVN に情報がないという意味ですか。
> A. 保存した直近の RSS の範囲にない、という意味だけです。JVN 全体に情報がないとは示しません。

## セキュリティ上の注意

- ACL（アクセス権の設定）は検査しません。
ストアに書ける人は、写しとハッシュを差し替えられます。
- `not_listed` は、この写しにないという意味だけです。
- 経過日数に既定の鮮度の閾値は設けず、古い写しを最新とは呼びません。
- 読み取り前後にパスを再確認しますが、同時に書き込む人は確認と open の間にリンクを差し替えられます。
ほかのローカルパス確認と同じ制限です。

## 保存済み情報の例を読む

次のコマンドと結果の抜粋は、KEV カタログと item 1件の JVN RSS のどちらにも `CVE-2026-0001` だけを含む合成ストアで実行したものです。
例のパスは、実行時の一時パスを置き換えています:

```bash
PYTHONPATH=src python -m patchwait.cli waitlist show synthetic-waitlist.json --intel-store 'C:\Example\scanmux-intel'
```

```json
"cves": ["CVE-2026-0001", "CVE-2026-9999"],
"kev": {
  "CVE-2026-0001": {"result": "listed", "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown"},
  "CVE-2026-9999": {"result": "not_listed"}
},
"jvn": {
  "CVE-2026-0001": {"result": "observed", "items": [{"identifier": "JVNVU#00000001", "link": "https://jvn.jp/vu/JVNVU00000001/", "modified": "2026-10-26T12:00+09:00"}]},
  "CVE-2026-9999": {"result": "not_observed_in_window", "oldest": "2026-10-26T12:00+09:00", "newest": "2026-10-26T12:00+09:00", "items": 1}
}
```

## 関連ドキュメント

- [概要とコマンド一覧](../README.ja.md)
- [使い始める](getting-started.ja.md)
- [ランタイムを走査する](scan.ja.md)
- [信頼を外されたルートを探す](roots.ja.md)
- [`undetermined` の理由](undetermined-reasons.ja.md)
