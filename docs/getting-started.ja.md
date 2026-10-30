[English](getting-started.md) | [日本語](getting-started.ja.md)

# 使い始める

チェックアウトから patchwait を試す人向けに、合成ファイルのバージョンを読んで比較する手順を説明します。

アプリに同梱されたランタイムは、アプリごとに更新時期が違います。
まず小さな例で、古い版・最低版と同じ版・比較材料がない版の違いを確かめます。

## 対象の範囲

以下は合成の例です。
偽の実行ファイルを起動しないでください。
最低の修正版は使う側が決めます。
ネットワークへの接続や証明書ストアの変更はしません。

## できること

- コマンドのヘルプを表示します。
- 合成の `Apps/` フォルダを作ります。
- ファイル1つのバージョンを読みます。
- 3つのランタイムを最低版と比べます。

## 必要なもの

- Python 3.11 以上。
外部パッケージは不要です。
- リポジトリのチェックアウト。
以下は、そのルートで PowerShell から実行します。
- 例を作る場所には、まだ `Apps/` と `distrust.pem` がないことを確かめてください。
- 試験は Windows でのみ実行しています。

## 最初の走査を実行する

1. `src` を Python の検索先に加え、コマンド一覧を表示します。

```powershell
$env:PYTHONPATH = "src"
python -m patchwait.cli --help
```

`version-of`・`scan`・`roots`・`ledger`・`waitlist` のヘルプが表示されます。

2. 試験用の生成コードで、偽の実行ファイル3つ、PEM の束2つ、バイナリ1つと、比較用の証明書を作ります。

```powershell
@'
from pathlib import Path
from tests.pe_builder import VersionSpec, build_pe
from tests.cert_builder import build_cert, pem

if Path("Apps").exists() or Path("distrust.pem").exists():
    raise SystemExit("Use a directory without Apps/ or distrust.pem")
for name, version in [
    ("ExampleEditor/resources/node.exe", "24.19.0"),
    ("ExampleCurrent/node.exe", "24.22.1"),
    ("ExampleTool/node.exe", "20.1.0"),
]:
    parts = tuple(int(part) for part in version.split(".")) + (0,)
    spec = VersionSpec(
        strings={"ProductName": "Node.js", "ProductVersion": version},
        fixed_file=parts, fixed_product=parts,
    )
    path = Path("Apps") / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pe(version=spec)[0])
bad = build_cert("Example Distrusted Root", b"example-key" * 40)
good = build_cert("Example Trusted Root", b"other-key" * 40)
for name, data in [
    ("Apps/ExampleEditor/certs/cacert.pem", pem(bad) + pem(good)),
    ("Apps/ExampleSync/certs.pem", pem(good)),
    ("Apps/ExampleSync/bin/sync.exe", b"synthetic prefix" + bad),
    ("distrust.pem", pem(bad)),
]:
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
print("Created Apps/ and distrust.pem")
'@ | python -
```

`Created Apps/ and distrust.pem` と表示されます。
試験も同じ種類のファイルをその場で作ります。
本物のバイナリや証明書は使いません。

3. ExampleEditor に同梱された Node.js のバージョンを読みます。

```powershell
python -m patchwait.cli version-of Apps/ExampleEditor/resources/node.exe --kind node
```

JSON の `result` と `value.version.result` が `found`、`value.version.value` が `24.19.0`、`value.evidence` が `pe-version-resource` になります。
終了コードは 0 です。

4. `Apps/` の Node.js を、例として渡す最低版と比べます。

```powershell
python -m patchwait.cli scan --kind node `
  --min node=24.22.1 `
  --source node=https://nodejs.org/en/blog/vulnerability `
  --root Apps
```

`counts` は `targets: 3`・`found: 1`・`not_found: 1`・`undetermined: 1` になります。
終了コードは 10 です。

| バージョン | 結果 | 理由 |
|---|---|---|
| `24.19.0` | `found` | 最低版 `24.22.1` より古い |
| `24.22.1` | `not_found` | 最低版より古くない |
| `20.1.0` | `undetermined` | 20.x 系列の最低版がないため `no_baseline` |

## 結果を保存する

`scan` と `roots` は JSON 文書を1つ標準出力に出します。
`--out FILE` を付けると、一時ファイルに書いてから出力先を1回で置き換えます。

## うまくいかないとき

> Q. 終了コードが 0 なら、すべて調べられていますか。
> A. 判定不能の項目があっても、`scan` と `roots` の終了コードは変わりません。`counts.undetermined`、またはルートの `counts.trust.undetermined` と `counts.distrust.undetermined` も見てください。

> Q. `20.1.0` が修正済みと判定されないのはなぜですか。
> A. 20.x 系列の最低版がないためです。`--min` は系列ごとに渡します。

## セキュリティ上の注意

- patchwait は調べる実行ファイルを起動しません。
- 証明書ストアや束を書き換えず、ネットワークに接続しません。
- patchwait が書くのは、指定した `--out` の結果と、`waitlist record` に渡したファイルだけです。

## 関連ドキュメント

- [ランタイムを走査する](scan.ja.md)
- [信頼を外されたルートを探す](roots.ja.md)
- [台帳と修正待ち一覧を使う](ledger-and-waitlist.ja.md)
- [`undetermined` の理由](undetermined-reasons.ja.md)
- [概要とコマンド一覧](../README.ja.md)
