[English](undetermined-reasons.md) | [日本語](undetermined-reasons.ja.md)

# `undetermined` の理由

判定できなかった項目を調べる人向けに、`undetermined` の理由コードと発生元を一覧にします。

読取不能や比較材料の不足は、見つからなかったことを意味しません。
理由と detail を読んで、何を確認できなかったかを確かめてください。

## 対象の範囲

表のコマンドは理由の発生元です。
`ledger` と `waitlist` は、保存・記録された結果の理由も表示します。

## 理由を調べる

detail が `__target__ route:` から始まる場合、理由はインストールマネージャーの sidecar または参照先についてのものです。
この経路で PE に関する理由は、参照先の PE を指します。

| 理由 | 意味 | 発生元のコマンド |
|---|---|---|
| `target_missing` | パスが存在しない（`scan` と `roots`） | `scan`, `roots` |
| `duplicate_key` | venv の `pyvenv.cfg` に同じキーが2回以上ある（`scan` と `version-of`） | `scan`, `version-of` |
| `file_unreadable` | 調べているファイルかディレクトリが読めない。インストールマネージャーの参照先の場合もある | `scan`, `version-of`, `roots` |
| `not_pe` | 調べているファイルが PE ファイルではない。インストールマネージャーの参照先の場合もある | `scan`, `version-of` |
| `no_version_resource` | PE の版リソースがない、または Python の補完処理（`pyvenv.cfg` か `__target__`）で版を取得できない。欠落した情報や拒否した入力は detail を参照 | `scan`, `version-of` |
| `malformed_version_resource` | 版リソースが壊れている、または版の先頭が `N.N.N` の形ではない（`scan` では `N.N.N` ちょうどでない）。venv の `pyvenv.cfg` が不正な場合や、版を比べられない場合も含む（`scan` と `version-of`） | `scan`, `version-of` |
| `version_mismatch` | 文字列表と固定情報で major.minor が食い違う、または venv の `home` の版と `version_info` で食い違う（`scan` と `version-of`） | `scan`, `version-of` |
| `unexpected_product` | `ProductName` が無いか、`--kind` で決まる製品名（node なら `Node.js`、python なら `Python`）と違う | `scan`, `version-of` |
| `no_baseline` | その系列の `--min` がない | `scan` |
| `store_unreadable` | レジストリの値か証明書ストアが読めない | `roots` |
| `malformed_ctl` | 証明書の信頼リストを解析できない | `roots` |
| `malformed_keystore` | Java キーストアの形式不明、構造不正、または未対応の version | `roots` |
| `keystore_unreadable` | Java キーストアに、証明書を含む可能性のある暗号化・未対応の部分がある | `roots` |
| `malformed_cert` | 一部の証明書が解析できず、一致もない | `roots` |
| `no_certs_recognised` | ファイルの中に証明書が見つからない | `roots` |
| `no_usable_identifier` | 渡した識別子では、その場所と比べられない | `roots` |
| `not_windows` | Windows 以外で `--windows` を使った | `roots` |
| `source_missing` | 使える保存済みの KEV または JVN RSS がない。そのフィードの取得記録がないか、失敗記録のみ | `waitlist show --intel-store` |
| `source_malformed` | KEV または JVN RSS の根拠を信用できない。記録の破損や未知の schema、不正な時刻、本体の破損、解析規則や source の不一致があり、使える代替の写しがない（未知の schema は常に照合を止める） | `waitlist show --intel-store` |

`scan --root` では、一覧取得できないディレクトリが必ず `undetermined` の項目になるとは限りません。
現在の利用者のパッケージ登録を使って走査した Store の根は `walk[].package_root` に記録します。読めない登録パッケージディレクトリは `file_unreadable` のままです。
レジストリの情報を読めない、または値が不正な場合は、元の `file_unreadable` の項目を残し、`walk[].package_root_error` を付けます。
`PackageRoot` を特定できた場合、それ以外のディレクトリで一覧取得と権限情報の読み取りの両方が拒否されると、`walk[].skipped_protected` に `reason: listing_and_permissions_denied` として記録します。
これは走査範囲の情報で、`undetermined` の理由ではありません。これらのフォルダーの中は調べていません。
適用条件は[走査ガイド](scan.ja.md)、件数の扱いは[走査フィールド](ledger-and-waitlist.ja.md#走査の範囲を読む)を参照してください。

## 関連ドキュメント

- [使い始める](getting-started.ja.md)
- [ランタイムを走査する](scan.ja.md)
- [信頼を外されたルートを探す](roots.ja.md)
- [台帳と修正待ち一覧を使う](ledger-and-waitlist.ja.md)
- [概要とコマンド一覧](../README.ja.md)
