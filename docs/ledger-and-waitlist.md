[English](ledger-and-waitlist.md) | [日本語](ledger-and-waitlist.ja.md)

# Use a ledger and waitlist

Use `ledger` and `waitlist` to keep check results and track items waiting on an app vendor.

Turn saved results into Markdown, then keep each waiting item with its last check date and recheck command.

## Scope

`ledger` keeps no state and does not compare runs.
`waitlist` prints recheck commands without running them.
Saved information is read without network requests.

## What it does

- Render saved results as Markdown.
- Show waiting items and record check dates and results.
- Match explicit CVE IDs against KEV and JVN copies saved by ScanMux.

## Requirements

For checkout setup, follow [Get started](getting-started.md).
The Bash examples below set `PYTHONPATH=src` for each command.

- Python 3.11 or later, with no third-party packages.
- Saved `scan` or `roots` documents for `ledger` and `record --from`.
- A local JSON waitlist file, kept out of any repository.
- A ScanMux store on a Windows local fixed or RAM drive for `--intel-store`.

## Render a ledger

```bash
PYTHONPATH=src python -m patchwait.cli ledger --brief scan.json
```

`ledger` reads one or more documents written by `scan --out` or `roots --out` and prints Markdown, one block per document in the order given:

```markdown
10-25: patchwait scan node: found 1 / not_found 1 / undetermined 2 (file_unreadable 1, no_baseline 1); not walked: skipped_reparse_points 1, excluded_dirs 0

- found: `Apps\ExampleEditor\resources\node.exe` — `24.19.0` < `24.22.1`, product `unknown` (inferred)
- undetermined: `Apps\ExampleTool\node.exe` — no_baseline: `no --min for node series 20`
- undetermined: `Apps\Locked` (directory) — file_unreadable: `PermissionError`
- not_found: 1 items
```

- The first line is a summary to paste into a ledger.
  Its date is the local date in the document's `generated`, not today's.
  For `roots` it reads `trust found N / not_found N / undetermined N; distrust found N / ...`.

- Reasons for `undetermined` are counted in parentheses, most frequent first.

- For `scan`, the summary ends with `; not walked: skipped_reparse_points N, excluded_dirs N` when a `--root` walk reports skipped reparse points, excluded directories, protected folders, or absent, unreadable or refused packages.
  When present, it also shows `skipped_protected` and nonzero `package_absent`, `package_unreadable` and `package_refused` counts. Separate lines show each protected path and its administrator-check note, each `package_root` with all counters and its current-user limitation, refused names, and any `package_root_error`. `ledger` and `waitlist record --from` strictly validate these optional fields, including list/count agreement and package accounting; malformed fields give exit code 2.
  For `roots`, a `--pem-root` directory that skipped reparse points or key-only PEM files shows `skipped_reparse_points N` and `skipped_key_only N` on its lines, and the summary ends with `; not walked: skipped_reparse_points N, skipped_key_only N` (each directory counted once).
  `--brief` keeps the summary and walk evidence, so these counts stay visible.

- Every `found` and `undetermined` item gets its own line.
  `not_found` items do too, unless `--brief` turns them into one count: `- not_found: N items` for `scan`, `- not_found: N items (trust N, distrust N)` for `roots`.
  `undetermined` items are never collapsed.

- Items are grouped as `found`, `undetermined`, `not_found` and keep the document's order inside each group.
  For a walked `--root`, its directory items (a missing root, unreadable directories) come after its file items.

- The words are the JSON values (`found`, `not_found`, `undetermined` and the reason names), not translations.

- `ledger` keeps no state and does not compare with earlier runs.

## Read scan walk evidence

A `scan` document has one `walk` entry per `--root`.

| Field | Meaning |
|---|---|
| `root` | The requested root path. |
| `matched_files` | Matching files before duplicate merging. |
| `unreadable_dirs` | Unresolved walk read failures emitted as directory items. Excludes a Store root represented by `package_root` and protected folders recorded as `skipped_protected`. |
| `skipped_reparse_points`, `excluded_dirs` | Skipped locations in this walk, already including the corresponding `package_root` counters. Do not add the package counters again. |
| `package_root` | Optional Store fallback evidence, with the fields below. |
| `package_root_error` | Optional registry read or validation failure; original unreadable items are retained. Cannot appear with `package_root` in the same entry. |
| `skipped_protected`, `skipped_protected_count` | Optional list of `{path, reason}` and its length. The reason is `listing_and_permissions_denied`. Both fields appear together. |

`walk[].package_root` contains `path`, `packages_registered`, `walked` (package directories successfully listed), `unreadable`, `absent`, `excluded`, `skipped_reparse_points`, `refused` (unsafe subkey names as ASCII JSON string literals, including quotes), and `note`. For example, an empty name is stored as the literal `""`, and a name containing one space as `" "`. Escaping preserves every character while keeping the entries readable by `ledger` and `waitlist record --from`. `packages_registered` equals `walked + unreadable + absent + excluded + skipped_reparse_points + len(refused)`.

`walked` counts packages whose own directory listing succeeded; it does not prove every subdirectory was inspected.
`counts.targets` and verdict counts cover only `items`.
An unreadable registered package directory remains an `undetermined` item and contributes to `unreadable_dirs`; its `package_root.unreadable` counter describes the same failure, so do not add them together.
The unlistable Store root represented by `package_root`, protected folders, and absent, excluded, reparse or refused package entries add no item or `counts.undetermined`.
See the [scan guide](scan.md) for the Windows handling and its limits.

## Read runtime evidence

`scan` items use `version_source` for the evidence described in the [scan guide](scan.md).
For venvs, print `` version from `<evidence>` `` or `no version taken`, then `pyvenv.cfg`, `home`, and `version_info` when given.
On `undetermined` lines, put these before the reason.
For aliases, print the sidecar and target paths.

| Shape | Validation |
|---|---|
| Venv | Require exactly `{evidence, pyvenv_cfg, home, version_info}`, on `file` items only. |
| Venv `evidence` | Allow `pyvenv-home-pe-version-resource`, `pyvenv-cfg-version-info`, or `null`. Allow `null` only for `undetermined`. |
| Home evidence | Require `home` for `pyvenv-home-pe-version-resource`. |
| Cfg evidence | Require `version_info` equal to `product_version` for `pyvenv-cfg-version-info`. |
| Alias | Require exactly `{evidence, target_file, target}`, on `file` items only. |
| Alias `evidence` | Require a non-null `target` for `install-manager-target-pe-version-resource`. Allow null `evidence` only for an `undetermined` verdict. |

## Read root evidence

Each `roots` line shows `role`, `location_kind`, and the distrust label.
A `found` line also shows `matched_by`.
AuthRoot and Disallowed list lines show `this_update` and `last_sync`.

ROOT and Disallowed store lines show each registry key and its last write.
For example: `` registry `HKLM\...\Certificates\<SHA-1>` last write `2026-10-22T04:36:15Z` ``.
A null time shows `unknown` with its note.
Missing and unreadable keys show their notes or errors.
When an item matches two or more certificates, prefix each part with the first 12 hex digits of that certificate's SHA-1.

| Field or value | Validation |
|---|---|
| Times | Require `YYYY-MM-DDTHH:MM:SSZ`, or `null` with a note. |
| Registry keys | Require both `key` and `last_write` on each object. |
| `cert_sha1` | Require 40 hex digits. |
| Keys and errors | Require lists of objects. |
| `registry_*`, `cert_sha1` | Allow only on ROOT and Disallowed store matches. |
| `last_sync` | Allow only on AuthRoot and Disallowed lists. |
| `der_certs N` | Show parsed raw DER counts on binary lines. Require a non-negative integer. |
| `ignored_pem_blocks N` | Show the full ignored-empty-PEM count on binary and bundle lines. Require a non-negative integer. |
| `ignored_pem_blocks` | Require a list of `{offset, reason}` with `reason: empty_pem_block`. |
| `ignored_pem_blocks_total` | When present, require exactly 20 listed blocks. |

When the same document proves that Disallowed also lists a trust-side certificate, append this note to its `found` line:
`note: Disallowed also lists this certificate; Windows does not trust it while it is in Disallowed`

- Require the same distrust label to be `found` in `cert-store:Disallowed`.
- Require a `found` ROOT-store or AuthRoot-list match with the same certificate SHA-256 as a Disallowed-store match.
- Add no note for a different certificate matched only by key, or a match without certificate SHA-256.
- Leave counts and exit codes unchanged.
  Add no note to bundles or binaries.

## Escape text safely

Write text taken from documents inside code spans.
This includes paths, locations, labels, versions, product names, details, and `matched_by`.
A crafted version or path cannot insert Markdown or HTML.

| Character or value | Rendering |
|---|---|
| Control and format characters | Use `\uXXXX`, or `\UXXXXXXXX` above U+FFFF. |
| Examples of escaped characters | Newlines, tabs, U+2028, U+2029, bidirectional characters, and zero-width characters. |
| Backslash resembling an escape prefix | Use `\u005c`. A path containing literal `\u000a` stays different from one containing a newline. |
| Spaces | Keep them, including Unicode spaces. |
| Email in a path or location segment | Use `<email>`, as in `...\legacy_credentials\<email>\...`. |
| Email with a suffix | `first.last@example.com (1)` becomes `<email> (1)`. |
| Email domain | Require a dot, a letter top-level domain, and a letter before it. Keep `pkg@1.0.0.tgz`. |

Keep the rest of the path verbatim.

## Validate ledger input and exit codes

Recompute counts from items.
Reject the following inputs with exit code 2, print nothing, and do not write `--out`:

| Rejected input | Condition |
|---|---|
| Document or read | Unreadable file, invalid JSON, or a document not from patchwait |
| Counts | `counts` disagree with items |
| `scan` `found` | Missing version, or version differs from `product_version` |
| `roots` `found` | Missing `matched_by` |
| `scan` location | `location_kind` is neither `file` nor `directory` |
| `roots` location | Unknown `location_kind`, or a `role` that does not fit it |

| Code | Condition |
|---|---|
| 10 | Any document contains a `found` for which `scan` or `roots` would exit 10 |
| 0 | No such `found` |
| 2 | Invalid input, or the output names an input file |

`--out FILE` writes Markdown atomically instead of printing it.
If it names an input document, by the same path or another name for the same file, exit with 2 and write nothing.

## Write a waitlist file

`waitlist` keeps the items you are waiting on in a JSON file on your PC (keep it out of any repository).
Each item has an id, a title, a state, a recheck command, the date of the last check and the last result:

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

Use one of these `status` shapes:

| State | Required shape |
|---|---|
| Waiting for the vendor | `{"state": "waiting_on_vendor", "vendor": ...}` |
| Work in progress | `{"state": "in_progress", "owner": ...}` |
| Waiting for a decision | `{"state": "awaiting_decision", "question": ...}` |
| Done | `{"state": "done", "resolution": ...}` |

- `last_result` is `{"result": "found", "value": ...}`, `{"result": "not_found"}` or `{"result": "undetermined", "reason": ..., "detail": ...}` with a reason name from the [reason reference](undetermined-reasons.md).

- An item may also have a `result_link`, which names the row of a saved `scan` or `roots` result it follows (see `record --from` below).
  Items without it are written without it.

- An optional `cves` array names exact uppercase ASCII CVE IDs, for example `"cves": ["CVE-2026-0001", "CVE-2026-9999"]`.
  Each ID is `CVE-YYYY-` followed by at least four digits, at most 64 characters in all.
  Empty arrays, duplicates, whitespace and lowercase IDs are rejected.
  Items without `cves` keep their shape, including when `record` or `record --from` rewrites the file.

- The file is read strictly.
  Missing or extra keys, an empty string, an unknown state or reason, a date that is not `YYYY-MM-DD`, a `last_checked` after today, a duplicate id or a duplicate JSON key gives exit code 2, an error on stderr and nothing on stdout.

## Show waiting items

```bash
PYTHONPATH=src python -m patchwait.cli waitlist show waitlist.json --stale-days 14 --format markdown
```

`show` prints each item with its state, the days since its last check, the last result and the recheck command.
The command is printed as text and never run.

```markdown
2026-10-26: patchwait waitlist: 2 items (waiting_on_vendor 1, in_progress 0, awaiting_decision 0, done 1); stale 1 (more than 14 days, not done)

- waiting_on_vendor: `editor-node` `ExampleEditor bundles node 24.19.0` — vendor `Example Vendor` — last checked 2026-10-01 (25 days) — stale — last result found `24.19.0` — recheck `patchwait version-of Apps/ExampleEditor/resources/node.exe --kind node`
- done: `tool-root` `Old root in ExampleTool cacert.pem` — resolution `ExampleTool 3.2 removed it` — last checked 2026-09-15 (41 days) — last result not_found — recheck `patchwait roots --distrust distrust.txt --pem Apps/ExampleTool/cacert.pem`
```

- Without `--format markdown` it prints JSON: `tool`, `schema`, `generated`, `today`, `stale_days`, `counts` (`items`, `state`, `last_result`, and `stale` when `--stale-days` is given) and `items`, each in the file's shape plus `days_since_check`.

- Days are counted from `--today YYYY-MM-DD`, or else from the local date.

- There is no default threshold.
  Only with `--stale-days N` is an item that is not `done` and was last checked more than N days ago marked stale (`"stale": true` in JSON, `false` on the others), and the exit code is 10 when at least one item is stale.
  Without it there are no marks and the exit code is 0.
  `done` items are never stale.

- In Markdown every free-text value (id, title, vendor, owner, question, resolution, value, detail, command) is written in a code span with the same escaping as `ledger`.

## Record one check

```bash
PYTHONPATH=src python -m patchwait.cli waitlist record waitlist.json --id editor-node --result found --value 24.22.1
```

`record` sets the last check date and the last result of one item.
It writes the whole file to a temporary file, replaces the file in one step and prints the updated item as one JSON line.

| Result argument | Required companion arguments |
|---|---|
| `--result found` | `--value` |
| `--result undetermined` | `--reason` (a reason name) and `--detail` |
| `--result not_found` | Neither |

Other combinations give exit code 2.

- `--date YYYY-MM-DD` is the date of the check.
  It defaults to the local date and may not be in the future, nor before the item's current `last_checked`.
  A date before it gives exit code 2 and leaves the file unchanged.
  The same date or a later one is recorded.

- The other items, their order and the item's state, title and command stay as they are.
  An unknown id or an invalid file gives exit code 2 and leaves the file unchanged.
  `record` writes only the file it is given.

- `record` writes the whole file again from the items it read, so the file comes out with LF line endings, two-space indentation and the keys in patchwait's order, even if it was edited by hand before.

## Record a saved result

```bash
PYTHONPATH=src python -m patchwait.cli scan --kind node --min node=24.22.1 --root Apps --out scan.json
PYTHONPATH=src python -m patchwait.cli waitlist record waitlist.json --from scan.json
```

`record --from FILE` takes a document written by `scan --out` or `roots --out` and updates every item that has a `result_link`, or with `--id ID` (repeatable) only those items.
The result is read as strictly as `ledger` reads it.
A waitlist, a document from another tool or any other shape gives exit code 2 and leaves the file unchanged.

When a saved scan has Store or protected-folder evidence, the command's JSON response includes its `walk` entries so that uninspected locations remain visible. This evidence is not written into the waitlist or turned into a result for a skipped folder. Older documents without these fields keep the previous response shape.

An item names the row it follows in `result_link`.
Copy the values from the result.
They are compared as exact strings: case, `/` versus `\` and the rest of the path are not normalised, so nothing is matched by guessing.

```json
"result_link": {"check": "scan", "kind": "node", "path": "Apps\\ExampleEditor\\resources\\node.exe"}
```

```json
"result_link": {"check": "roots", "location_kind": "pem", "location": "Apps\\ExampleEditor\\certs\\cacert.pem", "distrust": "Example Distrusted Root"}
```

- For `scan` the link is the document's `kind` and the item's `path`.
  For `roots` it is the item's `location_kind`, `location` and `distrust` label.

- The last result is the row's `verdict` as it is: `found`, `not_found`, or `undetermined` with its reason and detail.
  An `undetermined` row stays `undetermined`.
  For `roots`, the `found` value is the `matched_by` list joined with `, ` (for example `sha1, sha256`).
  `found` keeps the meaning it has in the result, so on the `distrust` side (Disallowed) it is good, as in `roots`.

- The last check date is the date in the result's `generated` (with the offset written there), not today.
  A result dated after today gives exit code 2.

Unchanged items appear under `unchanged`, with a `why` value:

| `why` | Condition |
|---|---|
| `no_result_link` | The item has no `result_link` |
| `not_found_in_result` | No row matches its link. A link for the other command never matches |
| `ambiguous_in_result` | Two or more rows match but have different verdicts. Equal verdicts count once, including repeated `--path` rows |
| `checked_after_result` | The item's `last_checked` is after the result date. An older result never replaces a newer check |

- `--result`, `--value`, `--reason`, `--detail` and `--date` cannot be used with `--from`.
  Without `--from`, `record` takes exactly one `--id`.
  An `--id` that is not in the file gives exit code 2.

- The output is one JSON document: `tool`, `schema`, `from`, `check` (`scan` or `roots`), `checked` (the date used), `counts` (`updated`, `changed`, `unchanged`), `updated` (each item as written, plus `changed`) and `unchanged`, plus `walk` when the saved scan contains Store or protected-folder evidence.
  The exit code is 0, also when items were left unchanged; read `counts.unchanged`.

- The file is written as `record` writes it, through a temporary file that replaces it in one step, and only when an item changed.
  Running the same command again changes nothing.
  The result file is only read, and no recheck command is run.

## Read saved KEV and JVN information from ScanMux

`waitlist show FILE --intel-store DIR` reads the CISA Known Exploited Vulnerabilities (KEV) catalog saved by ScanMux's `intel-refresh`.
patchwait never fetches it and never writes to that store.
It also reads the JVN recent-update RSS (`https://jvn.jp/rss/jvn.rdf`) saved in the same store.
That RSS holds only the latest updates, about 20 items.
It can show that a CVE appeared in a recent JVN update.
It cannot show that JVN has nothing on the CVE.
Without `--intel-store`, the output is unchanged, byte for byte for existing items.

## Choose the store

Choose a `DIR` that meets these store requirements:

| Check | Rule |
|---|---|
| Path | Require a normalized absolute directory on a Windows local fixed or RAM drive, accepted by the existing locality check. A drive root is refused. |
| Layout | Contain exactly the `attempts/` and `blobs/` directories. |
| Links | Keep the store, both children, every attempt, and every blob at their original paths. No symlinks, junctions, or other reparse points may be traversed. |
| Store failure | A refused store or child, missing store, non-directory, or any other layout gives exit code 2 and no stdout. |
| File failure | Count refused attempt or blob files as unusable. |
| URLs | Use them to identify feeds. Never contact them. |

## Read KEV metadata and results

JSON begins with `intel`.
Its `store` is the supplied path.
`intel.kev` contains these fields:

| Field | Meaning |
|---|---|
| `catalogVersion`, `dateReleased` | Selected catalog version and release time |
| `completedAt` | Selected copy's completion time |
| `days_since_fetch` | Whole elapsed 24-hour days since fetch |
| `latest_attempt` | `stored`, `failed`, or `none` |
| `invalid_attempts` | Invalid records and unusable copies encountered before selection |

Without a usable copy, version, release, completion, and age are `null`.
`intel.kev` also carries `result: undetermined`, `reason`, and `detail`.
`--today` affects waitlist ages only.
KEV times are checked against the current clock.

Items with `cves` also get `kev`, keyed by CVE ID:

| Result | Value shape |
|---|---|
| Listed | `{"result": "listed", "dateAdded": ..., "dueDate": ..., "knownRansomwareCampaignUse": ...}` |
| Absent from this copy | `{"result": "not_listed"}` |
| Undetermined | `{"result": "undetermined", "reason": ..., "detail": ...}` |

An omitted ransomware field is shown as `null`.
Items without `cves` gain neither `cves` nor `kev`.
Markdown shows the same metadata and per-CVE results in escaped code spans.
KEV results never change the exit code.
`--stale-days` still applies only to each item's last check.

## Select and validate KEV copies

Read attempts and KEV blobs using ScanMux's rules:

| Check | Rule |
|---|---|
| Attempt files | Read matching filenames within 64 KiB. Require exact key sets, validated feed URLs, and millisecond UTC timestamps. |
| JSON strings | Decode strict UTF-8, remove one leading BOM, retain the last duplicate key, and accept lone surrogates. |
| JSON numbers | Read doubles, as in JavaScript. Refuse NaN and Infinity tokens. |
| Printed strings | Replace lone surrogates with U+FFFD without changing the verdict. |
| Attempt order | Order valid KEV attempts by completion time, newest first, with failures first on a tie. |
| Newer failure | Show `latest_attempt: failed` while using the previous usable copy. |
| Future records | Count them as invalid and do not use them. |
| Unknown schema | A matching attempt filename containing a parsed JSON object with unknown `schema` blocks all KEV evaluation with `source_malformed`. Never silently select an older schema. |
| Before blob parsing | Check declared size and SHA-256, within 16 MiB. |
| KEV contents | Apply ScanMux's rules, including count, exact CVE IDs, required text, real dates, and agreeing duplicate CVEs. |
| Source agreement | Require catalog version and release to match the attempt's `source`, including its `version`, `date` key order. |
| Invalid counts | Count invalid records and unusable stored copies encountered before selection in `invalid_attempts`. |
| Previous-copy fallback | Try the previous valid copy after a damaged blob, parser drift, or source mismatch. |
| JSON nesting limit | If Python reaches its nesting limit in an attempt or catalog, give `source_malformed`. Explain that ScanMux may accept it; do not fall back. |

Without a usable copy, choose the reason as follows:

| Condition | Reason |
|---|---|
| No KEV records, or only failed KEV attempts | `source_missing` |
| Malformed KEV or unidentified records, invalid KEV times, damaged KEV blobs, or parser drift | `source_malformed` |

Broken JVN or JVNDB records count toward `invalid_attempts` but do not decide the KEV reason.
The unknown-schema rule always applies.
Neither reason yields `not_listed`.

## Read JVN metadata and results

Choose JVN copies the same way as KEV copies.
Use the newest stored `jvn` attempt whose blob meets these conditions:

- Its declared size and SHA-256 match, within the 1 MiB limit.
- It parses and matches the attempt's `source`: `{"version": null, "date": <channel time>}` for JVN.

| `intel.jvn` field | Meaning |
|---|---|
| `modified` | Channel `dcterms:modified`, or `dc:date` when absent. Use `null` if the chosen value is absent or not a valid time |
| `oldest`, `newest` | Earliest and latest item times |
| `items` | Item count |
| `completedAt`, `days_since_fetch`, `latest_attempt`, `invalid_attempts` | The same fields as `intel.kev` |

Without a usable copy, `modified`, `oldest`, `newest`, `items`, `completedAt`, and `days_since_fetch` are `null`.
`intel.jvn` also carries `result: undetermined`, `reason`, and `detail`.
`invalid_attempts` counts invalid records of any feed plus this feed's unusable copies.
KEV and JVN counts can therefore differ.
A broken record naming KEV or JVNDB does not make the JVN reason `source_malformed`.
The preceding section's unknown-schema and nesting-limit rules also apply to JVN.

Items with `cves` also get `jvn`, keyed by CVE ID:

| Result | Value shape |
|---|---|
| Observed | `{"result": "observed", "items": [{"identifier": ..., "link": ..., "modified": ...}]}` lists every RSS item naming the CVE |
| Absent from this window | `{"result": "not_observed_in_window", "oldest": ..., "newest": ..., "items": N}` |
| Undetermined | `{"result": "undetermined", "reason": ..., "detail": ...}` |

`not_observed_in_window` means only that the CVE is absent from the copied window.
Markdown shows a `jvn` line under each CVE's `kev` line.
JVN results never change the exit code.

## Validate JVN RSS

Read RSS using ScanMux's rules:

| Check | Rule |
|---|---|
| Encoding | Require strict UTF-8, removing one leading BOM. Accept only XML characters. |
| Declarations | Allow only an XML declaration as a processing instruction, only at the start. Refuse DOCTYPE and ENTITY declarations. |
| Comments and CDATA | Skip comments; commented items are not items. Allow CDATA only inside elements. |
| Root and nesting | Nest elements correctly under one closed `rdf:RDF` root. Outside it, allow only comments and JavaScript-trimmed whitespace, including U+FEFF. |
| Entities | Accept only the five predefined entities and numeric character references, in text and attribute values. |
| Attributes | Never repeat an attribute on one element. |
| Item count and position | Require 1 to 1000 `item` elements, all directly under the root. |
| Item fields | Allow `title`, `link`, `description`, `dc:identifier`, `dc:date`, `dcterms:issued`, and `dcterms:modified` at most once each, without child elements. |
| Identifier | Require the form `JVN…#…`. |
| Link | Require `https://jvn.jp/` followed by 1 to 500 ASCII characters from `!` to `~`, without spaces. |
| Title and time | Require a title. Use `dcterms:modified` for time, falling back to `dc:date` only when absent. |
| Time format | Require `YYYY-MM-DDThh:mm[:ss[.fraction]]`, with up to 9 fraction digits, followed by `Z` or `+hh:mm`/`-hh:mm`. |
| Time values | Require a real calendar day. Hours are at most 23; minutes and seconds at most 59, including the offset. |
| Channel fields | Apply the same once-only and no-child rules to these fields in `channel`. |
| CVE sources | Extract whole tokens from title and description only. Neither neighbour may be an ASCII letter, digit, `_`, or `-`. |
| CVE spelling | Match without case and print upper case. Drop tokens longer than 64 characters. |

## Troubleshooting

> Q. Why does `ledger` exit with 2 and print nothing?
> A. It rejects unreadable files, invalid JSON, non-patchwait documents, count mismatches, and invalid required fields. It also leaves `--out` untouched. An output path naming an input, including the same file under another name, is refused.

> Q. Why is an old waitlist item not stale?
> A. There is no default threshold. With `--stale-days N`, mark only non-`done` items last checked more than N days ago.

> Q. Why can `record --from` exit with 0 and leave items unchanged?
> A. Read `counts.unchanged` and each item's `why`. Older results and missing, unmatched, or ambiguous links leave items unchanged.

> Q. Does JVN `not_observed_in_window` mean JVN has no information?
> A. It means only that the CVE is absent from the copied recent RSS window, not from all JVN information.

## Security notes

- ACLs (access-control lists) are not checked.
  Anyone who can write to the store can replace a copy and its digest.
- `not_listed` means only that the CVE is not in this copy.
- Age has no default freshness threshold.
  An old copy is not called current.
- Paths are rechecked around reads.
  A concurrent writer can still swap a link between check and open, as with other local path checks.

## Read a saved-information example

The following command and result excerpt were run against a synthetic store whose KEV catalog and one-item JVN RSS both contain only `CVE-2026-0001`; the example paths replace the temporary paths used for that run:

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

## Related docs

- [Overview and commands](../README.md)
- [Get started](getting-started.md)
- [Scan runtimes](scan.md)
- [Find distrusted roots](roots.md)
- [Undetermined reasons](undetermined-reasons.md)
