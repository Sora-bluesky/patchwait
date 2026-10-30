[English](roots.md) | [日本語](roots.ja.md)

# Find distrusted roots

Use `roots` to find supplied distrusted certificates in Windows and application certificate locations.

A certificate that browsers distrust can remain among the roots listed by Windows or an app.

## Scope

`roots` finds certificates without changing stores or bundles.
A match does not prove that a program uses the location.

## What it does

- Match supplied certificates or identifiers.
- Read PEM, DER, binaries, and Java keystores.
- Check Windows trust and distrust lists and stores.

## Requirements

For checkout setup, follow [Get started](getting-started.md).
The Bash examples below set `PYTHONPATH=src` for each command.

- Python 3.11 or later, with no third-party packages.
- Windows for `--windows`.
- Certificates or identifiers supplied with `--distrust-pem` or `--distrust`.

## Run a roots check

```bash
PYTHONPATH=src python -m patchwait.cli roots \
  --distrust-pem distrust.pem \
  --pem-root Apps \
  --binary Apps/ExampleSync/bin/sync.exe
```

Output, shortened:

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

In the full output, `Apps\ExampleSync\certs.pem` is `not_found` and the binary `sync.exe` is `found`.
Each item's `matches` lists every match (`matched_by`, the certificate hash, the subject name, for binaries the offset and, for the ROOT and Disallowed certificate stores, `cert_sha1` and `registry_keys`).

## Choose distrust identifiers

PEM stores certificates as text.
DER encodes them as bytes.
SPKI (SubjectPublicKeyInfo) is the certificate's public-key structure.

- `--distrust-pem FILE` takes the distrusted certificates themselves.
  patchwait derives the SHA-256 and SHA-1 of the certificate, and the SHA-256 of its public key (SPKI).
  A match on the SPKI with a different certificate hash means a reissued or cross-signed certificate with the same key.
It also derives `signature_hash` (when the signature digest is known) and `public_key_md5` for the Windows Disallowed list, as described below.
The top-level `distrust` entries show these identifiers as hex, or `null` when unavailable.

- `--distrust FILE` takes a text list, one entry per line.
Use `sha256:<hex>`, `sha1:<hex>`, `spki:<hex>`, or a bare 64-character SHA-256.
An optional label can follow each identifier.
Colons inside the hex are accepted, and blank lines and `#` lines are skipped.
The bare form with a label is the preset format of [trust-store-audit](https://github.com/globe-teck/trust-store-audit).
Lines with the same label are merged into one entry, and both options can be used together.

## Read PEM bundles and binaries

- `--pem FILE` and `--pem-root DIR` read PEM bundles, or a single DER certificate.
  `--pem-root` walks for `*.pem`, `*.crt`, `*.cer`, `cacert*`, `roots.pem` and `ca-bundle*`, and does not follow symbolic links or junctions to directories below the root (they are counted in `skipped_reparse_points`).
  Skip a walked file when all its PEM blocks contain things other than certificates, such as keys or CRLs.
  The skipped counts are reported on an extra `pem_root` item for that directory.

- `--binary FILE` looks for roots embedded as PEM text and as raw DER.
Recognise raw DER certificates whose outer SEQUENCE uses a two-byte length, about 260 bytes to 64 KiB.
Their tbsCertificate must be at least 128 bytes long.
It counts only when it parses in full, and other bytes that start like one are not counted at all.
A smaller certificate embedded as raw DER is not recognised, but `--distrust-pem` still finds it through the raw DER search below.
Both kinds are matched by SHA-256, SHA-1 and SPKI, so a `--distrust` list works on them too.
When the list came from `--distrust-pem`, it also looks for the raw DER of each certificate and of its public key (`matched_by: raw_der` and `raw_spki`).
Such a hit inside a DER certificate that already matched the same entry is not reported a second time.
The file is read in chunks, so large binaries are fine.

- Some PEM `BEGIN CERTIFICATE` / `END CERTIFICATE` pairs contain only whitespace, NUL bytes, or literal `\n`, `\r`, and `\t` escapes.
Each escape is a backslash and a letter, as in a string literal.
These are templates, such as format strings, rather than broken certificates.
It is not counted as `malformed` and is listed in `details.ignored_pem_blocks` with its offset and `reason: empty_pem_block`.
Up to 20 are listed; with more, `details.ignored_pem_blocks_total` gives the full count.

- `details` for a binary: `pem_blocks` (PEM certificate markers seen), `certs` (certificates parsed from PEM), `der_certs` (raw DER certificates parsed), `malformed` (PEM blocks that could not be parsed) and `ignored_pem_blocks`.
  A bundle has the same keys without `der_certs`, and `ignored_pem_blocks` only when it has some.

## Read Java keystores

`--keystore FILE` detects Java keystore formats from their contents, not their names.
Java's `cacerts` is a typical input.
Repeat `--keystore` for several files.

```bash
PYTHONPATH=src python -m patchwait.cli roots --distrust-pem synthetic-distrusted.pem --keystore 'C:\Java\jdk\lib\security\cacerts'
```

| Format | Supported versions and contents |
|---|---|
| PKCS12 (PFX) | Version 3. Read X.509 `certBag` values from plain `data` ContentInfos, including nested `safeContentsBag` values. |
| JKS | Versions 1 and 2. Read trusted certificates and private-key certificate chains. Skip and count private keys. |
| JCEKS | Versions 1 and 2, with plain trusted-certificate entries only. Stop enumeration at a private-key or secret-key entry. |

Count PKCS12 `keyBag`, `pkcs8ShroudedKeyBag`, `crlBag`, and `secretBag` values.
Do not search them for certificate bytes.
Encrypted `encryptedData` and `envelopedData` ContentInfos and unknown structures cannot be read.

Refuse files above `MAX_KEYSTORE_FILE` (16 MiB) before reading their contents.
A bounded read also handles files that grow during the check.

Items have `location_kind: java_keystore` and `role: trust`.
Verdicts and matches use the bundle structure and SHA-256, SHA-1, and SPKI matching.

| Condition | Verdict |
|---|---|
| Any match | `found`, even if another part is unreadable |
| No match and complete enumeration | `not_found`, including a completely readable empty keystore |
| Encrypted or unsupported parts that could contain certificates | `undetermined` / `keystore_unreadable` |
| Unrecognised format or malformed structure | `undetermined` / `malformed_keystore` |
| Unparsable certificates | `undetermined` / `malformed_cert` |
| Missing file | `target_missing` |
| Unreadable or oversized file | `file_unreadable` |

These uncertainties also apply when zero certificates were read.

| `details` field | Meaning |
|---|---|
| `format`, `version` | Detected format and version |
| `certs`, `malformed` | Parsed and unparsable certificate counts |
| `bags`, `entries` | Counts by type |
| `content_infos` | Counts by content type |
| `declared_entries` | JKS/JCEKS header count |
| `encrypted_content_infos`, `unreadable_parts` | Encrypted ContentInfo and unreadable-part counts |
| `mac_data` | MAC presence, not verification |

Unavailable or inapplicable version, header count, and MAC presence are `null`.
Unused maps are empty.
An `undetermined` verdict's detail explains what could not be read.
`ledger` and `waitlist record --from` validate these fields.
Ledger output retains counts for each keystore, even for `not_found` under `--brief`.
`--binary` scanning remains available, but its count cannot prove complete keystore enumeration.

## Read Windows lists and stores

`--windows` reads the AuthRoot and Disallowed lists from the registry.
It enumerates the ROOT and Disallowed certificate stores through `ssl.enum_certificates`.
A certificate trust list is called a CTL.
It never runs `certutil`.
Every registry key is opened read-only.
No registry writes occur.

ROOT and Disallowed store matches include `matches[].cert_sha1` and `matches[].registry_keys`.
The former is the certificate's SHA-1.
The latter lists keys named after it as `{key, last_write}`.

| Store | Keys searched |
|---|---|
| ROOT | `ROOT` and `AuthRoot` under `SOFTWARE\Microsoft\SystemCertificates` and `SOFTWARE\Policies\Microsoft\SystemCertificates`, in both HKLM and HKCU |
| Disallowed | `Disallowed` under the same HKLM and HKCU locations |
| Enterprise ROOT | Only `ROOT` under HKLM `SOFTWARE\Microsoft\EnterpriseCertificates` (`root_store`) |
| Enterprise Disallowed | Only `Disallowed` under HKLM `SOFTWARE\Microsoft\EnterpriseCertificates` (`disallowed_store`) |

| Time or note | Meaning |
|---|---|
| `last_write` | The key's last-write time in UTC. Certificate property changes also change it, so it is not necessarily the addition time. |
| `last_write_note` | If the time is zero, out of range, or not an integer, `last_write` is `null` with this explanation. |
| `registry_keys_note` | When none of the searched locations has the key, explain the empty `registry_keys` list. |
| `registry_keys_errors` | Keys that could not be read, with error types. |
| `details.last_sync` | The last Windows sync time: AuthRoot `LastSyncTime` or Disallowed `DisallowedCertLastSyncTime`. |
| `details.last_sync_note` | Explain a missing or malformed sync time; `details.last_sync` is then `null`. |

The ROOT logical store can include locations patchwait does not read, such as service stores and other users' stores.
A certificate from those locations also gives an empty key list with its note.
No time is guessed.
Without Windows, these fields are absent and Windows items are `undetermined` / `not_windows`.

## Read the results

- `role` tells you how to read `found`.
  On the `trust` side (AuthRoot, ROOT, bundles, binaries) `found` is bad: the certificate or its key is present in a place that lists trusted roots.
  It does not prove that a given program uses that place.
  On the `distrust` side (Disallowed) `found` is good; `not_found` means the entry was compared and is not listed.

- An AuthRoot entry with Microsoft's "disallowed since" property is reported as `not_found` on the trust side, with the date in `matches[].disallowed`.
  A "not before" restriction keeps it `found` and shows the restriction in `matches[].not_before`.

- With no match, a bundle, binary or certificate store that had some unreadable certificates is `undetermined` (`malformed_cert`), and a bundle or binary in which no certificate was recognised at all, from PEM or raw DER, is `undetermined` (`no_certs_recognised`).
  Ignored empty PEM blocks count toward neither.
  A match always gives `found`, even from raw bytes in a binary with no parsed certificates.

- `not_found` for a binary means "not among the certificates patchwait could recognise in it".
  A binary that also stores roots in a form patchwait cannot read, such as compressed data, can still contain the certificate.

## Windows Disallowed matching

For SubjectAlgorithm `1.3.6.1.4.1.311.10.11.15`, match the Windows Disallowed list by signature hash or public-key MD5.
Identify it by OID, not identifier length.

| Identifier | Calculation and support |
|---|---|
| Signature hash | Use the certificate's outer signature algorithm to choose a digest. Hash the complete DER-encoded TBSCertificate, including tag and length. |
| Supported digests | MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 for RSA PKCS#1 v1.5 and the corresponding ECDSA algorithms. |
| RSASSA-PSS | Require an explicitly named supported hash in its parameters. |
| Public-key MD5 | Hash the subjectPublicKey BIT STRING value without its leading unused-bits octet. |

| Condition | Result |
|---|---|
| Match | Report `matched_by: signature_hash` or `public_key_md5` and the identifier hex. |
| Both hashes computed, neither matches | `not_found` |
| Signature hash unknown, public-key MD5 does not match | `undetermined` / `no_usable_identifier`, naming the signature algorithm |
| Text-only `--distrust` identifiers | Cannot supply these hashes; stay `undetermined` |

No certificate on a typical machine is expected to match this list.
`not_found` on the `distrust` side means the entry was compared and is not listed.

## Troubleshooting

> Q. Does an unreadable certificate count as absent?
> A. Any match gives `found`. Without a match, unreadable certificates in a bundle, binary, or certificate store give `undetermined` / `malformed_cert`.

> Q. What if no certificate is recognised?
> A. Bundles and binaries with no recognised PEM or raw DER certificates give `undetermined` / `no_certs_recognised`. Ignored empty PEM templates do not count. A raw-byte binary match still gives `found`, even without parsed certificates.

> Q. Does a binary's `not_found` prove the certificate is absent?
> A. It covers only recognised certificates. Roots can remain in unreadable forms, such as compressed data.

## Security notes

-
No password is requested.
- PKCS12 MACs and JKS/JCEKS integrity hashes are not verified.
- Certificate signatures and trust chains are not verified either.
- A structurally readable keystore can give `not_found` even when its integrity bytes were altered.

## Save output and read exit codes

`roots` prints one JSON document to stdout.
`--out FILE` writes through a temporary file and replaces the destination in one step.
See [README](../README.md#exit-codes-of-scan-and-roots) for exit codes and uncertainty counts.

## Related docs

- [Overview and commands](../README.md)
- [Get started](getting-started.md)
- [Scan runtimes](scan.md)
- [Use a ledger and waitlist](ledger-and-waitlist.md)
- [Undetermined reasons](undetermined-reasons.md)
