[English](README.md) | [日本語](README.ja.md)

# patchwait

patchwait checks bundled Node.js and Python versions and distrusted root certificates on Windows PCs for people waiting on an app vendor's fix.

Desktop apps often ship their own `node.exe` or `python.exe`.
Those copies update on the app's schedule.
A root certificate authority (CA) that browsers distrust can remain in the Windows AuthRoot list, an app's `cacert.pem`, or a compiled root store.
patchwait reads versions and looks for the certificates you supply in these places.

`scan` and `roots` give each item one of three results:

| Result | Meaning |
|---|---|
| `found` | A runtime is below its supplied minimum, or a certificate or key matches. For roots, read the item's `role`. |
| `not_found` | The comparison found no runtime below its minimum, or no matching certificate or key within the check's limits. One exception: an AuthRoot entry with Microsoft's "disallowed since" property is `not_found` even though it matches (see [roots](docs/roots.md)). |
| `undetermined` | A file was unreadable, a version could not be parsed, or the check lacked usable data. The item includes a reason. |

`version-of` reads one file and has [its own exit codes](docs/scan.md#version-of-exit-codes).

## What it does not do

- Match versions against a vulnerability database. You choose the minimum fixed version, for example from Node.js security releases, and pass `--min`.
- Infer CVEs from versions. `waitlist show --intel-store` matches explicit vulnerability identifiers (CVE IDs) against saved copies of CISA's Known Exploited Vulnerabilities (KEV) catalog and JVN's recent-update RSS feed.
- Scan repository lockfiles. For package and binary matching against OSV, use [osv-scanner](https://github.com/google/osv-scanner).
- Track "new since last run". Each run prints the full result, and the caller keeps any state.
- Run inspected executables or change certificate stores or bundles.

patchwait makes no network requests and does not execute the files it inspects.
It writes only reports requested with `--out` and the waitlist file passed to `waitlist record`.

Status: early (0.2.0). Not published to PyPI.

## What it does

A PE (Portable Executable) file is the executable format whose version resource patchwait reads.

- Read PE version resources and compare runtimes with caller-supplied minimum fixed versions.
- Find supplied distrusted certificates in Windows lists and stores, PEM bundles, binaries, and Java keystores.
- Turn saved results into Markdown for a tracking ledger.
- Keep vendor-fix items in a local waitlist and show how long they have gone unchecked.
- Match explicit CVE IDs against KEV and JVN information saved by ScanMux.

## Requirements

- Python 3.11 or later. No third-party packages.
- Windows for `roots --windows`. Tests have been run on Windows only.
- A local fixed or RAM drive on Windows for Python fallback targets and the optional ScanMux store.

On Windows, these checks use read-only APIs:

| Command or path | Windows reads |
|---|---|
| `roots --windows` | Registry values and key metadata through `winreg`, and certificate stores through `ssl.enum_certificates`. |
| `scan --root` when a directory cannot be listed | Appx `PackageRoot` and, for that root, current-user package registration through `winreg`; `GetDriveTypeW` for the configured root's drive; `GetFileSecurityW` for other directories whose listing is denied, once `PackageRoot` is identified. |
| Python fallbacks in `scan --kind python` and `version-of --kind python`; `waitlist show --intel-store` | `GetDriveTypeW` and `GetFileAttributesW` for local path checks. |

These checks do not write to the registry, permissions, certificate stores, or inspected files.
Only requested reports and the file passed to `waitlist record` are written.
See the guides for the checks that apply to those paths.

## Get started

Follow [Get started](docs/getting-started.md) from a checkout.
It walks through a synthetic `Apps/` folder, one `version-of` call, and one `scan` call.
The examples use fake files, like those built by the tests.

Choose minimums from the fix information you trust.
The versions in the examples illustrate comparisons.

## Commands

| Command | What it reads | What it writes | Guide |
|---|---|---|---|
| `version-of` | One executable, with Python fallback files when applicable | JSON to stdout | [Scan](docs/scan.md) |
| `scan` | Explicit files, a JSON target list, or directories | JSON to stdout or `--out FILE` | [Scan](docs/scan.md) |
| `roots` | Distrust identifiers and selected certificate locations | JSON to stdout or `--out FILE` | [Roots](docs/roots.md) |
| `ledger` | One or more saved `scan` or `roots` documents | Markdown to stdout or `--out FILE` | [Ledger and waitlist](docs/ledger-and-waitlist.md) |
| `waitlist show` | A waitlist and, optionally, a saved ScanMux store | JSON or Markdown to stdout | [Ledger and waitlist](docs/ledger-and-waitlist.md) |
| `waitlist record` | A waitlist and, with `--from`, a saved result | The given waitlist file and JSON to stdout | [Ledger and waitlist](docs/ledger-and-waitlist.md) |

`scan` and `roots` print one JSON document.
With `--out FILE`, they write it through a temporary file and replace the destination in one step.
`ledger` also writes `--out` atomically.

## Exit codes of `scan` and `roots`

| Code | `scan` | `roots` |
|---|---|---|
| 0 | Nothing below a minimum was found | No distrusted root was found on the trust side |
| 10 | At least one item is `found` | At least one trust-side item is `found` |
| 2 | Bad arguments or internal error | Bad arguments or internal error |

`undetermined` does not change these commands' exit codes.
Always read the uncertainty counts:

| Command | Fields to read |
|---|---|
| `scan` | `counts.undetermined` and [`walk` evidence](docs/ledger-and-waitlist.md#read-scan-walk-evidence) for locations not inspected |
| `roots` | `counts.trust.undetermined`, `counts.distrust.undetermined` |

Exit code 0 with undetermined items means nothing bad was found among what could be checked.

For roots, `found` on the `trust` side means the certificate or key remains in a location listing trusted roots.
It does not prove a program uses that location.
On the `distrust` side (Disallowed), `found` is a good result.
`not_found` there means the entry was compared and is not listed.

## Known limits

A venv is a Python virtual environment.

- A venv without a PE version resource can remain `undetermined` when `home` is unreadable and `version_info` gives only major.minor.
- Python `home` and alias targets are checked before and after reading. A concurrent writer can still swap a link between check and open.
- Some executables store roots in unreadable forms. They can report `malformed_cert`, `no_certs_recognised`, or `not_found` when other certificates are readable.
- When the configured Store package root cannot be listed, `scan --root` walks only packages registered for the current user, not every installed Store package.
- If Appx `PackageRoot` or the current-user package repository cannot be read, the unreadable root remains `undetermined`, with `walk[].package_root_error` explaining the failure.
- Once `PackageRoot` is identified, other directories that deny both listing and reading their owner/DACL are reported as `skipped_protected`, outside `items` and `counts.undetermined`. These folders were not looked into; an administrator must check if they matter.
- The Windows Disallowed list needs signature-hash or public-key-MD5 identifiers for some entries. Text-only identifiers cannot supply them.

See [Python virtual environments](docs/scan.md#python-virtual-environments) for fallback rules and path restrictions.
See [Windows Disallowed matching](docs/roots.md#windows-disallowed-matching) for the supported hashes and exact result rules.
A binary's `not_found` covers only certificates patchwait could recognise, including when other roots are compressed.

## Security notes

- A certificate match does not prove a program uses that location.
- Java keystore integrity, certificate signatures, and trust chains are not verified.
- Saved ScanMux stores have no ACL check. Anyone with write access can replace a copy and its digest.
- Saved information shows its age without a default freshness threshold. An old copy is not called current.

## Related docs

| Guide | Read it when |
|---|---|
| [Get started](docs/getting-started.md) | You want to run from a checkout and read the example output |
| [Scan runtimes](docs/scan.md) | You need minimums, target selection, Python venvs, or install-manager aliases |
| [Find distrusted roots](docs/roots.md) | You need certificate identifiers, Windows stores, bundles, binaries, or Java keystores |
| [Use a ledger and waitlist](docs/ledger-and-waitlist.md) | You want Markdown, vendor tracking, or saved KEV and JVN information |
| [Undetermined reasons](docs/undetermined-reasons.md) | A check could not decide and you need its reason code |

## Development

```bash
python -m unittest discover -s tests -t .
pyright src tests tools
```

Tests build synthetic PE files, certificates, and certificate trust lists at run time.
No real binaries or certificates are checked in.

`.githooks/` and `tools/publish_check.py` are the maintainer's local publishing checks.
They check a path allowlist and scan for markers.
They are not needed to use patchwait.
The test suite above also tests them.

## License

[MIT](LICENSE)
