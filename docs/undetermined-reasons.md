[English](undetermined-reasons.md) | [日本語](undetermined-reasons.ja.md)

# Undetermined reasons

Look up an `undetermined` reason code to see why a check could not decide.

An unreadable file or missing comparison data does not mean the target was absent.
Read the reason and detail to see what could not be checked.

## Scope

The command column names the originating check.
`ledger` and `waitlist` can also display reasons from saved or recorded results.

## Look up a reason

Details beginning with `__target__ route:` describe the install-manager sidecar or its target.
PE-related reasons on that route refer to the target PE.

| Reason | Meaning | Originating command |
|---|---|---|
| `target_missing` | the path does not exist (`scan` and `roots`) | `scan`, `roots` |
| `duplicate_key` | a venv's `pyvenv.cfg` gives the same key more than once (`scan` and `version-of`) | `scan`, `version-of` |
| `file_unreadable` | the file or directory being checked could not be read, including an install-manager target | `scan`, `version-of`, `roots` |
| `not_pe` | the checked file is not a PE file, including an install-manager target | `scan`, `version-of` |
| `no_version_resource` | no PE version resource was available, or a Python fallback (`pyvenv.cfg` or `__target__`) could not supply a version; see the detail for missing or refused input | `scan`, `version-of` |
| `malformed_version_resource` | the version resource is broken, or the version does not start with `N.N.N` (in `scan`: is not exactly `N.N.N`); also a malformed venv `pyvenv.cfg` or versions that cannot be compared (`scan` and `version-of`) | `scan`, `version-of` |
| `version_mismatch` | the string and fixed versions disagree on major.minor, or a venv's `home` version and `version_info` do (`scan` and `version-of`) | `scan`, `version-of` |
| `unexpected_product` | `ProductName` is missing or is not the one expected for `--kind` (`Node.js` for node, `Python` for python) | `scan`, `version-of` |
| `no_baseline` | no `--min` for that series | `scan` |
| `store_unreadable` | a registry value or certificate store could not be read | `roots` |
| `malformed_ctl` | a certificate trust list could not be parsed | `roots` |
| `malformed_keystore` | a Java keystore has an unrecognised format, malformed structure or unsupported version | `roots` |
| `keystore_unreadable` | a Java keystore has encrypted or unsupported parts that could contain certificates | `roots` |
| `malformed_cert` | some certificates could not be parsed and none matched | `roots` |
| `no_certs_recognised` | no certificates were found in the file | `roots` |
| `no_usable_identifier` | the given identifiers cannot be compared with this place | `roots` |
| `not_windows` | `--windows` was used on another OS | `roots` |
| `source_missing` | no saved usable KEV or JVN RSS copy: no attempt for that feed, or only failed attempts | `waitlist show --intel-store` |
| `source_malformed` | the KEV or JVN RSS evidence cannot be trusted: malformed/unknown attempt schema, invalid times, damaged blob, parser drift or source mismatch, with no usable fallback (unknown schema always blocks evaluation) | `waitlist show --intel-store` |

For `scan --root`, an unlistable directory does not always become an `undetermined` item.
A Store root handled through current-user package registration is recorded in `walk[].package_root`; an unreadable registered package directory still uses `file_unreadable`.
Unreadable or invalid registry evidence keeps the original `file_unreadable` item and adds `walk[].package_root_error`.
Once `PackageRoot` is identified, other directories that deny both listing and reading their permissions are recorded in `walk[].skipped_protected` with `reason: listing_and_permissions_denied`.
This is walk evidence, not an `undetermined` reason; these folders were not looked into.
See the [scan guide](scan.md) for the conditions and the [walk fields](ledger-and-waitlist.md#read-scan-walk-evidence) for counts.

## Related docs

- [Get started](getting-started.md)
- [Scan runtimes](scan.md)
- [Find distrusted roots](roots.md)
- [Use a ledger and waitlist](ledger-and-waitlist.md)
- [Overview and commands](../README.md)
