[English](scan.md) | [日本語](scan.ja.md)

# Scan runtimes

Use `version-of` and `scan` to check Node.js and Python copies bundled with desktop apps.

Apps update their runtimes at different times.
Read the file version and compare it with the minimum fixed version you choose.

## Scope

A PE (Portable Executable) file contains the version resource read here.

These commands read files without executing them.
On Windows, root walks can also read registry and permission information, and Python fallbacks use read-only path-checking APIs.
The checks do not change inspected files, the registry, or permissions.
They do not match vulnerability databases.
Supply minimums with `--min`.

## What it does

- Read a version from one file.
- Scan explicit files and directories.
- Read Python venv and install-manager fallback targets.

## Requirements

For checkout setup, follow [Get started](getting-started.md).
The Bash examples below set `PYTHONPATH=src` for each command.

- Python 3.11 or later, with no third-party packages.
- Windows local fixed or RAM drives for Python `home` and alias targets.

## Read one file with `version-of`

```bash
PYTHONPATH=src python -m patchwait.cli version-of Apps/ExampleEditor/resources/node.exe --kind node
```

```json
{"result": "found", "value": {"kind": "node", "location": "Apps/ExampleEditor/resources/node.exe", "version": {"result": "found", "value": "24.19.0"}, "evidence": "pe-version-resource"}}
```

`--kind` is required.
Read `ProductVersion`, falling back to `FileVersion` only when `ProductVersion` is missing.
The string must start with `N.N.N` in ASCII digits.
Arabic-Indic or fullwidth digits give `undetermined` with `malformed_version_resource`.
The string and fixed version block must agree on major.minor.
For example, python.exe stores `3.14.6` in the string table and `3.14.6150.1013` in the fixed block.
Only major.minor is compared.

For a `python.exe` without a version resource, the venv's `pyvenv.cfg` is used as in `scan`, only with `--kind python`.
When a version is taken from it, the top-level `version_source` string is `pyvenv-home-pe-version-resource` or `pyvenv-cfg-version-info`, depending on where it came from.

With `--kind python`, the install-manager fallback can also read `<exact file name>.__target__`.
It applies only when the file's own version is undetermined and no `pyvenv.cfg` applies.
See Python install-manager aliases below.
A usable Python PE target gives `version_source: install-manager-target-pe-version-resource`.
An existing usable version always wins.
Without a sidecar, the original output and exit code are unchanged.

## Version-of exit codes

| Code | Meaning |
|---|---|
| 0 | The file and its version were read |
| 1 | The path does not exist (`not_found`) |
| 3 | The result or the version is `undetermined` |
| 2 | Bad arguments or an internal error |

## Compare runtimes with `scan`

```bash
PYTHONPATH=src python -m patchwait.cli scan --kind node \
  --min node=24.22.1 \
  --source node=https://nodejs.org/en/blog/vulnerability \
  --root Apps
```

Output, shortened to the counts and one item:

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

In the full output, the other two files are `24.22.1` (`not_found`) and `20.1.0`.
The last one is `undetermined` with reason `no_baseline`, because no minimum was given for the 20.x series.

- `found` means a version below the minimum for its series is present.

- `--kind` is `node` (the default) or `python`.
  `--min` takes one minimum per series: major for node, major.minor for python.
  For example: `--min node=20.20.2,22.23.4,24.22.1`.
  Minimums use ASCII digits only (`0`-`9`).
Other digits, such as fullwidth ones, are a usage error.
  Comparisons require exactly `N.N.N`.
A suffix such as `3.14.0rc1` gives `undetermined` and is never treated as fixed.

- `--source` is copied into every item so you can see what the minimum was based on.

## Choose files and directories

| Option | Target selection |
|---|---|
| `--path FILE` | Check one explicit file. Repeat for several files. |
| `--targets FILE` | Read a JSON list of `{"path": ..., "product": ...}`. |
| `--root DIR` | Walk for `node.exe` or `python.exe`, according to `--kind`. Repeat for several roots. |
| `--exclude TEXT` | Skip subdirectories whose paths contain TEXT, ignoring case and `/` versus `\`. Never skip the root itself. |

- Skip symbolic links and junctions inside a walk.
  Count them in `skipped_reparse_points`.
- Enter the named root even when it is a link.
- Report an unreadable directory as an `undetermined` item, counted in `counts.undetermined`, except for the two Windows cases below.
- Check a walked file once if it also appears in `--path`, `--targets`, or an earlier root.
- Keep the explicit entry's product name.
  `walk[].matched_files` counts files before this merge.
- Keep repeated `--path` values as given.
- Infer product names from paths for a few known apps.
  Use `--targets` to set them yourself.

On Windows, when a directory cannot be listed, `scan` compares it with `PackageRoot` read from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx` for this walk. The registry string is expanded if needed and must identify an absolute path on a local fixed drive or RAM disk, checked with `GetDriveTypeW`; relative, UNC, device and remote-drive paths are refused. Only this configured root gets Store handling. If it cannot be listed, `scan` reads subkey names from `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages` and walks each existing `<PackageRoot>\<PackageFullName>` directory. It does not read `PackageRootFolder`, run PowerShell, or execute the applications. Filename matching, kind detection, ordering, exclusions, reparse handling and duplicate merging are the same as for other directories.

Names with separators, `..`, a drive, unsafe filename characters, reserved device names, a trailing dot, or more than 255 characters are refused before joining a path. A package directory that cannot be read remains an `undetermined` item whose detail names the package; missing packages are counted as `absent`. **Only Store packages registered for the current user are walked**, so this is not an inventory of other users' packages or every installed Store package. The unlistable Store root itself is represented by `package_root`, not an extra `undetermined` item, even if the current user's repository is empty.

File and standard output use UTF-8. Lone Unicode surrogates in filesystem paths are escaped at output, so saved JSON preserves the original path when read back and does not prevent other findings from being reported. Ordinary Unicode remains UTF-8.

If the PackageRoot value or repository cannot be read, or the value is invalid, the original unreadable item, verdict and counts remain; `walk[].package_root_error` explains the failure. If PackageRoot cannot be identified, unreadable directories conservatively remain `undetermined`, because `scan` cannot establish which one is the Store root. These optional walk fields are absent when they do not apply.

For other directories whose listing raises `PermissionError`, `scan` uses the read-only Windows `GetFileSecurityW` API to request the owner and DACL. Only `ERROR_ACCESS_DENIED` from that read moves the directory into `walk[].skipped_protected`: `[{"path": "Apps/Locked", "reason": "listing_and_permissions_denied"}]`, with `skipped_protected_count`. It no longer contributes an item or `counts.undetermined`. A readable descriptor, any other error, an unavailable API, or a non-Windows system retains the original unreadable item. The decision never depends on a directory name. **These folders were not looked into; an administrator must check if they matter.** Skipping them does not establish that they contain no vulnerable runtime. Store handling takes priority, and unreadable registered package directories remain undetermined.

For walk fields and how skipped locations affect counts, see [Scan walk evidence](ledger-and-waitlist.md#read-scan-walk-evidence).

## Python virtual environments

A virtual environment's (venv's) `python.exe` often has no version resource.
The trampoline uv puts in `<venv>\Scripts` is one example.
For a `python.exe` without that resource, `scan` reads `pyvenv.cfg` beside it, or else one directory up.
The filename comparison ignores case.
Other filenames remain `no_version_resource` unless the alias fallback below applies.
Local path checks use the read-only Windows APIs `GetDriveTypeW` and `GetFileAttributesW`.
Nothing is executed.

Choose the version in this order:

1.
   Read `<home>\python.exe`, the interpreter started by the venv.
   Require `ProductName` to be `Python`.
   Do not follow `home`'s `pyvenv.cfg`.
2.
   Use `version_info` only under the conditions in the table below.
   Require exactly `N.N.N`.
3.
   Otherwise keep `undetermined` / `no_version_resource` and explain the missing information in the detail.

| `home` and `version_info` condition | Behaviour |
|---|---|
| `version_info` is present but disagrees with home on major.minor | Give `undetermined` / `version_mismatch`. Take no version and do not substitute `version_info` |
| `version_info` is neither `N.N` nor `N.N.N` | Give `malformed_version_resource`. Take no version and do not substitute `version_info` |
| Home's resource was read but is broken or disagrees with itself | Keep its reason, for example a bad `VS_FIXEDFILEINFO` signature. Start the detail with `home python.exe: `. Do not use `version_info` |
| Home is missing, unreadable, not a PE file, lacks a resource, or names another product | Only these cases allow `version_info` as a substitute |
| `version_info` gives only major.minor, such as `3.12` | This alone cannot be compared with a fixed version such as `3.12.14`. uv often writes this form |

An example detail is `pyvenv.cfg version_info is 3.12 (major.minor only) and home python.exe is missing (...)`.
An item for which `pyvenv.cfg` was read has `version_source`:

```json
"version_source": {"evidence": "pyvenv-home-pe-version-resource", "pyvenv_cfg": "C:\\Apps\\proj\\.venv\\pyvenv.cfg", "home": "C:\\Python\\cpython-3.12-windows-x86_64-none", "version_info": "3.12"}
```

| Field | Meaning |
|---|---|
| `evidence` | `pyvenv-home-pe-version-resource`, `pyvenv-cfg-version-info`, or `null` when no version was taken |
| `pyvenv_cfg` | Absolute path of the file read |
| `home`, `version_info` | Values from `pyvenv.cfg`, or `null` |

Install-manager aliases use the separate shape below.
Other items have no `version_source`.

## Read `pyvenv.cfg` safely

| Condition | Reading rule |
|---|---|
| Size and file type | Refuse files larger than 64 KiB and non-regular files, including symlinks, junctions, and other reparse points. |
| Line endings | Split only at LF. Drop an optional CR before it. Keep other Unicode line breaks inside the value. |
| Duplicate keys | Compare keys without case. Two occurrences give `undetermined` / `duplicate_key`; neither value is used. |
| Lines resembling `home` | Count every case, including comments starting with `#` or `;`. Two or more lines give `duplicate_key`. |
| One `home` line | Require the lowercase form `home = ...`. `HOME = ...` and `# home = ...` also give `duplicate_key`; no value is used. |
| Key and value edges | Trim only ASCII spaces and tabs. Other whitespace at either edge gives `undetermined` / `malformed_version_resource`. |
| Version shape | Require exactly `N.N` or `N.N.N`, with at most 9 digits per part. `3.12.`, `3.12.not-a-version`, and longer runs give `undetermined` / `malformed_version_resource`. |

## Check Python home paths

Check `<home>\python.exe` before opening anything under `home`.
Accept only an `X:\` path on a local fixed drive or RAM disk.

| Check | Rule |
|---|---|
| Drive type | Call `GetDriveTypeW` with only the drive root. Whether Windows touches the volume to answer is not documented. |
| Refused locations | Refuse UNC (`\\host\share`, `//host/share`), device and extended paths (`\\.\`, `\\?\`), paths rooted without a drive (`\x`), and mapped-network, removable, or CD-ROM drives. The `\\?\` refusal applies to `home` itself. |
| Rewritten names | Refuse parts ending in a dot or space, except `.` and `..`, and a `:` after the drive. Windows rewrites these names before opening them. |
| Reserved device names | Refuse `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, `COM¹`-`COM³`, and `LPT¹`-`LPT³`. Compare without case or trailing spaces and dots, with any extension. Examples include `nul.txt` and `Com1 .log`. |
| Existence | Require every path part to exist. A missing part means nothing is opened; `version_info` may then be used under the rules above. |
| Per-part checks | Use `lstat` and `GetFileAttributesW`. The latter reports reparse points that `lstat` follows without reporting them. |
| Links | Read symlink and junction targets without opening them, then check each target the same way. Allow up to 16 links; refuse loops. Resolve relative targets from the link's directory. |
| NT-namespace targets | Immediately refuse `\Device\`, `\??\`, `\GLOBAL??\`, `\DosDevices\`, `\\?\UNC\`, `\\.\`, and targets rooted without a drive. Only `\??\X:\...` and `\\?\X:\...` are unwrapped to `X:\...`, then checked normally. |
| Other attributes | Refuse other reparse points, such as cloud placeholders, and every part marked offline or recall-on-access. |
| After reading | Repeat the check and compare the volume and file index. Changed links or files give `undetermined` / `no_version_resource`, with `home changed while it was read` in the detail. |

Reserved-name rules apply to `home` and every link target.
Windows 10 and earlier open a device for these names.
Newer builds treat some, such as `nul.txt` or `COM1 .log`, as ordinary files.
patchwait refuses them on every version because the behaviour differs between builds.

A refused `home` gives `undetermined` / `no_version_resource`.
Its detail contains `pyvenv.cfg home is not a local fixed-drive path`.
Nothing under `home` is opened, and `version_info` is not used.
An existing relative, drive-relative (`C:py`), empty, or NUL-containing `home` is refused the same way.
This check exists only on Windows.
Every `home` is refused elsewhere.

## Python install-manager aliases

Aliases such as `python.exe`, `python3.exe`, `python3.14.exe`, `pythonw.exe`, and `pip.exe` can carry `ProductName: manage` instead of the runtime version.
`scan` and `version-of` share this fallback:

| Condition | Behaviour |
|---|---|
| The file has a usable version | Always keep that version. |
| A `pyvenv.cfg` applies | Keep venv handling first, including an unusable cfg. |
| The file's version is undetermined and no cfg applies | Read `<exact file name>.__target__` in the same directory. |
| No sidecar exists | Leave the original output and exit code unchanged. |

A sidecar is the file beside the alias that names its target.

| Sidecar or target condition | Rule |
|---|---|
| File type | Require a regular file. Refuse links, reparse points, and offline or recall-on-access files. |
| Size | At most 4096 bytes. |
| Content | Require one absolute path in strict UTF-8. Refuse empty content, BOM, NUL, CR, and LF, including a trailing newline. |
| Target location | Apply the same local fixed/RAM-drive, name, and per-hop link checks as `home`. Repeat locality and file-change checks after reading. |
| Version evidence | Use only the target's PE resource, with `ProductName: Python` and the normal string/fixed-info agreement. |
| No further fallback | Do not follow the target's sidecar or `pyvenv.cfg`. Do not use a text version. |
| Invalid, missing, unreadable, or non-Python target | Keep `undetermined`; identify the `__target__` route in the detail. |

A synthetic `scan` evidence example:

```json
"version_source": {"evidence": "install-manager-target-pe-version-resource", "target_file": "C:\\Apps\\Python\\bin\\python.exe.__target__", "target": "C:\\Python\\pythoncore-3.14-64\\python.exe"}
```

| Field | Meaning |
|---|---|
| `target_file` | Absolute sidecar path |
| `target` | Decoded content, or `null` exactly under the conditions below |
| `evidence` | `install-manager-target-pe-version-resource`, or `null` when no version was taken |

`target` is `null` exactly when a sidecar read is refused or fails, including size and change checks.
It is also null for a UTF-8 BOM, invalid UTF-8, or empty or whitespace-only content.
Retain other content even if it is later rejected as a target path.
In `version-of`, `version_source` is the evidence string, as for venvs.
Nothing is executed.
Check and open resolve paths separately, so the same race limitation as `home` applies.

## Save output and read exit codes

`scan` prints one JSON document to stdout.
`--out FILE` writes through a temporary file and replaces the destination in one step.
See [README](../README.md#exit-codes-of-scan-and-roots) for exit codes and uncertainty counts.

## Troubleshooting

> Q. Why is a venv still `undetermined`?
> A. If `home` is unreadable and `version_info` gives only major.minor, such as `3.12`, it cannot be compared with `3.12.14`. Read the detail.

> Q. Why does an alias detail start with `__target__ route:`?
> A. The reason describes the sidecar or its target. PE-related reasons describe the target PE.

## Security notes

- Read files without executing them.
- The `home` check and open resolve paths separately.
  Rechecking after reading narrows the gap but does not close it.
- A process writing to the scanned tree can still swap a link between check and open.
  The same limitation applies to alias targets.

## Related docs

- [Overview and commands](../README.md)
- [Get started](getting-started.md)
- [Find distrusted roots](roots.md)
- [Use a ledger and waitlist](ledger-and-waitlist.md)
- [Undetermined reasons](undetermined-reasons.md)
