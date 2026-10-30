[English](getting-started.md) | [日本語](getting-started.ja.md)

# Get started

Run patchwait from a checkout to read and compare versions in synthetic files.

Apps update their bundled runtimes at different times.
Start with a small example that distinguishes an older version, a minimum version, and a version without a baseline.

## Scope

This is a synthetic example.
Do not launch the fake executables.
You choose minimum fixed versions.
No network request or certificate-store change is involved.

## What it does

- Show command help.
- Build a synthetic `Apps/` folder.
- Read one file version.
- Compare three runtimes with a minimum version.

## Requirements

- Python 3.11 or later, with no third-party packages.
- A repository checkout.
  Run these PowerShell commands from its root.
- An unused `Apps/` folder name and `distrust.pem` filename for the example.
- Tests have been run on Windows only.

## Run your first scan

1.
   Add `src` to Python's import path and show the available commands.

```powershell
$env:PYTHONPATH = "src"
python -m patchwait.cli --help
```

You should see help listing `version-of`, `scan`, `roots`, `ledger`, and `waitlist`.

2.
   Use the test builders to create three fake runtimes, two PEM bundles, one binary, and a certificate to search for.

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

You should see `Created Apps/ and distrust.pem`.
The tests build the same kinds of files from scratch.
No real binary or certificate is used.

3.
   Read the Node.js version bundled with ExampleEditor.

```powershell
python -m patchwait.cli version-of Apps/ExampleEditor/resources/node.exe --kind node
```

You should see JSON with `result` and `value.version.result` set to `found`, `value.version.value` to `24.19.0`, and `value.evidence` to `pe-version-resource`.
The exit code is 0.

4.
   Compare the Node.js copies under `Apps/` with an example minimum version.

```powershell
python -m patchwait.cli scan --kind node `
  --min node=24.22.1 `
  --source node=https://nodejs.org/en/blog/vulnerability `
  --root Apps
```

You should see `counts` with `targets: 3`, `found: 1`, `not_found: 1`, and `undetermined: 1`.
The exit code is 10.

| Version | Result | Why |
|---|---|---|
| `24.19.0` | `found` | Below the minimum `24.22.1` |
| `24.22.1` | `not_found` | Not below the minimum |
| `20.1.0` | `undetermined` | No minimum for the 20.x series: `no_baseline` |

## Save the result

`scan` and `roots` print one JSON document to stdout.
With `--out FILE`, they write through a temporary file and replace the destination in one step.

## Troubleshooting

> Q. Does exit code 0 mean every item was checked?
> A. Undetermined items do not change `scan` or `roots` exit codes. Also read `counts.undetermined`, or the roots fields `counts.trust.undetermined` and `counts.distrust.undetermined`.

> Q. Why is `20.1.0` not treated as fixed?
> A. No minimum was supplied for the 20.x series. Give one `--min` minimum per series.

## Security notes

- patchwait never runs the executables it inspects.
- It does not change certificate stores or bundles, or make network requests.
- patchwait writes only requested `--out` reports and the file passed to `waitlist record`.

## Related docs

- [Scan runtimes](scan.md)
- [Find distrusted roots](roots.md)
- [Use a ledger and waitlist](ledger-and-waitlist.md)
- [Undetermined reasons](undetermined-reasons.md)
- [Overview and commands](../README.md)
