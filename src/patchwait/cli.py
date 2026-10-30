"""Command line entry point.

``version-of`` exit codes: 0 found, 1 not found, 3 undetermined, 2 usage or internal error.

``scan`` exit codes (aligned with the caller's scan.py): 0 nothing found,
10 one or more found, 2 failure. Undetermined items do not change the exit
code; they are counted in ``counts.undetermined``.

``roots`` uses the same codes: 10 when any trust-side location holds a
distrusted root, 0 otherwise, 2 on failure. Distrust-side (Disallowed)
matches and undetermined items do not change the code; see ``counts``.

``ledger`` reads those documents and prints Markdown. It returns 10 when any
document has a found item that counts as bad (the codes above), 0 otherwise,
and 2 for an unreadable or invalid document (nothing is printed then).

``waitlist show`` returns 10 only when ``--stale-days`` is given and an item
is stale, 0 otherwise. ``waitlist record`` returns 0 after replacing the file;
with ``--from`` also when some items were left unchanged (they are listed).
Both return 2 for a bad file or bad arguments, printing nothing on stdout.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from collections.abc import Sequence

from patchwait import pyvenv
from patchwait.intel import IntelInputError, load_intel
from patchwait.ledger import LedgerInputError, ledger
from patchwait.model import (
    Found,
    NotFound,
    RuntimeKind,
    Undetermined,
    check_to_json,
    component_to_json,
    ledger_item_to_json,
)
from patchwait.roots import (
    RootsItem,
    RootsUsageError,
    WindowsAccess,
    audit_binary,
    audit_keystore,
    audit_pem,
    audit_pem_root,
    audit_windows,
    default_windows_access,
    load_distrust,
    roots_document,
    trust_found,
)
from patchwait.scan import (
    RUNTIME_FILE_NAMES,
    ScanUsageError,
    Target,
    load_targets_file,
    parse_baselines,
    scan_document,
    scan_with_walks,
    targets_from_paths,
    walk_root,
    write_atomic,
)
from patchwait.waitlist import (
    WaitlistInputError,
    any_stale,
    check_from_args,
    load_waitlist,
    parse_date_arg,
    parse_stale_days,
    record,
    record_from,
    record_from_document,
    render_markdown,
    rows,
    show_document,
)

EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_USAGE = 2
EXIT_UNDETERMINED = 3

EXIT_SCAN_CLEAN = 0
EXIT_SCAN_FOUND = 10
EXIT_SCAN_FAILURE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="patchwait")
    commands = parser.add_subparsers(dest="command", required=True)
    kinds = [kind.value for kind in RuntimeKind]
    version_of = commands.add_parser("version-of", help="read the version of a bundled runtime")
    version_of.add_argument("path")
    version_of.add_argument("--kind", required=True, choices=kinds)
    scan_cmd = commands.add_parser(
        "scan", help="compare bundled runtimes with caller-supplied minimums",
        epilog=("On Windows, an unreadable registry-configured Store package root is walked through "
                "packages registered for the current user only (package_root). Registry failures retain "
                "unreadable items (package_root_error). package_root reports path, packages_registered, "
                "walked, unreadable, absent, excluded, skipped_reparse_points, refused names "
                "as ASCII JSON string literals (including quotes), and note. "
                "Folders denying both listing and reading their "
                "owner/DACL are recorded as skipped_protected with skipped_protected_count, outside "
                "counts.undetermined. They were not looked into; an administrator must check if they matter."),
    )
    scan_cmd.add_argument("--path", action="append", default=[], help="target file (repeatable)")
    scan_cmd.add_argument("--targets", help='JSON file: [{"path": ..., "product": optional}]')
    scan_cmd.add_argument("--root", action="append", default=[], help="directory to walk for the kind's executable")
    scan_cmd.add_argument("--exclude", action="append", default=[], help="skip subdirectories whose path contains this")
    scan_cmd.add_argument("--kind", default=RuntimeKind.NODE.value, choices=kinds)
    scan_cmd.add_argument("--min", action="append", default=[], help="KIND=N.N.N[,N.N.N...] series minimums")
    scan_cmd.add_argument("--source", action="append", default=[], help="KIND=URL of the fix-version source")
    scan_cmd.add_argument("--out", help="write the document here atomically instead of stdout")
    roots_cmd = commands.add_parser("roots", help="audit where distrusted root certificates are still trusted")
    roots_cmd.add_argument("--distrust", action="append", default=[], help="list file: sha256:/sha1:/spki:<hex> label")
    roots_cmd.add_argument("--distrust-pem", action="append", default=[], help="PEM file of distrusted certificates")
    roots_cmd.add_argument("--windows", action="store_true", help="AuthRoot/Disallowed CTLs and ROOT/Disallowed stores")
    roots_cmd.add_argument("--pem", action="append", default=[], help="PEM bundle file (repeatable)")
    roots_cmd.add_argument("--pem-root", action="append", default=[], help="directory to walk for PEM bundles")
    roots_cmd.add_argument("--binary", action="append", default=[], help="binary to search for embedded roots")
    roots_cmd.add_argument("--keystore", action="append", default=[], help="Java PKCS12/JKS/JCEKS file (repeatable)")
    roots_cmd.add_argument("--out", help="write the document here atomically instead of stdout")
    ledger_cmd = commands.add_parser("ledger", help="turn scan/roots documents into Markdown for a ledger")
    ledger_cmd.add_argument("documents", nargs="+", help="JSON written by scan or roots")
    ledger_cmd.add_argument("--brief", action="store_true", help="collapse not_found items into a count")
    ledger_cmd.add_argument("--out", help="write the Markdown here atomically instead of stdout")
    waitlist_cmd = commands.add_parser("waitlist", help="items waiting on a vendor fix, kept in a JSON file")
    waitlist_actions = waitlist_cmd.add_subparsers(dest="action", required=True)
    show_cmd = waitlist_actions.add_parser("show", help="days since each item's last check; commands are printed, not run")
    show_cmd.add_argument("file")
    show_cmd.add_argument("--stale-days", help="mark items not done whose last check is more than N days old")
    show_cmd.add_argument("--today", help="YYYY-MM-DD to count days from (default: the local date)")
    show_cmd.add_argument("--format", default="json", choices=["json", "markdown"])
    show_cmd.add_argument("--intel-store", help="absolute local ScanMux store; read saved KEV only, never fetch")
    record_cmd = waitlist_actions.add_parser(
        "record", help="set one item's last check date and result, or update linked items from a saved result"
    )
    record_cmd.add_argument("file")
    record_cmd.add_argument("--id", action="append", default=[], help="the item (with --from: repeatable, optional)")
    record_cmd.add_argument("--from", dest="from_result", help="JSON written by scan or roots; uses each item's result_link")
    record_cmd.add_argument("--result", choices=["found", "not_found", "undetermined"])
    record_cmd.add_argument("--value", help="with --result found")
    record_cmd.add_argument("--reason", help="with --result undetermined: an undetermined reason name")
    record_cmd.add_argument("--detail", help="with --result undetermined")
    record_cmd.add_argument("--date", help="YYYY-MM-DD of the check (default: the local date; not in the future or before the item's last_checked)")
    return parser


def _version_of(args: argparse.Namespace) -> int:
    try:
        result, version_source = pyvenv.detect_runtime_with_venv(str(args.path), RuntimeKind(str(args.kind)))
        document = check_to_json(result, component_to_json)
        if version_source is not None and version_source.evidence is not None:
            document["version_source"] = version_source.evidence
        print(json.dumps(document, ensure_ascii=False))
    except Exception as error:  # noqa: BLE001 - report, never crash silently
        print(f"patchwait: internal error: {type(error).__name__}", file=sys.stderr)
        return EXIT_USAGE
    if isinstance(result, NotFound):
        return EXIT_NOT_FOUND
    if isinstance(result, Undetermined):
        return EXIT_UNDETERMINED
    assert isinstance(result, Found)
    # A component that was identified but whose version could not be read is
    # still "could not determine" from the caller's point of view.
    if isinstance(result.value.version, Undetermined):
        return EXIT_UNDETERMINED
    return EXIT_FOUND


def _write_stdout_utf8(text: str) -> None:
    """UTF-8 with LF, escaping lone surrogates just as file output does."""
    encoded = text.encode("utf-8", errors="backslashreplace")
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:  # replaced stdout, e.g. in tests
        sys.stdout.write(encoded.decode("utf-8"))
        return
    sys.stdout.flush()
    buffer.write(encoded)
    buffer.flush()


def _scan(args: argparse.Namespace) -> int:
    try:
        kind = RuntimeKind(str(args.kind))
        baselines = parse_baselines(list(args.min), list(args.source))
        targets: list[Target] = []
        if args.targets is not None:
            targets += load_targets_file(str(args.targets))
        targets += targets_from_paths([str(path) for path in args.path])
        roots = [str(root) for root in args.root]
        if not targets and not roots:
            raise ScanUsageError("no targets: give --path, --targets or --root")
        excludes = [str(text) for text in args.exclude]
        walks = [walk_root(root, RUNTIME_FILE_NAMES[kind], excludes) for root in roots]
        items = scan_with_walks(targets, walks, kind, baselines)
        document = scan_document(items, kind, baselines, walks=walks)
        text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        if args.out is not None:
            write_atomic(str(args.out), text)
        else:
            _write_stdout_utf8(text)
    except ScanUsageError as error:
        print(f"patchwait: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    except Exception as error:  # noqa: BLE001 - report, never crash silently
        print(f"patchwait: internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    counts = document["counts"]
    assert isinstance(counts, dict)
    found = counts["found"]
    assert isinstance(found, int)
    return EXIT_SCAN_FOUND if found > 0 else EXIT_SCAN_CLEAN


def _roots(args: argparse.Namespace, access: WindowsAccess | None = None) -> int:
    try:
        entries = load_distrust([str(p) for p in args.distrust], [str(p) for p in args.distrust_pem])
        if not (args.windows or args.pem or args.pem_root or args.binary or args.keystore):
            raise RootsUsageError("no locations: give --windows, --pem, --pem-root or --binary")
        items: list[RootsItem] = []
        if args.windows:
            items += audit_windows(entries, access if access is not None else default_windows_access())
        for path in args.pem:
            items += audit_pem(str(path), entries)
        for root in args.pem_root:
            items += audit_pem_root(str(root), entries)
        for path in args.binary:
            items += audit_binary(str(path), entries)
        for path in args.keystore:
            items += audit_keystore(str(path), entries)
        text = json.dumps(roots_document(items, entries), ensure_ascii=False, indent=2) + "\n"
        if args.out is not None:
            write_atomic(str(args.out), text)
        else:
            _write_stdout_utf8(text)
    except RootsUsageError as error:
        print(f"patchwait: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    except Exception as error:  # noqa: BLE001 - report, never crash silently
        print(f"patchwait: internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    return EXIT_SCAN_FOUND if trust_found(items) else EXIT_SCAN_CLEAN


def _same_file(a: str, b: str) -> bool:
    if os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b)):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:  # either one missing or unreadable: not shown to be the same
        return False


def _refuse_out_over_input(out: str, documents: Sequence[str]) -> None:
    for document in documents:
        if _same_file(out, document):
            raise LedgerInputError(f"{document}: --out names this input; refusing to overwrite it")


def _ledger(args: argparse.Namespace) -> int:
    try:
        if args.out is not None:
            _refuse_out_over_input(str(args.out), [str(path) for path in args.documents])
        rendered = ledger([str(path) for path in args.documents], brief=bool(args.brief))
        if args.out is not None:
            write_atomic(str(args.out), rendered.markdown)
        else:
            _write_stdout_utf8(rendered.markdown)
    except LedgerInputError as error:
        print(f"patchwait: ledger: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    except Exception as error:  # noqa: BLE001 - report, never crash silently
        print(f"patchwait: internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    return EXIT_SCAN_FOUND if rendered.bad_found else EXIT_SCAN_CLEAN


def _waitlist(args: argparse.Namespace, today: datetime.date | None) -> int:
    try:
        if args.action == "show":
            day = parse_date_arg(str(args.today), "--today") if args.today is not None else today
            day = day if day is not None else datetime.date.today()
            stale_days = parse_stale_days(str(args.stale_days)) if args.stale_days is not None else None
            items = load_waitlist(str(args.file), day)
            intel = load_intel(str(args.intel_store)) if args.intel_store is not None else None
            if args.format == "markdown":
                text = render_markdown(items, day, stale_days, intel)
            else:
                text = json.dumps(show_document(items, day, stale_days, intel=intel), ensure_ascii=False, indent=2) + "\n"
            _write_stdout_utf8(text)
            return EXIT_SCAN_FOUND if any_stale(rows(items, day, stale_days)) else EXIT_SCAN_CLEAN
        day = today if today is not None else datetime.date.today()
        if args.from_result is not None:
            ids = [str(item_id) for item_id in args.id]
            recorded = record_from(str(args.file), str(args.from_result), ids, day)
            document = record_from_document(recorded, str(args.from_result))
            _write_stdout_utf8(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
            return EXIT_SCAN_CLEAN
        result = check_from_args(str(args.result), args.value, args.reason, args.detail)
        when = parse_date_arg(str(args.date), "--date") if args.date is not None else day
        updated = record(str(args.file), str(args.id[0]), result, when, day)
        _write_stdout_utf8(json.dumps(ledger_item_to_json(updated), ensure_ascii=False) + "\n")
    except (WaitlistInputError, IntelInputError) as error:
        print(f"patchwait: waitlist: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    except OSError as error:
        print(f"patchwait: waitlist: cannot write {args.file}: {type(error).__name__}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    except Exception as error:  # noqa: BLE001 - report, never crash silently
        print(f"patchwait: internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILURE
    return EXIT_SCAN_CLEAN


def _check_record_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """``record`` takes one ``--id`` and ``--result``, or ``--from`` with optional ``--id``s. Exits with 2 otherwise."""
    if args.from_result is not None:
        options = {"--result": args.result, "--value": args.value, "--reason": args.reason,
                   "--detail": args.detail, "--date": args.date}
        given = [option for option, value in options.items() if value is not None]
        if given:
            parser.error(f"waitlist record --from takes no {', '.join(given)}: the result and the date come from the file")
        return
    missing = [option for option, value in (("--id", args.id), ("--result", args.result)) if not value]
    if missing:
        parser.error(f"waitlist record: the following arguments are required: {', '.join(missing)} (or --from)")
    if len(args.id) > 1:
        parser.error("waitlist record: give one --id, or use --from to update several items")


def main(
    argv: Sequence[str] | None = None,
    *,
    windows_access: WindowsAccess | None = None,
    today: datetime.date | None = None,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)  # exits with 2 on usage errors
    if args.command == "waitlist" and args.action == "record":
        _check_record_args(parser, args)
    if args.command == "scan":
        return _scan(args)
    if args.command == "roots":
        return _roots(args, windows_access)
    if args.command == "ledger":
        return _ledger(args)
    if args.command == "waitlist":
        return _waitlist(args, today)
    return _version_of(args)


if __name__ == "__main__":
    raise SystemExit(main())
