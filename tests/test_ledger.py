from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace

from patchwait.cli import main
from patchwait.ledger import DISALLOWED_NOTE
from patchwait.roots import AUTHROOT_VALUE, DISALLOWED_VALUE
from tests.cert_builder import build_cert, build_ctl, pem, subject_for
from tests.pe_builder import NODE_LIKE, VersionSpec, build_pe
from tests.test_roots import FakeWindows

KEY_BAD = bytes(range(1, 65))
KEY_OTHER = bytes(range(100, 164))
BAD = build_cert("Synthetic Distrusted Root G3", KEY_BAD, serial=3)
OTHER = build_cert("Synthetic Other Root", KEY_OTHER, serial=5)


def node_spec(version: str) -> VersionSpec:
    a, b, c = (int(part) for part in version.split("."))
    strings = dict(NODE_LIKE.strings, FileVersion=version, ProductVersion=version)
    return replace(NODE_LIKE, strings=strings, fixed_file=(a, b, c, 0), fixed_product=(a, b, c, 0))


def scan_doc(generated: str = "2026-10-25T00:45:23+09:00") -> dict[str, object]:
    """A hand-built scan document with one item of each result."""
    against = {"minimum": "24.22.1", "source": "https://example.invalid/node"}
    return {
        "tool": "patchwait",
        "schema": 1,
        "generated": generated,
        "kind": "node",
        "baselines": {},
        "counts": {"targets": 5, "found": 1, "not_found": 1, "undetermined": 3},
        "walk": [],
        "items": [
            {"path": "Apps\\Old\\node.exe", "location_kind": "file", "product": {"name": "Old", "inferred": True},
             "product_version": "24.19.0", "checked_against": against,
             "verdict": {"result": "found", "value": "24.19.0"}},
            {"path": "Apps\\New\\node.exe", "location_kind": "file", "product": {"name": "New", "inferred": False},
             "product_version": "24.22.1", "checked_against": against, "verdict": {"result": "not_found"}},
            {"path": "Apps\\Locked", "location_kind": "directory", "product": {"name": "unknown", "inferred": True},
             "product_version": None, "checked_against": {"minimum": None, "source": None},
             "verdict": {"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"}},
            {"path": "Apps\\Twenty\\node.exe", "location_kind": "file", "product": {"name": "unknown", "inferred": True},
             "product_version": "20.1.0", "checked_against": {"minimum": None, "source": None},
             "verdict": {"result": "undetermined", "reason": "no_baseline", "detail": "no --min for node series 20"}},
            {"path": "Apps\\Locked2", "location_kind": "directory", "product": {"name": "unknown", "inferred": True},
             "product_version": None, "checked_against": {"minimum": None, "source": None},
             "verdict": {"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"}},
        ],
    }


LOCATIONS = {"trust": ("cert-store:ROOT", "root_store"), "distrust": ("HKLM\\Disallowed", "disallowed_ctl")}


def roots_doc(role: str = "distrust", result: str = "found") -> dict[str, object]:
    verdict: dict[str, object] = {"result": result}
    if result == "found":
        verdict["value"] = ["sha256"]
    tally = {r: {"found": 0, "not_found": 0, "undetermined": 0} for r in ("trust", "distrust")}
    tally[role][result] = 1
    return {
        "tool": "patchwait",
        "schema": 1,
        "generated": "2026-10-24T23:59:00-07:00",
        "check": "roots",
        "distrust": [],
        "counts": {"items": 1, **tally},
        "items": [
            {"location": LOCATIONS[role][0], "location_kind": LOCATIONS[role][1], "role": role,
             "distrust": "Synthetic G3", "verdict": verdict, "matches": [], "details": {}},
        ],
    }


class LedgerCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.windows = FakeWindows()
        self.windows.registry[AUTHROOT_VALUE] = build_ctl([subject_for(OTHER), subject_for(BAD)])
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([])
        self.windows.stores["ROOT"] = [(OTHER, "x509_asn", True)]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, data: bytes) -> str:
        path = os.path.normpath(os.path.join(self.dir, rel))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def write_doc(self, name: str, doc: object) -> str:
        return self.write(name, json.dumps(doc).encode("utf-8"))

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv), windows_access=self.windows.access())
        return code, out.getvalue(), err.getvalue()

    def ledger(self, *argv: str) -> tuple[int, str]:
        code, out, err = self.run_cli("ledger", *argv)
        self.assertNotEqual(code, 2, err)
        return code, out

    def assert_rejected(self, *paths: str) -> str:
        code, out, err = self.run_cli("ledger", *paths)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("patchwait: ledger:", err)
        return err


class FromRealDocumentsTests(LedgerCase):
    """Documents written by the real scan and roots code, so the shapes stay in sync."""

    def real_scan(self) -> str:
        self.write("Apps/Old/node.exe", build_pe(version=node_spec("24.19.0"))[0])
        self.write("Apps/New/node.exe", build_pe(version=node_spec("24.22.1"))[0])
        self.write("Apps/Twenty/node.exe", build_pe(version=node_spec("20.1.0"))[0])
        out = os.path.join(self.dir, "scan.json")
        code, _, err = self.run_cli(
            "scan", "--min", "node=24.22.1", "--root", os.path.join(self.dir, "Apps"), "--out", out
        )
        self.assertEqual(code, 10, err)
        return out

    def real_roots(self) -> str:
        distrust = self.write("distrust.txt", f"{hashlib.sha256(BAD).hexdigest()} Synthetic G3\n".encode())
        bundle = self.write("Apps/Old/cacert.pem", pem(OTHER) + pem(BAD))
        del self.windows.stores["Disallowed"]  # unreadable: a distrust-side undetermined item
        out = os.path.join(self.dir, "roots.json")
        code, _, err = self.run_cli("roots", "--distrust", distrust, "--windows", "--pem", bundle, "--out", out)
        self.assertEqual(code, 10, err)
        return out

    def test_scan_document(self) -> None:
        path = self.real_scan()
        with open(path, encoding="utf-8") as handle:
            generated = json.load(handle)["generated"]
        code, out = self.ledger(path)
        self.assertEqual(code, 10)
        lines = out.splitlines()
        self.assertEqual(
            lines[0], f"{generated[5:10]}: patchwait scan node: found 1 / not_found 1 / undetermined 1 (no_baseline 1)"
        )
        old = os.path.join(self.dir, "Apps", "Old", "node.exe")
        self.assertIn(f"- found: `{old}` — `24.19.0` < `24.22.1`, product `unknown` (inferred)", lines)
        self.assertTrue(any(line.startswith("- undetermined: ") and "no_baseline: `no --min" in line for line in lines))
        self.assertEqual(sum(line.startswith("- not_found: ") for line in lines), 1)

    def test_roots_document(self) -> None:
        path = self.real_roots()
        with open(path, encoding="utf-8") as handle:
            generated = json.load(handle)["generated"]
        code, out = self.ledger(path)
        self.assertEqual(code, 10)
        lines = out.splitlines()
        self.assertEqual(
            lines[0],
            f"{generated[5:10]}: patchwait roots: trust found 2 / not_found 1 / undetermined 0; "
            "distrust found 0 / not_found 1 / undetermined 1 (store_unreadable 1)",
        )
        self.assertTrue(any(line.startswith("- undetermined: ") and "store_unreadable: " in line for line in lines))
        authroot = [line for line in lines if "location_kind authroot_ctl" in line]
        self.assertEqual(len(authroot), 1)
        self.assertTrue(authroot[0].startswith("- found: "))
        self.assertIn("role trust", authroot[0])
        self.assertIn("distrust `Synthetic G3`", authroot[0])
        self.assertIn("matched_by `sha256`", authroot[0])
        self.assertIn("this_update `2026-08-25T07:24:34Z`", authroot[0])

    def test_multiple_documents_keep_order(self) -> None:
        scan, roots = self.real_scan(), self.real_roots()
        _, out = self.ledger(roots, scan)
        summaries = [line for line in out.splitlines() if ": patchwait " in line]
        self.assertEqual(len(summaries), 2)
        self.assertIn("patchwait roots:", summaries[0])
        self.assertIn("patchwait scan node:", summaries[1])
        self.assertIn("\n\n", out)


class FormatTests(LedgerCase):
    def test_reason_counts_by_count_then_name_and_date_from_generated(self) -> None:
        code, out = self.ledger(self.write_doc("s.json", scan_doc()))
        self.assertEqual(code, 10)
        self.assertEqual(
            out.splitlines()[0],
            "10-25: patchwait scan node: found 1 / not_found 1 / undetermined 3 (file_unreadable 2, no_baseline 1)",
        )

    def test_date_is_the_documents_own_local_date(self) -> None:
        _, out = self.ledger(self.write_doc("r.json", roots_doc()))
        self.assertTrue(out.startswith("10-24: patchwait roots: "))  # 10-25 in UTC, 10-24 where it ran

    def test_full_listing(self) -> None:
        _, out = self.ledger(self.write_doc("s.json", scan_doc()))
        self.assertEqual(
            out.splitlines()[1:],
            [
                "",
                "- found: `Apps\\Old\\node.exe` — `24.19.0` < `24.22.1`, product `Old` (inferred)",
                "- undetermined: `Apps\\Locked` (directory) — file_unreadable: `PermissionError`",
                "- undetermined: `Apps\\Twenty\\node.exe` — no_baseline: `no --min for node series 20`",
                "- undetermined: `Apps\\Locked2` (directory) — file_unreadable: `PermissionError`",
                "- not_found: `Apps\\New\\node.exe` — `24.22.1` >= `24.22.1`, product `New`",
            ],
        )

    def test_brief_collapses_not_found_but_never_undetermined(self) -> None:
        _, out = self.ledger("--brief", self.write_doc("s.json", scan_doc()))
        lines = out.splitlines()
        self.assertEqual(sum(line.startswith("- undetermined: ") for line in lines), 3)
        self.assertEqual(lines[-1], "- not_found: 1 items")
        self.assertNotIn("Apps\\New", out)

    def test_brief_roots_splits_not_found_by_role(self) -> None:
        _, out = self.ledger("--brief", self.write_doc("r.json", roots_doc("trust", "not_found")))
        self.assertEqual(out.splitlines()[-1], "- not_found: 1 items (trust 1, distrust 0)")

    def test_distrust_found_is_not_bad(self) -> None:
        code, out = self.ledger(self.write_doc("r.json", roots_doc("distrust", "found")))
        self.assertEqual(code, 0)
        self.assertIn("- found: `HKLM\\Disallowed` — role distrust", out)
        self.assertIn("distrust found 1 / not_found 0 / undetermined 0", out)

    def test_trust_found_is_bad(self) -> None:
        code, _ = self.ledger(self.write_doc("r.json", roots_doc("trust", "found")))
        self.assertEqual(code, 10)

    def test_no_found_is_zero(self) -> None:
        doc = scan_doc()
        items = doc["items"]
        assert isinstance(items, list)
        del items[0]
        doc["counts"] = {"targets": 4, "found": 0, "not_found": 1, "undetermined": 3}
        code, _ = self.ledger(self.write_doc("s.json", doc))
        self.assertEqual(code, 0)

    def test_newlines_and_backticks_cannot_break_a_line(self) -> None:
        doc = roots_doc()
        items = doc["items"]
        assert isinstance(items, list)
        items[0]["distrust"] = "a`b\nc"  # pyright: ignore[reportIndexIssue]
        _, out = self.ledger(self.write_doc("r.json", doc))
        self.assertIn("distrust ``a`b\\u000ac``", out)

    def test_out_is_written_atomically_and_stdout_stays_empty(self) -> None:
        target = os.path.join(self.dir, "ledger.md")
        code, out, _ = self.run_cli("ledger", "--out", target, self.write_doc("s.json", scan_doc()))
        self.assertEqual((code, out), (10, ""))
        with open(target, "rb") as handle:
            data = handle.read()
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.decode("utf-8").startswith("10-25: patchwait scan node: "))
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".tmp")], [])


class RejectionTests(LedgerCase):
    def mutated(self, base: dict[str, object], **changes: object) -> str:
        doc = copy.deepcopy(base)
        for key, value in changes.items():
            if value is None:
                doc.pop(key, None)
            else:
                doc[key] = value
        return self.write_doc("bad.json", doc)

    def test_counts_mismatch(self) -> None:
        err = self.assert_rejected(
            self.mutated(scan_doc(), counts={"targets": 5, "found": 0, "not_found": 2, "undetermined": 3})
        )
        self.assertIn("found is 0 but the items give 1", err)

    def test_roots_counts_mismatch(self) -> None:
        doc = roots_doc()
        counts = doc["counts"]
        assert isinstance(counts, dict)
        counts["distrust"] = {"found": 0, "not_found": 1, "undetermined": 0}
        self.assert_rejected(self.write_doc("bad.json", doc))

    def test_wrong_tool_schema_and_missing_fields(self) -> None:
        for changes in (
            {"tool": "other"},
            {"schema": 2},
            {"schema": True},
            {"counts": None},
            {"items": None},
            {"items": {}},
            {"kind": None},
            {"kind": "ruby"},
            {"check": "roots"},
            {"generated": "yesterday"},
        ):
            with self.subTest(changes=changes):
                self.assert_rejected(self.mutated(scan_doc(), **changes))
        self.assert_rejected(self.mutated(roots_doc(), check="other"))

    def test_bad_verdicts(self) -> None:
        for verdict in (
            {"result": "maybe"},
            {"result": "found"},
            {"result": "undetermined", "reason": "made_up", "detail": "x"},
            {"result": "undetermined", "reason": "no_baseline"},
        ):
            with self.subTest(verdict=verdict):
                doc = scan_doc()
                items = doc["items"]
                assert isinstance(items, list)
                items[1]["verdict"] = verdict  # pyright: ignore[reportIndexIssue]
                self.assert_rejected(self.write_doc("bad.json", doc))

    def test_bad_json_missing_file_and_not_an_object(self) -> None:
        self.assert_rejected(self.write("bad.json", b"{not json"))
        self.assert_rejected(os.path.join(self.dir, "missing.json"))
        self.assert_rejected(self.write_doc("list.json", []))
        self.assert_rejected(self.write("bom.json", b"\xff\xfe{}"))

    def test_one_bad_document_prints_nothing_for_the_good_ones(self) -> None:
        good = self.write_doc("good.json", scan_doc())
        self.assert_rejected(good, self.write("bad.json", b"{"))

    def test_scan_found_needs_a_non_empty_version_value(self) -> None:
        for value in (None, "", "  ", 24, ["24.19.0"]):
            with self.subTest(value=value):
                doc = scan_doc()
                set_item(doc, 0, verdict={"result": "found", "value": value})
                self.assert_rejected(self.write_doc("bad.json", doc))

    def test_scan_found_value_must_match_product_version(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, verdict={"result": "found", "value": "24.18.0"})
        err = self.assert_rejected(self.write_doc("bad.json", doc))
        self.assertIn("does not match product_version", err)
        doc = scan_doc()
        set_item(doc, 0, product_version=None)
        self.assert_rejected(self.write_doc("bad.json", doc))

    def test_roots_found_needs_non_empty_matched_by(self) -> None:
        for value in ([], [""], [" "], [1], None, "sha256", ["sha256", ""]):
            with self.subTest(value=value):
                doc = roots_doc("trust", "found")
                set_item(doc, 0, verdict={"result": "found", "value": value})
                self.assert_rejected(self.write_doc("bad.json", doc))

    def test_roots_location_kind_and_role_must_agree(self) -> None:
        for changes in (
            {"location_kind": "registry"},
            {"location_kind": None},
            {"location_kind": "disallowed_store"},  # a distrust-side kind with role trust
            {"location_kind": "pem", "role": "distrust"},
            {"location_kind": "root_store", "role": "both"},
        ):
            with self.subTest(changes=changes):
                doc = roots_doc("trust", "found")
                set_item(doc, 0, **changes)
                self.assert_rejected(self.write_doc("bad.json", doc))

    def test_bad_walk_entries(self) -> None:
        for walk in (None, {}, [{"skipped_reparse_points": -1, "excluded_dirs": 0}], [{"excluded_dirs": 1}]):
            with self.subTest(walk=walk):
                self.assert_rejected(self.mutated(scan_doc(), walk=walk))

    def test_rejected_input_does_not_create_or_change_out(self) -> None:
        bad = self.write("bad.json", b"{")
        target = os.path.join(self.dir, "new.md")
        code, out, _ = self.run_cli("ledger", "--out", target, bad)
        self.assertEqual((code, out), (2, ""))
        self.assertFalse(os.path.exists(target))
        existing = self.write("old.md", b"previous ledger\n")
        code, out, _ = self.run_cli("ledger", "--out", existing, self.write_doc("good.json", scan_doc()), bad)
        self.assertEqual((code, out), (2, ""))
        with open(existing, "rb") as handle:
            self.assertEqual(handle.read(), b"previous ledger\n")
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".tmp")], [])


def set_item(doc: dict[str, object], index: int, **fields: object) -> None:
    """Set fields of doc["items"][index]."""
    items = doc["items"]
    assert isinstance(items, list)
    item = items[index]
    assert isinstance(item, dict)
    item.update(fields)  # pyright: ignore[reportUnknownMemberType]


class EscapingTests(LedgerCase):
    """Free text from a document is shown literally and cannot add Markdown or HTML."""

    def test_markdown_and_html_stay_inside_code_spans(self) -> None:
        doc = scan_doc()
        crafted = "24.19.0<img src=x>[a](b)"
        set_item(doc, 0, path="Apps\\<b>x</b>\\node.exe", product={"name": "*_<[", "inferred": False},
                 product_version=crafted, verdict={"result": "found", "value": crafted})
        set_item(doc, 2, verdict={"result": "undetermined", "reason": "file_unreadable", "detail": "*_<[ `x`"})
        _, out = self.ledger(self.write_doc("s.json", doc))
        lines = out.splitlines()
        self.assertEqual(
            lines[2], "- found: `Apps\\<b>x</b>\\node.exe` — `24.19.0<img src=x>[a](b)` < `24.22.1`, product `*_<[`"
        )
        self.assertEqual(lines[3], "- undetermined: `Apps\\Locked` (directory) — file_unreadable: `` *_<[ `x` ``")

    def test_roots_labels_methods_and_this_update_are_code(self) -> None:
        doc = roots_doc("trust", "found")
        set_item(doc, 0, distrust="<script>", verdict={"result": "found", "value": ["sha256", "*x*"]},
                 details={"this_update": "[t](u)"})
        _, out = self.ledger(self.write_doc("r.json", doc))
        self.assertIn(
            "- found: `cert-store:ROOT` — role trust, location_kind root_store, distrust `<script>`, "
            "matched_by `sha256`, `*x*`, this_update `[t](u)`",
            out,
        )

    def test_controls_are_escaped_and_spaces_kept(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="A  B\tC\u2028D\u3000E\nF.exe")
        set_item(doc, 1, path=" spaced ")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("- found: `A  B\\u0009C\\u2028D\u3000E\\u000aF.exe` — ", out)
        self.assertIn("- not_found: `  spaced  ` — ", out)  # padded so CommonMark keeps both spaces
        self.assertNotIn("\t", out)
        self.assertNotIn("\u2028", out)

    def test_email_shaped_path_segments_are_masked(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="C:\\Users\\u\\gcloud\\legacy_credentials\\someone.name+x@example.co.jp\\node.exe")
        set_item(doc, 1, path="C:/opt/user@host/v1@2/node.exe")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("`C:\\Users\\u\\gcloud\\legacy_credentials\\<email>\\node.exe`", out)
        self.assertNotIn("example.co.jp", out)
        self.assertIn("`C:/opt/user@host/v1@2/node.exe`", out)  # not email-shaped: kept
        roots = roots_doc("trust", "found")
        set_item(roots, 0, location="D:\\certs\\me@example.com\\cacert.pem", location_kind="pem")
        _, out = self.ledger(self.write_doc("r.json", roots))
        self.assertIn("- found: `D:\\certs\\<email>\\cacert.pem` — ", out)


class SummaryAndExitTests(LedgerCase):
    def test_not_walked_suffix(self) -> None:
        doc = scan_doc()
        doc["walk"] = [
            {"root": "A", "matched_files": 1, "unreadable_dirs": 0, "skipped_reparse_points": 2, "excluded_dirs": 0},
            {"root": "B", "matched_files": 0, "unreadable_dirs": 0, "skipped_reparse_points": 0, "excluded_dirs": 1},
        ]
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertTrue(out.splitlines()[0].endswith(
            "(file_unreadable 2, no_baseline 1); not walked: skipped_reparse_points 2, excluded_dirs 1"
        ))
        doc["walk"] = [{"root": "A", "matched_files": 1, "unreadable_dirs": 0, "skipped_reparse_points": 0,
                        "excluded_dirs": 0}]
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertNotIn("not walked", out)

    def test_later_document_with_the_only_bad_found_gives_10(self) -> None:
        clean = scan_doc()
        items = clean["items"]
        assert isinstance(items, list)
        del items[0]
        clean["counts"] = {"targets": 4, "found": 0, "not_found": 1, "undetermined": 3}
        first = self.write_doc("clean.json", clean)
        distrust = self.write_doc("distrust.json", roots_doc("distrust", "found"))
        self.assertEqual(self.ledger(first, distrust)[0], 0)
        self.assertEqual(self.ledger(first, distrust, self.write_doc("trust.json", roots_doc("trust", "found")))[0], 10)

    def test_brief_roots_never_collapses_undetermined(self) -> None:
        doc = roots_doc("trust", "not_found")
        items = doc["items"]
        assert isinstance(items, list)
        items.append({"location": "cert-store:Disallowed", "location_kind": "disallowed_store", "role": "distrust",
                      "distrust": "Synthetic G3", "matches": [], "details": {},
                      "verdict": {"result": "undetermined", "reason": "store_unreadable", "detail": "OSError"}})
        doc["counts"] = {"items": 2, "trust": {"found": 0, "not_found": 1, "undetermined": 0},
                         "distrust": {"found": 0, "not_found": 0, "undetermined": 1}}
        _, out = self.ledger("--brief", self.write_doc("r.json", doc))
        lines = out.splitlines()
        self.assertIn("- undetermined: `cert-store:Disallowed` — role distrust, location_kind disallowed_store, "
                      "distrust `Synthetic G3` — store_unreadable: `OSError`", lines)
        self.assertEqual(lines[-1], "- not_found: 1 items (trust 1, distrust 0)")


class DisallowedNoteTests(LedgerCase):
    def real_roots(self, *, disallowed: bool) -> list[str]:
        self.windows.stores["ROOT"] = [(OTHER, "x509_asn", True), (BAD, "x509_asn", True)]
        self.windows.stores["Disallowed"] = [(BAD, "x509_asn", True)] if disallowed else []
        distrust = self.write("distrust.txt", f"{hashlib.sha256(BAD).hexdigest()} Synthetic G3\n".encode())
        bundle = self.write("Apps/Old/cacert.pem", pem(BAD))
        out = os.path.join(self.dir, "roots.json")
        code, _, err = self.run_cli("roots", "--distrust", distrust, "--windows", "--pem", bundle, "--out", out)
        self.assertEqual(code, 10, err)
        code, text = self.ledger(out)
        self.assertEqual(code, 10)  # the note changes no exit code
        return text.splitlines()

    def found(self, lines: list[str], kind: str) -> str:
        [line] = [line for line in lines if line.startswith("- found: ") and f"location_kind {kind}," in line]
        return line

    def test_trust_side_windows_found_is_noted_when_disallowed_lists_it(self) -> None:
        lines = self.real_roots(disallowed=True)
        self.assertIn("trust found 3 / not_found 0 / undetermined 0; distrust found 1", lines[0])
        for kind in ("root_store", "authroot_ctl"):
            self.assertTrue(self.found(lines, kind).endswith(" — " + DISALLOWED_NOTE), kind)
        self.assertNotIn(DISALLOWED_NOTE, self.found(lines, "pem"))
        self.assertNotIn(DISALLOWED_NOTE, self.found(lines, "disallowed_store"))

    def test_no_note_without_a_disallowed_store_found(self) -> None:
        lines = self.real_roots(disallowed=False)
        self.assertNotIn(DISALLOWED_NOTE, "\n".join(lines))

    def test_note_is_per_label(self) -> None:
        doc = roots_doc("trust", "found")
        items = doc["items"]
        assert isinstance(items, list)
        items.append({"location": "cert-store:Disallowed", "location_kind": "disallowed_store", "role": "distrust",
                      "distrust": "Another Root", "matches": [], "details": {},
                      "verdict": {"result": "found", "value": ["sha256"]}})
        doc["counts"] = {"items": 2, "trust": {"found": 1, "not_found": 0, "undetermined": 0},
                         "distrust": {"found": 1, "not_found": 0, "undetermined": 0}}
        _, out = self.ledger(self.write_doc("r.json", doc))
        self.assertNotIn(DISALLOWED_NOTE, out)


CERT_A = "a" * 64
CERT_B = "b" * 64


def two_sided(
    trust_matches: Sequence[Mapping[str, object]], disallowed_matches: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """A trust-side ROOT store found and a Disallowed store found for the same label."""
    doc = roots_doc("trust", "found")
    set_item(doc, 0, matches=[dict(m) for m in trust_matches])
    items = doc["items"]
    assert isinstance(items, list)
    items.append({"location": "cert-store:Disallowed", "location_kind": "disallowed_store", "role": "distrust",
                  "distrust": "Synthetic G3", "matches": [dict(m) for m in disallowed_matches], "details": {},
                  "verdict": {"result": "found", "value": sorted({str(m["matched_by"]) for m in disallowed_matches})}})
    doc["counts"] = {"items": 2, "trust": {"found": 1, "not_found": 0, "undetermined": 0},
                     "distrust": {"found": 1, "not_found": 0, "undetermined": 0}}
    return doc


class DisallowedSameCertificateTests(LedgerCase):
    def note_on_trust_line(self, doc: dict[str, object]) -> bool:
        _, out = self.ledger(self.write_doc("r.json", doc))
        [line] = [line for line in out.splitlines() if "location_kind root_store" in line]
        return line.endswith(" — " + DISALLOWED_NOTE)

    def test_no_note_when_disallowed_holds_another_certificate(self) -> None:
        doc = two_sided([{"matched_by": "sha256", "cert_sha256": CERT_A}],
                        [{"matched_by": "spki_sha256", "cert_sha256": CERT_B}])
        self.assertFalse(self.note_on_trust_line(doc))

    def test_note_when_disallowed_holds_the_same_certificate(self) -> None:
        doc = two_sided([{"matched_by": "sha256", "cert_sha256": CERT_A}],
                        [{"matched_by": "spki_sha256", "cert_sha256": CERT_A.upper()}])
        self.assertTrue(self.note_on_trust_line(doc))

    def test_no_note_when_the_certificate_cannot_be_shown(self) -> None:
        for trust, disallowed in (
            ([{"matched_by": "sha1", "cert_sha256": None}], [{"matched_by": "sha1", "cert_sha256": CERT_A}]),
            ([{"matched_by": "sha256", "cert_sha256": CERT_A}], [{"matched_by": "sha1"}]),
            ([], [{"matched_by": "sha256", "cert_sha256": CERT_A}]),
        ):
            with self.subTest(trust=trust, disallowed=disallowed):
                self.assertFalse(self.note_on_trust_line(two_sided(trust, disallowed)))

    def test_bad_cert_sha256_is_rejected(self) -> None:
        for value in ("xyz", 12, "a" * 63):
            with self.subTest(value=value):
                doc = two_sided([{"matched_by": "sha256", "cert_sha256": value}], [])
                self.assert_rejected(self.write_doc("bad.json", doc))
        doc = roots_doc("trust", "found")
        set_item(doc, 0, matches={})
        self.assert_rejected(self.write_doc("bad.json", doc))


class UnambiguousEscapeTests(LedgerCase):
    def test_literal_escape_text_and_a_real_newline_differ(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="A\\u000aB.exe")  # the six characters \u000a
        set_item(doc, 1, path="A\nB.exe")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("- found: `A\\u005cu000aB.exe` — ", out)
        self.assertIn("- not_found: `A\\u000aB.exe` — ", out)

    def test_other_backslashes_are_kept(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="C:\\Users\\u\\x\\U1234\\node.exe")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("- found: `C:\\Users\\u\\x\\U1234\\node.exe` — ", out)

    def test_format_characters_are_escaped(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="a\u202eb\u2066c\u2069d\u200be\ufefff\U000e0001g\\U000e0001.exe")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("- found: `a\\u202eb\\u2066c\\u2069d\\u200be\\ufefff\\U000e0001g\\u005cU000e0001.exe` — ", out)
        for ch in ("\u202e", "\u2066", "\u2069", "\u200b", "\ufeff", "\U000e0001"):
            self.assertNotIn(ch, out)


class EmailInSegmentTests(LedgerCase):
    def test_email_inside_a_segment_is_masked_and_versions_are_kept(self) -> None:
        doc = scan_doc()
        set_item(doc, 0, path="C:\\creds\\first.last@example.com (1)\\x@y.example.org.json\\node.exe")
        set_item(doc, 1, path="C:\\cache\\pkg@1.0.0.tgz\\lib@2.3\\a@b\\node.exe")
        _, out = self.ledger(self.write_doc("s.json", doc))
        self.assertIn("- found: `C:\\creds\\<email> (1)\\<email>\\node.exe` — ", out)
        self.assertNotIn("example", out.split("\n- not_found")[0].split("— ")[0])
        self.assertIn("- not_found: `C:\\cache\\pkg@1.0.0.tgz\\lib@2.3\\a@b\\node.exe` — ", out)


class ScanLocationKindTests(LedgerCase):
    def test_location_kind_must_be_file_or_directory(self) -> None:
        for value in ("symlink", "File", None, 1):
            with self.subTest(value=value):
                doc = scan_doc()
                set_item(doc, 1, location_kind=value)
                self.assert_rejected(self.write_doc("bad.json", doc))


def pem_root_doc(details: dict[str, object]) -> dict[str, object]:
    """Two labels, each with a not_found item for one pem_root directory with the same details."""
    doc = roots_doc("trust", "not_found")
    doc["items"] = [
        {"location": "D:\\certs", "location_kind": "pem_root", "role": "trust", "distrust": label,
         "verdict": {"result": "not_found"}, "matches": [], "details": dict(details)}
        for label in ("Synthetic G3", "Synthetic G4")
    ]
    doc["counts"] = {"items": 2, "trust": {"found": 0, "not_found": 2, "undetermined": 0},
                     "distrust": {"found": 0, "not_found": 0, "undetermined": 0}}
    return doc


class PemRootSkipTests(LedgerCase):
    def test_skips_are_on_the_line_and_in_the_summary_once_per_directory(self) -> None:
        path = self.write_doc("r.json", pem_root_doc({"files": 0, "skipped_reparse_points": 2, "skipped_key_only": 1}))
        _, out = self.ledger(path)
        lines = out.splitlines()
        self.assertEqual(
            lines[0],
            "10-24: patchwait roots: trust found 0 / not_found 2 / undetermined 0; "
            "distrust found 0 / not_found 0 / undetermined 0; not walked: skipped_reparse_points 2, skipped_key_only 1",
        )
        self.assertIn("- not_found: `D:\\certs` — role trust, location_kind pem_root, distrust `Synthetic G3`, "
                      "skipped_reparse_points 2, skipped_key_only 1", lines)
        _, brief = self.ledger("--brief", path)
        self.assertEqual(brief.splitlines()[0], lines[0])

    def test_one_kind_of_skip_and_none(self) -> None:
        _, out = self.ledger(self.write_doc("r.json", pem_root_doc({"files": 3, "skipped_key_only": 4})))
        self.assertTrue(out.splitlines()[0].endswith("; not walked: skipped_reparse_points 0, skipped_key_only 4"))
        self.assertIn("pem_root, distrust `Synthetic G4`, skipped_key_only 4", out)
        self.assertNotIn("skipped_reparse_points 0,", out.split("\n", 1)[1])
        _, out = self.ledger(self.write_doc("r.json", pem_root_doc({"files": 3})))
        self.assertNotIn("not walked", out)

    def test_bad_skip_counts_are_rejected(self) -> None:
        for value in (-1, "2", 1.5, None):
            with self.subTest(value=value):
                self.assert_rejected(self.write_doc("bad.json", pem_root_doc({"skipped_key_only": value})))

    def test_real_roots_with_a_key_only_file(self) -> None:
        distrust = self.write("distrust.txt", f"{hashlib.sha256(BAD).hexdigest()} Synthetic G3\n".encode())
        self.write("bundles/key.pem", b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        out = os.path.join(self.dir, "roots.json")
        self.run_cli("roots", "--distrust", distrust, "--pem-root", os.path.join(self.dir, "bundles"), "--out", out)
        _, text = self.ledger(out)
        self.assertIn("; not walked: skipped_reparse_points 0, skipped_key_only 1", text.splitlines()[0])


def binary_doc(details: object) -> dict[str, object]:
    doc = roots_doc("trust", "not_found")
    set_item(doc, 0, location="D:\\rt.exe", location_kind="binary", details=details)
    return doc


BINARY_DETAILS: dict[str, object] = {
    "pem_blocks": 1, "certs": 0, "der_certs": 118, "malformed": 0,
    "ignored_pem_blocks": [{"offset": 4242, "reason": "empty_pem_block"}],
}


class BinaryDetailsTests(LedgerCase):
    def test_der_certs_and_ignored_blocks_are_on_the_line(self) -> None:
        _, out = self.ledger(self.write_doc("r.json", binary_doc(BINARY_DETAILS)))
        self.assertIn("- not_found: `D:\\rt.exe` — role trust, location_kind binary, distrust `Synthetic G3`, "
                      "der_certs 118, ignored_pem_blocks 1", out.splitlines())

    def test_capped_list_shows_the_total_and_none_ignored_shows_nothing(self) -> None:
        listed = [{"offset": n, "reason": "empty_pem_block"} for n in range(20)]
        details = dict(BINARY_DETAILS, ignored_pem_blocks=listed, ignored_pem_blocks_total=31)
        _, out = self.ledger(self.write_doc("r.json", binary_doc(details)))
        self.assertIn("der_certs 118, ignored_pem_blocks 31", out)
        _, out = self.ledger(self.write_doc("r.json", binary_doc(dict(BINARY_DETAILS, ignored_pem_blocks=[]))))
        self.assertIn("distrust `Synthetic G3`, der_certs 118\n", out)
        old = {"pem_blocks": 1, "certs": 1, "malformed": 0}  # written before der_certs existed
        _, out = self.ledger(self.write_doc("r.json", binary_doc(old)))
        self.assertIn("distrust `Synthetic G3`\n", out)

    def test_bad_shapes_are_rejected(self) -> None:
        good = [{"offset": 1, "reason": "empty_pem_block"}]
        for changes in (
            {"der_certs": -1}, {"der_certs": "118"}, {"der_certs": True}, {"certs": 1.5}, {"malformed": None},
            {"pem_blocks": -2}, {"ignored_pem_blocks": {}}, {"ignored_pem_blocks": [1]},
            {"ignored_pem_blocks": [{"offset": -1, "reason": "empty_pem_block"}]},
            {"ignored_pem_blocks": [{"offset": "1", "reason": "empty_pem_block"}]},
            {"ignored_pem_blocks": [{"offset": 1}]}, {"ignored_pem_blocks": [{"offset": 1, "reason": ""}]},
            {"ignored_pem_blocks": good, "ignored_pem_blocks_total": 1},
            {"ignored_pem_blocks": good, "ignored_pem_blocks_total": -5},
            {"ignored_pem_blocks": good, "ignored_pem_blocks_total": "9"},
        ):
            with self.subTest(changes=changes):
                self.assert_rejected(self.write_doc("bad.json", binary_doc(dict(BINARY_DETAILS, **changes))))
        no_list = {key: value for key, value in BINARY_DETAILS.items() if key != "ignored_pem_blocks"}
        self.assert_rejected(self.write_doc("bad.json", binary_doc(dict(no_list, ignored_pem_blocks_total=21))))

    def test_reason_must_be_empty_pem_block_and_a_total_needs_exactly_20_listed(self) -> None:
        for reason in ("malformed", "Empty_pem_block", 1, None):
            with self.subTest(reason=reason):
                details = dict(BINARY_DETAILS, ignored_pem_blocks=[{"offset": 1, "reason": reason}])
                self.assert_rejected(self.write_doc("bad.json", binary_doc(details)))
        for count in (1, 19, 21, 30):
            with self.subTest(count=count):
                listed = [{"offset": n, "reason": "empty_pem_block"} for n in range(count)]
                details = dict(BINARY_DETAILS, ignored_pem_blocks=listed, ignored_pem_blocks_total=31)
                self.assert_rejected(self.write_doc("bad.json", binary_doc(details)))
        self.assert_rejected(self.write_doc("bad.json", binary_doc([])))

    def test_real_roots_on_a_binary(self) -> None:
        distrust = self.write("distrust.txt", f"{hashlib.sha256(BAD).hexdigest()} Synthetic G3\n".encode())
        template = b"-----BEGIN CERTIFICATE-----\n" + b"\0" * 8 + b"-----END CERTIFICATE-----"
        binary = self.write("rt.exe", b"MZ" + template + OTHER + b"\0" * 9 + OTHER)
        out = os.path.join(self.dir, "roots.json")
        code, _, err = self.run_cli("roots", "--distrust", distrust, "--binary", binary, "--out", out)
        self.assertEqual(code, 0, err)
        _, text = self.ledger(out)
        self.assertIn("location_kind binary, distrust `Synthetic G3`, der_certs 2, ignored_pem_blocks 1", text)


class OutOverInputTests(LedgerCase):
    def test_out_naming_an_input_is_refused_and_nothing_is_written(self) -> None:
        source = self.write_doc("s.json", scan_doc())
        with open(source, "rb") as handle:
            before = handle.read()
        other = self.write_doc("r.json", roots_doc())
        spellings = [source, os.path.join(self.dir, ".", "s.json"), os.path.relpath(source)]
        if os.name == "nt":
            spellings.append(source.upper())
        for out in spellings:
            with self.subTest(out=out):
                code, stdout, err = self.run_cli("ledger", "--out", out, other, source)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("--out names this input", err)
                with open(source, "rb") as handle:
                    self.assertEqual(handle.read(), before)
        self.assertEqual(sorted(os.listdir(self.dir)), ["r.json", "s.json"])

    def test_out_through_a_hard_link_is_refused(self) -> None:
        source = self.write_doc("s.json", scan_doc())
        link = os.path.join(self.dir, "link.md")
        try:
            os.link(source, link)
        except OSError:
            self.skipTest("hard links are not available here")
        code, stdout, _ = self.run_cli("ledger", "--out", link, source)
        self.assertEqual((code, stdout), (2, ""))


CERT_G3 = hashlib.sha256(BAD).hexdigest()
SHA1_G3 = hashlib.sha1(BAD).hexdigest()
SHA1_KEY = "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\" + SHA1_G3.upper()


def store_doc(match_extra: Mapping[str, object]) -> dict[str, object]:
    """A root_store found; a match with registry_keys gets the certificate's cert_sha1 unless it states one."""
    doc = roots_doc("trust", "found")
    sha1: dict[str, object] = {"cert_sha1": SHA1_G3} if "registry_keys" in match_extra else {}
    set_item(doc, 0, matches=[{"matched_by": "sha256", "cert_sha256": CERT_G3, **sha1, **match_extra}])
    return doc


def ctl_doc(details: Mapping[str, object]) -> dict[str, object]:
    doc = roots_doc("distrust", "found")
    set_item(doc, 0, details=dict(details))
    return doc


class RegistryKeyTimeTests(LedgerCase):
    def line(self, doc: dict[str, object]) -> str:
        _, out = self.ledger(self.write_doc("r.json", doc))
        (line,) = [line for line in out.splitlines() if line.startswith("- ")]
        return line

    def test_key_times_on_a_store_found_line(self) -> None:
        other = SHA1_KEY.replace("HKLM", "HKCU")
        doc = store_doc({"registry_keys": [
            {"key": other, "last_write": None, "last_write_note": "the time is zero or out of range"},
            {"key": SHA1_KEY, "last_write": "2026-10-22T04:36:15Z"},
        ]})
        line = self.line(doc)
        self.assertIn(f", registry `{SHA1_KEY}` last write `2026-10-22T04:36:15Z`", line)
        self.assertIn(f", registry `{other}` last write unknown (`the time is zero or out of range`)", line)

    def test_not_found_note_and_errors(self) -> None:
        doc = store_doc({"registry_keys": [], "registry_keys_note": "not found in the registry locations checked"})
        self.assertIn(", registry `not found in the registry locations checked`", self.line(doc))
        doc = store_doc({"registry_keys": [], "registry_keys_note": "not found in the registry locations that could be read",
                         "registry_keys_errors": [{"key": SHA1_KEY, "error": "PermissionError"}]})
        self.assertIn(f", registry `{SHA1_KEY}` unreadable `PermissionError`", self.line(doc))

    def test_a_certificate_matched_two_ways_lists_its_keys_once(self) -> None:
        keys = {"cert_sha1": SHA1_G3, "registry_keys": [{"key": SHA1_KEY, "last_write": "2026-10-22T04:36:15Z"}]}
        doc = store_doc(keys)
        set_item(doc, 0, matches=[{"matched_by": m, "cert_sha256": CERT_G3, **keys} for m in ("sha256", "sha1")],
                 verdict={"result": "found", "value": ["sha1", "sha256"]})
        line = self.line(doc)
        self.assertEqual(line.count("registry "), 1)
        self.assertIn(", registry `", line)  # one certificate: no SHA-1 prefix

    def test_two_certificates_prefix_each_registry_part_with_the_sha1(self) -> None:
        other_sha256, other_sha1 = "cd" * 32, "EF" * 20
        note = "not found in the registry locations checked"
        doc = store_doc({})
        set_item(doc, 0, matches=[
            {"matched_by": "sha256", "cert_sha256": CERT_G3, "cert_sha1": SHA1_G3,
             "registry_keys": [{"key": SHA1_KEY, "last_write": "2026-10-22T04:36:15Z"}]},
            {"matched_by": "spki_sha256", "cert_sha256": other_sha256, "cert_sha1": other_sha1,
             "registry_keys": [], "registry_keys_note": note},
        ], verdict={"result": "found", "value": ["sha256", "spki_sha256"]})
        line = self.line(doc)
        g3 = SHA1_G3.upper()[:12]
        self.assertIn(f", `{g3}` registry `{SHA1_KEY}` last write `2026-10-22T04:36:15Z`", line)
        self.assertIn(f", `{other_sha1[:12]}` registry `{note}`", line)
        self.assertEqual(line.count("` registry `"), 2)

    def test_last_sync_on_ctl_lines(self) -> None:
        self.assertIn(", last_sync `2026-10-22T04:36:15Z`", self.line(ctl_doc({"last_sync": "2026-10-22T04:36:15Z"})))
        line = self.line(ctl_doc({"last_sync": None, "last_sync_note": "LastSyncTime not found"}))
        self.assertIn(", last_sync unknown (`LastSyncTime not found`)", line)

    def test_real_roots_document(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        sha1 = hashlib.sha1(BAD).hexdigest().upper()
        key = f"HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\{sha1}"
        self.windows.keys[key] = 134371173750000000  # 2026-10-22T04:36:15Z
        self.windows.registry["LastSyncTime"] = (134371173750000000).to_bytes(8, "little")
        distrust = self.write("distrust.txt", f"{CERT_G3} Synthetic G3\n".encode())
        out = os.path.join(self.dir, "roots.json")
        code, _, err = self.run_cli("roots", "--distrust", distrust, "--windows", "--out", out)
        self.assertEqual(code, 10, err)
        _, text = self.ledger(out)
        lines = text.splitlines()
        (root,) = [line for line in lines if "location_kind root_store" in line]
        self.assertIn(f"registry `{key}` last write `2026-10-22T04:36:15Z`", root)
        (authroot,) = [line for line in lines if "location_kind authroot_ctl" in line]
        self.assertIn("last_sync `2026-10-22T04:36:15Z`", authroot)
        (disallowed,) = [line for line in lines if "location_kind disallowed_ctl" in line]
        self.assertIn("last_sync unknown (`DisallowedCertLastSyncTime not found`)", disallowed)

    def test_bad_shapes_are_rejected(self) -> None:
        good = {"key": SHA1_KEY, "last_write": "2026-10-22T04:36:15Z"}
        for extra in (
            {"registry_keys": {}}, {"registry_keys": [1]}, {"registry_keys": [{"last_write": None}]},
            {"registry_keys": [{"key": "", "last_write": None, "last_write_note": "n"}]},
            {"registry_keys": [dict(good, last_write="2026-10-22 04:36:15")]},
            {"registry_keys": [dict(good, last_write="2026-13-40T04:36:15Z")]},
            {"registry_keys": [dict(good, last_write=134371173750000000)]},
            {"registry_keys": [dict(good, last_write=None)]},  # null needs a note
            {"registry_keys": [dict(good, last_write_note="n")]},  # a note with a time
            {"registry_keys": []},  # empty needs the note
            {"registry_keys": [good], "registry_keys_note": "n"},
            {"registry_keys_note": "n"}, {"registry_keys_errors": [{"key": SHA1_KEY, "error": "E"}]},
            {"registry_keys": [good], "registry_keys_errors": []},
            {"registry_keys": [good], "registry_keys_errors": {}},
            {"registry_keys": [good], "registry_keys_errors": [{"key": SHA1_KEY}]},
            {"registry_keys": [good], "registry_keys_errors": [{"key": SHA1_KEY, "error": 5}]},
            {"registry_keys": [{"key": SHA1_KEY}]},  # last_write must be stated
            {"registry_keys": [{"key": SHA1_KEY, "last_write_note": "n"}]},  # even when null with a note
            {"registry_keys": [{"last_write": "2026-10-22T04:36:15Z"}]},  # key must be stated
            {"registry_keys": [good], "cert_sha1": None}, {"registry_keys": [good], "cert_sha1": "AB" * 19},
            {"cert_sha1": SHA1_G3},  # cert_sha1 needs registry_keys
        ):
            with self.subTest(extra=extra):
                self.assert_rejected(self.write_doc("bad.json", store_doc(extra)))
        for key in ({"key": SHA1_KEY}, {"key": SHA1_KEY, "last_write_note": "n"}):
            err = self.assert_rejected(self.write_doc("bad.json", store_doc({"registry_keys": [key]})))
            self.assertIn("registry_keys[0].last_write: is missing", err)
        for details in (
            {"last_sync": 5}, {"last_sync": "yesterday"}, {"last_sync": None}, {"last_sync": None, "last_sync_note": ""},
            {"last_sync": "2026-10-22T04:36:15Z", "last_sync_note": "n"}, {"last_sync_note": "n"},
        ):
            with self.subTest(details=details):
                self.assert_rejected(self.write_doc("bad.json", ctl_doc(details)))

    def test_keys_must_be_the_paths_looked_up(self) -> None:
        sha1 = SHA1_G3.upper()
        base = "SOFTWARE\\Microsoft\\SystemCertificates"
        for key in (
            f"HKLM\\{base}\\Disallowed\\Certificates\\{sha1}",  # a store not looked up for root_store
            f"HKLM\\{base}\\AuthRoot\\Certificates\\" + "BB" * 20,  # another certificate
            f"HKU\\{base}\\AuthRoot\\Certificates\\{sha1}",  # unknown hive
            f"HKLM\\SOFTWARE\\Other\\AuthRoot\\Certificates\\{sha1}",  # unknown base
            SHA1_KEY + "\\Extra", " " + SHA1_KEY,
        ):
            with self.subTest(key=key):
                doc = store_doc({"registry_keys": [{"key": key, "last_write": "2026-10-22T04:36:15Z"}]})
                err = self.assert_rejected(self.write_doc("bad.json", doc))
                self.assertIn("registry_keys[0].key: is not a registry key looked up", err)
                doc = store_doc({"registry_keys": [], "registry_keys_note": "n",
                                 "registry_keys_errors": [{"key": key, "error": "PermissionError"}]})
                err = self.assert_rejected(self.write_doc("bad.json", doc))
                self.assertIn("registry_keys_errors[0].key: is not a registry key looked up", err)

    def test_every_path_looked_up_is_accepted_in_any_case(self) -> None:
        sha1 = SHA1_G3.upper()
        for key in (
            SHA1_KEY.lower(),
            f"HKCU\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\{sha1}",
            f"HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\ROOT\\Certificates\\{sha1}",
        ):
            with self.subTest(key=key):
                doc = store_doc({"registry_keys": [{"key": key, "last_write": "2026-10-22T04:36:15Z"}]})
                self.assertIn(f"registry `{key}` last write", self.line(doc))

    def test_registry_fields_only_on_store_matches(self) -> None:
        keys: dict[str, object] = {"cert_sha1": SHA1_G3, "registry_keys": [{"key": SHA1_KEY, "last_write": None,
                                                                             "last_write_note": "n"}]}
        for name in ("registry_keys", "cert_sha1", "registry_keys_note", "registry_keys_errors"):
            with self.subTest(field=name):
                doc = ctl_doc({})
                value = keys.get(name, "n" if name == "registry_keys_note" else [{"key": SHA1_KEY, "error": "E"}])
                set_item(doc, 0, matches=[{"matched_by": "sha256", "cert_sha256": CERT_G3, name: value}])
                err = self.assert_rejected(self.write_doc("bad.json", doc))
                self.assertIn(f".{name}: is only for root_store and disallowed_store matches", err)
        doc = ctl_doc({})
        set_item(doc, 0, matches=[{"matched_by": "sha256", "cert_sha256": CERT_G3, **keys}])
        err = self.assert_rejected(self.write_doc("bad.json", doc))  # the whole set, well formed, is still refused
        self.assertIn("is only for root_store and disallowed_store matches", err)

    def test_last_sync_only_on_ctl_details(self) -> None:
        for details in ({"last_sync": "2026-10-22T04:36:15Z"}, {"last_sync": None, "last_sync_note": "n"},
                        {"last_sync_note": "n"}):
            with self.subTest(details=details):
                doc = store_doc({})
                set_item(doc, 0, details=dict(details))
                err = self.assert_rejected(self.write_doc("bad.json", doc))
                self.assertIn("is only for authroot_ctl and disallowed_ctl details", err)


if __name__ == "__main__":
    unittest.main()
