"""``waitlist record --from``: update linked items from a saved scan or roots result.

All results here are synthetic documents written in the shape ``scan --out`` and
``roots --out`` produce; no real machine data is used.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import unittest
from typing import Any
from unittest import mock

from patchwait.cli import main
from patchwait.model import Found, NotFound, Reason, RootsLink, RuntimeKind, ScanLink, Undetermined, ledger_item_from_json
from tests.test_waitlist import TODAY, Base, document, item

EDITOR = "Apps\\ExampleEditor\\resources\\node.exe"
TOOL = "Apps\\ExampleTool\\node.exe"
LOCKED = "Apps\\Locked\\node.exe"
BUNDLE = "Apps\\ExampleEditor\\certs\\cacert.pem"
LABEL = "Example Distrusted Root"
CERT_SHA256 = "ab" * 32


def scan_row(path: str, verdict: dict[str, Any], version: str | None = "24.19.0") -> dict[str, Any]:
    return {
        "path": path,
        "location_kind": "file",
        "product": {"name": "unknown", "inferred": True},
        "product_version": version,
        "checked_against": {"minimum": "24.22.1", "source": "https://example.invalid/node"},
        "verdict": verdict,
    }


def scan_result(*rows: dict[str, Any], kind: str = "node", generated: str = "2026-10-25T00:45:23+09:00") -> dict[str, Any]:
    results = [row["verdict"]["result"] for row in rows]
    return {
        "tool": "patchwait",
        "schema": 1,
        "generated": generated,
        "kind": kind,
        "baselines": {kind: {"minimums": ["24.22.1"], "source": "https://example.invalid/node"}},
        "counts": {"targets": len(rows), **{result: results.count(result) for result in ("found", "not_found", "undetermined")}},
        "walk": [],
        "items": list(rows),
    }


def sample_scan() -> dict[str, Any]:
    return scan_result(
        scan_row(EDITOR, {"result": "found", "value": "24.19.0"}),
        scan_row(TOOL, {"result": "not_found"}, version="24.22.1"),
        scan_row(LOCKED, {"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"}, version=None),
    )


def roots_row(location: str, location_kind: str, verdict: dict[str, Any], role: str = "trust") -> dict[str, Any]:
    matches = [{"matched_by": "sha256", "cert_sha256": CERT_SHA256, "subject_cn": LABEL}] if verdict["result"] == "found" else []
    return {
        "location": location,
        "location_kind": location_kind,
        "role": role,
        "distrust": LABEL,
        "verdict": verdict,
        "matches": matches,
        "details": {"pem_blocks": 2, "certs": 2, "malformed": 0},
    }


def roots_result(*rows: dict[str, Any]) -> dict[str, Any]:
    tally = {role: dict.fromkeys(("found", "not_found", "undetermined"), 0) for role in ("trust", "distrust")}
    for row in rows:
        tally[row["role"]][row["verdict"]["result"]] += 1
    return {
        "tool": "patchwait",
        "schema": 1,
        "generated": "2026-10-24T09:00:00+09:00",
        "check": "roots",
        "distrust": [{"label": LABEL, "sha256": CERT_SHA256, "sha1": None, "spki_sha256": None, "raw_der": False}],
        "counts": {"items": len(rows), **tally},
        "items": list(rows),
    }


def scan_link(path: str, kind: str = "node") -> dict[str, Any]:
    return {"check": "scan", "kind": kind, "path": path}


def roots_link(location: str, location_kind: str = "pem") -> dict[str, Any]:
    return {"check": "roots", "location_kind": location_kind, "location": location, "distrust": LABEL}


def linked_waitlist() -> dict[str, Any]:
    return document(
        item("W-1", "2026-10-01", result_link=scan_link(EDITOR)),
        item("W-2", "2026-10-01", result_link=scan_link(TOOL)),
        item("W-3", "2026-10-01", result_link=scan_link(LOCKED)),
        item("W-4", "2026-10-01", result_link=scan_link("Apps\\Gone\\node.exe")),
        item("W-5", "2026-10-01"),
        item("W-6", "2026-10-01", result_link=roots_link(BUNDLE)),
    )


class FromBase(Base):
    def setUp(self) -> None:
        super().setUp()
        self.result_path = os.path.join(self.dir, "result.json")

    def write_result(self, data: object) -> str:
        with open(self.result_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        return self.result_path

    def record_from(self, *extra: str) -> tuple[int, dict[str, Any]]:
        code, out, err = self.run_cli("waitlist", "record", self.path, "--from", self.result_path, *extra)
        self.assertEqual(err, "")
        return code, json.loads(out)

    def items_by_id(self) -> dict[str, dict[str, Any]]:
        with open(self.path, encoding="utf-8") as handle:
            return {entry["id"]: entry for entry in json.load(handle)["items"]}


class ResultLinkTests(unittest.TestCase):
    def test_round_trip_and_absent_link(self) -> None:
        scan = ledger_item_from_json(item("W-1", "2026-10-01", result_link=scan_link(EDITOR)))
        self.assertEqual(scan.result_link, ScanLink(RuntimeKind.NODE, EDITOR))
        roots = ledger_item_from_json(item("W-2", "2026-10-01", result_link=roots_link(BUNDLE)))
        self.assertEqual(roots.result_link, RootsLink("pem", BUNDLE, LABEL))
        self.assertIsNone(ledger_item_from_json(item("W-3", "2026-10-01")).result_link)

    def test_rejections(self) -> None:
        cases: list[tuple[object, str]] = [
            ({"check": "ledger", "path": "x"}, "result_link.check"),
            ({"check": "scan", "kind": "node"}, "missing path"),
            ({"check": "scan", "kind": "node", "path": "x", "location": "y"}, "unknown location"),
            ({"check": "scan", "kind": "ruby", "path": "x"}, "result_link.kind"),
            ({"check": "scan", "kind": "node", "path": " "}, "result_link.path"),
            ({"check": "roots", "location_kind": "pem", "location": "x"}, "missing distrust"),
            ("scan", "must be an object"),
        ]
        for link, needle in cases:
            with self.subTest(link=link):
                with self.assertRaises(ValueError) as raised:
                    ledger_item_from_json(item("W-1", "2026-10-01", result_link=link))
                self.assertIn(needle, str(raised.exception))


class RecordFromTests(FromBase):
    def test_cves_survive_from_and_absent_cves_keep_shape(self) -> None:
        data = linked_waitlist()
        data["items"][0]["cves"] = ["CVE-2026-0001"]
        self.write_doc(data)
        self.write_result(sample_scan())
        code, payload = self.record_from()
        self.assertEqual(code, 0)
        updated = payload["updated"]
        self.assertEqual(updated[0]["cves"], ["CVE-2026-0001"])
        self.assertNotIn("cves", updated[1])
        with open(self.path, encoding="utf-8") as handle:
            saved = json.load(handle)["items"]
        self.assertEqual(saved[0]["cves"], ["CVE-2026-0001"])
        self.assertNotIn("cves", saved[1])

    def test_scan_input(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        code, out = self.record_from()
        self.assertEqual(code, 0)
        self.assertEqual(out["check"], "scan")
        self.assertEqual(out["checked"], "2026-10-25")  # the date in the result's generated, not today
        self.assertEqual(out["counts"], {"updated": 3, "changed": 3, "unchanged": 3})
        self.assertEqual([entry["id"] for entry in out["updated"]], ["W-1", "W-2", "W-3"])
        self.assertEqual(
            out["unchanged"],
            [{"id": "W-4", "why": "not_found_in_result"}, {"id": "W-5", "why": "no_result_link"},
             {"id": "W-6", "why": "not_found_in_result"}],
        )
        items = self.items_by_id()
        self.assertEqual(items["W-1"]["last_result"], {"result": "found", "value": "24.19.0"})
        self.assertEqual(items["W-2"]["last_result"], {"result": "not_found"})
        for item_id in ("W-1", "W-2", "W-3"):
            self.assertEqual(items[item_id]["last_checked"], "2026-10-25")
        for item_id in ("W-4", "W-5", "W-6"):
            self.assertEqual(items[item_id], linked_waitlist()["items"][int(item_id[2:]) - 1])
        self.assertEqual(items["W-1"]["result_link"], scan_link(EDITOR))  # the link is kept

    def test_unknown_stays_unknown(self) -> None:
        self.write_doc(document(item("W-3", "2026-10-01", result_link=scan_link(LOCKED))))
        self.write_result(sample_scan())
        self.record_from()
        parsed = ledger_item_from_json(self.items_by_id()["W-3"])
        self.assertEqual(parsed.last_result, Undetermined(Reason.FILE_UNREADABLE, "PermissionError"))

    def test_roots_input(self) -> None:
        self.write_doc(linked_waitlist())
        binary = "Apps\\ExampleSync\\bin\\sync.exe"
        self.write_result(roots_result(
            roots_row(BUNDLE, "pem", {"result": "found", "value": ["sha1", "sha256", "spki_sha256"]}),
            roots_row(binary, "binary", {"result": "undetermined", "reason": "no_certs_recognised", "detail": "none"}),
        ))
        code, out = self.record_from()
        self.assertEqual(code, 0)
        self.assertEqual(out["check"], "roots")
        self.assertEqual([entry["id"] for entry in out["updated"]], ["W-6"])
        self.assertEqual(
            [entry["why"] for entry in out["unchanged"]],
            ["not_found_in_result"] * 4 + ["no_result_link"],  # scan links never match a roots result
        )
        items = self.items_by_id()
        self.assertEqual(items["W-6"]["last_result"], {"result": "found", "value": "sha1, sha256, spki_sha256"})
        self.assertEqual(items["W-6"]["last_checked"], "2026-10-24")

    def test_roots_link_needs_the_same_location_kind_and_label(self) -> None:
        self.write_doc(document(
            item("W-1", "2026-10-01", result_link=roots_link(BUNDLE, "binary")),
            item("W-2", "2026-10-01", result_link={**roots_link(BUNDLE), "distrust": "Other Root"}),
        ))
        self.write_result(roots_result(roots_row(BUNDLE, "pem", {"result": "not_found"})))
        before = self.read_bytes()
        _, out = self.record_from()
        self.assertEqual(out["counts"], {"updated": 0, "changed": 0, "unchanged": 2})
        self.assertEqual(self.read_bytes(), before)

    def test_matching_is_exact(self) -> None:
        # Same file on Windows, but not the same string: never guessed.
        variants = [EDITOR.lower(), EDITOR.replace("\\", "/"), EDITOR + " ", "C:\\" + EDITOR]
        self.write_doc(document(*(item(f"W-{n}", "2026-10-01", result_link=scan_link(path)) for n, path in enumerate(variants))))
        self.write_result(sample_scan())
        before = self.read_bytes()
        _, out = self.record_from()
        self.assertEqual({entry["why"] for entry in out["unchanged"]}, {"not_found_in_result"})
        self.assertEqual(self.read_bytes(), before)

    def test_kind_must_match(self) -> None:
        self.write_doc(document(item("W-1", "2026-10-01", result_link=scan_link(EDITOR, "python"))))
        self.write_result(sample_scan())
        _, out = self.record_from()
        self.assertEqual(out["unchanged"], [{"id": "W-1", "why": "not_found_in_result"}])

    def test_partial_match_with_ids(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        _, out = self.record_from("--id", "W-2", "--id", "W-4")
        self.assertEqual([entry["id"] for entry in out["updated"]], ["W-2"])
        self.assertEqual(out["unchanged"], [{"id": "W-4", "why": "not_found_in_result"}])
        items = self.items_by_id()
        self.assertEqual(items["W-2"]["last_checked"], "2026-10-25")
        self.assertEqual(items["W-1"]["last_checked"], "2026-10-01")  # linked but not selected

    def test_unknown_id_is_refused(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        before = self.read_bytes()
        self.assert_rejected("waitlist", "record", self.path, "--from", self.result_path, "--id", "W-9", needle="no item with id")
        self.assertEqual(self.read_bytes(), before)

    def test_ambiguous_rows_are_not_used(self) -> None:
        self.write_doc(document(item("W-1", "2026-10-01", result_link=scan_link(EDITOR)),
                                item("W-2", "2026-10-01", result_link=scan_link(TOOL))))
        self.write_result(scan_result(
            scan_row(EDITOR, {"result": "found", "value": "24.19.0"}),
            scan_row(EDITOR, {"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"}, None),
            scan_row(TOOL, {"result": "not_found"}, "24.22.1"),
            scan_row(TOOL, {"result": "not_found"}, "24.22.1"),  # a repeated --path with the same verdict
        ))
        _, out = self.record_from()
        self.assertEqual(out["unchanged"], [{"id": "W-1", "why": "ambiguous_in_result"}])
        self.assertEqual([entry["id"] for entry in out["updated"]], ["W-2"])
        self.assertEqual(self.items_by_id()["W-1"]["last_checked"], "2026-10-01")

    def test_newer_check_is_not_overwritten(self) -> None:
        newer = item("W-1", "2026-10-26", result_link=scan_link(EDITOR), last_result={"result": "not_found"})
        self.write_doc(document(newer))
        self.write_result(sample_scan())
        before = self.read_bytes()
        _, out = self.record_from()
        self.assertEqual(out["unchanged"], [{"id": "W-1", "why": "checked_after_result"}])
        self.assertEqual(self.read_bytes(), before)

    def test_idempotent_rerun(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        _, first = self.record_from()
        after_first = self.read_bytes()
        with mock.patch("patchwait.waitlist.write_atomic") as write:
            _, second = self.record_from()
        write.assert_not_called()  # nothing changed, so the file is not rewritten
        self.assertEqual(self.read_bytes(), after_first)
        self.assertEqual(second["counts"], {"updated": 3, "changed": 0, "unchanged": 3})
        self.assertEqual([entry["changed"] for entry in second["updated"]], [False] * 3)
        self.assertEqual(
            [{k: v for k, v in entry.items() if k != "changed"} for entry in first["updated"]],
            [{k: v for k, v in entry.items() if k != "changed"} for entry in second["updated"]],
        )

    def test_show_keeps_the_link(self) -> None:
        self.write_doc(linked_waitlist())
        _, shown = self.show()
        self.assertEqual(shown["items"][0]["result_link"], scan_link(EDITOR))
        self.assertNotIn("result_link", shown["items"][4])


class RefusalTests(FromBase):
    def assert_refused(self, result: object, needle: str) -> None:
        self.write_doc(linked_waitlist())
        before = self.read_bytes()
        if isinstance(result, str):
            with open(self.result_path, "w", encoding="utf-8") as handle:
                handle.write(result)
        else:
            self.write_result(result)
        self.assert_rejected("waitlist", "record", self.path, "--from", self.result_path, needle=needle)
        self.assertEqual(self.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(self.dir)), ["result.json", "waitlist.json"])

    def test_unknown_shapes_are_refused(self) -> None:
        both = sample_scan()
        both["check"] = "roots"
        bad_counts = sample_scan()
        bad_counts["counts"]["found"] = 0
        no_reason = sample_scan()
        del no_reason["items"][2]["verdict"]["reason"]
        extra_verdict_key = sample_scan()
        extra_verdict_key["items"][1]["verdict"]["value"] = "24.22.1"
        roots_empty_found = roots_result(roots_row(BUNDLE, "pem", {"result": "found", "value": ["sha256"]}))
        roots_empty_found["items"][0]["verdict"]["value"] = []
        cases: list[tuple[object, str]] = [
            (linked_waitlist(), "not a saved scan or roots result"),
            ({"tool": "other", "schema": 1, "kind": "node", "counts": {}, "items": []}, "not a saved scan or roots result"),
            ([], "not a saved scan or roots result"),
            (both, "exactly one of kind (scan) or check (roots)"),
            (bad_counts, "found is 0 but the items give 1"),
            (no_reason, "verdict.reason"),
            (extra_verdict_key, "verdict: unknown value"),
            (roots_empty_found, "non-empty list"),
            ("{not json", "not JSON"),
            ('{"tool": "patchwait", "tool": "patchwait"}', "duplicate key"),
        ]
        for result, needle in cases:
            with self.subTest(needle=needle):
                self.assert_refused(result, needle)

    def test_missing_result_file(self) -> None:
        self.write_doc(linked_waitlist())
        self.assert_rejected("waitlist", "record", self.path, "--from", os.path.join(self.dir, "nope.json"),
                             needle="cannot read")

    def test_result_from_the_future(self) -> None:
        self.assert_refused(scan_result(scan_row(EDITOR, {"result": "not_found"}), generated="2026-10-27T08:00:00+09:00"),
                            "is after today")

    def test_bad_roots_location_kind_in_waitlist(self) -> None:
        self.write_doc(document(item("W-1", "2026-10-01", result_link=roots_link(BUNDLE, "registry"))))
        self.write_result(sample_scan())
        self.assert_rejected("waitlist", "record", self.path, "--from", self.result_path, needle="unknown location_kind")

    def test_options_that_do_not_go_with_from(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        for extra in (["--result", "not_found"], ["--value", "1"], ["--reason", "not_pe"], ["--detail", "d"],
                      ["--date", "2026-10-01"]):
            with self.subTest(extra=extra):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                    main(["waitlist", "record", self.path, "--from", self.result_path, *extra], today=TODAY)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("--from takes no", err.getvalue())

    def test_several_ids_need_from(self) -> None:
        self.write_doc(linked_waitlist())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["waitlist", "record", self.path, "--id", "W-1", "--id", "W-2", "--result", "not_found"], today=TODAY)
        self.assertEqual(raised.exception.code, 2)

    def test_failed_replace_keeps_old_file(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        before = self.read_bytes()
        with mock.patch("os.replace", side_effect=PermissionError("locked")):
            self.assert_rejected("waitlist", "record", self.path, "--from", self.result_path, needle="cannot write")
        self.assertEqual(self.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(self.dir)), ["result.json", "waitlist.json"])  # temporary file removed

    def test_failed_write_keeps_old_file(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        before = self.read_bytes()
        with mock.patch("os.fsync", side_effect=OSError("disk full")):
            self.assert_rejected("waitlist", "record", self.path, "--from", self.result_path, needle="cannot write")
        self.assertEqual(self.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(self.dir)), ["result.json", "waitlist.json"])

    def test_result_file_is_not_modified(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        with open(self.result_path, "rb") as handle:
            before = handle.read()
        self.record_from()
        with open(self.result_path, "rb") as handle:
            self.assertEqual(handle.read(), before)


class FromNeverRunsCommandTests(FromBase):
    def test_no_process_is_started(self) -> None:
        self.write_doc(linked_waitlist())
        self.write_result(sample_scan())
        boom = mock.Mock(side_effect=AssertionError("a process was started"))
        patches = [mock.patch.object(subprocess, name, boom) for name in ("run", "Popen", "call", "check_call", "check_output")]
        patches += [mock.patch.object(os, "system", boom), mock.patch.object(os, "popen", boom)]
        if hasattr(os, "startfile"):
            patches.append(mock.patch.object(os, "startfile", boom))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            code, _ = self.record_from()
        self.assertEqual(code, 0)
        boom.assert_not_called()


class CheckConversionTests(unittest.TestCase):
    def test_only_the_three_values(self) -> None:
        from patchwait.waitlist import saved_result_from_document

        saved = saved_result_from_document(sample_scan(), "scan.json")
        self.assertEqual(saved.rows[ScanLink(RuntimeKind.NODE, EDITOR)], [Found("24.19.0")])
        self.assertEqual(saved.rows[ScanLink(RuntimeKind.NODE, TOOL)], [NotFound()])
        self.assertIsInstance(saved.rows[ScanLink(RuntimeKind.NODE, LOCKED)][0], Undetermined)


if __name__ == "__main__":
    unittest.main()
