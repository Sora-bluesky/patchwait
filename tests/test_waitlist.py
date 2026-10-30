from __future__ import annotations

import ast
import contextlib
import copy
import datetime
import io
import json
import os
import subprocess
import tempfile
import unittest
from typing import Any
from unittest import mock

import patchwait.waitlist as waitlist_module
from patchwait.cli import main
from patchwait.model import (
    Done,
    Found,
    NotFound,
    Reason,
    Undetermined,
    WaitingOnVendor,
    ledger_item_from_json,
    ledger_item_to_json,
)

TODAY = datetime.date(2026, 10, 26)


def item(item_id: str, last_checked: str, status: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": item_id,
        "title": f"Synthetic item {item_id}",
        "status": status if status is not None else {"state": "waiting_on_vendor", "vendor": "Example Vendor"},
        "recheck_command": f"patchwait version-of Apps/Example{item_id}/node.exe --kind node",
        "last_checked": last_checked,
        "last_result": {"result": "found", "value": "24.19.0"},
    }
    data.update(extra)
    return data


def document(*items: dict[str, Any]) -> dict[str, Any]:
    return {"tool": "patchwait", "schema": 1, "kind": "waitlist", "items": list(items)}


def sample() -> dict[str, Any]:
    return document(
        item("W-1", "2026-10-01"),
        item("W-2", "2026-10-20", {"state": "in_progress", "owner": "Example Team"},
             last_result={"result": "not_found"}),
        item("W-3", "2026-10-26", {"state": "awaiting_decision", "question": "Replace the app?"},
             last_result={"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"}),
        item("W-4", "2026-01-01", {"state": "done", "resolution": "Vendor shipped 24.22.1"}),
    )


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.path = os.path.join(self.dir, "waitlist.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_doc(self, data: object) -> str:
        return self.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    def write_text(self, text: str) -> str:
        with open(self.path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return self.path

    def read_bytes(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def run_cli(self, *argv: str, today: datetime.date | None = TODAY) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv), today=today)
        return code, out.getvalue(), err.getvalue()

    def show(self, *extra: str) -> tuple[int, dict[str, Any]]:
        code, out, err = self.run_cli("waitlist", "show", self.path, *extra)
        self.assertEqual(err, "")
        return code, json.loads(out)

    def assert_rejected(self, *argv: str, needle: str, today: datetime.date | None = TODAY) -> None:
        code, out, err = self.run_cli(*argv, today=today)
        self.assertEqual(code, 2, msg=err)
        self.assertEqual(out, "")
        self.assertIn(needle, err)


class ItemFromJsonTests(unittest.TestCase):
    def test_cves_are_optional_exact_unique_ids(self) -> None:
        base = item("W-1", "2026-10-01")
        self.assertNotIn("cves", ledger_item_to_json(ledger_item_from_json(base)))
        raw = {**base, "cves": ["CVE-2026-0001", "CVE-2026-12345"]}
        parsed = ledger_item_from_json(raw)
        self.assertEqual(parsed.cves, ("CVE-2026-0001", "CVE-2026-12345"))
        self.assertEqual(ledger_item_to_json(parsed), raw)
        for cves in (None, [], {}, "CVE-2026-0001", [1], [True], ["cve-2026-0001"], [" CVE-2026-0001"],
                     ["CVE-2026-0001x"], ["CVE-２０２６-0001"], ["CVE-2026-123"],
                     ["CVE-2026-" + "1" * 56], ["CVE-2026-0001", "CVE-2026-0001"]):
            with self.subTest(cves=cves), self.assertRaisesRegex(ValueError, "cves"):
                ledger_item_from_json({**base, "cves": cves})

    def test_round_trip(self) -> None:
        parsed = ledger_item_from_json(item("W-1", "2026-10-01"))
        self.assertEqual(parsed.status, WaitingOnVendor("Example Vendor"))
        self.assertEqual(parsed.last_checked, datetime.date(2026, 10, 1))
        self.assertEqual(parsed.last_result, Found("24.19.0"))
        undetermined = ledger_item_from_json(
            item("W-2", "2026-10-01", last_result={"result": "undetermined", "reason": "not_pe", "detail": "d"})
        )
        self.assertEqual(undetermined.last_result, Undetermined(Reason.NOT_PE, "d"))
        self.assertEqual(ledger_item_from_json(item("W-3", "2026-10-01", last_result={"result": "not_found"})).last_result, NotFound())
        self.assertEqual(
            ledger_item_from_json(item("W-4", "2026-10-01", {"state": "done", "resolution": "r"})).status, Done("r")
        )

    def test_rejections(self) -> None:
        base = item("W-1", "2026-10-01")
        bad_cases: list[tuple[str, dict[str, Any]]] = [
            ("missing", {k: v for k, v in base.items() if k != "title"}),
            ("unknown", {**base, "extra": 1}),
            ("non-empty", {**base, "id": "  "}),
            ("non-empty", {**base, "title": 5}),
            ("non-empty", {**base, "recheck_command": ""}),
            ("state", {**base, "status": {"state": "parked", "vendor": "x"}}),
            ("unknown", {**base, "status": {"state": "in_progress", "vendor": "x"}}),
            ("unknown", {**base, "status": {"state": "done", "resolution": "x", "owner": "y"}}),
            ("non-empty", {**base, "status": {"state": "done", "resolution": ""}}),
            ("object", {**base, "status": "waiting_on_vendor"}),
            ("YYYY-MM-DD", {**base, "last_checked": "20261001"}),
            ("YYYY-MM-DD", {**base, "last_checked": "2026-W40-1"}),
            ("YYYY-MM-DD", {**base, "last_checked": "2026-10-01T00:00:00"}),
            ("not a valid date", {**base, "last_checked": "2026-02-30"}),
            ("result", {**base, "last_result": {"result": "maybe"}}),
            ("missing", {**base, "last_result": {"result": "found"}}),
            ("non-empty", {**base, "last_result": {"result": "found", "value": " "}}),
            ("non-empty", {**base, "last_result": {"result": "found", "value": ["24.19.0"]}}),
            ("unknown", {**base, "last_result": {"result": "not_found", "value": "x"}}),
            ("unknown reason", {**base, "last_result": {"result": "undetermined", "reason": "nope", "detail": "d"}}),
            ("non-empty", {**base, "last_result": {"result": "undetermined", "reason": "not_pe", "detail": ""}}),
            ("missing", {**base, "last_result": {"result": "undetermined", "reason": "not_pe"}}),
        ]
        for needle, data in bad_cases:
            with self.subTest(data=data):
                with self.assertRaises(ValueError) as raised:
                    ledger_item_from_json(data)
                self.assertIn(needle, str(raised.exception))


class LoadTests(Base):
    def test_file_rejections(self) -> None:
        good = sample()
        cases: list[tuple[str, object]] = [
            ("must be an object", [good]),
            ("keys must be", {**good, "generated": "x"}),
            ("keys must be", {k: v for k, v in good.items() if k != "kind"}),
            ("tool must be", {**good, "tool": "other"}),
            ("tool must be", {**good, "kind": "scan"}),
            ("unsupported schema", {**good, "schema": 2}),
            ("unsupported schema", {**good, "schema": True}),
            ("items: must be a list", {**good, "items": {}}),
            ("items[1].status.state", document(item("W-1", "2026-10-01"), item("W-2", "2026-10-01", {"state": "parked"}))),
            ("duplicate id", document(item("W-1", "2026-10-01"), item("W-1", "2026-10-02"))),
            ("is after today", document(item("W-1", "2026-10-27"))),
        ]
        for needle, data in cases:
            with self.subTest(needle=needle, data=data):
                self.write_doc(data)
                self.assert_rejected("waitlist", "show", self.path, needle=needle)

    def test_text_rejections(self) -> None:
        good = json.dumps(sample())
        cases = [
            ("not JSON", "{"),
            ("not JSON", good[:-1]),
            ("duplicate key", '{"tool": "patchwait", "tool": "patchwait", "schema": 1, "kind": "waitlist", "items": []}'),
            ("NaN", '{"tool": "patchwait", "schema": NaN, "kind": "waitlist", "items": []}'),
            ("not JSON", "﻿" + good),
        ]
        for needle, text in cases:
            with self.subTest(text=text[:40]):
                self.write_text(text)
                self.assert_rejected("waitlist", "show", self.path, needle=needle)

    def test_missing_and_undecodable(self) -> None:
        self.assert_rejected("waitlist", "show", os.path.join(self.dir, "none.json"), needle="cannot read")
        with open(self.path, "wb") as handle:
            handle.write(b'{"tool": "\xff"}')
        self.assert_rejected("waitlist", "show", self.path, needle="cannot read: UnicodeDecodeError")

    def test_lone_surrogate_is_a_field_error(self) -> None:
        raw = json.dumps(document(item("W-1", "2026-10-01", title="TITLE"))).encode("utf-8")
        raw = raw.replace(b'"TITLE"', b'"\\ud800"')  # the escape itself; the file stays valid UTF-8
        runs = [
            ("waitlist", "show", self.path),
            ("waitlist", "show", self.path, "--format", "markdown"),
            ("waitlist", "record", self.path, "--id", "W-1", "--result", "not_found"),
        ]
        for argv in runs:
            with self.subTest(argv=argv):
                with open(self.path, "wb") as handle:
                    handle.write(raw)
                self.assert_rejected(*argv, needle="items[0].title: must be valid Unicode")
                self.assertEqual(self.read_bytes(), raw)

    def test_future_is_relative_to_today_option(self) -> None:
        self.write_doc(document(item("W-1", "2026-10-26")))
        self.assert_rejected("waitlist", "show", self.path, "--today", "2026-10-25", needle="is after today 2026-10-25")
        code, payload = self.show("--today", "2026-10-26")
        self.assertEqual(code, 0)
        self.assertEqual(payload["items"][0]["days_since_check"], 0)

    def test_future_is_relative_to_local_date_by_default(self) -> None:
        self.write_doc(document(item("W-1", "9999-12-31")))
        self.assert_rejected("waitlist", "show", self.path, needle="is after today", today=None)
        self.write_doc(document(item("W-1", "2000-01-01")))
        code, _, _ = self.run_cli("waitlist", "show", self.path, today=None)
        self.assertEqual(code, 0)

    def test_empty_items_is_valid(self) -> None:
        self.write_doc(document())
        code, payload = self.show()
        self.assertEqual(code, 0)
        self.assertEqual(payload["counts"]["items"], 0)


class ShowTests(Base):
    def test_without_intel_option_matches_pre_intel_support_bytes(self) -> None:
        # Captured from waitlist show before intel support, with a fixed generated time.
        expected_json = '''{
  "tool": "patchwait",
  "schema": 1,
  "generated": "2026-10-26T12:00:00+00:00",
  "today": "2026-10-26",
  "stale_days": null,
  "counts": {
    "items": 1,
    "state": {
      "waiting_on_vendor": 1,
      "in_progress": 0,
      "awaiting_decision": 0,
      "done": 0
    },
    "last_result": {
      "found": 1,
      "not_found": 0,
      "undetermined": 0
    }
  },
  "items": [
    {
      "id": "W-1",
      "title": "Synthetic item W-1",
      "status": {
        "state": "waiting_on_vendor",
        "vendor": "Example Vendor"
      },
      "recheck_command": "patchwait version-of Apps/ExampleW-1/node.exe --kind node",
      "last_checked": "2026-10-01",
      "last_result": {
        "result": "found",
        "value": "24.19.0"
      },
      "days_since_check": 25
    }
  ]
}
'''
        expected_md = (
            "2026-10-26: patchwait waitlist: 1 items (waiting_on_vendor 1, in_progress 0, awaiting_decision 0, done 0)\n\n"
            "- waiting_on_vendor: `W-1` `Synthetic item W-1` — vendor `Example Vendor`"
            " — last checked 2026-10-01 (25 days) — last result found `24.19.0`"
            " — recheck `patchwait version-of Apps/ExampleW-1/node.exe --kind node`\n"
        )

        class FixedDatetime(datetime.datetime):
            @classmethod
            def now(cls, tz: datetime.tzinfo | None = None) -> FixedDatetime:
                return cls(2026, 10, 26, 12, tzinfo=datetime.timezone.utc)

            def astimezone(self, tz: datetime.tzinfo | None = None) -> FixedDatetime:
                return self  # Freeze the local timezone as well as the clock.

        self.write_doc(document(item("W-1", "2026-10-01")))
        with mock.patch.object(waitlist_module.datetime, "datetime", FixedDatetime), \
             mock.patch("patchwait.cli.load_intel", side_effect=AssertionError("read an unrequested store")):
            for fmt, expected in (("json", expected_json), ("markdown", expected_md)):
                with self.subTest(fmt=fmt):
                    code, out, err = self.run_cli("waitlist", "show", self.path, "--format", fmt)
                    self.assertEqual((code, err), (0, ""))
                    self.assertEqual(out.encode("utf-8"), expected.encode("utf-8"))

    def test_without_stale_days_has_no_marks(self) -> None:
        self.write_doc(sample())
        code, payload = self.show()
        self.assertEqual(code, 0)
        self.assertEqual(
            sorted(payload), ["counts", "generated", "items", "schema", "stale_days", "today", "tool"]
        )
        self.assertEqual(payload["tool"], "patchwait")
        self.assertEqual(payload["today"], "2026-10-26")
        self.assertIsNone(payload["stale_days"])
        self.assertEqual(
            payload["counts"],
            {
                "items": 4,
                "state": {"waiting_on_vendor": 1, "in_progress": 1, "awaiting_decision": 1, "done": 1},
                "last_result": {"found": 2, "not_found": 1, "undetermined": 1},
            },
        )
        self.assertEqual([row["days_since_check"] for row in payload["items"]], [25, 6, 0, 298])
        for row in payload["items"]:
            self.assertNotIn("stale", row)
        first = dict(payload["items"][0])
        del first["days_since_check"]
        self.assertEqual(first, sample()["items"][0])

    def test_stale_days_marks_and_exits_10(self) -> None:
        self.write_doc(sample())
        code, payload = self.show("--stale-days", "7")
        self.assertEqual(code, 10)
        self.assertEqual(payload["stale_days"], 7)
        self.assertEqual([row["stale"] for row in payload["items"]], [True, False, False, False])
        self.assertEqual(payload["counts"]["stale"], 1)

    def test_threshold_is_strictly_more_than(self) -> None:
        self.write_doc(sample())
        code, payload = self.show("--stale-days", "25")
        self.assertEqual(code, 0)
        self.assertEqual([row["stale"] for row in payload["items"]], [False, False, False, False])
        self.assertEqual(payload["counts"]["stale"], 0)

    def test_zero_days(self) -> None:
        self.write_doc(sample())
        code, payload = self.show("--stale-days", "0")
        self.assertEqual(code, 10)
        # W-3 was checked today (0 days, not more than 0); W-4 is done.
        self.assertEqual([row["stale"] for row in payload["items"]], [True, True, False, False])

    def test_done_is_never_stale(self) -> None:
        self.write_doc(document(item("W-4", "2000-01-01", {"state": "done", "resolution": "fixed"})))
        code, payload = self.show("--stale-days", "0")
        self.assertEqual(code, 0)
        self.assertIs(payload["items"][0]["stale"], False)

    def test_bad_stale_days_and_today(self) -> None:
        self.write_doc(sample())
        for value in ("-1", "+5", " 5", "５", "1.5", "", "x"):
            with self.subTest(value=value):
                self.assert_rejected("waitlist", "show", self.path, "--stale-days", value, needle="--stale-days")
        for value in ("20261026", "2026-13-01", "today"):
            with self.subTest(value=value):
                self.assert_rejected("waitlist", "show", self.path, "--today", value, needle="--today")

    def test_markdown(self) -> None:
        self.write_doc(sample())
        code, out, err = self.run_cli("waitlist", "show", self.path, "--format", "markdown", "--stale-days", "7")
        self.assertEqual((code, err), (10, ""))
        lines = out.splitlines()
        self.assertEqual(
            lines[0],
            "2026-10-26: patchwait waitlist: 4 items (waiting_on_vendor 1, in_progress 1, awaiting_decision 1, done 1);"
            " stale 1 (more than 7 days, not done)",
        )
        self.assertEqual(lines[1], "")
        self.assertEqual(len(lines), 6)
        self.assertEqual(
            lines[2],
            "- waiting_on_vendor: `W-1` `Synthetic item W-1` — vendor `Example Vendor`"
            " — last checked 2026-10-01 (25 days) — stale — last result found `24.19.0`"
            " — recheck `patchwait version-of Apps/ExampleW-1/node.exe --kind node`",
        )
        self.assertIn("— last result not_found —", lines[3])
        self.assertIn("— last result undetermined file_unreadable: `PermissionError` —", lines[4])
        self.assertNotIn("stale", lines[5])

    def test_markdown_without_stale_days(self) -> None:
        self.write_doc(sample())
        code, out, _ = self.run_cli("waitlist", "show", self.path, "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertNotIn("stale", out)
        self.assertTrue(out.splitlines()[0].endswith("done 1)"))

    def test_markdown_escapes_malicious_text(self) -> None:
        title = "x` <img src=x onerror=alert(1)> [link](https://example.invalid)\n# heading"
        command = "rm -rf / ``‮; echo `pwned`"
        self.write_doc(document(item("W-1", "2026-10-01", title=title, recheck_command=command)))
        code, out, _ = self.run_cli("waitlist", "show", self.path, "--format", "markdown")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 3)  # the newline in the title did not start a new line
        line = lines[2]
        self.assertIn("``x` <img src=x onerror=alert(1)> [link](https://example.invalid)\\u000a# heading``", line)
        self.assertIn("``` rm -rf / ``\\u202e; echo `pwned` ```", line)
        self.assertNotIn("‮", out)


class RecordTests(Base):
    def record(self, *extra: str) -> tuple[int, str, str]:
        return self.run_cli("waitlist", "record", self.path, *extra)

    def items(self) -> list[dict[str, Any]]:
        with open(self.path, encoding="utf-8") as handle:
            return json.load(handle)["items"]

    def test_each_result_kind(self) -> None:
        cases: list[tuple[list[str], dict[str, Any]]] = [
            (["--result", "found", "--value", "24.22.1"], {"result": "found", "value": "24.22.1"}),
            (["--result", "not_found"], {"result": "not_found"}),
            (
                ["--result", "undetermined", "--reason", "source_rate_limited", "--detail", "HTTP 429"],
                {"result": "undetermined", "reason": "source_rate_limited", "detail": "HTTP 429"},
            ),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                original = sample()
                self.write_doc(original)
                code, out, err = self.record("--id", "W-2", *args, "--date", "2026-10-25")
                self.assertEqual((code, err), (0, ""))
                after = self.items()
                self.assertEqual(after[1]["last_result"], expected)
                self.assertEqual(after[1]["last_checked"], "2026-10-25")
                self.assertEqual(json.loads(out), after[1])
                untouched = copy.deepcopy(original["items"])
                untouched[1]["last_result"] = expected
                untouched[1]["last_checked"] = "2026-10-25"
                self.assertEqual(after, untouched)  # other items equal and order kept
                with open(self.path, encoding="utf-8") as handle:
                    self.assertEqual(sorted(json.load(handle)), ["items", "kind", "schema", "tool"])

    def test_cves_preserved_and_absent_cves_not_added(self) -> None:
        first = item("W-1", "2026-10-01", cves=["CVE-2026-0001", "CVE-2026-9999"])
        second = item("W-2", "2026-10-01")
        self.write_doc(document(first, second))
        code, _, err = self.record("--id", "W-1", "--result", "not_found")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.items()[0]["cves"], first["cves"])
        self.assertEqual(self.items()[1], second)
        self.assertNotIn("cves", self.items()[1])

    def test_written_file_is_lf_utf8_and_round_trips(self) -> None:
        data = sample()
        data["items"][0]["title"] = "日本語の件名"
        self.write_doc(data)
        code, _, _ = self.record("--id", "W-1", "--result", "not_found")
        self.assertEqual(code, 0)
        raw = self.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertIn("日本語の件名".encode("utf-8"), raw)
        self.assertEqual(self.items()[0]["last_checked"], "2026-10-26")  # --date defaults to today
        code, _ = self.show()
        self.assertEqual(code, 0)

    def test_hand_edited_file_is_rewritten_in_canonical_form(self) -> None:
        data = sample()
        shuffled = {key: data[key] for key in ("items", "kind", "schema", "tool")}
        shuffled["items"] = copy.deepcopy(data["items"])
        second = shuffled["items"][1]
        second["status"] = dict(reversed(second["status"].items()))
        shuffled["items"][1] = dict(reversed(second.items()))
        self.write_text(json.dumps(shuffled, ensure_ascii=False, indent=4).replace("\n", "\r\n") + "\r\n")
        code, _, err = self.record("--id", "W-1", "--result", "not_found", "--date", "2026-10-25")
        self.assertEqual((code, err), (0, ""))
        data["items"][0]["last_result"] = {"result": "not_found"}
        data["items"][0]["last_checked"] = "2026-10-25"
        self.assertEqual(self.read_bytes(), (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    def test_bad_combinations(self) -> None:
        self.write_doc(sample())
        before = self.read_bytes()
        cases: list[tuple[list[str], str]] = [
            (["--result", "found"], "non-empty --value"),
            (["--result", "found", "--value", "  "], "non-empty --value"),
            (["--result", "found", "--value", "1", "--reason", "not_pe"], "--value only"),
            (["--result", "not_found", "--value", "1"], "takes no"),
            (["--result", "not_found", "--detail", "d"], "takes no"),
            (["--result", "undetermined", "--detail", "d"], "needs --reason"),
            (["--result", "undetermined", "--reason", "made_up", "--detail", "d"], "needs --reason"),
            (["--result", "undetermined", "--reason", "not_pe"], "non-empty --detail"),
            (["--result", "undetermined", "--reason", "not_pe", "--detail", ""], "non-empty --detail"),
            (["--result", "undetermined", "--reason", "not_pe", "--detail", "d", "--value", "v"], "not --value"),
            (["--result", "not_found", "--date", "2026-10-27"], "is after today"),
            (["--result", "not_found", "--date", "2026/10/01"], "--date"),
        ]
        for args, needle in cases:
            with self.subTest(args=args):
                self.assert_rejected("waitlist", "record", self.path, "--id", "W-1", *args, needle=needle)
                self.assertEqual(self.read_bytes(), before)

    def test_usage_errors_from_argparse(self) -> None:
        self.write_doc(sample())
        for argv in (["--result", "not_found"], ["--id", "W-1"], ["--id", "W-1", "--result", "maybe"]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    main(["waitlist", "record", self.path, *argv], today=TODAY)
                self.assertEqual(raised.exception.code, 2)

    def test_unknown_id_and_bad_file(self) -> None:
        self.write_doc(sample())
        before = self.read_bytes()
        self.assert_rejected("waitlist", "record", self.path, "--id", "W-9", "--result", "not_found", needle="no item with id")
        self.assertEqual(self.read_bytes(), before)
        self.write_doc(document(item("W-1", "2026-10-01"), item("W-1", "2026-10-01")))
        before = self.read_bytes()
        self.assert_rejected("waitlist", "record", self.path, "--id", "W-1", "--result", "not_found", needle="duplicate id")
        self.assertEqual(self.read_bytes(), before)

    def test_date_before_last_checked_is_rejected(self) -> None:
        self.write_doc(sample())
        before = self.read_bytes()
        self.assert_rejected(
            "waitlist", "record", self.path, "--id", "W-2", "--result", "not_found", "--date", "2026-10-19",
            needle="is before the item's last_checked 2026-10-20",
        )
        self.assertEqual(self.read_bytes(), before)

    def test_same_or_later_date_than_last_checked_is_recorded(self) -> None:
        for when in ("2026-10-20", "2026-10-21"):
            with self.subTest(when=when):
                self.write_doc(sample())
                code, _, err = self.record("--id", "W-2", "--result", "found", "--value", "1", "--date", when)
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(self.items()[1]["last_checked"], when)
                self.assertEqual(self.items()[1]["last_result"], {"result": "found", "value": "1"})

    def test_future_date_relative_to_local_date(self) -> None:
        self.write_doc(document(item("W-1", "2000-01-01")))
        self.assert_rejected(
            "waitlist", "record", self.path, "--id", "W-1", "--result", "not_found", "--date", "9999-12-31",
            needle="is after today", today=None,
        )

    def test_failed_replace_keeps_old_file(self) -> None:
        self.write_doc(sample())
        before = self.read_bytes()
        with mock.patch("os.replace", side_effect=PermissionError("locked")):
            self.assert_rejected(
                "waitlist", "record", self.path, "--id", "W-1", "--result", "not_found", needle="cannot write"
            )
        self.assertEqual(self.read_bytes(), before)
        self.assertEqual(os.listdir(self.dir), ["waitlist.json"])  # the temporary file was removed


class NeverRunsCommandTests(Base):
    def test_no_process_is_started(self) -> None:
        self.write_doc(sample())
        boom = mock.Mock(side_effect=AssertionError("a process was started"))
        patches = [
            mock.patch.object(subprocess, "run", boom),
            mock.patch.object(subprocess, "Popen", boom),
            mock.patch.object(subprocess, "call", boom),
            mock.patch.object(subprocess, "check_call", boom),
            mock.patch.object(subprocess, "check_output", boom),
            mock.patch.object(os, "system", boom),
            mock.patch.object(os, "popen", boom),
        ]
        if hasattr(os, "startfile"):
            patches.append(mock.patch.object(os, "startfile", boom))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            for argv in (
                ["waitlist", "show", self.path],
                ["waitlist", "show", self.path, "--stale-days", "1", "--format", "markdown"],
                ["waitlist", "record", self.path, "--id", "W-1", "--result", "not_found"],
            ):
                code, _, err = self.run_cli(*argv)
                self.assertIn(code, (0, 10), msg=err)
        boom.assert_not_called()

    def test_module_imports_nothing_that_runs_processes(self) -> None:
        source_path = waitlist_module.__file__
        assert source_path is not None
        with open(source_path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                self.assertNotIn(node.attr, {"system", "popen", "startfile", "execv", "spawnv"})
        self.assertFalse(imported & {"subprocess", "os", "shlex", "multiprocessing", "pty"})


if __name__ == "__main__":
    unittest.main()
