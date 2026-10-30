"""Synthetic ScanMux stores only: no feed downloads or real machine findings."""

from __future__ import annotations

import datetime
import hashlib
import json
import json.scanner
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from patchwait import intel
from patchwait.locality import Locality
from patchwait.model import Found, NotFound, Reason, Undetermined
from tests.jvn_cases import CASES, rss, window_summary
from tests.jvn_cases import item as rss_item
from tests.test_waitlist import Base, document, item

NOW = datetime.datetime(2026, 10, 27, 12, tzinfo=datetime.timezone.utc)
START = "2026-10-25T10:00:00.000Z"
END = "2026-10-25T10:00:01.000Z"
CVE = "CVE-2026-0001"
ABSENT = "CVE-2026-9999"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TERMS = "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt"


def entry(**changes: Any) -> dict[str, Any]:
    return {"cveID": CVE, "vendorProject": "Example Vendor", "product": "Example Product",
            "vulnerabilityName": "Synthetic vulnerability", "shortDescription": "Synthetic description",
            "requiredAction": "Apply the example update", "dateAdded": "2026-10-01", "dueDate": "2026-10-22",
            "knownRansomwareCampaignUse": "Unknown", **changes}


def catalog(*entries: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return {"catalogVersion": "2026.10.25", "dateReleased": "2026-10-25T09:00:00Z",
            "count": len(entries), "vulnerabilities": list(entries), **changes}


def encoded(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True) + "\n").encode("utf-8")


class StoreBase(Base):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix=".intel-test-", dir=os.getcwd())
        self.dir = self._tmp.name
        self.path = os.path.join(self.dir, "waitlist.json")
        self.store = Path(self.dir, "intel-store")
        (self.store / "attempts").mkdir(parents=True)
        (self.store / "blobs").mkdir()
        self.sequence = 0
        # Exercise file IO on every platform, with real Windows locality separately below.
        self.local = mock.patch.object(intel, "local_path_check", return_value=Locality(None, False, ()))
        self.local.start()
        self.addCleanup(self.local.stop)

    def attempt(self, body: bytes | None = None, *, start: str = START, end: str = END,
                outcome: dict[str, Any] | None = None, **changes: Any) -> tuple[Path, dict[str, Any]]:
        self.sequence += 1
        if body is None:
            body = encoded(catalog(entry()))
        digest = hashlib.sha256(body).hexdigest()
        (self.store / "blobs" / digest).write_bytes(body)
        data: dict[str, Any] = {
            "schema": "scanmux.intel-attempt/v1", "feed": "kev", "url": URL, "termsUrl": TERMS,
            "startedAt": start, "completedAt": end,
            "outcome": outcome if outcome is not None else {
                "kind": "stored", "httpStatus": 200, "contentType": "application/json", "bytes": len(body),
                "sha256": digest, "source": {"version": "2026.10.25", "date": "2026-10-25T09:00:00Z"}},
            **changes,
        }
        stamp = start.translate(str.maketrans("", "", "-:."))
        path = self.store / "attempts" / f"{stamp}-00000000-0000-0000-0000-{self.sequence:012x}.json"
        path.write_bytes(encoded(data))
        return path, data

    def jvn_attempt(self, body: bytes | None = None, *, start: str = START, end: str = END,
                    source_date: str | None = "2026-10-26T17:46:49+09:00", **changes: Any) -> tuple[Path, dict[str, Any]]:
        body = rss() if body is None else body
        outcome = {"kind": "stored", "httpStatus": 200, "contentType": "application/rdf+xml", "bytes": len(body),
                   "sha256": hashlib.sha256(body).hexdigest(), "source": {"version": None, "date": source_date}}
        fields: dict[str, Any] = {"feed": "jvn", "url": "https://jvn.jp/rss/jvn.rdf", "termsUrl": None, "outcome": outcome}
        return self.attempt(body, start=start, end=end, **{**fields, **changes})

    def load(self) -> intel.Intel:
        return intel.load_intel(str(self.store), NOW)

    def assert_unknown(self, reason: Reason = Reason.SOURCE_MALFORMED) -> intel.Intel:
        loaded = self.load()
        result = loaded.kev_check(ABSENT)
        self.assertIsInstance(result, Undetermined)
        assert isinstance(result, Undetermined)
        self.assertEqual(result.reason, reason)
        self.assertEqual(loaded.kev_to_json(CVE)["result"], "undetermined")
        return loaded


class SelectionTests(StoreBase):
    def test_listed_and_not_listed_with_metadata(self) -> None:
        self.attempt()
        loaded = self.load()
        self.assertIsInstance(loaded.kev.data, Found)
        self.assertIsInstance(loaded.kev_check(CVE), Found)
        self.assertEqual(loaded.kev_check(ABSENT), NotFound())
        self.assertEqual(loaded.kev_to_json(CVE), {"result": "listed", "dateAdded": "2026-10-01",
                         "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown"})
        self.assertEqual(loaded.kev_to_json(ABSENT), {"result": "not_listed"})
        self.assertEqual(loaded.to_json(), {"store": str(self.store), "kev": {
            "catalogVersion": "2026.10.25", "dateReleased": "2026-10-25T09:00:00Z", "completedAt": END,
            "days_since_fetch": 2, "latest_attempt": "stored", "invalid_attempts": 0}, "jvn": {
            "modified": None, "oldest": None, "newest": None, "items": None, "completedAt": None,
            "days_since_fetch": None, "latest_attempt": "none", "invalid_attempts": 0, "result": "undetermined",
            "reason": "source_missing", "detail": "no usable JVN RSS copy"}})

    def test_empty_catalog_is_usable(self) -> None:
        self.attempt(encoded(catalog()))
        self.assertEqual(self.load().kev_check(CVE), NotFound())

    def test_newest_completed_not_started(self) -> None:
        self.attempt(encoded(catalog()), start="2026-10-25T09:00:00.000Z", end="2026-10-25T11:00:00.000Z")
        self.attempt()
        self.assertEqual(self.load().kev_check(CVE), NotFound())

    def test_newer_failure_and_tie_use_previous_copy(self) -> None:
        for end in (END, "2026-10-26T11:00:00.000Z"):
            with self.subTest(end=end):
                failed, _ = self.attempt(end=end, outcome={"kind": "failed", "reason": "network", "httpStatus": None})
                stored, _ = self.attempt()
                self.assertLess(failed.name, stored.name)
                loaded = self.load()
                self.assertEqual(loaded.kev.latest_attempt, "failed")
                self.assertEqual(loaded.kev.completed_at, END)
                self.assertIsInstance(loaded.kev_check(CVE), Found)

    def test_identical_completion_uses_descending_name(self) -> None:
        self.attempt()
        self.attempt(encoded(catalog()))
        self.assertEqual(self.load().kev_check(CVE), NotFound())

    def test_absent_and_failed_only_are_missing(self) -> None:
        self.assert_unknown(Reason.SOURCE_MISSING)
        self.attempt(outcome={"kind": "failed", "reason": "timeout", "httpStatus": 200})
        loaded = self.assert_unknown(Reason.SOURCE_MISSING)
        self.assertEqual(loaded.kev.latest_attempt, "failed")

    def test_invalid_name_and_partial_are_ignored(self) -> None:
        (self.store / "attempts" / "not-an-attempt.json").write_bytes(b"broken")
        path, _ = self.attempt()
        (self.store / "attempts" / (path.name + ".partial")).write_bytes(b"broken")
        loaded = self.load()
        self.assertIsInstance(loaded.kev_check(CVE), Found)
        self.assertEqual(loaded.kev.invalid_attempts, 0)

    def test_unknown_schema_blocks_older_copy_even_other_feed_or_future(self) -> None:
        self.attempt()
        cases: list[dict[str, Any]] = [
            {"schema": "scanmux.intel-attempt/v2"}, {"schema": None, "feed": "jvn"},
            {"schema": "new", "start": "2027-01-01T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                path, _ = self.attempt(**changes)
                loaded = self.assert_unknown()
                assert isinstance(loaded.kev.data, Undetermined)
                self.assertIn("unknown schema", loaded.kev.data.detail)
                self.assertEqual(loaded.kev.invalid_attempts, 1)
                path.unlink()

    def test_invalid_record_counts_but_older_copy_works(self) -> None:
        path, _ = self.attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        path.write_bytes(b"{")
        self.assert_unknown()
        self.attempt()
        loaded = self.load()
        self.assertEqual(loaded.kev.invalid_attempts, 1)
        self.assertIsInstance(loaded.kev_check(CVE), Found)

    def test_future_records_do_not_decide_result(self) -> None:
        for start, end in (("2027-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z"),
                           (START, "2027-01-01T00:00:00.000Z")):
            with self.subTest(start=start, end=end):
                path, _ = self.attempt(encoded(catalog()), start=start, end=end)
                self.assert_unknown()
                good_path, _ = self.attempt()
                self.assertIsInstance(self.load().kev_check(CVE), Found)
                path.unlink()
                good_path.unlink()

    def test_blob_failures_fall_back(self) -> None:
        self.attempt()
        for problem in ("missing", "drift", "source", "over_limit"):
            with self.subTest(problem=problem):
                body = encoded(catalog(entry(product="New")))
                if problem == "drift":
                    body = encoded(catalog(entry(dueDate="2026-02-30")))
                path, data = self.attempt(body, start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
                blob = self.store / "blobs" / data["outcome"]["sha256"]
                if problem == "missing":
                    blob.unlink()
                elif problem == "source":
                    data["outcome"]["source"]["version"] = "wrong"
                elif problem == "over_limit":
                    data["outcome"]["bytes"] = intel.MAX_KEV_BYTES + 1
                path.write_bytes(encoded(data))
                loaded = self.load()
                self.assertEqual(loaded.kev.completed_at, END)
                self.assertEqual(loaded.kev.invalid_attempts, 1)
                self.assertIsInstance(loaded.kev_check(CVE), Found)
                path.unlink()

    def test_digest_mismatch_with_valid_same_size_catalog(self) -> None:
        body = encoded(catalog(entry()))
        changed = encoded(catalog(entry(cveID=ABSENT)))
        self.assertEqual(len(body), len(changed))
        self.assertNotEqual(hashlib.sha256(body).digest(), hashlib.sha256(changed).digest())
        self.assertIn(ABSENT, intel.parse_kev(changed).entries)
        _, data = self.attempt(body, start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        (self.store / "blobs" / data["outcome"]["sha256"]).write_bytes(changed)
        with self.subTest(fallback=False):
            self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)
        self.attempt(encoded(catalog(entry(product="Older copy"))))
        with self.subTest(fallback=True):
            loaded = self.load()
            self.assertEqual(loaded.kev.completed_at, END)
            self.assertIsInstance(loaded.kev_check(CVE), Found)
            self.assertEqual(loaded.kev_check(ABSENT), NotFound())
            self.assertEqual(loaded.kev.invalid_attempts, 1)

    def test_declared_size_larger_than_valid_blob(self) -> None:
        path, data = self.attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        data["outcome"]["bytes"] += 1
        path.write_bytes(encoded(data))
        with self.subTest(fallback=False):
            self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)
        self.attempt(encoded(catalog(entry(product="Older copy"))))
        with self.subTest(fallback=True):
            loaded = self.load()
            self.assertEqual(loaded.kev.completed_at, END)
            self.assertIsInstance(loaded.kev_check(CVE), Found)
            self.assertEqual(loaded.kev.invalid_attempts, 1)

    def test_source_key_order_mismatch_is_unusable(self) -> None:
        path, data = self.attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        source = data["outcome"]["source"]
        data["outcome"]["source"] = {"date": source["date"], "version": source["version"]}
        path.write_bytes(encoded(data))
        with self.subTest(fallback=False):
            self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)
        self.attempt()
        with self.subTest(fallback=True):
            loaded = self.load()
            self.assertEqual(loaded.kev.completed_at, END)
            self.assertIsInstance(loaded.kev_check(CVE), Found)
            self.assertEqual(loaded.kev.invalid_attempts, 1)

    def test_bom_duplicate_keys_and_surrogates_use_newest_copy(self) -> None:
        self.attempt(encoded(catalog()))
        valid = encoded(catalog(entry()))
        cases = [b"\xef\xbb\xbf" + valid,
                 valid.replace(b'"count": 1', b'"count":0,"count":1'),
                 encoded(catalog(entry(product="Product\ud800", knownRansomwareCampaignUse="Use\udfff")))]
        for body in cases:
            with self.subTest(body=body[:30]):
                path, _ = self.attempt(body, start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
                loaded = self.load()
                self.assertIsInstance(loaded.kev_check(CVE), Found)
                self.assertEqual(loaded.kev.completed_at, "2026-10-26T10:00:01.000Z")
                self.assertEqual(loaded.kev.invalid_attempts, 0)
                path.unlink()

    def test_5000_digit_unknown_number_uses_newest_copy(self) -> None:
        self.attempt(encoded(catalog()))
        body = encoded(catalog(entry(), extra="large-number")).replace(b'"large-number"', b"1" * 5000)
        self.attempt(body, start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        loaded = self.load()
        self.assertIsInstance(loaded.kev_check(CVE), Found)
        self.assertEqual(loaded.kev.completed_at, "2026-10-26T10:00:01.000Z")
        self.assertEqual(loaded.kev.invalid_attempts, 0)

    def test_deep_catalog_blocks_older_not_listed(self) -> None:
        self.attempt(encoded(catalog()))
        body = encoded(catalog(entry(), extra="nested")).replace(b'"nested"', b"[" * 5000 + b"0" + b"]" * 5000)
        self.attempt(body, start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        # The 3.14 C decoder accepts this depth; the Python decoder reproduces
        # the recursion limit reached by older runtimes without changing it.
        with mock.patch("json.scanner.make_scanner", getattr(json.scanner, "py_make_scanner")):
            loaded = self.assert_unknown()
        assert isinstance(loaded.kev.data, Undetermined)
        self.assertIn("patchwait could not parse", loaded.kev.data.detail)
        self.assertIn("ScanMux may accept", loaded.kev.data.detail)

    def test_nan_in_hashed_catalog_is_malformed(self) -> None:
        valid = encoded(catalog(entry()))
        self.attempt(valid.replace(b'"count": 1', b'"count": 1, "extra": NaN'))
        self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)

    def test_invalid_utf8_in_hashed_catalog_is_malformed(self) -> None:
        valid = encoded(catalog(entry()))
        self.attempt(valid.replace(b'"Example Product"', b'"Example \xff Product"'))
        self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)

    def test_oversized_valid_hashed_catalog_is_malformed(self) -> None:
        valid = encoded(catalog(entry()))
        size = 16 * 1024 * 1024 + 1
        body = valid + b" " * (size - len(valid))
        self.assertEqual(len(body), size)
        self.attempt(body)
        self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)

    def test_bad_blob_without_fallback_is_undetermined(self) -> None:
        _, data = self.attempt()
        (self.store / "blobs" / data["outcome"]["sha256"]).unlink()
        self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)

    def test_other_feeds_never_become_kev(self) -> None:
        self.attempt(feed="jvn", url="https://jvn.jp/rss/jvn.rdf", termsUrl=None)
        self.attempt(feed="jvndb", url="https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_2026.rdf", termsUrl=None,
                     outcome={"kind": "unsupported", "httpStatus": 200})
        self.assertEqual(self.assert_unknown(Reason.SOURCE_MISSING).kev.invalid_attempts, 0)

    def test_broken_other_feeds_do_not_make_kev_malformed(self) -> None:
        self.attempt(outcome={"kind": "failed", "reason": "network", "httpStatus": None})
        for feed, url in (("jvn", "https://jvn.jp/rss/jvn.rdf"),
                          ("jvndb", "https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_2026.rdf")):
            self.attempt(feed=feed, url=url, termsUrl=None, outcome={"kind": "broken"})
        loaded = self.assert_unknown(Reason.SOURCE_MISSING)
        self.assertEqual(loaded.kev.invalid_attempts, 2)
        self.assertEqual(loaded.kev.latest_attempt, "failed")


class AttemptValidationTests(StoreBase):
    def test_exact_keys_and_field_types(self) -> None:
        _, good = self.attempt()
        cases: list[dict[str, Any]] = []
        for key in good:
            if key != "schema":
                cases.append({k: v for k, v in good.items() if k != key})
        cases += [{**good, "extra": 1}, {**good, "feed": "other"}, {**good, "feed": []},
                  {**good, "url": URL + "?x"}, {**good, "termsUrl": None}]
        for changes in ({"bytes": True}, {"bytes": 0}, {"bytes": -1}, {"bytes": intel.MAX_KEV_BYTES + 1},
                        {"sha256": "../outside"}, {"sha256": "A" * 64}, {"contentType": "x\ny"},
                        {"contentType": "x" * 201}, {"httpStatus": True}, {"httpStatus": 201},
                        {"source": {"version": "x"}}, {"source": {"version": "x", "date": None, "extra": 0}},
                        {"source": {"version": "x" * 65, "date": None}}, {"kind": "unsupported"}):
            cases.append({**good, "outcome": {**good["outcome"], **changes}})
        for key in good["outcome"]:
            cases.append({**good, "outcome": {k: v for k, v in good["outcome"].items() if k != key}})
        cases.append({**good, "outcome": {**good["outcome"], "extra": 1}})
        for outcome in ({"kind": "failed", "reason": "other", "httpStatus": None},
                        {"kind": "failed", "reason": "network", "httpStatus": True},
                        {"kind": "failed", "reason": "network", "httpStatus": 600},
                        {"kind": "failed", "reason": "network", "httpStatus": None, "extra": 1}):
            cases.append({**good, "outcome": outcome})
        path = next((self.store / "attempts").iterdir())
        for data in cases:
            with self.subTest(data=data):
                path.write_bytes(encoded(data))
                self.assert_unknown()

    def test_strict_attempt_timestamps(self) -> None:
        path, good = self.attempt()
        values = ["2026-02-30T10:00:00.000Z", "2026-10-25T24:00:00.000Z", "2026-10-25T10:60:00.000Z",
                  "2026-10-25T10:00:60.000Z", "2026-10-25T10:00:00Z", "2026-10-25T10:00:00.00Z",
                  "2026-10-25T10:00:00.000+00:00", "2026-10-25T09:59:59.999Z", 1]
        for value in values:
            with self.subTest(value=value):
                path.write_bytes(encoded({**good, "completedAt": value}))
                self.assert_unknown()
        path.write_bytes(encoded({**good, "startedAt": "2026-10-25T10:00:00.001Z"}))
        self.assert_unknown()  # filename and startedAt must agree

    def test_attempt_json_utf8_and_bounded_reads(self) -> None:
        path, good = self.attempt()
        valid = encoded(good)
        for body in (b"\xef\xbb\xbf\xef\xbb\xbf" + valid, b"\xff", b"[]", b"{" * 1100,
                     valid.replace(b'"bytes":', b'"extra":NaN,"bytes":'),
                     valid.replace(b'"bytes":', b'"extra":Infinity,"bytes":'),
                     valid + b" " * (64 * 1024 + 1 - len(valid))):
            with self.subTest(body=body[:30]):
                path.write_bytes(body)
                self.assert_unknown()
        # Exactly the bound is allowed; one more byte is refused before decoding.
        path.write_bytes(valid + b" " * (intel.MAX_ATTEMPT_BYTES - len(valid)))
        self.assertIsInstance(self.load().kev_check(CVE), Found)

    def test_deep_attempt_blocks_older_not_listed(self) -> None:
        self.attempt(encoded(catalog()))
        path, good = self.attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        # JSON.parse keeps the second outcome, after parsing the deep first one.
        body = encoded(good).replace(b'"outcome":', b'"outcome":' + b"[" * 5000 + b"0" + b"]" * 5000 + b',"outcome":')
        path.write_bytes(body)
        with mock.patch("json.scanner.make_scanner", getattr(json.scanner, "py_make_scanner")):
            loaded = self.assert_unknown()
        assert isinstance(loaded.kev.data, Undetermined)
        self.assertIn("patchwait could not parse", loaded.kev.data.detail)
        self.assertIn("ScanMux may accept", loaded.kev.data.detail)

    def test_json_number_forms_preserve_integer_validation(self) -> None:
        path, good = self.attempt()
        valid = encoded(good)
        size = good["outcome"]["bytes"]
        body = valid.replace(b'"httpStatus": 200', b'"httpStatus": 2e2')
        body = body.replace(f'"bytes": {size}'.encode(), f'"bytes": {size}.0'.encode())
        path.write_bytes(body)
        self.assertIsInstance(self.load().kev_check(CVE), Found)
        for key, value in (("httpStatus", "200.5"), ("httpStatus", "1e500"),
                           ("bytes", f"{size}.5"), ("bytes", "9007199254740992")):
            with self.subTest(key=key, value=value):
                old = f'"{key}": {good["outcome"][key]}'.encode()
                path.write_bytes(valid.replace(old, f'"{key}": {value}'.encode()))
                self.assert_unknown()

    def test_attempt_bom_duplicate_keys_and_surrogates(self) -> None:
        path, good = self.attempt()
        valid = encoded(good)
        for body in (b"\xef\xbb\xbf" + valid,
                     valid.replace(b'"feed": "kev"', b'"feed":"jvn","feed":"kev"')):
            with self.subTest(body=body[:30]):
                path.write_bytes(body)
                self.assertIsInstance(self.load().kev_check(CVE), Found)
                self.assertEqual(self.load().kev.invalid_attempts, 0)
        # A source with a lone surrogate passes attempt validation, then mismatches
        # the catalog's source. It must still be the latest stored attempt.
        good["outcome"]["source"]["version"] = "\ud800"
        path.write_bytes(encoded(good))
        loaded = self.assert_unknown()
        self.assertEqual(loaded.kev.latest_attempt, "stored")

    def test_hashed_blob_must_match_declared_size_before_parse(self) -> None:
        path, data = self.attempt()
        data["outcome"]["bytes"] -= 1
        path.write_bytes(encoded(data))
        with mock.patch.object(intel, "parse_kev", side_effect=AssertionError("parsed unverified bytes")):
            self.assert_unknown()

    def test_reads_are_bounded_even_if_file_grows(self) -> None:
        self.attempt()
        path = self.store / "blobs" / "growing"
        path.write_bytes(b"x")
        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        handle.fileno.return_value = 0
        handle.read.return_value = b"xx"
        with mock.patch("builtins.open", return_value=handle), mock.patch.object(intel.os, "fstat", return_value=path.stat()):
            with self.assertRaises(ValueError):
                intel._bounded_read(str(path), 1)
        handle.read.assert_called_once_with(2)


class KevParsingTests(unittest.TestCase):
    def parse(self, data: object) -> intel.KevCatalog:
        return intel.parse_kev(encoded(data))

    def test_duplicates_must_agree_on_all_known_fields(self) -> None:
        self.assertEqual(len(self.parse(catalog(entry(), entry())).entries), 1)
        for key in entry():
            if key == "cveID":
                continue
            changed = {key: "2026-10-02" if key in ("dateAdded", "dueDate") else "Different"}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.parse(catalog(entry(), entry(**changed)))

    def test_optional_ransomware_and_unknown_fields(self) -> None:
        row = entry()
        del row["knownRansomwareCampaignUse"]
        parsed = self.parse(catalog({**row, "notes": "future metadata"}, title="Synthetic catalog"))
        self.assertIsNone(parsed.entries[CVE].ransomware)
        self.assertEqual(self.parse(catalog(entry(knownRansomwareCampaignUse=""))).entries[CVE].ransomware, "")
        with self.assertRaises(ValueError):
            self.parse(catalog(entry(knownRansomwareCampaignUse=None)))

    def test_catalog_and_entry_drift(self) -> None:
        bad: list[object] = [[], {}, catalog(count=True), catalog(entry(), count=0), catalog(vulnerabilities={}),
                             catalog(catalogVersion="x y"), catalog(catalogVersion="x" * 65)]
        for key in catalog():
            bad.append({k: v for k, v in catalog().items() if k != key})
        for key in entry():
            if key != "knownRansomwareCampaignUse":
                bad.append(catalog({k: v for k, v in entry().items() if k != key}))
        for key in ("vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction"):
            for value in ("", "x" * 4097, "\U0001f600" * 2049, None, 1):
                bad.append(catalog(entry(**{key: value})))
        for cve in (CVE.lower(), " " + CVE, CVE + "x", "CVE-２０２６-0001", "CVE-2026-123", "CVE-2026-" + "1" * 56):
            bad.append(catalog(entry(cveID=cve)))
        for value in ("2026-02-30", "2026-13-01", "20261001", "2026-10-01T00:00:00Z"):
            bad.extend((catalog(entry(dateAdded=value)), catalog(entry(dueDate=value))))
        for value in ("2026-02-30T00:00:00Z", "2026-10-25T24:00:00Z", "2026-10-25T00:00:60Z",
                      "2026-10-25T00:00:00+24:00", "2026-10-25T00:00:00+00:60", "2026-10-25", "2026-10-25T00:00:00"):
            bad.append(catalog(dateReleased=value))
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.parse(data)

    def test_valid_syntax_boundaries(self) -> None:
        for value in ("2026-10-25T09:00Z", "2026-10-25T09:00:00.123456789+23:59", "0000-02-29T00:00:00Z"):
            self.assertEqual(self.parse(catalog(dateReleased=value)).released, value)
        self.parse(catalog(entry(dateAdded="0000-02-29", product="\U0001f600" * 2048)))

    def test_blob_json_and_byte_limit(self) -> None:
        valid = encoded(catalog(entry()))
        for body in (b"\xff", b"\xef\xbb\xbf\xef\xbb\xbf" + valid,
                     valid.replace(b'"count": 1', b'"count":NaN'),
                     valid.replace(b'"count": 1', b'"count":Infinity'),
                     valid.replace(b'"count": 1', b'"count":-Infinity'),
                     valid + b" " * (16 * 1024 * 1024 + 1 - len(valid))):
            with self.subTest(body=body[:30]), self.assertRaises(ValueError):
                intel.parse_kev(body)
        intel.parse_kev(valid + b" " * (intel.MAX_KEV_BYTES - len(valid)))

    def test_count_uses_safe_integer_rules(self) -> None:
        valid = encoded(catalog(entry()))
        for number in (b"1.0", b"1e0"):
            self.assertIn(CVE, intel.parse_kev(valid.replace(b'"count": 1', b'"count":' + number)).entries)
        for number in (b"true", b"1.5", b"9007199254740992", b"1e500", b"1" * 5000):
            with self.subTest(number=number[:30]), self.assertRaises(ValueError):
                intel.parse_kev(valid.replace(b'"count": 1', b'"count":' + number))


class JvnParsingTests(unittest.TestCase):
    def test_cases_match_scanmux(self) -> None:
        for name, body, window in CASES:
            with self.subTest(name=name):
                if window is None:
                    with self.assertRaises(ValueError):
                        intel.parse_jvn_rss(body)
                else:
                    self.assertEqual(window_summary(intel.parse_jvn_rss(body)), window)

    def test_byte_limit(self) -> None:
        body = rss()
        intel.parse_jvn_rss(body + b" " * (intel.MAX_JVN_BYTES - len(body)))
        with self.assertRaises(ValueError):
            intel.parse_jvn_rss(body + b" " * (intel.MAX_JVN_BYTES + 1 - len(body)))


class JvnSelectionTests(StoreBase):
    def test_observed_and_not_observed_in_window(self) -> None:
        self.jvn_attempt()
        loaded = self.load()
        self.assertEqual(loaded.jvn_to_json(CVE), {"result": "observed", "items": [
            {"identifier": "JVNVU#00000001", "link": "https://jvn.jp/vu/JVNVU00000001/",
             "modified": "2026-10-26T12:00+09:00"}]})
        self.assertEqual(loaded.jvn_to_json(ABSENT), {"result": "not_observed_in_window",
                                                      "oldest": "2026-10-26T12:00+09:00",
                                                      "newest": "2026-10-26T12:00+09:00", "items": 1})
        self.assertEqual(loaded.to_json()["jvn"], {
            "modified": "2026-10-26T17:46:49+09:00", "oldest": "2026-10-26T12:00+09:00",
            "newest": "2026-10-26T12:00+09:00", "items": 1, "completedAt": END, "days_since_fetch": 2,
            "latest_attempt": "stored", "invalid_attempts": 0})
        self.assertEqual(loaded.kev_to_json(CVE)["reason"], "source_missing")  # a JVN copy is not a KEV copy

    def test_every_item_naming_the_cve_is_listed(self) -> None:
        second = rss_item("JVN#2", "https://jvn.jp/jp/JVN2/", "Other", f"also {CVE.lower()}", "2026-10-20T00:00Z")
        self.jvn_attempt(rss(rss_item(), second))
        observed: dict[str, Any] = self.load().jvn_to_json(CVE)
        self.assertEqual([entry["identifier"] for entry in observed["items"]], ["JVNVU#00000001", "JVN#2"])

    def test_damaged_newer_copy_falls_back_and_kev_is_unaffected(self) -> None:
        self.attempt()
        self.jvn_attempt(rss(rss_item(title="old")))
        _, data = self.jvn_attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
        (self.store / "blobs" / data["outcome"]["sha256"]).write_bytes(rss(rss_item(title="tampered")))
        loaded = self.load()
        self.assertEqual(loaded.jvn_to_json(CVE)["result"], "not_observed_in_window")  # the older copy names no CVE
        self.assertEqual(loaded.jvn.invalid_attempts, 1)
        self.assertEqual(loaded.jvn.completed_at, END)
        self.assertEqual(loaded.kev_to_json(CVE)["result"], "listed")
        self.assertEqual(loaded.kev.invalid_attempts, 0)

    def test_only_copy_unusable_is_malformed(self) -> None:
        cases: list[tuple[str, bytes, str | None]] = [
            ("source mismatch", rss(), "2026-10-26T17:46:50+09:00"),
            ("source date must be null without a channel time", rss(channel=""), "2026-10-26T17:46:49+09:00"),
            ("not ScanMux's XML", rss(rss_item(title="&nope;")), "2026-10-26T17:46:49+09:00"),
        ]
        for name, body, source in cases:
            with self.subTest(name=name):
                path, _ = self.jvn_attempt(body, source_date=source)
                result = self.load().jvn_check(CVE)
                assert isinstance(result, Undetermined)
                self.assertEqual(result.reason, Reason.SOURCE_MALFORMED)
                path.unlink()
        self.jvn_attempt(rss(channel=""), source_date=None)
        self.assertEqual(self.load().jvn_to_json(CVE)["result"], "observed")

    def test_newer_failure_is_reported_and_previous_copy_used(self) -> None:
        self.jvn_attempt()
        self.jvn_attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z",
                         outcome={"kind": "failed", "reason": "http_status", "httpStatus": 503})
        loaded = self.load()
        self.assertEqual(loaded.jvn.latest_attempt, "failed")
        self.assertEqual(loaded.jvn_to_json(CVE)["result"], "observed")

    def test_missing_failed_only_and_record_damage(self) -> None:
        self.assertEqual(self.load().jvn_to_json(CVE)["reason"], "source_missing")
        self.jvn_attempt(outcome={"kind": "failed", "reason": "timeout", "httpStatus": None})
        self.assertEqual(self.load().jvn_to_json(CVE)["reason"], "source_missing")
        cases: list[tuple[dict[str, Any], str, str]] = [
            ({"feed": "kev"}, "source_missing", "source_malformed"),
            ({"feed": "jvn"}, "source_malformed", "source_missing"),
            ({"feed": "jvndb"}, "source_missing", "source_missing"),
            ({}, "source_malformed", "source_malformed"),
        ]
        for record, jvn_reason, kev_reason in cases:
            with self.subTest(record=record):
                path = self.store / "attempts" / "20261026T100000000Z-00000000-0000-0000-0000-00000000ffff.json"
                path.write_bytes(encoded({**record, "schema": "scanmux.intel-attempt/v1", "broken": True}))
                loaded = self.load()
                self.assertEqual(loaded.jvn_to_json(CVE)["reason"], jvn_reason)
                self.assertEqual(loaded.kev_to_json(CVE)["reason"], kev_reason)
                self.assertEqual((loaded.jvn.invalid_attempts, loaded.kev.invalid_attempts), (1, 1))
                path.unlink()

    def test_oversized_jvn_record_is_invalid(self) -> None:
        body = rss()
        outcome = {"kind": "stored", "httpStatus": 200, "contentType": None, "bytes": 1024 * 1024 + 1,
                   "sha256": hashlib.sha256(body).hexdigest(), "source": {"version": None, "date": None}}
        self.jvn_attempt(body, outcome=outcome)
        loaded = self.load()
        self.assertEqual(loaded.jvn_to_json(CVE)["reason"], "source_malformed")
        self.assertEqual(loaded.jvn.invalid_attempts, 1)

    def test_unknown_schema_blocks_jvn_too(self) -> None:
        self.jvn_attempt()
        self.attempt(schema="scanmux.intel-attempt/v2")
        result = self.load().jvn_check(CVE)
        assert isinstance(result, Undetermined)
        self.assertIn("unknown schema", result.detail)


class CliTests(StoreBase):
    def test_lone_surrogate_is_replaced_only_in_output(self) -> None:
        self.attempt(encoded(catalog(entry(knownRansomwareCampaignUse="Use\ud800\U0001f600"))))
        self.write_doc(document(item("W-1", "2026-10-01", cves=[CVE])))
        loaded = self.load()
        check = loaded.kev_check(CVE)
        assert isinstance(check, Found)
        self.assertEqual(check.value.ransomware, "Use\ud800\U0001f600")
        for format in ("json", "markdown"):
            with self.subTest(format=format):
                code, text, err = self.run_cli("waitlist", "show", self.path, "--intel-store", str(self.store),
                                               "--format", format)
                self.assertEqual((code, err), (0, ""))
                self.assertIn('"result": "listed"', text)
                self.assertIn("Use\ufffd\U0001f600", text)
                self.assertEqual(text.encode("utf-8").decode("utf-8"), text)

    def test_json_and_markdown_same_information_exit_and_no_rewrite(self) -> None:
        self.attempt()
        self.jvn_attempt()
        self.write_doc(document(item("W-1", "2026-10-01", cves=[CVE, ABSENT]), item("W-2", "2026-10-01")))
        before = self.read_bytes()
        with mock.patch("patchwait.cli.load_intel", return_value=self.load()):
            code, payload = self.show("--intel-store", str(self.store))
            self.assertEqual(code, 0)
            self.assertEqual(next(iter(payload)), "intel")
            self.assertEqual(payload["items"][0]["cves"], [CVE, ABSENT])
            self.assertEqual(payload["items"][0]["kev"][CVE]["result"], "listed")
            self.assertEqual(payload["items"][0]["kev"][ABSENT]["result"], "not_listed")
            self.assertEqual(payload["items"][0]["jvn"][CVE]["result"], "observed")
            self.assertEqual(payload["items"][0]["jvn"][ABSENT]["result"], "not_observed_in_window")
            self.assertEqual(payload["intel"]["jvn"]["items"], 1)
            self.assertNotIn("kev", payload["items"][1])
            self.assertNotIn("jvn", payload["items"][1])
            self.assertNotIn("cves", payload["items"][1])
            code, text, err = self.run_cli("waitlist", "show", self.path, "--intel-store", str(self.store),
                                           "--format", "markdown", "--stale-days", "7")
            self.assertEqual((code, err), (10, ""))
            self.assertIn("intel `", text)
            self.assertIn(f'`{CVE}` kev `{{"result": "listed"', text)
            self.assertIn(f'`{CVE}` jvn `{{"result": "observed", "items": [{{"identifier": "JVNVU#00000001"', text)
            self.assertIn(f'`{ABSENT}` jvn `{{"result": "not_observed_in_window"', text)
            for field in ("modified", "oldest", "newest"):
                self.assertIn(f'"{field}"', text)
            for field in ("catalogVersion", "dateReleased", "completedAt", "days_since_fetch", "latest_attempt", "invalid_attempts"):
                self.assertIn(field, text)
        self.assertEqual(self.read_bytes(), before)

    def test_undetermined_is_not_not_listed_and_exit_unchanged(self) -> None:
        self.write_doc(document(item("W-1", "2026-10-01", cves=[ABSENT])))
        code, payload = self.show("--intel-store", str(self.store))
        self.assertEqual(code, 0)
        self.assertEqual(payload["items"][0]["kev"][ABSENT]["reason"], "source_missing")
        path, _ = self.attempt()
        path.write_bytes(b"broken")
        code, payload = self.show("--intel-store", str(self.store))
        self.assertEqual(code, 0)
        self.assertEqual(payload["items"][0]["kev"][ABSENT]["reason"], "source_malformed")

    def test_store_layout_errors_exit_2(self) -> None:
        self.write_doc(document())
        extra = self.store / "unexpected"
        extra.write_bytes(b"x")
        for store in (str(self.store), str(self.store / "absent"), self.path, "relative"):
            with self.subTest(store=store):
                self.assert_rejected("waitlist", "show", self.path, "--intel-store", store, needle="--intel-store")
        extra.unlink()
        (self.store / "blobs").rmdir()
        self.assert_rejected("waitlist", "show", self.path, "--intel-store", str(self.store), needle="--intel-store")
        (self.store / "blobs").write_bytes(b"not a directory")
        self.assert_rejected("waitlist", "show", self.path, "--intel-store", str(self.store), needle="--intel-store")

    def test_noncanonical_store_paths_exit_2(self) -> None:
        self.write_doc(document())
        paths = (str(self.store) + os.sep, str(self.store) + os.sep + ".",
                 str(self.store) + os.sep + ".." + os.sep + self.store.name,
                 os.path.abspath(os.sep))
        for path in paths:
            with self.subTest(path=path), mock.patch.object(intel.os, "listdir", side_effect=AssertionError("accessed store")):
                self.assert_rejected("waitlist", "show", self.path, "--intel-store", path, needle="--intel-store")

    def test_no_network_or_subprocess(self) -> None:
        self.attempt()
        self.write_doc(document(item("W-1", "2026-10-01", cves=[CVE, ABSENT])))
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertEqual(self.show("--intel-store", str(self.store))[0], 0)

    def test_markdown_escapes_store_metadata_and_ransomware(self) -> None:
        body = encoded(catalog(entry(knownRansomwareCampaignUse="x`\n# heading\u202e")))
        self.attempt(body)
        self.write_doc(document(item("W-1", "2026-10-01", cves=[CVE])))
        code, text, err = self.run_cli("waitlist", "show", self.path, "--intel-store", str(self.store), "--format", "markdown")
        self.assertEqual((code, err), (0, ""))
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\n# heading", text)
        self.assertIn("``", text)


class LocalityTests(StoreBase):
    def junction(self, link: Path, target: Path) -> None:
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if result.returncode:
            self.skipTest(f"OS refused junction creation: {result.stderr.decode(errors='replace').strip()}")

    @unittest.skipUnless(os.name == "nt", "junction creation requires Windows")
    def test_real_store_and_child_junctions_exit_2(self) -> None:
        self.local.stop()
        self.attempt()
        self.write_doc(document())
        alias = Path(self.dir, "store-alias")
        self.junction(alias, self.store)
        with self.subTest(name="store"):
            try:
                self.assert_rejected("waitlist", "show", self.path, "--intel-store", str(alias), needle="--intel-store")
            finally:
                alias.rmdir()
        for name in ("attempts", "blobs"):
            with self.subTest(name=name):
                child = self.store / name
                sibling = Path(self.dir, name + "-sibling")
                child.rename(sibling)
                try:
                    self.junction(child, sibling)
                    try:
                        self.assert_rejected("waitlist", "show", self.path, "--intel-store", str(self.store),
                                             needle="--intel-store")
                    finally:
                        child.rmdir()
                finally:
                    sibling.rename(child)

    @unittest.skipUnless(os.name == "nt", "junction creation requires Windows")
    def test_real_parent_junction_exits_2(self) -> None:
        self.local.stop()
        self.attempt()
        self.write_doc(document())
        alias = Path(self.dir, "j")
        self.junction(alias, Path(self.dir))
        try:
            path = alias / self.store.name
            check = intel.local_path_check(str(path))
            self.assertIsNone(check.problem)
            self.assertTrue(check.chain)
            self.assertFalse(intel.is_reparse_point(path))
            self.assert_rejected("waitlist", "show", self.path, "--intel-store", str(path), needle="--intel-store")
        finally:
            alias.rmdir()

    def test_real_attempt_and_blob_symlinks_are_unusable(self) -> None:
        if os.name == "nt":
            self.local.stop()
        for kind in ("attempt", "blob"):
            with self.subTest(kind=kind):
                path, data = self.attempt(start="2026-10-26T10:00:00.000Z", end="2026-10-26T10:00:01.000Z")
                link = path if kind == "attempt" else self.store / "blobs" / data["outcome"]["sha256"]
                sibling = Path(self.dir, kind + "-sibling.json")
                link.rename(sibling)
                try:
                    try:
                        link.symlink_to(sibling)
                    except OSError as error:
                        self.skipTest(f"OS refused file symlink creation: {error}")
                    try:
                        self.assertEqual(self.assert_unknown().kev.invalid_attempts, 1)
                        older, _ = self.attempt(encoded(catalog(entry(product="Older copy"))))
                        loaded = self.load()
                        self.assertEqual(loaded.kev.completed_at, END)
                        self.assertIsInstance(loaded.kev_check(CVE), Found)
                        self.assertEqual(loaded.kev.invalid_attempts, 1)
                        older.unlink()
                    finally:
                        link.unlink()
                finally:
                    sibling.rename(link)
                    path.unlink()

    def test_remote_store_is_refused_before_access(self) -> None:
        with mock.patch.object(intel, "local_path_check", return_value=Locality("remote", False, ())), \
             mock.patch.object(intel.os, "listdir", side_effect=AssertionError("accessed store")):
            with self.assertRaises(intel.IntelInputError):
                intel.load_intel(str(self.store), NOW)

    def test_remote_child_is_never_opened(self) -> None:
        _, data = self.attempt()
        target = str(self.store / "blobs" / data["outcome"]["sha256"])
        real_open = open

        def checked(path: str) -> Locality:
            return Locality("remote" if path == target else None, False, ())

        def guarded(path: str, *args: Any, **kwargs: Any) -> Any:
            self.assertNotEqual(path, target)
            return real_open(path, *args, **kwargs)

        with mock.patch.object(intel, "local_path_check", side_effect=checked), mock.patch("builtins.open", side_effect=guarded):
            self.assert_unknown()

    def test_changed_locality_after_read_is_rejected(self) -> None:
        path = self.store / "blobs" / "example"
        path.write_bytes(b"x")
        with mock.patch.object(intel, "local_path_check", side_effect=[Locality(None, False, ()),
                               Locality(None, False, (("link", "changed"),))]):
            with self.assertRaises(ValueError):
                intel._bounded_read(str(path), 1)

    @unittest.skipUnless(os.name == "nt", "Windows-only locality check")
    def test_real_locality_on_synthetic_store(self) -> None:
        self.attempt()
        self.local.stop()
        self.assertIsInstance(self.load().kev_check(CVE), Found)


if __name__ == "__main__":
    unittest.main()
