from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from patchwait import scan as scan_module
from patchwait.cli import main
from patchwait.model import Component, Found, Reason, RuntimeKind
from patchwait.pe_version import EVIDENCE
from patchwait.scan import ScanUsageError, infer_product, parse_baselines
from tests.pe_builder import NODE_LIKE, PYTHON_LIKE, VersionSpec, build_pe

MIN_NODE = "node=24.22.1,26.12.1"
SOURCE = "node=https://example.invalid/node-security"


def node_spec(version: str) -> VersionSpec:
    a, b, c = (int(part) for part in version.split("."))
    strings = dict(NODE_LIKE.strings, FileVersion=version, ProductVersion=version)
    return replace(NODE_LIKE, strings=strings, fixed_file=(a, b, c, 0), fixed_product=(a, b, c, 0))


class ScanCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, data: bytes) -> str:
        path = os.path.normpath(os.path.join(self.dir, rel))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def node(self, rel: str, version: str) -> str:
        return self.write(rel, build_pe(version=node_spec(version))[0])

    def run_scan(self, *argv: str) -> tuple[int, dict[str, object]]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", *argv])
        payload: dict[str, object] = json.loads(out.getvalue()) if out.getvalue() else {}
        if payload:
            self.assert_consistent(payload)
        return code, payload

    def assert_consistent(self, doc: dict[str, object]) -> None:
        items = doc["items"]
        counts = doc["counts"]
        assert isinstance(items, list) and isinstance(counts, dict)
        tally = {"found": 0, "not_found": 0, "undetermined": 0}
        for entry in items:  # pyright: ignore[reportUnknownVariableType]
            tally[entry["verdict"]["result"]] += 1  # pyright: ignore[reportUnknownArgumentType]
        self.assertEqual(counts, {"targets": len(items), **tally})  # pyright: ignore[reportUnknownArgumentType]

    def items(self, doc: dict[str, object]) -> list[dict[str, object]]:
        items = doc["items"]
        assert isinstance(items, list)
        return items  # pyright: ignore[reportUnknownVariableType]

    def verdict(self, item: dict[str, object]) -> dict[str, object]:
        verdict = item["verdict"]
        assert isinstance(verdict, dict)
        return verdict  # pyright: ignore[reportUnknownVariableType]


class ScanTests(ScanCase):
    def test_below_minimum_is_found_exit_10(self) -> None:
        path = self.node("Cursor/resources/node.exe", "24.19.0")
        code, doc = self.run_scan("--path", path, "--min", MIN_NODE, "--source", SOURCE)
        self.assertEqual(code, 10)
        (item,) = self.items(doc)
        self.assertEqual(item["path"], path)
        self.assertEqual(item["product"], {"name": "Cursor", "inferred": True})
        self.assertEqual(item["product_version"], "24.19.0")
        self.assertEqual(
            item["checked_against"], {"minimum": "24.22.1", "source": "https://example.invalid/node-security"}
        )
        self.assertEqual(self.verdict(item), {"result": "found", "value": "24.19.0"})

    def test_equal_and_above_minimum_are_not_found_exit_0(self) -> None:
        equal = self.node("a/node.exe", "24.22.1")
        above = self.node("b/node.exe", "24.23.0")
        code, doc = self.run_scan("--path", equal, "--path", above, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        self.assertEqual([self.verdict(i)["result"] for i in self.items(doc)], ["not_found", "not_found"])

    def test_numeric_not_lexical_comparison(self) -> None:
        path = self.node("a/node.exe", "24.9.0")
        code, doc = self.run_scan("--path", path, "--min", "node=24.10.0")
        self.assertEqual(code, 10)
        self.assertEqual(self.verdict(self.items(doc)[0])["result"], "found")

    def test_two_series_each_use_their_own_minimum(self) -> None:
        old26 = self.node("x/node.exe", "26.12.0")
        new24 = self.node("y/node.exe", "24.22.1")
        code, doc = self.run_scan("--path", old26, "--path", new24, "--min", MIN_NODE)
        self.assertEqual(code, 10)
        first, second = self.items(doc)
        self.assertEqual(first["checked_against"], {"minimum": "26.12.1", "source": None})
        self.assertEqual(self.verdict(first)["result"], "found")
        self.assertEqual(second["checked_against"], {"minimum": "24.22.1", "source": None})
        self.assertEqual(self.verdict(second)["result"], "not_found")

    def test_missing_baseline_for_series_is_undetermined(self) -> None:
        path = self.node("a/node.exe", "22.1.0")
        code, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        item = self.items(doc)[0]
        self.assertEqual(item["product_version"], "22.1.0")
        self.assertEqual(item["checked_against"], {"minimum": None, "source": None})
        self.assertEqual(self.verdict(item)["reason"], Reason.NO_BASELINE.value)

    def test_no_min_at_all_is_undetermined(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        code, doc = self.run_scan("--path", path)
        self.assertEqual(code, 0)
        self.assertEqual(self.verdict(self.items(doc)[0])["reason"], "no_baseline")

    def test_absent_target_is_undetermined_not_dropped(self) -> None:
        absent = os.path.join(self.dir, "Codex", "node.exe")
        present = self.node("Hermes/node.exe", "24.19.0")
        code, doc = self.run_scan("--path", absent, "--path", present, "--min", MIN_NODE)
        self.assertEqual(code, 10)
        first, second = self.items(doc)
        self.assertEqual(first["path"], absent)
        self.assertEqual(first["product_version"], None)
        self.assertEqual(self.verdict(first)["reason"], Reason.TARGET_MISSING.value)
        self.assertEqual(second["product"], {"name": "Hermes", "inferred": True})

    def test_non_pe_is_undetermined(self) -> None:
        path = self.write("a/node.exe", b"not a pe")
        code, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        self.assertEqual(self.verdict(self.items(doc)[0])["reason"], "not_pe")

    def test_version_mismatch_propagates(self) -> None:
        spec = replace(node_spec("24.19.0"), fixed_product=(20, 0, 0, 0))
        path = self.write("a/node.exe", build_pe(version=spec)[0])
        _, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        item = self.items(doc)[0]
        self.assertEqual(item["product_version"], None)
        self.assertEqual(self.verdict(item)["reason"], "version_mismatch")

    def test_unexpected_product_is_undetermined(self) -> None:
        path = self.write("a/python.exe", build_pe(version=PYTHON_LIKE)[0])
        _, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(self.verdict(self.items(doc)[0])["reason"], "unexpected_product")

    def test_python_series_is_major_minor(self) -> None:
        path = self.write("a/python.exe", build_pe(version=PYTHON_LIKE)[0])
        code, doc = self.run_scan("--path", path, "--kind", "python", "--min", "python=3.13.9,3.14.7")
        self.assertEqual(code, 10)
        item = self.items(doc)[0]
        self.assertEqual(item["checked_against"], {"minimum": "3.14.7", "source": None})

    def test_unreadable_target_is_undetermined(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            _, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(self.verdict(self.items(doc)[0])["reason"], "file_unreadable")

    def test_targets_file_product_is_not_inferred(self) -> None:
        named = self.node("vendor/app/node.exe", "24.19.0")
        unnamed = self.node("Programs/cursor/node.exe", "24.22.1")
        targets = self.write(
            "targets.json",
            json.dumps([{"path": named, "product": "Some App"}, {"path": unnamed}]).encode("utf-8"),
        )
        code, doc = self.run_scan("--targets", targets, "--min", MIN_NODE)
        self.assertEqual(code, 10)
        first, second = self.items(doc)
        self.assertEqual(first["product"], {"name": "Some App", "inferred": False})
        self.assertEqual(second["product"], {"name": "Cursor", "inferred": True})

    def test_document_shape(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        _, doc = self.run_scan("--path", path, "--min", MIN_NODE, "--source", SOURCE)
        self.assertEqual(doc["tool"], "patchwait")
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["kind"], "node")
        self.assertEqual(
            doc["baselines"],
            {"node": {"minimums": ["24.22.1", "26.12.1"], "source": "https://example.invalid/node-security"}},
        )
        generated = doc["generated"]
        assert isinstance(generated, str)
        self.assertRegex(generated, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d$")

    def test_out_is_written_atomically(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        out = os.path.join(self.dir, "report.json")
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("old")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), mock.patch(
            "patchwait.scan.os.replace", wraps=os.replace
        ) as replaced:
            code = main(["scan", "--path", path, "--min", MIN_NODE, "--out", out])
        self.assertEqual(code, 10)
        self.assertEqual(stdout.getvalue(), "")
        replaced.assert_called_once()
        tmp_path, final_path = replaced.call_args.args
        self.assertEqual(os.path.dirname(tmp_path), self.dir)
        self.assertEqual(final_path, out)
        with open(out, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r\n", raw)
        doc = json.loads(raw.decode("utf-8"))
        self.assert_consistent(doc)
        self.assertEqual(sorted(os.listdir(self.dir)), ["a", "report.json"])

    def test_out_failure_keeps_old_file_and_exits_2(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        out = os.path.join(self.dir, "report.json")
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("old")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch(
            "patchwait.scan.os.replace", side_effect=OSError("disk")
        ):
            code = main(["scan", "--path", path, "--min", MIN_NODE, "--out", out])
        self.assertEqual(code, 2)
        with open(out, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "old")
        self.assertEqual(sorted(os.listdir(self.dir)), ["a", "report.json"])

    def test_exit_2_cases(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        broken = self.write("broken.json", b"{not json")
        not_list = self.write("obj.json", b'{"path": "x"}')
        bad_entry = self.write("bad.json", b'[{"product": "x"}]')
        cases = [
            ("--targets", os.path.join(self.dir, "missing.json")),
            ("--targets", broken),
            ("--targets", not_list),
            ("--targets", bad_entry),
            ("--path", path, "--min", "node=24.22"),
            ("--path", path, "--min", "node=24.22.1,24.23.0"),
            ("--path", path, "--min", "ruby=1.0.0"),
            ("--path", path, "--source", "node"),
            ("--min", MIN_NODE),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, doc = self.run_scan(*argv)
                self.assertEqual((code, doc), (2, {}))

    def test_internal_error_exits_2(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        with mock.patch("patchwait.pyvenv.detect_runtime_with_venv", side_effect=RuntimeError("boom")):
            code, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual((code, doc), (2, {}))

    def test_every_target_yields_one_item_in_order(self) -> None:
        paths = [
            self.node("Cursor/node.exe", "24.19.0"),
            os.path.join(self.dir, "gone.exe"),
            self.write("junk.exe", b"MZ"),
            self.node("Codex/node.exe", "26.12.1"),
            self.node("Cursor/node.exe", "24.19.0"),  # duplicate path is kept
        ]
        argv: list[str] = []
        for path in paths:
            argv += ["--path", path]
        code, doc = self.run_scan(*argv, "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], paths)
        self.assertEqual(doc["counts"], {"targets": 5, "found": 2, "not_found": 1, "undetermined": 2})

    def test_version_of_still_works(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["version-of", path, "--kind", "node"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["result"], "found")


def _make_dir_link(link: str, target: str) -> str | None:
    """A directory symlink, else a junction on Windows; None if the OS refuses both."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        try:
            import _winapi

            _winapi.CreateJunction(target, link)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
            return "junction"
        except (OSError, AttributeError):
            pass
    return None


class WalkCase(ScanCase):
    def walk(self, doc: dict[str, object]) -> list[dict[str, object]]:
        walk = doc["walk"]
        assert isinstance(walk, list)
        return walk  # pyright: ignore[reportUnknownVariableType]


class RootWalkTests(WalkCase):
    def test_nested_node_found_at_depth(self) -> None:
        deep = self.node("root/a/b/c/d/LogiOptionsPlus/node.exe", "24.19.0")
        root = os.path.join(self.dir, "root")
        code, doc = self.run_scan("--root", root, "--min", MIN_NODE)
        self.assertEqual(code, 10)
        (item,) = self.items(doc)
        self.assertEqual(item["path"], deep)
        self.assertEqual(item["location_kind"], "file")
        self.assertEqual(item["product"], {"name": "Logi Options+", "inferred": True})
        self.assertEqual(
            self.walk(doc),
            [{"root": root, "matched_files": 1, "unreadable_dirs": 0, "skipped_reparse_points": 0, "excluded_dirs": 0}],
        )

    def test_file_name_is_case_insensitive(self) -> None:
        upper = self.node("root/x/NODE.EXE", "24.19.0")
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [upper])

    def test_python_kind_walks_for_python_exe(self) -> None:
        py = self.write("root/tools/python.exe", build_pe(version=PYTHON_LIKE)[0])
        self.node("root/tools/node.exe", "24.19.0")
        code, doc = self.run_scan(
            "--root", os.path.join(self.dir, "root"), "--kind", "python", "--min", "python=3.13.9,3.14.7"
        )
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [py])

    def test_non_matching_names_ignored(self) -> None:
        for rel in ("root/node.exe.bak", "root/nodejs.exe", "root/node", "root/sub/node.dll"):
            self.write(rel, b"MZ")
        self.write("root/node.exe/inner.txt", b"a directory named node.exe")
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual((code, self.items(doc)), (0, []))
        self.assertEqual(self.walk(doc)[0]["matched_files"], 0)

    def test_exclude_is_case_insensitive_substring(self) -> None:
        kept = self.node("root/keep/node.exe", "24.19.0")
        self.node("root/Node_Modules/x/node.exe", "24.19.0")
        self.node("root/other/cache/node.exe", "24.19.0")
        root = os.path.join(self.dir, "root")
        code, doc = self.run_scan("--root", root, "--exclude", "node_modules", "--exclude", "CACHE", "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [kept])
        self.assertEqual(self.walk(doc)[0]["excluded_dirs"], 2)

    def test_dedupe_with_path_keeps_explicit_item(self) -> None:
        self.node("root/Cursor/node.exe", "24.19.0")
        other = self.node("root/zz/node.exe", "24.22.1")
        spelled = os.path.join(self.dir, "root", "cursor", ".", "NODE.exe")
        code, doc = self.run_scan("--path", spelled, "--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [spelled, other])
        self.assertEqual(self.walk(doc)[0]["matched_files"], 2)

    def test_dedupe_with_targets_keeps_targets_product(self) -> None:
        path = self.node("root/vendor/node.exe", "24.19.0")
        targets = self.write("targets.json", json.dumps([{"path": path, "product": "Vendor App"}]).encode("utf-8"))
        code, doc = self.run_scan("--targets", targets, "--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual(code, 10)
        (item,) = self.items(doc)
        self.assertEqual(item["product"], {"name": "Vendor App", "inferred": False})

    def test_overlapping_roots_scan_a_file_once(self) -> None:
        path = self.node("root/a/node.exe", "24.19.0")
        root = os.path.join(self.dir, "root")
        _, doc = self.run_scan("--root", root, "--root", os.path.join(root, "a"), "--min", MIN_NODE)
        self.assertEqual([i["path"] for i in self.items(doc)], [path])
        self.assertEqual([w["matched_files"] for w in self.walk(doc)], [1, 1])

    def test_directory_link_is_not_followed(self) -> None:
        target = os.path.join(self.dir, "elsewhere")
        self.node("elsewhere/node.exe", "24.19.0")
        os.makedirs(os.path.join(self.dir, "root"))
        made = _make_dir_link(os.path.join(self.dir, "root", "link"), target)
        if made is None:
            self.skipTest("the OS refused both a directory symlink and a junction")
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual((code, self.items(doc)), (0, []), made)
        self.assertEqual(self.walk(doc)[0]["skipped_reparse_points"], 1, made)

    @unittest.skipUnless(sys.platform == "win32", "junctions are Windows only")
    def test_junction_is_not_followed(self) -> None:
        import _winapi

        target = os.path.join(self.dir, "elsewhere")
        self.node("elsewhere/node.exe", "24.19.0")
        os.makedirs(os.path.join(self.dir, "root"))
        _winapi.CreateJunction(target, os.path.join(self.dir, "root", "junction"))  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual((code, self.items(doc)), (0, []))
        self.assertEqual(self.walk(doc)[0]["skipped_reparse_points"], 1)

    def test_reparse_point_without_symlink_flag_is_not_followed(self) -> None:
        self.node("root/mounted/node.exe", "24.19.0")
        kept = self.node("root/plain/node.exe", "24.19.0")
        real = scan_module._is_reparse_point  # pyright: ignore[reportPrivateUsage]

        def is_reparse(entry: os.DirEntry[str]) -> bool:
            return entry.name == "mounted" or real(entry)

        with mock.patch.object(scan_module, "_is_reparse_point", side_effect=is_reparse):
            code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [kept])
        self.assertEqual(self.walk(doc)[0]["skipped_reparse_points"], 1)


@unittest.skipUnless(sys.platform == "win32", "'/' and '\' are the same separator only on Windows")
class SeparatorTests(WalkCase):
    """A root or exclude spelled with '/' must behave like the '\' spelling."""

    def layout(self) -> tuple[str, str]:
        kept = self.node("root/keep/node.exe", "24.19.0")
        self.node("root/Vendor/Local/Scratch/x/node.exe", "24.19.0")
        self.node("root/Vendor/Local/Scratchpad/node.exe", "24.19.0")
        return kept, os.path.join(self.dir, "root")

    def assert_unmixed(self, doc: dict[str, object]) -> None:
        paths = [str(i["path"]) for i in self.items(doc)] + [str(w["root"]) for w in self.walk(doc)]
        self.assertEqual([p for p in paths if "/" in p], [])

    def test_forward_slash_root_with_backslash_exclude(self) -> None:
        kept, root = self.layout()
        slashed = root.replace("\\", "/")
        code, doc = self.run_scan("--root", slashed, "--exclude", "\\Vendor\\Local\\Scratch\\", "--min", MIN_NODE)
        self.assertEqual(code, 10)
        scratchpad = os.path.join(root, "Vendor", "Local", "Scratchpad", "node.exe")
        self.assertEqual([i["path"] for i in self.items(doc)], [scratchpad, kept])
        self.assertEqual(self.walk(doc)[0]["root"], root)
        self.assertEqual(self.walk(doc)[0]["excluded_dirs"], 1)
        self.assert_unmixed(doc)

    def test_backslash_root_with_forward_slash_exclude(self) -> None:
        kept, root = self.layout()
        code, doc = self.run_scan("--root", root, "--exclude", "/vendor/LOCAL/Scratch", "--min", MIN_NODE)
        self.assertEqual(code, 10)
        # Substring semantics: without a trailing separator "Scratch" also matches "Scratchpad".
        self.assertEqual([i["path"] for i in self.items(doc)], [kept])
        self.assertEqual(self.walk(doc)[0]["excluded_dirs"], 2)
        self.assert_unmixed(doc)

    def test_mixed_root_reports_normalised_paths_and_dedupes(self) -> None:
        kept, root = self.layout()
        mixed = root.replace("\\", "/") + "/./"
        explicit = kept.replace("\\", "/")
        code, doc = self.run_scan("--path", explicit, "--root", mixed, "--exclude", "/Vendor/", "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], [explicit])  # explicit spelling kept as given
        self.assertEqual(self.walk(doc)[0]["root"], root)
        self.assertEqual(self.walk(doc)[0]["matched_files"], 1)

    def test_missing_forward_slash_root_is_reported_normalised(self) -> None:
        missing = os.path.join(self.dir, "nope", "sub")
        code, doc = self.run_scan("--root", missing.replace("\\", "/"), "--min", MIN_NODE)
        (item,) = self.items(doc)
        self.assertEqual((item["path"], self.walk(doc)[0]["root"]), (missing, missing))
        self.assertEqual(code, 0)


class _FakeEntry:
    def __init__(self, *, symlink: bool = False, attributes: int | None = None) -> None:
        self.path = "x"
        self._symlink = symlink
        self._attributes = attributes

    def is_symlink(self) -> bool:
        return self._symlink

    def stat(self, *, follow_symlinks: bool = True) -> object:
        del follow_symlinks
        result = mock.Mock(spec=[] if self._attributes is None else ["st_file_attributes"])
        if self._attributes is not None:
            result.st_file_attributes = self._attributes
        return result


class ReparsePointTests(unittest.TestCase):
    def check(self, entry: _FakeEntry) -> bool:
        return scan_module._is_reparse_point(entry)  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    def test_symlink(self) -> None:
        self.assertTrue(self.check(_FakeEntry(symlink=True)))

    def test_windows_reparse_attribute_is_a_junction(self) -> None:
        flags = stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT
        self.assertTrue(self.check(_FakeEntry(attributes=flags)))
        self.assertFalse(self.check(_FakeEntry(attributes=stat.FILE_ATTRIBUTE_DIRECTORY)))

    def test_isjunction_used_when_no_attributes(self) -> None:
        with mock.patch.object(scan_module.os.path, "isjunction", create=True, return_value=True):
            self.assertTrue(self.check(_FakeEntry()))
        with mock.patch.object(scan_module.os.path, "isjunction", create=True, return_value=False):
            self.assertFalse(self.check(_FakeEntry()))


class RootWalkErrorTests(WalkCase):
    def test_unreadable_directory_is_an_undetermined_item(self) -> None:
        kept = self.node("root/a/node.exe", "24.19.0")
        self.node("root/b/node.exe", "24.19.0")
        locked = os.path.join(self.dir, "root", "b")
        real = os.scandir

        def scandir(path: str) -> object:
            if os.path.normcase(path) == os.path.normcase(locked):
                raise PermissionError(13, "denied", path)
            return real(path)

        with mock.patch("patchwait.scan.os.scandir", side_effect=scandir):
            code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE, "--source", SOURCE)
        self.assertEqual(code, 10)
        first, second = self.items(doc)
        self.assertEqual(first["path"], kept)
        self.assertEqual(second["path"], locked)
        self.assertEqual(second["location_kind"], "directory")
        self.assertEqual(second["product_version"], None)
        self.assertEqual(self.verdict(second), {"result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"})
        self.assertEqual(doc["counts"], {"targets": 2, "found": 1, "not_found": 0, "undetermined": 1})
        self.assertEqual(self.walk(doc)[0]["unreadable_dirs"], 1)

    def test_missing_root_is_target_missing(self) -> None:
        root = os.path.join(self.dir, "no-such-root")
        code, doc = self.run_scan("--root", root, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        (item,) = self.items(doc)
        self.assertEqual((item["path"], item["location_kind"]), (root, "directory"))
        self.assertEqual(self.verdict(item)["reason"], Reason.TARGET_MISSING.value)
        self.assertEqual(doc["counts"], {"targets": 1, "found": 0, "not_found": 0, "undetermined": 1})
        self.assertEqual(self.walk(doc)[0]["matched_files"], 0)

    def test_zero_matches_exit_0(self) -> None:
        self.write("root/readme.txt", b"nothing here")
        root = os.path.join(self.dir, "root")
        code, doc = self.run_scan("--root", root, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        self.assertEqual(self.items(doc), [])
        self.assertEqual(
            self.walk(doc),
            [{"root": root, "matched_files": 0, "unreadable_dirs": 0, "skipped_reparse_points": 0, "excluded_dirs": 0}],
        )

    def test_walked_file_below_minimum_exit_10_and_order_is_sorted(self) -> None:
        paths = [
            self.node("root/A/node.exe", "24.22.1"),
            self.node("root/A/b/node.exe", "24.19.0"),
            self.node("root/c/node.exe", "26.12.1"),
        ]
        self.node("root/B/node.exe", "24.22.1")
        paths.insert(2, os.path.join(self.dir, "root", "B", "node.exe"))
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--min", MIN_NODE)
        self.assertEqual(code, 10)
        self.assertEqual([i["path"] for i in self.items(doc)], paths)
        self.assertEqual(doc["counts"], {"targets": 4, "found": 1, "not_found": 3, "undetermined": 0})

    def test_walk_is_empty_without_root(self) -> None:
        path = self.node("a/node.exe", "24.19.0")
        _, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(doc["walk"], [])
        self.assertEqual(self.items(doc)[0]["location_kind"], "file")


class InferProductTests(unittest.TestCase):
    def test_known_products(self) -> None:
        cases = {
            "C:/Apps/Cursor/resources/node.exe": "Cursor",
            "C:\\Users\\u\\AppData\\Local\\Programs\\cursor\\node.exe": "Cursor",
            "C:/Apps/openai.codex-1.2/bin/node.exe": "Codex",
            "C:/Apps/hermes-agent/node.exe": "Hermes",
            "C:/Apps/ms-playwright/node.exe": "Playwright",
            "C:/Program Files/LogiOptionsPlus/node.exe": "Logi Options+",
        }
        for path, name in cases.items():
            with self.subTest(path=path):
                product = infer_product(path)
                self.assertEqual((product.name, product.inferred), (name, True))

    def test_unknown_product(self) -> None:
        for path in ("C:/Program Files/nodejs/node.exe", "C:/Program Files/Some Technologies/node.exe"):
            with self.subTest(path=path):
                product = infer_product(path)
                self.assertEqual((product.name, product.inferred), ("unknown", True))


class ParseBaselinesTests(unittest.TestCase):
    def test_repeated_min_merges(self) -> None:
        baselines = parse_baselines(["node=24.22.1", "node=26.12.1"], [])
        self.assertEqual(baselines["node"].minimums, ("24.22.1", "26.12.1"))

    def test_duplicate_source_rejected(self) -> None:
        with self.assertRaises(ScanUsageError):
            parse_baselines([], ["node=https://a.invalid", "node=https://b.invalid"])


class AsciiDigitBaselineTests(unittest.TestCase):
    def test_non_ascii_digits_in_a_minimum_are_refused(self) -> None:
        for text in ("node=\uff12\uff14.\uff12\uff12.\uff11", "node=24.2\u0662.1", "node=\u0662\u0664.22.1"):
            with self.subTest(text=text), self.assertRaises(ScanUsageError):
                parse_baselines([text], [])
        self.assertIsNone(scan_module.parse_version("\u0662\u0664.\u0661\u0669.\u0660"))
        self.assertEqual(scan_module.parse_version("24.19.0"), (24, 19, 0))


class TrailingNewlineTests(ScanCase):
    def test_a_minimum_with_a_trailing_newline_is_not_a_version(self) -> None:
        # --min values are strip()ped before parsing, so the parser itself must refuse the newline.
        for text in ("24.22.1\n", "24.22.1\r\n", "\n24.22.1"):
            with self.subTest(text=text):
                self.assertIsNone(scan_module.parse_version(text))

    def test_product_version_with_a_trailing_newline_is_not_compared(self) -> None:
        # The PE reader strip()s string values, so the newline is fed to scan's own parser directly.
        path = self.node("a/node.exe", "24.19.0")
        component = Component(RuntimeKind.NODE, path, Found("24.19.0\n"), EVIDENCE)
        with mock.patch("patchwait.pyvenv.detect_runtime_with_venv", return_value=(Found(component), None)):
            code, doc = self.run_scan("--path", path, "--min", MIN_NODE)
        self.assertEqual(code, 0)
        (item,) = self.items(doc)
        verdict = self.verdict(item)
        self.assertEqual(verdict["result"], "undetermined")
        self.assertEqual(verdict["reason"], Reason.MALFORMED_VERSION_RESOURCE.value)


if __name__ == "__main__":
    unittest.main()
