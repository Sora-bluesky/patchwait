from __future__ import annotations

import contextlib
import io
import json
import ntpath
import os
import stat
import unittest
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import replace
from functools import partial
from typing import BinaryIO
from unittest import mock

from patchwait import locality, pyvenv
from patchwait.cli import main
from patchwait.model import Reason, RuntimeKind, Undetermined, check_to_json, component_to_json
from patchwait.pe_version import detect_runtime
from tests.pe_builder import build_pe
from tests.test_locality import DRIVE_REMOTE, FakeDisk, _FILE, _JUNCTION
from tests.test_pyvenv import VenvCase, python_spec
from tests.test_waitlist import document, item
from tests.test_waitlist_from import FromBase, scan_link, scan_result, scan_row

EVIDENCE = "install-manager-target-pe-version-resource"
TARGET = r"C:\Synthetic\Python\python.exe"
SIDECAR = "python.exe.__target__"


class InstallManagerTests(VenvCase):
    def setUp(self) -> None:
        super().setUp()
        self.target_pe = self.write("runtime/python.exe", build_pe(version=python_spec("3.14.10"))[0])
        self.disk = FakeDisk({"C:\\": locality.DRIVE_FIXED, "Z:\\": DRIVE_REMOTE})
        self.disk.add(r"C:\Synthetic")
        self.disk.add(r"C:\Synthetic\Python")
        self.disk.add(TARGET, _FILE)
        self.check = partial(
            locality.locality_check, drive_type=self.disk.drive_type, lstat=self.disk.lstat,
            readlink=self.disk.readlink, get_attributes=self.disk.attributes,
        )
        # Sidecar contents contain only synthetic absolute paths. The real PE reader
        # reads a generated fixture, never any synthetic UNC/device path.
        read_exe = pyvenv._read_home_exe
        self.target_reads: list[str] = []

        def read_target(path: str):
            self.target_reads.append(path)
            return read_exe(self.target_pe)

        self.addCleanup(mock.patch.stopall)
        mock.patch("patchwait.pyvenv.local_path_check", self.check).start()
        mock.patch("patchwait.pyvenv._read_home_exe", read_target).start()

    def alias(self, data: bytes | None = None, *, name: str = "python.exe") -> str:
        exe = self.write(f"bin/{name}", build_pe(version=python_spec("3.14.1", "manage"))[0])
        if data is not None:
            self.write(f"bin/{name}.__target__", data)
        return exe

    @contextlib.contextmanager
    def forbid_target_lookups(self) -> Iterator[None]:
        # These are the paths production receives, rather than the PE fixture's path.
        forbidden = {ntpath.normcase(path) for path in (
            TARGET, TARGET + ".__target__", r"C:\Synthetic\Python\pyvenv.cfg", r"C:\Synthetic\pyvenv.cfg",
        )}

        def guard(function, path, *args, **kwargs):
            self.assertNotIn(ntpath.normcase(path), forbidden, f"forbidden target lookup: {function.__name__}")
            return function(path, *args, **kwargs)

        with contextlib.ExitStack() as stack:
            for name in ("find_cfg", "_read_cfg", "install_manager_runtime", "_read_plain_file"):
                stack.enter_context(mock.patch.object(pyvenv, name, side_effect=partial(guard, getattr(pyvenv, name))))
            yield

    def version_of(self, exe: str, kind: str = "python") -> tuple[int, dict[str, object]]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["version-of", "--kind", kind, exe])
        self.assertEqual(err.getvalue(), "")
        return code, json.loads(out.getvalue())

    def assert_found(self, exe: str) -> None:
        code, doc = self.version_of(exe)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["version_source"], EVIDENCE)
        self.assertEqual(doc["value"], {
            "kind": "python", "location": exe,
            "version": {"result": "found", "value": "3.14.10"}, "evidence": EVIDENCE,
        })

    def assert_refused(self, exe: str, detail: str, reason: str | None = None) -> None:
        code, doc = self.version_of(exe)
        self.assertEqual(code, 3)
        self.assertEqual(doc["result"], "undetermined")
        self.assertIn("__target__", str(doc["detail"]))
        self.assertIn(detail, str(doc["detail"]))
        if reason is not None:
            self.assertEqual(doc["reason"], reason)
        self.assertNotIn("value", doc)
        self.assertNotIn("version_source", doc)
        _, item = self.one("--path", exe)
        self.assertIsNone(item["product_version"])
        self.assertEqual(self.verdict(item), doc)
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertIsNone(source["evidence"])

    def test_scan_finds_alias_target_and_path_evidence(self) -> None:
        for name in ("python.exe", "python3.exe", "python3.14.exe", "pythonw.exe", "pip.exe"):
            with self.subTest(name=name):
                exe = self.alias(TARGET.encode(), name=name)
                code, item = self.one("--path", exe)
                self.assertEqual((code, item["product_version"]), (0, "3.14.10"))
                self.assertEqual(item["version_source"], {
                    "evidence": EVIDENCE, "target_file": exe + ".__target__", "target": TARGET,
                })

    def test_version_of_finds_target(self) -> None:
        self.assert_found(self.alias(TARGET.encode()))

    def test_both_commands_use_shared_detection(self) -> None:
        exe = self.alias(TARGET.encode())
        for command in ("scan", "version-of"):
            with self.subTest(command=command):
                with mock.patch(
                    "patchwait.pyvenv.detect_runtime_with_venv", wraps=pyvenv.detect_runtime_with_venv,
                ) as shared:
                    if command == "scan":
                        _, item = self.one("--path", exe)
                        self.assertEqual(item["product_version"], "3.14.10")
                    else:
                        self.assert_found(exe)
                    shared.assert_called_once_with(exe, RuntimeKind.PYTHON)

    def test_own_valid_version_ignores_sidecar(self) -> None:
        exe = self.alias(TARGET.encode())
        self.assert_found(exe)  # proves the sidecar is otherwise usable
        self.write("bin/python.exe", build_pe(version=python_spec("3.12.13"))[0])
        self.target_reads.clear()
        with mock.patch("patchwait.pyvenv.find_cfg", side_effect=AssertionError("fallback used")):
            code, doc = self.version_of(exe)
            _, item = self.one("--path", exe)
        self.assertEqual(code, 0)
        self.assertNotIn("version_source", doc)
        self.assertNotIn("version_source", item)
        self.assertEqual(item["product_version"], "3.12.13")
        self.assertEqual(self.target_reads, [])

    def test_sidecar_is_only_used_for_python(self) -> None:
        exe = self.alias(TARGET.encode())
        self.assert_found(exe)
        self.target_reads.clear()
        code, doc = self.version_of(exe, "node")
        self.assertEqual(code, 3)
        self.assertEqual(doc["reason"], "unexpected_product")
        self.assertNotIn("__target__", str(doc["detail"]))
        self.assertEqual(self.target_reads, [])

    def test_venv_remains_first_and_cfg_blocks_alias_fallback(self) -> None:
        exe = self.alias(TARGET.encode())
        self.assert_found(exe)
        self.write("bin/pyvenv.cfg", b"version_info = 3.12.13\n")
        # A cfg applies to python.exe even when its own resource names manage.
        code, doc = self.version_of(exe)
        self.assertEqual((code, doc["reason"]), (3, "unexpected_product"))
        self.write("bin/python.exe", build_pe(version=None)[0])
        code, doc = self.version_of(exe)
        self.assertEqual((code, doc["version_source"]), (0, "pyvenv-cfg-version-info"))
        self.write("bin/pyvenv.cfg", b"version_info = 3.12\n")
        self.assertEqual(self.version_of(exe)[0], 3)  # no alias rescue for an unusable cfg

    def test_cfg_one_directory_up_blocks_alias_fallback(self) -> None:
        exe = self.alias(TARGET.encode())
        self.assert_found(exe)
        self.target_reads.clear()
        self.write("pyvenv.cfg", b"version_info = 3.12.13\n")
        code, doc = self.version_of(exe)
        _, scanned = self.one("--path", exe)
        self.assertEqual((code, doc["reason"]), (3, "unexpected_product"))
        self.assertNotIn("version_source", scanned)
        self.assertEqual(self.target_reads, [])

    def test_sidecar_of_exactly_4096_bytes_is_accepted(self) -> None:
        # Lexically valid, synthetic Windows path; no long path is created on disk.
        target = "C:\\" + ("segment\\" * 510) + "pythonabc.exe"
        self.assertEqual(len(target.encode("utf-8")), 4096)
        for index in range(1, 511):
            self.disk.add("C:\\" + "\\".join(["segment"] * index))
        self.disk.add(target, _FILE)
        exe = self.alias(target.encode("utf-8"))
        self.assert_found(exe)
        _, scanned = self.one("--path", exe)
        self.assertEqual(scanned["product_version"], "3.14.10")

    def test_invalid_sidecar_content(self) -> None:
        for data, detail in (
            (b"\xef\xbb\xbf" + TARGET.encode(), "BOM"),
            (TARGET.encode() + b"\r\n", "CR or LF"),
            (TARGET.encode() + b"\n", "CR or LF"),
            (TARGET.encode() + b"\r", "CR or LF"),
            (TARGET.encode() + b"\0", "NUL"),
            (b"", "empty"),
            (b" \t ", "absolute"),
            (b"Python\\python.exe", "absolute"),
            (b"C:python.exe", "absolute"),
            (b"x" * 4097, "larger than 4096 bytes"),
            (b"\xff", "UTF-8"),
        ):
            with self.subTest(data=data[:40]):
                self.assert_refused(self.alias(data), detail)
        self.assertEqual(self.target_reads, [])

    def test_target_uses_home_safety_checks(self) -> None:
        for target in (
            r"\\host\share\python.exe", "//host/share/python.exe",
            r"\Device\Mup\host\share\python.exe", r"\??\C:\Python\python.exe",
            r"\\?\C:\Python\python.exe", r"\\.\pipe\python.exe",
            r"C:\Synthetic\NUL.exe", r"C:\Synthetic\COM1.log", r"Z:\Python\python.exe",
            r"C:\Synthetic\bad.\python.exe", r"C:\Synthetic\python.exe:stream",
        ):
            with self.subTest(target=target):
                self.disk.calls.clear()
                self.assert_refused(self.alias(target.encode()), "not a local fixed-drive path")
                self.assertEqual(self.disk.looked_at(), [])
        self.assertEqual(self.target_reads, [])

    def test_target_link_to_network_is_not_opened(self) -> None:
        link = r"C:\Synthetic\link"
        self.disk.add(link, _JUNCTION, r"\\host\share")
        self.assert_refused(self.alias((link + r"\python.exe").encode()), "link target")
        self.assertEqual(self.target_reads, [])

    def test_target_missing(self) -> None:
        self.assert_refused(self.alias(b"C:\\Synthetic\\gone.exe"), "missing", "no_version_resource")
        self.assertEqual(self.target_reads, [])

    def test_target_unreadable(self) -> None:
        with self.forbid_target_lookups(), mock.patch("patchwait.pyvenv._read_home_exe", return_value=(
            Undetermined(Reason.FILE_UNREADABLE, "PermissionError"), False,
        )):
            self.assert_refused(self.alias(TARGET.encode()), "PermissionError", "file_unreadable")

    def test_manage_target_never_follows_another_sidecar(self) -> None:
        self.write("runtime/python.exe", build_pe(version=python_spec("3.14.10", "manage"))[0])
        exe = self.alias(TARGET.encode())
        with self.forbid_target_lookups(), mock.patch("patchwait.pyvenv.detect_runtime", wraps=detect_runtime) as detect:
            self.assert_refused(exe, "ProductName 'manage'", "unexpected_product")
        self.assertEqual(detect.call_count, 2)  # one own-file detection per command
        self.assertEqual(self.target_reads, [TARGET, TARGET])

    def test_target_without_pe_or_resource_has_no_text_fallback(self) -> None:
        for data, reason in ((b"not PE", "not_pe"), (build_pe(version=None)[0], "no_version_resource")):
            with self.subTest(reason=reason):
                self.write("runtime/python.exe", data)
                with self.forbid_target_lookups():
                    self.assert_refused(self.alias(TARGET.encode()), reason, reason)

    def test_target_fixed_info_disagreement_is_refused(self) -> None:
        spec = replace(python_spec("3.14.10"), fixed_product=(3, 12, 10, 0))
        self.write("runtime/python.exe", build_pe(version=spec)[0])
        self.assert_refused(self.alias(TARGET.encode()), "disagrees with fixed info", "version_mismatch")

    def test_target_file_change_is_refused(self) -> None:
        real_read = pyvenv.read_version_info_from

        def grow(stream: BinaryIO):
            with open(self.target_pe, "ab") as other:
                other.write(b"\0" * 4096)
            return real_read(stream)

        with mock.patch("patchwait.pyvenv.read_version_info_from", grow):
            self.assert_refused(self.alias(TARGET.encode()), "changed while it was read")

    def test_target_locality_change_is_refused(self) -> None:
        before = self.check(TARGET)
        after = replace(before, chain=((r"C:\Synthetic", r"\\host\share"),))
        with mock.patch("patchwait.pyvenv.local_path_check", side_effect=[before, after, before, after]):
            self.assert_refused(self.alias(TARGET.encode()), "changed while it was read")

    def test_sidecar_kind_and_attributes_are_checked_before_open(self) -> None:
        exe = self.alias(TARGET.encode())
        real_stat = os.lstat
        original = real_stat(exe + ".__target__")
        for mode, attr, detail in (
            (stat.S_IFDIR, 0, "not a regular file"),
            (stat.S_IFLNK, 0, "link or reparse point"),
            (stat.S_IFREG, stat.FILE_ATTRIBUTE_REPARSE_POINT, "link or reparse point"),
            (stat.S_IFREG, locality.FILE_ATTRIBUTE_OFFLINE, "offline or recalled"),
            (stat.S_IFREG, locality.FILE_ATTRIBUTE_RECALL_ON_OPEN, "offline or recalled"),
            (stat.S_IFREG, locality.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "offline or recalled"),
        ):
            with self.subTest(mode=mode, attr=attr):
                fake = os.stat_result((mode, original.st_ino, original.st_dev, 0, 0, 0, 0, 0, 0, 0),
                                      {"st_file_attributes": attr})

                def lstat(path: str):
                    return fake if os.fspath(path).endswith(".__target__") else real_stat(path)

                with mock.patch("patchwait.pyvenv.os.lstat", lstat), mock.patch(
                    "patchwait.pyvenv.open", side_effect=AssertionError("sidecar was opened"), create=True,
                ):
                    self.assert_refused(exe, detail)
        self.assertEqual(self.target_reads, [])

    def test_sidecar_changed_while_opening_is_refused(self) -> None:
        exe = self.alias(TARGET.encode())
        original = os.stat(exe + ".__target__")
        fake = os.stat_result((stat.S_IFREG, original.st_ino + 1, original.st_dev, 0, 0, 0, 0, 0, 0, 0))
        with mock.patch("patchwait.pyvenv.os.fstat", return_value=fake):
            self.assert_refused(exe, "changed while being opened")
        self.assertEqual(self.target_reads, [])

    @unittest.skipUnless(os.name == "nt", "Windows native file attributes")
    def test_sidecar_reparse_point_invisible_to_lstat_is_refused(self) -> None:
        exe = self.alias(TARGET.encode())
        sidecar = exe + ".__target__"
        disk = FakeDisk()
        disk.add(sidecar, _FILE)  # lstat reports a plain file, as for non-name-surrogate points.
        for attributes, detail in (
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, "link or reparse point"),
            (locality.FILE_ATTRIBUTE_OFFLINE, "offline or recalled"),
            (locality.FILE_ATTRIBUTE_RECALL_ON_OPEN, "offline or recalled"),
            (locality.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "offline or recalled"),
        ):
            with self.subTest(attributes=attributes):
                disk.extra_attributes[ntpath.normcase(sidecar)] = attributes
                with mock.patch("patchwait.pyvenv.windows_file_attributes", disk.attributes), mock.patch(
                    "patchwait.pyvenv.open", side_effect=AssertionError("sidecar was opened"), create=True,
                ):
                    self.assert_refused(exe, detail, "no_version_resource")
        self.assertEqual(self.target_reads, [])

    @unittest.skipUnless(os.name == "nt", "Windows native file attributes")
    def test_sidecar_native_attributes_unreadable_is_refused(self) -> None:
        exe = self.alias(TARGET.encode())
        with mock.patch("patchwait.pyvenv.windows_file_attributes", side_effect=PermissionError), mock.patch(
            "patchwait.pyvenv.open", side_effect=AssertionError("sidecar was opened"), create=True,
        ):
            self.assert_refused(exe, "PermissionError", "no_version_resource")
        self.assertEqual(self.target_reads, [])

    def test_sidecar_changed_while_reading_is_refused(self) -> None:
        exe = self.alias(TARGET.encode())
        sidecar = exe + ".__target__"
        real_open = open

        @contextlib.contextmanager
        def changing_open(path: str, mode: str):
            with real_open(path, mode) as stream:
                def read(size: int) -> bytes:
                    data = stream.read(size)
                    with real_open(sidecar, "ab") as other:
                        other.write(b"x")
                    return data

                yield mock.Mock(wraps=stream, read=read)

        with mock.patch("patchwait.pyvenv.open", changing_open, create=True):
            self.assert_refused(exe, "changed while it was read", "no_version_resource")
        self.assertEqual(self.target_reads, [])

    def test_sidecar_missing_preserves_output_then_exact_filename_enables_fallback(self) -> None:
        for own in (python_spec("3.14.1", "manage"), None):
            exe = self.write("bin/python.exe", build_pe(version=own)[0])
            self.write("bin/python3.exe.__target__", TARGET.encode())
            expected = check_to_json(detect_runtime(exe, RuntimeKind.PYTHON), component_to_json)
            self.assertEqual(self.version_of(exe), (3, expected))
            _, item = self.one("--path", exe)
            self.assertNotIn("version_source", item)
            self.write("bin/" + SIDECAR, TARGET.encode())
            self.assert_found(exe)
            os.unlink(exe + ".__target__")

    def test_own_undetermined_version_can_use_target(self) -> None:
        exe = self.alias(TARGET.encode())
        bad = replace(python_spec("3.14.1"), fixed_product=(3, 12, 0, 0))
        self.write("bin/python.exe", build_pe(version=bad)[0])
        self.assert_found(exe)

    def test_scan_output_can_be_rendered_by_ledger(self) -> None:
        exe = self.alias(TARGET.encode())
        _, doc = self.run_scan("--path", exe, "--kind", "python", "--min", "python=3.14.11")
        from patchwait.ledger import LedgerInputError, render_document

        text = render_document(doc, "synthetic-scan").markdown
        self.assertIn(EVIDENCE, text)
        self.assertIn(TARGET, text)
        (item,) = self.items(doc)
        source = item["version_source"]
        assert isinstance(source, dict)
        for bad_source in (
            {**source, "target": None}, {**source, "target_file": ""},
            {**source, "evidence": None}, {**source, "evidence": "pyvenv-home-pe-version-resource"},
            {**source, "extra": 1}, {k: v for k, v in source.items() if k != "target"},
        ):
            with self.subTest(source=bad_source):
                bad = deepcopy(doc)
                self.items(bad)[0]["version_source"] = bad_source
                with self.assertRaises(LedgerInputError):
                    render_document(bad, "synthetic-scan")
        bad = deepcopy(doc)
        self.items(bad)[0]["version_source"] = {"evidence": EVIDENCE}
        with self.assertRaises(LedgerInputError) as raised:
            render_document(bad, "synthetic-scan")
        self.assertIn("evidence, home, pyvenv_cfg, version_info", str(raised.exception))
        self.assertIn("evidence, target, target_file", str(raised.exception))
        self.write("runtime/python.exe", build_pe(version=python_spec("3.14.10", "manage"))[0])
        for data in (TARGET.encode(), b"", b" \t "):
            with self.subTest(data=data):
                self.write("bin/" + SIDECAR, data)
                _, refused = self.run_scan("--path", exe, "--kind", "python", "--min", "python=3.14.11")
                self.assertIn("no version taken", render_document(refused, "synthetic-scan").markdown)


class InstallManagerRecordFromTests(FromBase):
    def test_record_from_accepts_alias_version_source(self) -> None:
        alias = r"C:\Synthetic\Python\bin\python.exe"
        for verdict, version, evidence in (
            ({"result": "found", "value": "3.14.10"}, "3.14.10", EVIDENCE),
            ({"result": "undetermined", "reason": "no_version_resource", "detail": "__target__ missing"}, None, None),
        ):
            with self.subTest(verdict=verdict):
                self.write_doc(document(item("alias-python", "2026-10-01", result_link=scan_link(alias, "python"))))
                row = scan_row(alias, verdict, version=version)
                row["checked_against"] = {"minimum": "3.14.11", "source": None}
                row["version_source"] = {"evidence": evidence, "target_file": alias + ".__target__", "target": TARGET}
                scan = scan_result(row, kind="python")
                scan["baselines"] = {"python": {"minimums": ["3.14.11"], "source": None}}
                self.write_result(scan)
                code, payload = self.record_from()
                self.assertEqual(code, 0)
                self.assertEqual(payload["counts"], {"updated": 1, "changed": 1, "unchanged": 0})
                self.assertEqual(self.items_by_id()["alias-python"]["last_result"], verdict)
                self.assertEqual(self.items_by_id()["alias-python"]["last_checked"], "2026-10-25")
