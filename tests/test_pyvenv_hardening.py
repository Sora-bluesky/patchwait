"""pyvenv.cfg hardening: remote homes, link cfgs, names, crafted numbers, duplicate keys, malformed homes.

Every home that could be remote is read through a stub, so no test can open a UNC
or device path even when the code under test regresses.
"""

from __future__ import annotations

import ntpath
import os
import stat
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import IO, BinaryIO
from unittest import mock

from patchwait import locality
from patchwait.pyvenv import DuplicateKeyError, MalformedCfgError, parse_cfg
from tests.pe_builder import PYTHON_LIKE, VersionSpec, build_pe
from tests.test_ledger import LedgerCase
from tests.test_locality import FakeDisk, _FILE
from tests.test_pyvenv import MIN_PY, VenvCase

HUGE = "1" * 5000  # longer than int()'s 4300-digit limit
REAL_OPEN = open


def crafted_spec(product_version: str) -> VersionSpec:
    strings = dict(PYTHON_LIKE.strings, ProductName="Python", FileVersion=product_version, ProductVersion=product_version)
    return replace(PYTHON_LIKE, strings=strings, fixed_file=(3, 12, 0, 0), fixed_product=(3, 12, 0, 0))


def home_opener(on_home: Callable[[str], IO[bytes]]) -> Callable[..., IO[bytes]]:
    """An ``open`` for pyvenv that hands every path but ``pyvenv.cfg`` to ``on_home``."""

    def fake(path: str, mode: str = "r", *args: object, **kwargs: object) -> IO[bytes]:
        if os.path.basename(path) == "pyvenv.cfg":
            return REAL_OPEN(path, mode, *args, **kwargs)  # pyright: ignore[reportCallIssue, reportArgumentType, reportUnknownVariableType]
        return on_home(path)

    return fake


@contextmanager
def stub_home_reads() -> Iterator[list[str]]:
    """Replace pyvenv's opener of ``<home>\\python.exe``; records paths and opens nothing."""
    opened: list[str] = []

    def refuse(path: str) -> IO[bytes]:
        opened.append(path)
        raise PermissionError("stub: not opened")

    with mock.patch("patchwait.pyvenv.open", home_opener(refuse), create=True):
        yield opened


class RemoteHomeTests(VenvCase):
    def test_remote_home_is_refused_without_opening_it(self) -> None:
        homes = ("\\\\host\\share\\py", "//host/share/py", "\\\\?\\C:\\py", "\\\\?\\UNC\\host\\share\\py", "\\\\.\\pipe\\py")
        for index, home in enumerate(homes):
            with self.subTest(home=home):
                exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n", rel=f"v{index}")
                with stub_home_reads() as opened:
                    _, item = self.one("--path", exe)
                self.assertEqual(opened, [])
                verdict = self.verdict(item)
                self.assertEqual(verdict["reason"], "no_version_resource")  # no fallback to version_info
                self.assertIn("pyvenv.cfg home is not a local fixed-drive path", str(verdict["detail"]))
                source = item["version_source"]
                assert isinstance(source, dict)
                self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]

    def test_local_link_to_unc_home_is_refused(self) -> None:
        link = os.path.join(self.dir, "uv", "cpython-3.12")
        os.makedirs(os.path.dirname(link), exist_ok=True)
        try:
            os.symlink("\\\\host\\share\\cpython", link, target_is_directory=True)  # does not touch the target
        except OSError as error:
            self.skipTest(f"cannot create a symlink here: {error}")
        try:
            exe = self.venv(f"home = {link}\nversion_info = 3.12.13\n")
            with stub_home_reads() as opened:
                _, item = self.one("--path", exe)
            self.assertEqual(opened, [])
            self.assertIn("link target", str(self.verdict(item)["detail"]))
        finally:
            os.rmdir(link)  # remove the link itself before cleanup walks the tree

    def test_local_junction_home_is_used(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows junctions")
        import _winapi

        real = self.home("3.12.13")
        junction = os.path.join(self.dir, "uv", "cpython-3.12")
        _winapi.CreateJunction(real, junction)
        exe = self.venv(f"home = {junction}\nversion_info = 3.12\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})


class CfgFileTests(VenvCase):
    def assert_cfg_refused_without_open(self, exe: str, detail: str) -> None:
        with mock.patch("patchwait.pyvenv.open", side_effect=PermissionError("cfg was opened"), create=True) as opened:
            code, item = self.one("--path", exe)
        self.assertEqual(opened.call_count, 0, "pyvenv.cfg must not be opened")
        self.assertEqual(code, 0)
        verdict = self.verdict(item)
        self.assertEqual(verdict["result"], "undetermined")
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn(detail, str(verdict["detail"]))
        self.assertIsNone(item["product_version"])
        self.assertEqual(item["version_source"], {
            "evidence": None, "pyvenv_cfg": os.path.join(self.dir, "venv", "pyvenv.cfg"),
            "home": None, "version_info": None,
        })

    @unittest.skipUnless(os.name == "nt", "Windows native file attributes")
    def test_cfg_reparse_point_invisible_to_lstat_is_refused(self) -> None:
        exe = self.venv("version_info = 3.12.13\n")
        cfg = os.path.join(self.dir, "venv", "pyvenv.cfg")
        disk = FakeDisk()
        disk.add(cfg, _FILE)  # lstat reports a plain file, as for non-name-surrogate points.
        self.assertTrue(stat.S_ISREG(os.lstat(cfg).st_mode))
        for attributes, detail in (
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, "pyvenv.cfg is a link or reparse point; not read"),
            (locality.FILE_ATTRIBUTE_OFFLINE, "pyvenv.cfg is offline or recalled on access; not read"),
            (locality.FILE_ATTRIBUTE_RECALL_ON_OPEN, "pyvenv.cfg is offline or recalled on access; not read"),
            (locality.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "pyvenv.cfg is offline or recalled on access; not read"),
        ):
            with self.subTest(attributes=attributes):
                disk.extra_attributes[ntpath.normcase(cfg)] = attributes
                with mock.patch("patchwait.pyvenv.windows_file_attributes", disk.attributes):
                    self.assert_cfg_refused_without_open(exe, detail)

    @unittest.skipUnless(os.name == "nt", "Windows native file attributes")
    def test_cfg_native_attributes_unreadable_is_refused(self) -> None:
        exe = self.venv("version_info = 3.12.13\n")
        for error in (OSError, PermissionError, FileNotFoundError):
            with self.subTest(error=error.__name__):
                with mock.patch("patchwait.pyvenv.windows_file_attributes", side_effect=error):
                    self.assert_cfg_refused_without_open(exe, f"pyvenv.cfg is unreadable: {error.__name__}")

    @unittest.skipUnless(os.name == "nt", "Windows native file attributes")
    def test_cfg_lstat_recall_attributes_are_checked_before_open(self) -> None:
        exe = self.venv("version_info = 3.12.13\n")
        cfg = os.path.join(self.dir, "venv", "pyvenv.cfg")
        real_stat = os.lstat
        original = real_stat(cfg)
        for attributes in (
            locality.FILE_ATTRIBUTE_OFFLINE,
            locality.FILE_ATTRIBUTE_RECALL_ON_OPEN,
            locality.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ):
            with self.subTest(attributes=attributes):
                fake = os.stat_result(
                    (stat.S_IFREG, original.st_ino, original.st_dev, 0, 0, 0, 0, 0, 0, 0),
                    {"st_file_attributes": attributes},
                )

                def lstat(path: str) -> os.stat_result:
                    return fake if os.fspath(path) == cfg else real_stat(path)

                with mock.patch("patchwait.pyvenv.os.lstat", lstat), mock.patch(
                    "patchwait.pyvenv.windows_file_attributes", return_value=stat.FILE_ATTRIBUTE_ARCHIVE,
                ):
                    self.assert_cfg_refused_without_open(exe, "pyvenv.cfg is offline or recalled on access; not read")

    def test_cfg_that_is_a_link_is_not_read(self) -> None:
        exe = self.venv(None)
        real = self.write("elsewhere/pyvenv.cfg", b"version_info = 3.12.13\n")
        try:
            os.symlink(real, os.path.join(self.dir, "venv", "pyvenv.cfg"))
        except OSError as error:
            self.skipTest(f"cannot create a symlink here: {error}")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn("pyvenv.cfg is a link or reparse point; not read", str(verdict["detail"]))

    def test_cfg_file_problem(self) -> None:
        from patchwait.pyvenv import cfg_file_problem

        self.assertIsNone(cfg_file_problem(stat.S_IFREG, 0))
        self.assertIsNotNone(cfg_file_problem(stat.S_IFLNK, 0))
        self.assertIsNotNone(cfg_file_problem(stat.S_IFREG, stat.FILE_ATTRIBUTE_REPARSE_POINT))
        self.assertIsNotNone(cfg_file_problem(stat.S_IFDIR, 0))

    def test_only_python_exe_uses_pyvenv_cfg(self) -> None:
        exe = self.write("venv/Scripts/not-python.exe", build_pe(version=None)[0])
        self.write("venv/pyvenv.cfg", b"version_info = 3.12.13\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item)["reason"], "no_version_resource")
        self.assertNotIn("version_source", item)
        upper = self.write("other/Scripts/PYTHON.EXE", build_pe(version=None)[0])
        self.write("other/pyvenv.cfg", b"version_info = 3.12.13\n")
        _, item = self.one("--path", upper)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})


class CraftedNumberTests(VenvCase):
    def test_huge_version_info_without_home(self) -> None:
        exe = self.venv(f"version_info = 3.12.{HUGE}\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn("is not N.N.N", str(verdict["detail"]))

    def test_huge_version_info_with_home(self) -> None:
        exe = self.venv(f"home = {self.home('3.12.13')}\nversion_info = {HUGE}.12\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "malformed_version_resource")
        self.assertIn("is not N.N or N.N.N; not compared with home python.exe '3.12.13'", str(verdict["detail"]))

    def test_huge_home_product_version(self) -> None:
        home = os.path.dirname(self.write("uv/huge/python.exe", build_pe(version=crafted_spec(f"3.12.{HUGE}"))[0]))
        exe = self.venv(f"home = {home}\nversion_info = 3.12\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "malformed_version_resource")
        self.assertTrue(str(verdict["detail"]).startswith("home python.exe: ProductVersion is not N.N.N"), verdict)

    def test_huge_product_version_on_a_plain_target(self) -> None:
        exe = self.write("plain/python.exe", build_pe(version=crafted_spec(f"3.12.{HUGE}"))[0])
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item)["reason"], "malformed_version_resource")

    def test_parse_version_caps_digit_runs(self) -> None:
        from patchwait.scan import parse_version

        self.assertIsNone(parse_version(f"3.12.{HUGE}"))
        self.assertIsNone(parse_version("3.12.1234567890"))
        self.assertEqual(parse_version("3.12.123456789"), (3, 12, 123456789))

    def test_root_walk_survives_crafted_venvs(self) -> None:
        good = self.venv(f"home = {self.home('3.12.13')}\nversion_info = 3.12\n", rel="root/good/.venv")
        huge_home = os.path.dirname(self.write("uv/huge/python.exe", build_pe(version=crafted_spec(f"3.12.{HUGE}"))[0]))
        self.venv(f"version_info = 3.12.{HUGE}\n", rel="root/a/.venv")
        self.venv(f"home = {huge_home}\nversion_info = 3.12\n", rel="root/b/.venv")
        self.venv(f"home = {self.home('3.14.7')}\nversion_info = 3.{HUGE}\n", rel="root/c/.venv")
        self.write("root/d/python.exe", build_pe(version=crafted_spec(f"3.12.{HUGE}"))[0])
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--kind", "python", "--min", MIN_PY)
        self.assertEqual(code, 10)
        items = self.items(doc)
        self.assertEqual(len(items), 5)
        by_path = {str(item["path"]): item for item in items}
        self.assertEqual(self.verdict(by_path[good]), {"result": "found", "value": "3.12.13"})
        self.assertEqual(sum(1 for item in items if self.verdict(item)["result"] == "undetermined"), 4)


class CfgLineTests(VenvCase):
    def test_duplicate_keys_are_undetermined(self) -> None:
        home = self.home("3.12.13")
        home_detail = "pyvenv.cfg mentions home more than once or in another form"
        cases = (
            (home_detail, f"home = {home}\nhome = {home}\nversion_info = 3.12\n"),
            ("pyvenv.cfg gives the key 'version_info' more than once", f"home = {home}\nversion_info = 3.12\nversion_info = 3.12.13\n"),
            (home_detail, f"HOME = {home}\r\nhome = {home}\r\n"),
        )
        for index, (expected, text) in enumerate(cases):
            with self.subTest(index=index):
                exe = self.venv(text, rel=f"dup{index}")
                code, item = self.one("--path", exe)
                self.assertEqual(code, 0)
                verdict = self.verdict(item)
                self.assertEqual(verdict["reason"], "duplicate_key")
                self.assertIn(expected, str(verdict["detail"]))
                cfg = os.path.join(self.dir, f"dup{index}", "pyvenv.cfg")
                self.assertEqual(item["version_source"], {"evidence": None, "pyvenv_cfg": cfg, "home": None, "version_info": None})

    def test_only_newline_ends_a_line(self) -> None:
        for separator in ("\u2028", "\u0085", "\v", "\f", "\r"):
            with self.subTest(separator=repr(separator)):
                self.assertEqual(
                    parse_cfg(f"home = C:\\py{separator}version_info = 3.12.13\n"),
                    {"home": f"C:\\py{separator}version_info = 3.12.13"},
                )
        exe = self.venv("version_info = 3.12\u2028version_info = 3.12.13\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item)["reason"], "no_version_resource")


class MalformedHomeTests(VenvCase):
    def test_malformed_home_resource_takes_no_version(self) -> None:
        cases = (
            ("malformed_version_resource", crafted_spec("abc")),
            ("version_mismatch", crafted_spec("3.14.7")),  # fixed info says 3.12
        )
        for reason, spec in cases:
            with self.subTest(reason=reason):
                home = os.path.dirname(self.write(f"uv/{reason}/python.exe", build_pe(version=spec)[0]))
                exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n", rel=f"v-{reason}")
                _, item = self.one("--path", exe)
                verdict = self.verdict(item)
                self.assertEqual(verdict["reason"], reason)
                self.assertTrue(str(verdict["detail"]).startswith("home python.exe: "), verdict)
                source = item["version_source"]
                assert isinstance(source, dict)
                self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]


class HardeningLedgerTests(LedgerCase):
    def test_null_evidence_and_duplicate_key_render(self) -> None:
        home_exe = self.write("uv/bad/python.exe", build_pe(version=crafted_spec("abc"))[0])
        self.write("Apps/a/Scripts/python.exe", build_pe(version=None)[0])
        self.write("Apps/a/pyvenv.cfg", f"home = {os.path.dirname(home_exe)}\nversion_info = 3.12\n".encode())
        self.write("Apps/b/Scripts/python.exe", build_pe(version=None)[0])
        self.write("Apps/b/pyvenv.cfg", b"version_info = 3.12\nVersion_Info = 3.12.13\n")
        out = os.path.join(self.dir, "scan.json")
        apps = os.path.join(self.dir, "Apps")
        code, _, err = self.run_cli("scan", "--kind", "python", "--min", MIN_PY, "--root", apps, "--out", out)
        self.assertEqual(code, 0, err)
        _, text = self.ledger(out)
        exe_a = os.path.join(self.dir, "Apps", "a", "Scripts", "python.exe")
        exe_b = os.path.join(self.dir, "Apps", "b", "Scripts", "python.exe")
        line_a = next(line for line in text.splitlines() if exe_a in line)
        self.assertIn("no version taken", line_a)
        self.assertNotIn("version from", line_a)
        self.assertIn("malformed_version_resource: `home python.exe: ", line_a)
        line_b = next(line for line in text.splitlines() if exe_b in line)
        self.assertIn("duplicate_key: ", line_b)


class CorruptHomeResourceTests(VenvCase):
    def test_broken_fixed_info_is_propagated_without_fallback(self) -> None:
        spec = replace(crafted_spec("3.12.13"), signature=0xDEADBEEF)
        home = os.path.dirname(self.write("uv/corrupt/python.exe", build_pe(version=spec)[0]))
        exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n")
        _, item = self.one("--path", exe)
        self.assertEqual(
            self.verdict(item),
            {"result": "undetermined", "reason": "malformed_version_resource", "detail": "home python.exe: VS_FIXEDFILEINFO signature mismatch"},
        )
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]

    def test_home_that_is_not_a_pe_still_falls_back(self) -> None:
        home = os.path.dirname(self.write("uv/text/python.exe", b"not a PE"))
        exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})


class FullVersionInfoMatchTests(VenvCase):
    def test_version_info_must_be_exactly_n_n_or_n_n_n(self) -> None:
        home = self.home("3.12.13")
        for index, text in enumerate(("3.12.not-a-version", f"3.12.{HUGE}", "3.12.", "3.12.13.0", "3.12.13\u0663")):
            with self.subTest(index=index):
                exe = self.venv(f"home = {home}\nversion_info = {text}\n", rel=f"v{index}")
                _, item = self.one("--path", exe)
                verdict = self.verdict(item)
                self.assertEqual(verdict["reason"], "malformed_version_resource", verdict)
                self.assertIn("is not N.N or N.N.N; not compared with home python.exe '3.12.13'", str(verdict["detail"]))

    def test_home_version_with_a_suffix_is_not_compared(self) -> None:
        home = os.path.dirname(self.write("uv/rc/python.exe", build_pe(version=crafted_spec("3.12.0rc1"))[0]))
        exe = self.venv(f"home = {home}\nversion_info = 3.12\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "malformed_version_resource")
        self.assertIn("home python.exe version '3.12.0rc1' is not N.N.N", str(verdict["detail"]))


class HomeLineTests(VenvCase):
    def test_home_mentioned_twice_or_in_another_form(self) -> None:
        for text in (
            "# home = C:/elsewhere\nhome = C:/py\n",
            "; HOME=C:/elsewhere\nhome = C:/py\n",
            "home = C:/py\n  #home\n",
            "HOME = C:/py\n",
            "Home = C:/py\n",
            "home\n",
            "# home = C:/py\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(DuplicateKeyError) as caught:
                    parse_cfg(text)
                self.assertEqual(caught.exception.detail, "pyvenv.cfg mentions home more than once or in another form")

    def test_one_home_line_is_accepted(self) -> None:
        self.assertEqual(
            parse_cfg(" \thome\t= C:/Users/home/py \t\nprompt = home\nhomepage = x\n"),
            {"home": "C:/Users/home/py", "prompt": "home", "homepage": "x"},
        )

    def test_non_ascii_whitespace_at_an_edge(self) -> None:
        for text in ("home = C:/py\u00a0\n", "version_info\u3000= 3.12.13\n", "\u2028home = C:/py\n", "version_info = \x0b3.12.13\n", "x = \x85\n"):
            with self.subTest(text=repr(text)):
                with self.assertRaises(MalformedCfgError):
                    parse_cfg(text)
        self.assertEqual(parse_cfg("prompt = a\u00a0b\n"), {"prompt": "a\u00a0b"})

    def test_scan_reports_the_cfg_problems(self) -> None:
        home = self.home("3.12.13")
        cases = (
            ("duplicate_key", f"# home = {self.home('3.14.7')}\nhome = {home}\nversion_info = 3.12\n"),
            ("malformed_version_resource", f"home = {home}\nversion_info = 3.12.13\u00a0\n"),
        )
        for index, (reason, text) in enumerate(cases):
            with self.subTest(reason=reason):
                exe = self.venv(text, rel=f"c{index}")
                _, item = self.one("--path", exe)
                verdict = self.verdict(item)
                self.assertEqual(verdict["reason"], reason, verdict)
                self.assertEqual(item["version_source"], {"evidence": None, "pyvenv_cfg": os.path.join(self.dir, f"c{index}", "pyvenv.cfg"), "home": None, "version_info": None})


@unittest.skipUnless(os.name == "nt", "Windows junctions")
class HomeSwapTests(VenvCase):
    def swap_during_read(self, swap: Callable[[], None], *, after_open: bool = False) -> dict[str, object]:
        from patchwait import pyvenv

        real_read = pyvenv.read_version_info_from

        def open_with_swap(path: str) -> IO[bytes]:
            if not after_open:
                swap()  # deterministic: between the locality check and the open
            return REAL_OPEN(path, "rb")

        def read_after_swap(stream: BinaryIO) -> object:
            swap()  # between the first fstat of the open handle and the read
            return real_read(stream)

        exe = self.venv(f"home = {self.junction}\nversion_info = 3.12\n")
        with mock.patch("patchwait.pyvenv.open", home_opener(open_with_swap), create=True):
            if after_open:
                with mock.patch("patchwait.pyvenv.read_version_info_from", read_after_swap):
                    _, item = self.one("--path", exe)
            else:
                _, item = self.one("--path", exe)
        return item

    def setUp(self) -> None:
        super().setUp()
        import _winapi

        self.first = self.home("3.12.13")
        self.second = self.home("3.12.20")
        self.junction = os.path.join(self.dir, "uv", "cpython-3.12")
        _winapi.CreateJunction(self.first, self.junction)

    def assert_changed(self, item: dict[str, object]) -> None:
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource", verdict)
        self.assertIn("home changed while it was read", str(verdict["detail"]))
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]

    def test_junction_swapped_between_check_and_read(self) -> None:
        import _winapi

        def swap() -> None:
            os.rmdir(self.junction)
            _winapi.CreateJunction(self.second, self.junction)

        self.assert_changed(self.swap_during_read(swap))

    def test_file_rewritten_while_it_is_read(self) -> None:
        def grow() -> None:
            with REAL_OPEN(os.path.join(self.first, "python.exe"), "ab") as other:
                other.write(b"\0" * 4096)

        self.assert_changed(self.swap_during_read(grow, after_open=True))

    def test_home_is_opened_once(self) -> None:
        opened: list[str] = []

        def record(path: str) -> IO[bytes]:
            opened.append(path)
            return REAL_OPEN(path, "rb")

        exe = self.venv(f"home = {self.junction}\nversion_info = 3.12\n")
        with mock.patch("patchwait.pyvenv.open", home_opener(record), create=True):
            _, item = self.one("--path", exe)
        self.assertEqual(opened, [os.path.join(self.junction, "python.exe")])
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})

    def test_no_swap_is_found(self) -> None:
        self.assertEqual(self.verdict(self.swap_during_read(lambda: None)), {"result": "found", "value": "3.12.13"})


class ReservedNameHomeTests(VenvCase):
    def test_reserved_device_name_in_home_is_refused_without_opening_it(self) -> None:
        from patchwait import locality

        touched: list[str] = []

        def no_disk(path: str) -> os.stat_result:
            touched.append(path)
            raise PermissionError("stub: disk not touched")

        def stub_check(path: str) -> locality.Locality:
            return locality.locality_check(
                path,
                drive_type=lambda _root: locality.DRIVE_FIXED,
                lstat=no_disk,
                readlink=lambda link: str(no_disk(link)),
                get_attributes=lambda path: int(no_disk(path).st_mode),
            )

        for index, home in enumerate((r"C:\x\NUL\py", r"C:\x\nul.txt\py", r"C:\x\Com1 .log\py")):
            with self.subTest(home=home):
                touched.clear()
                exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n", rel=f"r{index}")
                with stub_home_reads() as opened, mock.patch("patchwait.pyvenv.local_path_check", stub_check):
                    _, item = self.one("--path", exe)
                self.assertEqual(opened, [])
                self.assertEqual(touched, [])
                verdict = self.verdict(item)
                self.assertEqual(verdict["result"], "undetermined")
                self.assertEqual(verdict["reason"], "no_version_resource")  # version_info is not used
                detail = str(verdict["detail"])
                self.assertIn("pyvenv.cfg home is not a local fixed-drive path", detail)
                self.assertIn("reserved device name", detail)
                source = item["version_source"]
                assert isinstance(source, dict)
                self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]
