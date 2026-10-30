from __future__ import annotations

import contextlib
import io
import json
import os
from dataclasses import replace
from functools import partial
from typing import BinaryIO
from unittest import mock

from patchwait import locality, pyvenv
from patchwait.cli import main
from patchwait.model import Component, Found, NotFound, RuntimeKind, Undetermined, check_to_json, component_to_json
from patchwait.pe_version import detect_runtime
from tests.pe_builder import NODE_LIKE, build_pe
from tests.test_locality import DRIVE_REMOTE, FakeDisk, _JUNCTION
from tests.test_pyvenv import VenvCase, python_spec
from tests.test_pyvenv_hardening import stub_home_reads


class VenvVersionOfTests(VenvCase):
    def version_of(self, exe: str, kind: str = "python") -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["version-of", exe, "--kind", kind])
        self.assertEqual(err.getvalue(), "")
        return code, out.getvalue()

    def assert_refused(self, exe: str, reason: str, detail: str) -> None:
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["result"], "undetermined")
        self.assertEqual(verdict["reason"], reason)
        self.assertIn(detail, str(verdict["detail"]))
        code, out = self.version_of(exe)
        self.assertEqual(code, 3)
        self.assertEqual(out, json.dumps(verdict, ensure_ascii=False) + "\n")

    def test_both_commands_use_shared_detection(self) -> None:
        exe = self.venv(None)
        evidence = "pyvenv-cfg-version-info"
        source = pyvenv.VersionSource(evidence, "pyvenv.cfg", None, "3.12.13")
        result = Found(Component(RuntimeKind.PYTHON, exe, Found("3.12.13"), evidence))
        for command in ("scan", "version-of"):
            with self.subTest(command=command):
                with mock.patch(
                    "patchwait.pyvenv.detect_runtime_with_venv", return_value=(result, source)
                ) as shared:
                    if command == "scan":
                        _, item = self.one("--path", exe)
                        self.assertEqual(item["version_source"], source.to_json())
                    else:
                        code, out = self.version_of(exe)
                        self.assertEqual(code, 0)
                        self.assertEqual(json.loads(out)["version_source"], evidence)
                    shared.assert_called_once_with(exe, RuntimeKind.PYTHON)

    def test_home_version_resource_gives_version_and_source(self) -> None:
        exe = self.venv(f"home = {self.home('3.12.13')}\nversion_info = 3.12\n")
        code, out = self.version_of(exe)
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(out),
            {
                "result": "found",
                "value": {
                    "kind": "python", "location": exe,
                    "version": {"result": "found", "value": "3.12.13"},
                    "evidence": "pyvenv-home-pe-version-resource",
                },
                "version_source": "pyvenv-home-pe-version-resource",
            },
        )

    def test_version_info_only_gives_version_and_source(self) -> None:
        exe = self.venv("version_info = 3.14.6\n")
        code, out = self.version_of(exe)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["result"], "found")
        self.assertEqual(payload["value"]["version"], {"result": "found", "value": "3.14.6"})
        self.assertEqual(payload["value"]["evidence"], "pyvenv-cfg-version-info")
        self.assertEqual(payload["version_source"], "pyvenv-cfg-version-info")

    def test_major_minor_mismatch_is_version_mismatch(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.13.2\n")
        code, out = self.version_of(exe)
        payload = json.loads(out)
        self.assertEqual(code, 3)
        self.assertEqual(payload["result"], "undetermined")
        self.assertEqual(payload["reason"], "version_mismatch")
        self.assertIn("'3.13.2'", str(payload["detail"]))
        self.assertNotIn("version_source", payload)

    def test_malformed_cfg_is_malformed_version_resource(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.12.13\u00a0\n")
        code, out = self.version_of(exe)
        payload = json.loads(out)
        self.assertEqual(code, 3)
        self.assertEqual(payload["result"], "undetermined")
        self.assertEqual(payload["reason"], "malformed_version_resource")
        self.assertIn("starts or ends with non-ASCII whitespace", str(payload["detail"]))
        self.assertNotIn("version_source", payload)

    def test_without_fallback_output_and_exit_code_are_unchanged(self) -> None:
        plain = self.write("plain/python.exe", build_pe(version=python_spec("3.12.13"))[0])
        self.write("plain/pyvenv.cfg", b"version_info = 3.14.6\n")
        node = self.write("node/node.exe", build_pe(version=NODE_LIKE)[0])
        self.write("node/pyvenv.cfg", b"version_info = 3.14.6\n")
        mismatch = replace(python_spec("3.12.13"), fixed_product=(3, 14, 0, 0))
        cases = (
            (plain, RuntimeKind.PYTHON),
            (node, RuntimeKind.NODE),
            (self.venv(None), RuntimeKind.PYTHON),
            (self.write("other/not-python.exe", build_pe(version=None)[0]), RuntimeKind.PYTHON),
            (self.write("broken/python.exe", b"not a PE"), RuntimeKind.PYTHON),
            (self.write("mismatch/python.exe", build_pe(version=mismatch)[0]), RuntimeKind.PYTHON),
            (os.path.join(self.dir, "missing.exe"), RuntimeKind.PYTHON),
            (plain, RuntimeKind.NODE),
        )
        with mock.patch("patchwait.pyvenv.venv_runtime", wraps=pyvenv.venv_runtime) as fallback:
            for exe, kind in cases:
                with self.subTest(exe=exe, kind=kind):
                    result = detect_runtime(exe, kind)
                    code = 0
                    if isinstance(result, NotFound):
                        code = 1
                    elif isinstance(result, Undetermined) or isinstance(result.value.version, Undetermined):
                        code = 3
                    expected = json.dumps(check_to_json(result, component_to_json), ensure_ascii=False) + "\n"
                    self.assertEqual(self.version_of(exe, kind.value), (code, expected))
            self.assertEqual(fallback.call_count, 2)  # no cfg, or not named python.exe

    def test_internal_error_exits_2_without_stdout(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("patchwait.pyvenv.detect_runtime", side_effect=RuntimeError("boom")):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["version-of", "python.exe", "--kind", "python"])
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertEqual(err.getvalue(), "patchwait: internal error: RuntimeError\n")

    def test_node_kind_does_not_use_python_exe_cfg(self) -> None:
        exe = self.venv("version_info = 3.12.13\n")
        for command in ("scan", "version-of"):
            with self.subTest(command=command):
                with mock.patch("patchwait.pyvenv.venv_runtime", wraps=pyvenv.venv_runtime) as fallback:
                    if command == "scan":
                        code, doc = self.run_scan("--path", exe, "--kind", "node", "--min", "node=24.22.1")
                        (item,) = self.items(doc)
                        verdict = self.verdict(item)
                        self.assertEqual(code, 0)
                        self.assertIsNone(item["product_version"])
                        self.assertNotIn("version_source", item)
                    else:
                        code, out = self.version_of(exe, "node")
                        verdict = json.loads(out)
                        self.assertEqual(code, 3)
                        self.assertNotIn("value", verdict)
                        self.assertNotIn("version_source", verdict)
                    self.assertEqual(verdict["result"], "undetermined")
                    self.assertEqual(verdict["reason"], "no_version_resource")
                    fallback.assert_not_called()

    def test_non_absolute_homes_take_no_version(self) -> None:
        homes = (
            r"\Device\Mup\host\share\py", r"\??\UNC\host\share\py", r"\\?\UNC\host\share\py",
            r"\\.\C:\py", r"\py", "/py", r"C:py", "py", "C:\\py\0", "",
        )
        for index, home in enumerate(homes):
            exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n", rel=f"v{index}")
            for command in ("scan", "version-of"):
                with self.subTest(home=home, command=command):
                    with stub_home_reads() as opened:
                        if command == "scan":
                            _, item = self.one("--path", exe)
                            verdict = self.verdict(item)
                            self.assertIsNone(item["product_version"])
                            source = item["version_source"]
                            assert isinstance(source, dict)
                            self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]
                        else:
                            code, out = self.version_of(exe)
                            verdict = json.loads(out)
                            self.assertEqual(code, 3)
                            self.assertNotIn("value", verdict)
                            self.assertNotIn("version_source", verdict)
                        self.assertEqual(verdict["result"], "undetermined")
                        self.assertEqual(verdict["reason"], "no_version_resource")
                        self.assertIn("home is not a local fixed-drive path", str(verdict["detail"]))
                    self.assertEqual(opened, [])

    def test_refused_homes_are_not_opened(self) -> None:
        homes = (
            r"\\host\share\py", "//host/share/py", r"\\?\C:\py", r"\\?\UNC\host\share\py",
            r"\\.\pipe\py", r"Z:\Python",
            r"C:\x\NUL\py", r"C:\x\nul.txt\py", r"C:\x\Com1 .log\py",
        )
        for index, home in enumerate(homes):
            with self.subTest(home=home):
                disk = FakeDisk({"C:\\": locality.DRIVE_FIXED, "Z:\\": DRIVE_REMOTE})
                check = partial(
                    locality.locality_check, drive_type=disk.drive_type, lstat=disk.lstat,
                    readlink=disk.readlink, get_attributes=disk.attributes,
                )
                exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n", rel=f"v{index}")
                with stub_home_reads() as opened, mock.patch("patchwait.pyvenv.local_path_check", check):
                    self.assert_refused(exe, "no_version_resource", "home is not a local fixed-drive path")
                self.assertEqual(opened, [])
                self.assertEqual(disk.looked_at(), [])

    def test_links_to_refused_targets_are_not_opened(self) -> None:
        targets = (
            r"\\host\share\py", r"\??\UNC\host\share\py", r"\Device\Mup\host\share\py",
            r"\\.\pipe\py", r"Z:\py", r"C:\NUL\py",
        )
        for index, target in enumerate(targets):
            with self.subTest(target=target):
                disk = FakeDisk({"C:\\": locality.DRIVE_FIXED, "Z:\\": DRIVE_REMOTE})
                disk.add(r"C:\uv")
                disk.add(r"C:\uv\link", _JUNCTION, target)
                check = partial(
                    locality.locality_check, drive_type=disk.drive_type, lstat=disk.lstat,
                    readlink=disk.readlink, get_attributes=disk.attributes,
                )
                exe = self.venv("home = C:\\uv\\link\nversion_info = 3.12.13\n", rel=f"v{index}")
                with stub_home_reads() as opened, mock.patch("patchwait.pyvenv.local_path_check", check):
                    self.assert_refused(exe, "no_version_resource", "link target")
                self.assertEqual(opened, [])
                self.assertTrue(all(path in (r"C:\uv", r"C:\uv\link") for path in disk.looked_at()))

    def test_duplicate_home_is_refused(self) -> None:
        exe = self.venv("home = C:/py\nhome = C:/other\nversion_info = 3.12.13\n")
        with stub_home_reads() as opened:
            self.assert_refused(exe, "duplicate_key", "mentions home more than once")
        self.assertEqual(opened, [])

    def test_file_changed_while_read_is_refused(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n")
        real_read = pyvenv.read_version_info_from

        def grow(stream: BinaryIO) -> object:
            with open(os.path.join(home, "python.exe"), "ab") as other:
                other.write(b"\0" * 4096)
            return real_read(stream)

        with mock.patch("patchwait.pyvenv.read_version_info_from", grow):
            self.assert_refused(exe, "no_version_resource", "home changed while it was read")

    def test_locality_changed_after_read_is_refused(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.12.13\n")
        before = locality.local_path_check(os.path.join(home, "python.exe"))
        after = replace(before, chain=((home, r"\\host\share\py"),))
        with mock.patch("patchwait.pyvenv.local_path_check", side_effect=[before, after, before, after]):
            self.assert_refused(exe, "no_version_resource", "home changed while it was read")
