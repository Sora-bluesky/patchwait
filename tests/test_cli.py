from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace

from patchwait.cli import main
from tests.pe_builder import NODE_LIKE, build_pe


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_cli(self, *argv: str) -> tuple[int, dict[str, object]]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(list(argv))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def test_found(self) -> None:
        path = self.write("node.exe", build_pe(version=NODE_LIKE)[0])
        code, payload = self.run_cli("version-of", path, "--kind", "node")
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"], "found")
        value = payload["value"]
        assert isinstance(value, dict)
        self.assertEqual(value["version"], {"result": "found", "value": "24.19.0"})

    def test_not_found(self) -> None:
        code, payload = self.run_cli("version-of", os.path.join(self.dir, "none.exe"), "--kind", "node")
        self.assertEqual((code, payload), (1, {"result": "not_found"}))

    def test_undetermined(self) -> None:
        path = self.write("x.exe", b"not a pe")
        code, payload = self.run_cli("version-of", path, "--kind", "python")
        self.assertEqual(code, 3)
        self.assertEqual(payload["reason"], "not_pe")

    def test_identified_but_version_undetermined(self) -> None:
        spec = replace(NODE_LIKE, fixed_product=(20, 0, 0, 0))
        path = self.write("node.exe", build_pe(version=spec)[0])
        code, payload = self.run_cli("version-of", path, "--kind", "node")
        self.assertEqual(code, 3)
        self.assertEqual(payload["result"], "found")

    def test_ascii_suffix_is_still_accepted(self) -> None:
        strings = {**NODE_LIKE.strings, "ProductVersion": "24.19.0rc1"}
        path = self.write("node.exe", build_pe(version=replace(NODE_LIKE, strings=strings))[0])
        code, payload = self.run_cli("version-of", path, "--kind", "node")
        self.assertEqual(code, 0)
        value = payload["value"]
        assert isinstance(value, dict)
        self.assertEqual(value["version"], {"result": "found", "value": "24.19.0rc1"})

    def test_non_ascii_suffix_is_malformed(self) -> None:
        for version in ("24.19.0.１", "24.19.0-١"):  # fullwidth one, Arabic-Indic one
            strings = {**NODE_LIKE.strings, "ProductVersion": version}
            path = self.write("node.exe", build_pe(version=replace(NODE_LIKE, strings=strings))[0])
            code, payload = self.run_cli("version-of", path, "--kind", "node")
            self.assertEqual(code, 3, msg=repr(version))
            value = payload["value"]
            assert isinstance(value, dict)
            version_result = value["version"]
            assert isinstance(version_result, dict)
            self.assertEqual(version_result["result"], "undetermined", msg=repr(version))
            self.assertEqual(version_result["reason"], "malformed_version_resource", msg=repr(version))

    def test_usage_error(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            main(["version-of", "x.exe", "--kind", "ruby"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
