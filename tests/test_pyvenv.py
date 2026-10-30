from __future__ import annotations

import copy
import json
import os
from dataclasses import replace

from patchwait.pyvenv import MAX_CFG_BYTES, parse_cfg
from tests.pe_builder import PYTHON_LIKE, VersionSpec, build_pe
from tests.test_ledger import LedgerCase
from tests.test_scan import ScanCase

MIN_PY = "python=3.12.14,3.14.7"


def python_spec(version: str, product: str = "Python") -> VersionSpec:
    a, b, c = (int(part) for part in version.split("."))
    strings = dict(PYTHON_LIKE.strings, ProductName=product, FileVersion=version, ProductVersion=version)
    return replace(PYTHON_LIKE, strings=strings, fixed_file=(a, b, c, 0), fixed_product=(a, b, c, 0))


class VenvCase(ScanCase):
    def venv(self, cfg: str | bytes | None, *, rel: str = "venv", scripts: bool = True) -> str:
        """A venv whose python.exe has no version resource (like uv's trampoline)."""
        exe_rel = f"{rel}/Scripts/python.exe" if scripts else f"{rel}/python.exe"
        exe = self.write(exe_rel, build_pe(version=None)[0])
        if cfg is not None:
            data = cfg.encode("utf-8") if isinstance(cfg, str) else cfg
            self.write(f"{rel}/pyvenv.cfg", data)
        return exe

    def home(self, version: str, product: str = "Python") -> str:
        exe = self.write(f"uv/cpython-{version}/python.exe", build_pe(version=python_spec(version, product))[0])
        return os.path.dirname(exe)

    def one(self, *argv: str) -> tuple[int, dict[str, object]]:
        code, doc = self.run_scan(*argv, "--kind", "python", "--min", MIN_PY)
        (item,) = self.items(doc)
        return code, item


class VenvScanTests(VenvCase):
    def test_home_version_resource_gives_the_version(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nimplementation = CPython\nversion_info = 3.12\n")
        code, item = self.one("--path", exe)
        self.assertEqual(code, 10)
        self.assertEqual(item["product_version"], "3.12.13")
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})
        self.assertEqual(
            item["version_source"],
            {
                "evidence": "pyvenv-home-pe-version-resource",
                "pyvenv_cfg": os.path.join(self.dir, "venv", "pyvenv.cfg"),
                "home": home,
                "version_info": "3.12",
            },
        )

    def test_home_wins_over_a_full_version_info(self) -> None:
        home = self.home("3.14.7")
        exe = self.venv(f"home={home}\nversion_info=3.14.6\n")
        code, item = self.one("--path", exe)
        self.assertEqual((code, item["product_version"]), (0, "3.14.7"))
        self.assertEqual(self.verdict(item), {"result": "not_found"})

    def test_version_info_used_when_home_is_missing(self) -> None:
        missing = os.path.join(self.dir, "gone")
        exe = self.venv(f"home = {missing}\nversion_info = 3.12.13\n")
        code, item = self.one("--path", exe)
        self.assertEqual(code, 10)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertEqual(source["evidence"], "pyvenv-cfg-version-info")  # pyright: ignore[reportUnknownArgumentType]
        self.assertEqual(source["home"], missing)  # pyright: ignore[reportUnknownArgumentType]

    def test_major_minor_version_info_without_home_is_undetermined(self) -> None:
        missing = os.path.join(self.dir, "gone")
        exe = self.venv(f"home = {missing}\nversion_info = 3.12\n")
        code, item = self.one("--path", exe)
        self.assertEqual(code, 0)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn(
            "pyvenv.cfg version_info is 3.12 (major.minor only) and home python.exe is missing (",
            str(verdict["detail"]),
        )
        self.assertIsNone(item["product_version"])
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]

    def test_major_minor_mismatch_is_version_mismatch(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.13.2\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "version_mismatch")
        self.assertIn("'3.13.2'", str(verdict["detail"]))
        source = item["version_source"]
        assert isinstance(source, dict)
        self.assertIsNone(source["evidence"])  # pyright: ignore[reportUnknownArgumentType]  # no version taken

    def test_home_with_another_product_falls_back_to_version_info(self) -> None:
        home = self.home("3.12.13", product="manage")
        exe = self.venv(f"home = {home}\nversion_info = 3.12.11\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.11"})

    def test_home_without_resource_is_not_followed_further(self) -> None:
        inner = self.venv(f"home = {self.home('3.12.13')}\n", rel="base")
        exe = self.venv(f"home = {os.path.dirname(inner)}\n")
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn("pyvenv.cfg has no version_info and home python.exe gives no_version_resource", str(verdict["detail"]))

    def test_relative_home_is_not_used(self) -> None:
        exe = self.venv("home = cpython\nversion_info = 3.12\n")
        _, item = self.one("--path", exe)
        self.assertIn("home is not a local fixed-drive path", str(self.verdict(item)["detail"]))

    def test_cfg_next_to_python_exe(self) -> None:
        exe = self.venv("version_info = 3.14.6\n", scripts=False)
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.14.6"})

    def test_no_cfg_is_unchanged(self) -> None:
        exe = self.venv(None)
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item)["reason"], "no_version_resource")
        self.assertNotIn("version_source", item)

    def test_python_exe_with_resource_ignores_cfg(self) -> None:
        exe = self.write("venv/Scripts/python.exe", build_pe(version=python_spec("3.14.7"))[0])
        self.write("venv/pyvenv.cfg", b"version_info = 3.12.1\n")
        _, item = self.one("--path", exe)
        self.assertEqual(item["product_version"], "3.14.7")
        self.assertNotIn("version_source", item)

    def test_huge_cfg_is_not_read(self) -> None:
        exe = self.venv(b"version_info = 3.12.13\n" + b"#" * MAX_CFG_BYTES)
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn("larger than 65536 bytes", str(verdict["detail"]))
        self.assertEqual(
            item["version_source"],
            {"evidence": None, "pyvenv_cfg": os.path.join(self.dir, "venv", "pyvenv.cfg"), "home": None, "version_info": None},
        )

    def test_malformed_cfg_bytes_are_handled(self) -> None:
        exe = self.venv(b"\xef\xbb\xbf\xff\xfe garbage\n=no key\nVERSION_INFO = 3.12.13\nnoequals\n\x00\x00\n")
        _, item = self.one("--path", exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})

    def test_non_plain_version_info_is_not_used(self) -> None:
        for text in ("3.12.1.final.0", "3.12.1rc1", "٣.12.1", ""):
            with self.subTest(text=text):
                exe = self.venv(f"version_info = {text}\n", rel=f"v{len(text)}")
                _, item = self.one("--path", exe)
                self.assertEqual(self.verdict(item)["reason"], "no_version_resource")

    def test_cfg_that_is_a_directory_is_undetermined(self) -> None:
        exe = self.venv(None)
        os.makedirs(os.path.join(self.dir, "venv", "pyvenv.cfg"))
        _, item = self.one("--path", exe)
        verdict = self.verdict(item)
        self.assertEqual(verdict["reason"], "no_version_resource")
        self.assertIn("pyvenv.cfg is not a regular file; not read", str(verdict["detail"]))

    def test_node_kind_is_unaffected(self) -> None:
        exe = self.write("venv/Scripts/node.exe", build_pe(version=None)[0])
        self.write("venv/pyvenv.cfg", b"version_info = 24.19.0\n")
        code, doc = self.run_scan("--path", exe, "--min", "node=24.22.1")
        (item,) = self.items(doc)
        self.assertEqual(code, 0)
        self.assertEqual(self.verdict(item)["reason"], "no_version_resource")
        self.assertNotIn("version_source", item)

    def test_root_walk_finds_the_venv(self) -> None:
        home = self.home("3.12.13")
        exe = self.venv(f"home = {home}\nversion_info = 3.12\n", rel="root/proj/.venv")
        code, doc = self.run_scan("--root", os.path.join(self.dir, "root"), "--kind", "python", "--min", MIN_PY)
        self.assertEqual(code, 10)
        (item,) = self.items(doc)
        self.assertEqual(item["path"], exe)
        self.assertEqual(self.verdict(item), {"result": "found", "value": "3.12.13"})

    def test_parse_cfg(self) -> None:
        self.assertEqual(
            parse_cfg("# c\n; c\n\nhome = a = b\r\nVersion_Info=1\nnoequals\n"),
            {"home": "a = b", "version_info": "1"},
        )


class VenvLedgerTests(LedgerCase):
    def venv_doc(self) -> str:
        home_exe = self.write("uv/cpython-3.12.13/python.exe", build_pe(version=python_spec("3.12.13"))[0])
        home = os.path.dirname(home_exe)
        self.write("Apps/a/Scripts/python.exe", build_pe(version=None)[0])
        self.write("Apps/a/pyvenv.cfg", f"home = {home}\nversion_info = 3.12\n".encode())
        self.write("Apps/b/Scripts/python.exe", build_pe(version=None)[0])
        self.write("Apps/b/pyvenv.cfg", b"version_info = 3.12\n")
        out = os.path.join(self.dir, "scan.json")
        code, _, err = self.run_cli(
            "scan", "--kind", "python", "--min", MIN_PY, "--root", os.path.join(self.dir, "Apps"), "--out", out
        )
        self.assertEqual(code, 10, err)
        return out

    def test_renders_version_source(self) -> None:
        path = self.venv_doc()
        _, out = self.ledger(path)
        exe_a = os.path.join(self.dir, "Apps", "a", "Scripts", "python.exe")
        cfg_a = os.path.join(self.dir, "Apps", "a", "pyvenv.cfg")
        home = os.path.join(self.dir, "uv", "cpython-3.12.13")
        self.assertIn(
            f"- found: `{exe_a}` — `3.12.13` < `3.12.14`, product `unknown` (inferred), "
            f"version from `pyvenv-home-pe-version-resource`, pyvenv.cfg `{cfg_a}`, home `{home}`, version_info `3.12`",
            out.splitlines(),
        )
        exe_b = os.path.join(self.dir, "Apps", "b", "Scripts", "python.exe")
        cfg_b = os.path.join(self.dir, "Apps", "b", "pyvenv.cfg")
        line = next(text for text in out.splitlines() if exe_b in text)
        self.assertTrue(
            line.startswith(
                f"- undetermined: `{exe_b}` — no version taken, pyvenv.cfg `{cfg_b}`, version_info `3.12` — no_version_resource: "
            ),
            line,
        )

    def test_rejects_bad_version_source(self) -> None:
        path = self.venv_doc()
        with open(path, encoding="utf-8") as handle:
            good = json.load(handle)
        found = next(i for i, item in enumerate(good["items"]) if item["verdict"]["result"] == "found")
        undetermined = next(i for i, item in enumerate(good["items"]) if item["verdict"]["result"] == "undetermined")
        cases: list[tuple[str, int, object]] = [
            ("not an object", found, "x"),
            ("extra key", found, {**good["items"][found]["version_source"], "extra": 1}),
            ("missing key", found, {k: v for k, v in good["items"][found]["version_source"].items() if k != "home"}),
            ("unknown evidence", found, {**good["items"][found]["version_source"], "evidence": "guess"}),
            ("null evidence on found", found, {**good["items"][found]["version_source"], "evidence": None}),
            ("home evidence without home", found, {**good["items"][found]["version_source"], "home": None}),
            ("empty cfg", found, {**good["items"][found]["version_source"], "pyvenv_cfg": ""}),
            ("cfg not text", found, {**good["items"][found]["version_source"], "pyvenv_cfg": 3}),
            ("version_info not text", undetermined, {**good["items"][undetermined]["version_source"], "version_info": 3}),
            (
                "cfg evidence not equal to product_version",
                found,
                {**good["items"][found]["version_source"], "evidence": "pyvenv-cfg-version-info"},
            ),
        ]
        for name, index, value in cases:
            with self.subTest(name=name):
                doc = copy.deepcopy(good)
                doc["items"][index]["version_source"] = value
                self.assert_rejected(self.write_doc(f"{len(name)}-{index}.json", doc))
        with self.subTest(name="on a directory item"):
            doc = copy.deepcopy(good)
            doc["items"][found]["location_kind"] = "directory"
            self.assert_rejected(self.write_doc("dir.json", doc))


class AsciiDigitVersionInfoTests(VenvCase):
    def test_non_ascii_digits_in_version_info_are_not_used(self) -> None:
        missing = os.path.join(self.dir, "gone")
        for index, text in enumerate(("\u0663.\u0661\u0662.\u0661\u0663", "3.12.1\uff13")):
            with self.subTest(text=text):
                exe = self.venv(f"home = {missing}\nversion_info = {text}\n", rel=f"venv{index}")
                code, item = self.one("--path", exe)
                self.assertEqual(code, 0)
                self.assertEqual(self.verdict(item)["result"], "undetermined")
                self.assertIsNone(item["product_version"])
