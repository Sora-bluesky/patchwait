"""Synthetic registry, permission and saved-walk boundaries; no live Windows data."""

from __future__ import annotations

import contextlib
import ctypes
import datetime
import importlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from patchwait import ledger, scan, waitlist
from patchwait.cli import main
from patchwait.model import RuntimeKind, ScanLink
from tests.pe_builder import build_pe
from tests.test_scan import node_spec
from tests.test_waitlist import document, item


class RegistryError(OSError):
    def __init__(self, code: int) -> None:
        super().__init__(code, "synthetic registry error")
        self.winerror = code


def fake_registry(root: object = r"C:\SyntheticApps", names: tuple[str, ...] = ()) -> Any:
    registry = mock.MagicMock()
    registry.REG_SZ, registry.REG_EXPAND_SZ = 1, 2
    registry.KEY_READ = 0x20019
    registry.HKEY_LOCAL_MACHINE, registry.HKEY_CURRENT_USER = "machine", "user"
    registry.QueryValueEx.return_value = (root, registry.REG_SZ)
    registry.ExpandEnvironmentStrings.side_effect = lambda value: value.replace("%APPS%", r"C:\SyntheticApps")
    registry.EnumKey.side_effect = [*names, RegistryError(259)]
    return registry


class SecurityAPI:
    def __init__(self, *steps: tuple[bool, int, int]) -> None:
        self.steps = list(steps)
        self.error = 0
        self.calls: list[tuple[str, int, object, int]] = []
        self.function = mock.Mock(side_effect=self.call)

    def call(self, path: str, flags: int, buffer: object, size: int, needed: object) -> bool:
        self.calls.append((path, flags, buffer, size))
        success, self.error, length = self.steps.pop(0)
        ctypes.cast(needed, ctypes.POINTER(ctypes.c_uint32)).contents.value = length  # type: ignore[arg-type]
        return success

    @contextlib.contextmanager
    def patched(self):
        dll = types.SimpleNamespace(GetFileSecurityW=self.function)
        with mock.patch("ctypes.WinDLL", return_value=dll, create=True), mock.patch(
            "ctypes.get_last_error", side_effect=lambda: self.error, create=True
        ):
            yield self


class RegistryReadsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.windows = importlib.import_module("patchwait.windows_walk")
        self.registry = fake_registry()
        self.context = contextlib.ExitStack()
        self.addCleanup(self.context.close)
        self.context.enter_context(mock.patch.dict("sys.modules", winreg=self.registry))
        self.context.enter_context(mock.patch("sys.platform", "win32"))
        self.drive = self.context.enter_context(mock.patch("patchwait.locality.windows_drive_type", return_value=3))

    def test_registry_read_failures_preserve_items(self) -> None:
        for error in (FileNotFoundError(), PermissionError(), OSError()):
            with self.subTest(error=type(error).__name__):
                self.registry.OpenKey.side_effect = error
                with self.assertRaises(self.windows.PackageReadError):
                    self.windows.read_package_root()
                self.registry.OpenKey.side_effect = None
                self.registry.QueryValueEx.side_effect = error
                with self.assertRaises(self.windows.PackageReadError):
                    self.windows.read_package_root()
                self.registry.QueryValueEx.side_effect = None
        self.registry.OpenKey.assert_called_with(
            "machine", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx", 0, 0x20019
        )
        self.registry.QueryValueEx.assert_called_with(mock.ANY, "PackageRoot")

    def test_registry_value_types(self) -> None:
        for value, kind in ((42, 1), (r"C:\SyntheticApps", 4), (None, 1), ("", 1)):
            with self.subTest(value=value, kind=kind):
                self.registry.QueryValueEx.return_value = value, kind
                with self.assertRaises(self.windows.PackageReadError):
                    self.windows.read_package_root()

    def test_registry_expansion_and_refresh(self) -> None:
        self.registry.QueryValueEx.return_value = (r"%APPS%\Packages", 2)
        self.assertEqual(self.windows.read_package_root(), r"C:\SyntheticApps\Packages")
        self.registry.QueryValueEx.return_value = (r"D:\Changed", 1)
        self.assertEqual(self.windows.read_package_root(), r"D:\Changed")
        self.assertEqual(self.registry.QueryValueEx.call_count, 2)
        self.registry.QueryValueEx.return_value = (r"%APPS%", 2)
        self.registry.ExpandEnvironmentStrings.side_effect = OSError()
        with self.assertRaises(self.windows.PackageReadError):
            self.windows.read_package_root()

    def test_registry_nonlocal_paths(self) -> None:
        paths = ("relative", "C:relative", r"\rooted", r"\\server\share", "//server/share",
                 r"\\?\C:\Apps", r"\\.\pipe\example", "C:\\bad\0path")
        for path in paths:
            with self.subTest(path=path):
                self.registry.QueryValueEx.return_value = path, 1
                with self.assertRaises(self.windows.PackageReadError):
                    self.windows.read_package_root()
        self.drive.assert_not_called()

    def test_registry_drive_types(self) -> None:
        for kind in (0, 1, 2, 4, 5):
            with self.subTest(kind=kind):
                self.drive.return_value = kind
                with self.assertRaises(self.windows.PackageReadError):
                    self.windows.read_package_root()
        self.drive.side_effect = OSError()
        with self.assertRaises(self.windows.PackageReadError):
            self.windows.read_package_root()
        self.drive.side_effect = None
        for kind in (3, 6):
            self.drive.return_value = kind
            self.assertEqual(self.windows.read_package_root(), r"C:\SyntheticApps")

    def test_repository_failures_and_empty(self) -> None:
        for error in (FileNotFoundError(), PermissionError()):
            self.registry.OpenKey.side_effect = error
            with self.assertRaises(self.windows.PackageReadError):
                self.windows.registered_packages()
        self.registry.OpenKey.side_effect = None
        self.assertEqual(self.windows.registered_packages(), ())
        self.registry.OpenKey.assert_called_with(
            "user", r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
            0, 0x20019,
        )
        self.registry.QueryValueEx.assert_not_called()

    def test_repository_enumeration_errors(self) -> None:
        for error in (PermissionError(), RegistryError(2), RegistryError(234)):
            self.registry.EnumKey.side_effect = ["Example_1_x64__publisher", error]
            with self.assertRaises(self.windows.PackageReadError):
                self.windows.registered_packages()
        self.registry.EnumKey.side_effect = ["Zed", "Alpha", RegistryError(259)]
        self.assertEqual(self.windows.registered_packages(), ("Alpha", "Zed"))


class SecurityReadsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.windows = importlib.import_module("patchwait.windows_walk")

    def denied(self, api: SecurityAPI) -> bool:
        with mock.patch("sys.platform", "win32"), api.patched():
            result = self.windows.permissions_access_denied(r"C:\SyntheticApps\Locked")
        self.assertEqual(api.function.argtypes, [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p,
                                               ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)])
        self.assertEqual(api.function.restype, ctypes.c_int)
        self.assertTrue(all(flags == 5 for _, flags, _, _ in api.calls))
        return result

    def test_security_probe_outcomes(self) -> None:
        self.assertTrue(self.denied(SecurityAPI((False, 5, 0))))
        self.assertFalse(self.denied(SecurityAPI((True, 5, 0))))
        for error in (0, 2, 3, 6, 87, 1314):
            with self.subTest(error=error):
                self.assertFalse(self.denied(SecurityAPI((False, error, 0))))

    def test_security_buffer_outcomes(self) -> None:
        for success, error, expected in ((True, 5, False), (False, 5, True), (False, 2, False),
                                         (False, 122, False), (False, 1314, False)):
            with self.subTest(success=success, error=error):
                api = SecurityAPI((False, 122, 64), (success, error, 64))
                self.assertEqual(self.denied(api), expected)
                self.assertEqual(len(api.calls), 2)
                self.assertEqual(api.calls[0][2:], (None, 0))
                self.assertIsNotNone(api.calls[1][2])
                self.assertEqual(api.calls[1][3], 64)
        self.assertFalse(self.denied(SecurityAPI((False, 122, 0))))

    def test_security_unavailable(self) -> None:
        with mock.patch("sys.platform", "linux"):
            self.assertFalse(self.windows.permissions_access_denied("Locked"))
        with mock.patch("sys.platform", "win32"):
            with mock.patch.dict("sys.modules", ctypes=None):
                self.assertFalse(self.windows.permissions_access_denied("Locked"))
            for error in (OSError(), AttributeError()):
                with mock.patch("ctypes.WinDLL", side_effect=error, create=True):
                    self.assertFalse(self.windows.permissions_access_denied("Locked"))
            for error in (MemoryError(), OverflowError()):
                with SecurityAPI((False, 122, 64)).patched(), mock.patch(
                    "ctypes.create_string_buffer", side_effect=error
                ):
                    self.assertFalse(self.windows.permissions_access_denied("Locked"))


class ProtectedWalkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=".")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).absolute()
        self.root = self.parent / "StorePackages"
        self.root.mkdir()
        self.names: tuple[str, ...] = ()
        self.denied_paths = {str(self.root)}
        self.error: OSError = PermissionError("synthetic denial")
        self.permission_denied = True

    def node(self, relative: str, version: str = "24.19.0") -> str:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(build_pe(version=node_spec(version))[0])
        return str(path)

    @contextlib.contextmanager
    def environment(self, registry_root: str | None = None, registry_error: Exception | None = None):
        # The old walker has no Windows boundary module; this keeps fail-before
        # evidence on its observable output rather than on a missing import.
        try:
            windows = importlib.import_module("patchwait.windows_walk")
            error_type = windows.PackageReadError
        except ImportError:
            windows = types.SimpleNamespace()
            error_type = OSError
        real_scandir = os.scandir

        def listing(path: Any):
            if str(path) in self.denied_paths:
                raise self.error
            return real_scandir(path)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(scan, "windows_walk", windows, create=True))
            root_read = stack.enter_context(mock.patch.object(
                windows, "read_package_root", return_value=registry_root or str(self.root), create=True
            ))
            if registry_error is not None:
                root_read.side_effect = error_type(str(registry_error))
            stack.enter_context(mock.patch.object(windows, "registered_packages", return_value=self.names, create=True))
            permission = stack.enter_context(mock.patch.object(
                windows, "permissions_access_denied", return_value=self.permission_denied, create=True
            ))
            stack.enter_context(mock.patch("patchwait.scan.os.scandir", side_effect=listing))
            yield permission

    def scanned(self, excludes: tuple[str, ...] = ()) -> dict[str, Any]:
        walked = scan.walk_root(str(self.parent), "node.exe", excludes)
        baselines = scan.parse_baselines(["node=24.22.1,26.12.1"], ["node=https://example.invalid/security"])
        items = scan.scan_with_walks([], [walked], RuntimeKind.NODE, baselines)
        return scan.scan_document(items, RuntimeKind.NODE, baselines,
                                  datetime.datetime(2026, 10, 29, tzinfo=datetime.timezone.utc), [walked])

    def test_registered_packages_and_unreadable(self) -> None:
        first = self.node("Alpha_1_x64__publisher/a/node.exe")
        second = self.node("Zed_1_x64__publisher/node.exe", "26.12.1")
        self.node("Unregistered/node.exe")
        bad = self.root / "Locked_1_x64__publisher"
        bad.mkdir()
        self.names = ("Zed_1_x64__publisher", "Missing_1_x64__publisher", "Locked_1_x64__publisher",
                      "Alpha_1_x64__publisher")
        self.denied_paths.add(str(bad))
        with self.environment() as permission:
            result = self.scanned()
        self.assertEqual([row["path"] for row in result["items"]], [first, second, str(bad)])
        self.assertIn("Locked_1_x64__publisher", result["items"][-1]["verdict"]["detail"])
        self.assertEqual(result["counts"], {"targets": 3, "found": 1, "not_found": 1, "undetermined": 1})
        package = result["walk"][0]["package_root"]
        self.assertEqual((package["packages_registered"], package["walked"], package["unreadable"], package["absent"]),
                         (4, 2, 1, 1))
        self.assertIn("current user", package["note"])
        self.assertNotIn("skipped_protected", result["walk"][0])
        permission.assert_not_called()

    def test_only_normalized_registry_root_is_special(self) -> None:
        self.names = ("Example_1_x64__publisher",)
        path = self.node("Example_1_x64__publisher/NODE.EXE")
        registry_path = str(self.root)
        if sys.platform == "win32":
            registry_path = registry_path.upper()
        registry_path += os.sep + "."
        with self.environment(registry_path):
            result = self.scanned()
        self.assertEqual([row["path"] for row in result["items"]], [path])
        self.assertIn("package_root", result["walk"][0])
        self.permission_denied = False
        with self.environment(str(self.parent / "OtherRoot")):
            result = self.scanned()
        self.assertNotIn("package_root", result["walk"][0])
        self.assertEqual(result["items"][0]["verdict"]["detail"], "PermissionError")

    def check_refused(self, names: tuple[str, ...]) -> None:
        self.names = names
        join = os.path.join

        def safe_join(*parts: str) -> str:
            if parts and str(parts[0]) == str(self.root):
                self.assertNotIn(parts[-1], names, "unsafe name reached path join")
            return join(*parts)

        with self.environment(), mock.patch("patchwait.scan.os.path.join", side_effect=safe_join):
            result = self.scanned()
        package = result["walk"][0].get("package_root", {})
        self.assertEqual([json.loads(name) for name in package.get("refused", [])], sorted(names))
        self.assertEqual(package.get("packages_registered"), len(names))
        self.assertEqual(result["items"], [])

    def test_package_names_refused_before_join(self) -> None:
        self.check_refused(("bad\0name", "bad*name", "bad?name", "CON", "nul.txt", "bad name", "trailing."))

    def test_package_separators_refused_before_join(self) -> None:
        self.check_refused((r"bad\child", "bad/child"))

    def test_package_dotdot_refused_before_join(self) -> None:
        self.check_refused(("..", "Alpha..Beta"))

    def test_package_drive_refused_before_join(self) -> None:
        self.check_refused(("C:relative", r"C:\absolute"))

    def test_package_length_refused_before_join(self) -> None:
        self.check_refused(("A" * 256,))

    def cli_utf8(self, args: list[str], today: datetime.date | None = None) -> tuple[int, str]:
        with io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\n") as out:
            error = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
                code = main(args, today=today)
            out.flush()
            self.assertEqual(error.getvalue(), "", f"CLI exit {code}")
            raw = out.buffer.getvalue()
        self.assertNotIn(b"\r", raw)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        return code, raw.decode("utf-8")

    def round_trip(self, counts: dict[str, int]) -> dict[str, Any]:
        expected_code = 10 if counts["found"] else 0
        args = ["scan", "--kind", "node", "--root", str(self.parent),
                "--min", "node=24.22.1", "--source", "node=https://example.invalid/security"]
        result_path = self.parent / "scan.json"
        code, out = self.cli_utf8([*args, "--out", str(result_path)])
        self.assertEqual(code, expected_code)
        self.assertEqual(out, "")
        raw = result_path.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        result = json.loads(raw.decode("utf-8"))
        checked = datetime.datetime.fromisoformat(result["generated"]).date()
        self.assertEqual(result["counts"], counts)
        code, out = self.cli_utf8(args)
        self.assertEqual(code, expected_code)
        printed = json.loads(out)
        for field in ("counts", "walk", "items"):
            self.assertEqual(printed[field], result[field])

        code, markdown = self.cli_utf8(["ledger", str(result_path)])
        self.assertEqual(code, expected_code)
        self.assertIn(f"found {counts['found']} / not_found {counts['not_found']} / "
                      f"undetermined {counts['undetermined']}", markdown)
        ledger_path = self.parent / "ledger.md"
        code, out = self.cli_utf8(["ledger", str(result_path), "--out", str(ledger_path)])
        self.assertEqual(code, expected_code)
        self.assertEqual(out, "")
        self.assertEqual(ledger_path.read_bytes(), markdown.encode("utf-8"))

        file_rows = [row for row in result["items"] if row["location_kind"] == "file"]
        saved_result = waitlist.saved_result_from_document(result, "synthetic")
        for row in result["items"]:
            self.assertIn(ScanLink(RuntimeKind.NODE, row["path"]), saved_result.rows)
        linked = item("runtime-check", (checked - datetime.timedelta(days=10)).isoformat())
        if file_rows:
            # The saved scan can contain opaque OS paths; the existing waitlist
            # input contract requires valid Unicode in its own result links.
            linked["result_link"] = {"check": "scan", "kind": "node", "path": file_rows[0]["path"]}
        waitlist_path = self.parent / "waitlist.json"
        waitlist_path.write_bytes((json.dumps(document(linked)) + "\n").encode("utf-8"))
        code, out = self.cli_utf8(["waitlist", "record", str(waitlist_path), "--from", str(result_path)],
                                 today=checked)
        self.assertEqual(code, 0)
        recorded = json.loads(out)
        self.assertEqual(recorded["walk"], result["walk"])
        if file_rows:
            self.assertEqual(len(recorded["updated"]), 1)
            self.assertEqual(recorded["updated"][0]["last_result"], file_rows[0]["verdict"])
            saved = json.loads(waitlist_path.read_bytes().decode("utf-8"))["items"][0]
            self.assertEqual(saved["last_checked"], checked.isoformat())
            self.assertEqual(saved["result_link"], linked["result_link"])
            self.assertEqual(saved["last_result"], file_rows[0]["verdict"])
        return result

    def refused_round_trip(self, name: str) -> None:
        target = self.parent / "node.exe"
        for version, counts in (("24.19.0", {"targets": 1, "found": 1, "not_found": 0, "undetermined": 0}),
                                ("24.22.1", {"targets": 1, "found": 0, "not_found": 1, "undetermined": 0})):
            target.write_bytes(build_pe(version=node_spec(version))[0])
            self.names = ("Example",)
            with self.environment():
                baseline = self.round_trip(counts)
            self.names = ("Example", name)
            with self.environment():
                result = self.round_trip(counts)
            self.assertEqual(result["items"], baseline["items"])
            package = result["walk"][0]["package_root"]
            self.assertEqual(package["packages_registered"], 2)
            self.assertEqual(package["walked"], 0)
            self.assertEqual(package["absent"], 1)
            self.assertEqual(len(package["refused"]), 1)
            escaped = package["refused"][0]
            self.assertTrue(escaped.isascii())
            self.assertTrue(escaped.startswith('"') and escaped.endswith('"'))
            self.assertEqual(json.loads(escaped), name)

    def test_whitespace_refused_name_round_trip(self) -> None:
        self.refused_round_trip(" ")

    def test_empty_refused_name_round_trip(self) -> None:
        self.refused_round_trip("")

    def test_surrogate_refused_name_round_trip(self) -> None:
        self.refused_round_trip("\ud800")

    def test_control_refused_name_round_trip(self) -> None:
        self.refused_round_trip("bad\0\t\r\n\x1f\x7fname")

    def test_long_refused_name_round_trip(self) -> None:
        self.refused_round_trip("A" * 10000)

    def path_round_trips(self, state: str) -> None:
        # A virtual listing allows names the test host cannot create. Runtime
        # detection still uses a real synthetic PE, without executing it.
        real_target = self.node("Example/node.exe")
        detected = scan.pyvenv.detect_runtime_with_venv(real_target, RuntimeKind.NODE)
        directory_info = self.root.stat()
        self.names = ("Example",)
        self.permission_denied = state == "protected"
        for suffix in ("", " \t\n\x1f", "\ud800", "\udfff", "\u65e5\u672c\u8a9e_\U0001f600", r"\ud800", "A" * 10000):
            with self.subTest(state=state, suffix=suffix):
                root = str(self.root) + suffix
                package = os.path.join(root, "Example")
                child = os.path.join(package, "Child")
                target = os.path.join(child, "node.exe")
                sibling = str(self.parent / "node.exe")

                def entry(path: str, directory: bool) -> Any:
                    value = mock.Mock()
                    value.path, value.name = path, os.path.basename(path)
                    value.is_dir.return_value = directory
                    value.is_file.return_value = not directory
                    value.is_symlink.return_value = False
                    return value

                def listing(path: Any):
                    path = str(path)
                    if path == str(self.parent):
                        entries = [entry(root, True), entry(sibling, False)]
                    elif path == package and state not in ("package_unreadable", "lstat", "reparse", "protected"):
                        entries = [entry(child, True)]
                    elif path == child and state == "matched":
                        entries = [entry(target, False)]
                    else:
                        raise PermissionError("untrusted OS message: " + suffix)
                    return contextlib.nullcontext(iter(entries))

                def lstat(path: Any):
                    if str(path) == package and state == "lstat":
                        raise PermissionError("untrusted OS message: " + suffix)
                    return directory_info

                def reparse(value: Any) -> bool:
                    if isinstance(value, Path) and str(value) == package and state == "reparse":
                        raise OSError("untrusted OS message: " + suffix)
                    return False

                registry_root = str(self.parent / "OtherRoot") if state == "protected" else root
                counts = {"targets": 2, "found": 1, "not_found": 0, "undetermined": 1}
                if state == "matched":
                    counts.update(found=2, undetermined=0)
                elif state == "protected":
                    counts.update(targets=1, undetermined=0)
                with self.environment(registry_root), mock.patch(
                    "patchwait.scan.os.scandir", side_effect=listing
                ), mock.patch("patchwait.scan.os.lstat", side_effect=lstat), mock.patch(
                    "patchwait.scan._is_reparse_point", side_effect=reparse
                ), mock.patch("patchwait.scan.pyvenv.detect_runtime_with_venv", return_value=detected):
                    result = self.round_trip(counts)
                walk = result["walk"][0]
                if state == "protected":
                    self.assertEqual(walk["skipped_protected"][0]["path"], root)
                else:
                    self.assertEqual(walk["package_root"]["path"], root)
                    self.assertEqual(walk["package_root"]["packages_registered"], 1)
                    if state == "matched":
                        self.assertEqual(result["items"][-1]["path"], target)
                    else:
                        self.assertEqual(result["items"][-1]["path"], child if state == "descendant_unreadable" else package)

    def test_matched_package_paths_round_trip(self) -> None:
        self.path_round_trips("matched")

    def test_unreadable_package_paths_round_trip(self) -> None:
        self.path_round_trips("package_unreadable")

    def test_unreadable_descendant_paths_round_trip(self) -> None:
        self.path_round_trips("descendant_unreadable")

    def test_package_existence_error_paths_round_trip(self) -> None:
        self.path_round_trips("lstat")

    def test_package_reparse_error_paths_round_trip(self) -> None:
        self.path_round_trips("reparse")

    def test_protected_paths_round_trip(self) -> None:
        self.path_round_trips("protected")

    def test_registry_error_messages_round_trip(self) -> None:
        self.node("Example/node.exe")
        self.names = ("Example",)
        windows = importlib.import_module("patchwait.windows_walk")
        for message in ("", " ", "\ud800", "\0\t\r\n", "A" * 10000):
            for reader in ("read_package_root", "registered_packages"):
                with self.subTest(message=message, reader=reader):
                    registry = fake_registry()
                    registry.OpenKey.side_effect = PermissionError(message)
                    with mock.patch.dict("sys.modules", winreg=registry), mock.patch("sys.platform", "win32"):
                        with self.assertRaises(windows.PackageReadError) as caught:
                            getattr(windows, reader)()
                    with self.environment() as permission, mock.patch.object(windows, reader, side_effect=caught.exception):
                        result = self.round_trip({"targets": 1, "found": 0, "not_found": 0, "undetermined": 1})
                    self.assertIn("PermissionError", result["walk"][0]["package_root_error"])
                    if message.strip():
                        self.assertNotIn(message, result["walk"][0]["package_root_error"])
                    permission.assert_not_called()

    def test_package_existence_errors(self) -> None:
        self.names = ("Missing", "Denied", "File")
        (self.root / "File").write_bytes(b"synthetic")
        real_stat = os.lstat

        def lstat(path: Any, *args: Any, **kwargs: Any):
            if str(path) == str(self.root / "Denied"):
                raise PermissionError()
            return real_stat(path, *args, **kwargs)

        with self.environment(), mock.patch("patchwait.scan.os.lstat", side_effect=lstat):
            result = self.scanned()
        package = result["walk"][0]["package_root"]
        self.assertEqual((package["absent"], package["unreadable"]), (1, 2))
        self.assertEqual(result["counts"]["undetermined"], 2)
        self.assertTrue(all("Store package" in row["verdict"]["detail"] for row in result["items"]))

    def test_package_reparse_and_excludes(self) -> None:
        for name in ("Kept", "Excluded", "Linked", "StatusDenied"):
            self.node(f"{name}/node.exe")
        self.names = ("Kept", "Excluded", "Linked", "StatusDenied")
        original = scan._is_reparse_point

        def reparse(entry: Any) -> bool:
            path = str(entry) if isinstance(entry, Path) else entry.path
            if path == str(self.root / "Linked"):
                return True
            if path == str(self.root / "StatusDenied"):
                raise PermissionError()
            return original(entry)

        with self.environment(), mock.patch("patchwait.scan._is_reparse_point", side_effect=reparse):
            result = self.scanned(("excluded",))
        walk = result["walk"][0]
        self.assertEqual((walk["excluded_dirs"], walk["skipped_reparse_points"]), (1, 1))
        self.assertEqual((walk["package_root"]["walked"], walk["package_root"]["unreadable"]), (1, 1))
        self.assertEqual([Path(row["path"]).parent.name for row in result["items"] if row["location_kind"] == "file"],
                         ["Kept"])

    def test_protected_only_on_double_denial(self) -> None:
        for listing_error in (PermissionError(), OSError(), FileNotFoundError()):
            for descriptor_denied in (True, False):
                with self.subTest(error=type(listing_error).__name__, denied=descriptor_denied):
                    self.error, self.permission_denied = listing_error, descriptor_denied
                    with self.environment(str(self.parent / "OtherRoot")) as permission:
                        result = self.scanned()
                    protected = isinstance(listing_error, PermissionError) and descriptor_denied
                    self.assertEqual(result["counts"]["undetermined"], 0 if protected else 1)
                    if protected:
                        self.assertEqual(result["walk"][0]["skipped_protected"], [
                            {"path": str(self.root), "reason": "listing_and_permissions_denied"}
                        ])
                        self.assertEqual(result["walk"][0]["skipped_protected_count"], 1)
                    else:
                        self.assertEqual(result["items"][0]["verdict"]["detail"], type(listing_error).__name__)
                    self.assertEqual(permission.call_count, 1 if isinstance(listing_error, PermissionError) else 0)

    def test_matching_names_with_readable_permissions_stay_undetermined(self) -> None:
        self.root.rmdir()
        for name in ("WindowsApps", "Classification/Configuration", "legacy_credentials/SyntheticAccount"):
            (self.parent / name).mkdir(parents=True)
        self.denied_paths = {str(self.parent / name) for name in (
            "WindowsApps", "Classification/Configuration", "legacy_credentials/SyntheticAccount"
        )}
        self.permission_denied = False
        with self.environment(str(self.parent / "OtherRoot")):
            result = self.scanned()
        self.assertEqual(result["counts"]["undetermined"], 3)
        self.assertNotIn("skipped_protected", result["walk"][0])

    def test_registry_failure_preserves_original_result(self) -> None:
        with self.environment(registry_error=OSError("PackageRoot: synthetic failure")):
            result = self.scanned()
        expected = {"root": str(self.parent), "matched_files": 0, "unreadable_dirs": 1,
                    "skipped_reparse_points": 0, "excluded_dirs": 0}
        actual_walk = dict(result["walk"][0])
        explanation = actual_walk.pop("package_root_error", None)
        self.assertEqual(json.dumps(actual_walk), json.dumps(expected))
        self.assertIsInstance(explanation, str)
        self.assertIn("PackageRoot", str(explanation))
        self.assertEqual(result["items"][0]["verdict"], {
            "result": "undetermined", "reason": "file_unreadable", "detail": "PermissionError"
        })
        self.assertEqual(result["counts"], {"targets": 1, "found": 0, "not_found": 0, "undetermined": 1})

    def test_repository_failure_keeps_root_undetermined(self) -> None:
        other = self.parent / "ZProtected"
        other.mkdir()
        self.denied_paths.add(str(other))
        with self.environment() as permission:
            windows = scan.windows_walk
            with mock.patch.object(windows, "registered_packages", side_effect=windows.PackageReadError("repository unavailable")):
                result = self.scanned()
        self.assertEqual(result["items"][0]["verdict"]["detail"], "PermissionError")
        self.assertIn("repository unavailable", result["walk"][0]["package_root_error"])
        permission.assert_called_once_with(str(other))
        self.assertEqual(result["walk"][0]["skipped_protected_count"], 1)

    def test_empty_repository_is_reported(self) -> None:
        with self.environment():
            result = self.scanned()
        self.assertEqual(result["items"], [])
        self.assertEqual(result["walk"][0]["package_root"]["packages_registered"], 0)

    def test_explicit_target_deduplication_and_python_kind(self) -> None:
        path = self.node("Example/node.exe")
        self.names = ("Example",)
        self.node("Example/python.exe")  # Node PE under a Python name must still fail kind detection.
        with self.environment():
            node_walk = scan.walk_root(str(self.parent), "node.exe", ())
            python_walk = scan.walk_root(str(self.parent), "python.exe", ())
        baselines = scan.parse_baselines(["node=24.22.1"], [])
        explicit = scan.Target(path, scan.Product("Synthetic", False))
        items = scan.scan_with_walks([explicit], [node_walk, node_walk], RuntimeKind.NODE, baselines)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].target.product.name, "Synthetic")
        python_items = scan.scan_with_walks([], [python_walk], RuntimeKind.PYTHON, {})
        self.assertEqual(python_items[0].verdict.reason.value, "unexpected_product")  # type: ignore[union-attr]


def walk_document() -> dict[str, Any]:
    return {
        "tool": "patchwait", "schema": 1, "generated": "2026-10-29T00:00:00+00:00", "kind": "node",
        "baselines": {}, "counts": {"targets": 0, "found": 0, "not_found": 0, "undetermined": 0}, "items": [],
        "walk": [{"root": "Apps", "matched_files": 0, "unreadable_dirs": 0,
                  "skipped_reparse_points": 0, "excluded_dirs": 0}],
    }


def protected_evidence() -> dict[str, Any]:
    return {"skipped_protected_count": 1,
            "skipped_protected": [{"path": "Apps/Locked", "reason": "listing_and_permissions_denied"}]}


def package_evidence() -> dict[str, Any]:
    return {"path": "Apps/StorePackages", "packages_registered": 6, "walked": 1, "unreadable": 1,
            "absent": 1, "excluded": 1, "skipped_reparse_points": 1, "refused": ["bad/name"],
            "note": "Only Store packages registered for the current user are walked."}


class SavedWalkTests(unittest.TestCase):
    def rejected(self, fields: dict[str, Any]) -> None:
        value = walk_document()
        value["walk"][0].update(fields)
        with self.assertRaises(ledger.LedgerInputError):
            ledger.render_document(value, "synthetic")
        with self.assertRaises(waitlist.WaitlistInputError):
            waitlist.saved_result_from_document(value, "synthetic")

    def test_protected_json_validation(self) -> None:
        evidence = protected_evidence()
        value = walk_document()
        value["walk"][0].update(evidence)
        for brief in (True, False):
            rendered = ledger.render_document(value, "synthetic", brief=brief)
            self.assertIn("not walked:", rendered.markdown)
            self.assertIn("skipped_protected 1", rendered.markdown)
            self.assertIn("Apps/Locked", rendered.markdown)
            self.assertIn("administrator", rendered.markdown)
        waitlist.saved_result_from_document(value, "synthetic")
        for count in (-1, True, "1", None, 0, 2):
            self.rejected(dict(evidence, skipped_protected_count=count))
        for entries in (None, {}, [None], [{}], [{"path": "", "reason": "listing_and_permissions_denied"}],
                        [{"path": "Apps/Locked", "reason": "other"}],
                        [{"path": "Apps/Locked", "reason": "listing_and_permissions_denied", "extra": 1}]):
            self.rejected(dict(evidence, skipped_protected=entries))
        self.rejected({"skipped_protected": evidence["skipped_protected"]})
        self.rejected({"skipped_protected_count": 0})

    def test_package_json_validation(self) -> None:
        package = package_evidence()
        value = walk_document()
        value["walk"][0]["package_root"] = package
        rendered = ledger.render_document(value, "synthetic", brief=True).markdown
        for text in ("package_root", "walked 1", "absent 1", "refused", "bad/name", "current user", "not walked"):
            self.assertIn(text, rendered)
        waitlist.saved_result_from_document(value, "synthetic")
        for name in package:
            missing = dict(package)
            del missing[name]
            self.rejected({"package_root": missing})
        for name in ("packages_registered", "walked", "unreadable", "absent", "excluded", "skipped_reparse_points"):
            for bad in (-1, True, "1", None, 42):
                self.rejected({"package_root": dict(package, **{name: bad})})
        for name in ("path", "note"):
            for bad in ("", None, 1):
                self.rejected({"package_root": dict(package, **{name: bad})})
        for bad in (None, {}, [""], [None], "name"):
            self.rejected({"package_root": dict(package, refused=bad)})
        self.rejected({"package_root": dict(package, extra=1)})
        self.rejected({"package_root": None})

    def test_registry_error_json_validation(self) -> None:
        value = walk_document()
        value["walk"][0]["package_root_error"] = "PackageRoot: unavailable"
        self.assertIn("PackageRoot: unavailable", ledger.render_document(value, "synthetic").markdown)
        waitlist.saved_result_from_document(value, "synthetic")
        for bad in ("", None, 1, {}):
            self.rejected({"package_root_error": bad})
        self.rejected({"package_root_error": "failed", "package_root": package_evidence()})

    def test_new_walk_text_is_escaped(self) -> None:
        value = walk_document()
        evidence = protected_evidence()
        evidence["skipped_protected"][0]["path"] = "Apps/<script>\n`example@example.invalid`"
        value["walk"][0].update(evidence)
        rendered = ledger.render_document(value, "synthetic").markdown
        self.assertIn("\\u000a", rendered)
        self.assertIn("<email>", rendered)
        self.assertNotIn("example@example.invalid", rendered)

    def test_waitlist_record_keeps_walk_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=".") as temporary:
            result_path = Path(temporary) / "scan.json"
            waitlist_path = Path(temporary) / "waitlist.json"
            value = walk_document()
            value["walk"][0].update(protected_evidence())
            value["walk"][0]["package_root"] = package_evidence()
            result_path.write_bytes((json.dumps(value) + "\n").encode("utf-8"))
            waitlist_path.write_bytes((json.dumps(document(item("runtime-check", "2026-10-20"))) + "\n").encode("utf-8"))
            before = waitlist_path.read_bytes()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["waitlist", "record", str(waitlist_path), "--from", str(result_path)],
                            today=datetime.date(2026, 10, 29))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue()).get("walk"), value["walk"])
            self.assertEqual(waitlist_path.read_bytes(), before)
            value["walk"][0]["skipped_protected_count"] = 2
            result_path.write_bytes(json.dumps(value).encode("utf-8"))
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["waitlist", "record", str(waitlist_path), "--from", str(result_path)],
                            today=datetime.date(2026, 10, 29))
            self.assertEqual(code, 2)
            self.assertEqual(waitlist_path.read_bytes(), before)

    def test_absent_fields_keep_old_output(self) -> None:
        value = walk_document()
        before = "10-29: patchwait scan node: found 0 / not_found 0 / undetermined 0\n"
        self.assertEqual(ledger.render_document(value, "synthetic").markdown, before)
        saved = waitlist.saved_result_from_document(value, "synthetic")
        encoded = waitlist.record_from_document(waitlist.Recorded(saved, [], []), "synthetic.json")
        self.assertNotIn("walk", encoded)


class ProtectedHelpTests(unittest.TestCase):
    def test_help_describes_walk_evidence(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as caught:
            main(["scan", "--help"])
        self.assertEqual(caught.exception.code, 0)
        for text in ("current user", "package_root", "skipped_protected", "administrator"):
            self.assertIn(text, " ".join(out.getvalue().split()))
