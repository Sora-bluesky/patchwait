from __future__ import annotations

import ntpath
import os
import stat
import tempfile
import unittest
from unittest import mock

from patchwait import locality
from patchwait.locality import DRIVE_FIXED, HOP_LIMIT, locality_check, locality_problem

DRIVE_REMOVABLE = 2
DRIVE_REMOTE = 4

_DIR = os.stat_result((stat.S_IFDIR, 0, 0, 0, 0, 0, 0, 0, 0, 0))
_FILE = os.stat_result((stat.S_IFREG, 0, 0, 0, 0, 0, 0, 0, 0, 0))
_JUNCTION = os.stat_result(
    (stat.S_IFDIR, 0, 0, 0, 0, 0, 0, 0, 0, 0), {"st_file_attributes": stat.FILE_ATTRIBUTE_REPARSE_POINT}
)
_SYMLINK = os.stat_result((stat.S_IFLNK, 0, 0, 0, 0, 0, 0, 0, 0, 0))


class FakeDisk:
    """Paths to (stat, link target or None). Records every call; never touches the real disk."""

    def __init__(self, drives: dict[str, int] | None = None) -> None:
        self.drives = drives if drives is not None else {"C:\\": DRIVE_FIXED}
        self.entries: dict[str, tuple[os.stat_result, str | None]] = {}
        self.extra_attributes: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []

    def add(self, path: str, info: os.stat_result = _DIR, target: str | None = None) -> None:
        self.entries[ntpath.normcase(path)] = (info, target)

    def drive_type(self, root: str) -> int:
        self.calls.append(("drive_type", root))
        return self.drives.get(root, 0)

    def lstat(self, path: str) -> os.stat_result:
        self.calls.append(("lstat", path))
        entry = self.entries.get(ntpath.normcase(path))
        if entry is None:
            raise FileNotFoundError(path)
        return entry[0]

    def attributes(self, path: str) -> int:
        """What GetFileAttributesW would say: the entry's own kind, plus anything set in ``extra_attributes``."""
        self.calls.append(("attributes", path))
        entry = self.entries.get(ntpath.normcase(path))
        if entry is None:
            raise FileNotFoundError(path)
        info = entry[0]
        value = stat.FILE_ATTRIBUTE_DIRECTORY if stat.S_ISDIR(info.st_mode) else stat.FILE_ATTRIBUTE_ARCHIVE
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) or 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            value |= stat.FILE_ATTRIBUTE_REPARSE_POINT
        return value | self.extra_attributes.get(ntpath.normcase(path), 0)

    def readlink(self, path: str) -> str:
        self.calls.append(("readlink", path))
        entry = self.entries.get(ntpath.normcase(path))
        if entry is None or entry[1] is None:
            raise OSError(22, "not a link", path)
        return entry[1]

    def check(self, path: str) -> str | None:
        return locality_problem(
            path, drive_type=self.drive_type, lstat=self.lstat, readlink=self.readlink, get_attributes=self.attributes
        )

    def looked_at(self) -> list[str]:
        """Every path handed to lstat, attributes or readlink."""
        return [path for name, path in self.calls if name != "drive_type"]


class LocalityDecisionTests(unittest.TestCase):
    def uv_disk(self) -> FakeDisk:
        disk = FakeDisk()
        disk.add("C:\\uv")
        disk.add("C:\\uv\\cpython-3.12.13")
        disk.add("C:\\uv\\cpython-3.12.13\\python.exe", _FILE)
        return disk

    def test_refused_forms_are_not_inspected(self) -> None:
        for path in (
            "\\\\host\\share\\python.exe",
            "//host/share/python.exe",
            "\\/host\\share\\python.exe",
            "\\\\?\\C:\\uv\\python.exe",
            "\\\\?\\UNC\\host\\share\\python.exe",
            "\\\\.\\pipe\\x\\python.exe",
            "\\??\\C:\\uv\\python.exe",
            "\\Device\\Mup\\host\\share\\python.exe",
            "C:uv\\python.exe",
            "\\uv\\python.exe",
            "/uv/python.exe",
            "CC:\\uv\\python.exe",
            "C:\\uv\\x:stream\\python.exe",
            "C:\\uv\0\\python.exe",
        ):
            with self.subTest(path=path):
                disk = self.uv_disk()
                self.assertIsNotNone(disk.check(path))
                self.assertEqual(disk.looked_at(), [])

    def test_only_fixed_and_ram_drives(self) -> None:
        for kind, accepted in ((DRIVE_FIXED, True), (6, True), (DRIVE_REMOTE, False), (DRIVE_REMOVABLE, False), (5, False), (0, False), (1, False)):
            with self.subTest(kind=kind):
                disk = FakeDisk({"Z:\\": kind})
                disk.add("Z:\\uv")
                disk.add("Z:\\uv\\python.exe", _FILE)
                problem = disk.check("z:\\uv\\python.exe")
                self.assertEqual(problem is None, accepted, problem)
                if not accepted:
                    self.assertEqual(disk.calls, [("drive_type", "Z:\\")])  # nothing on the drive is looked at

    def test_mapped_network_drive(self) -> None:
        disk = FakeDisk({"C:\\": DRIVE_FIXED, "Z:\\": DRIVE_REMOTE})
        self.assertIn("drive Z: is remote", str(disk.check("Z:\\Python\\python.exe")))

    def test_plain_local_path(self) -> None:
        disk = self.uv_disk()
        self.assertIsNone(disk.check("C:\\uv\\cpython-3.12.13\\python.exe"))
        self.assertIsNone(disk.check("C:/uv/./x/../cpython-3.12.13/python.exe"))

    def test_missing_component_is_refused(self) -> None:
        disk = self.uv_disk()
        result = locality_check(
            "C:\\uv\\gone\\python.exe", drive_type=disk.drive_type, lstat=disk.lstat, readlink=disk.readlink, get_attributes=disk.attributes
        )
        self.assertTrue(result.missing)
        self.assertIn("'C:\\\\uv\\\\gone' does not exist", str(result.problem))
        self.assertIsNotNone(disk.check("C:\\uv\\cpython-3.12.13\\gone.exe"))

    def test_junction_to_local_fixed_drive_is_accepted(self) -> None:
        for target in ("\\\\?\\C:\\uv\\cpython-3.12.13", "\\??\\C:\\uv\\cpython-3.12.13", "C:\\uv\\cpython-3.12.13"):
            with self.subTest(target=target):
                disk = self.uv_disk()
                disk.add("C:\\uv\\cpython-3.12", _JUNCTION, target)
                result = locality_check(
                    "C:\\uv\\cpython-3.12\\python.exe",
                    drive_type=disk.drive_type,
                    lstat=disk.lstat,
                    readlink=disk.readlink,
                    get_attributes=disk.attributes,
                )
                self.assertIsNone(result.problem)
                self.assertEqual(result.chain, (("C:\\uv\\cpython-3.12", target),))
                self.assertIn(("lstat", "C:\\uv\\cpython-3.12.13\\python.exe"), disk.calls)

    def test_unwrapped_target_is_checked_for_its_drive(self) -> None:
        for target in ("\\??\\Z:\\py", "\\\\?\\Z:\\py"):
            with self.subTest(target=target):
                disk = self.uv_disk()
                disk.drives["Z:\\"] = DRIVE_REMOTE
                disk.add("C:\\uv\\cpython-3.12", _JUNCTION, target)
                self.assertIn("link target drive Z: is remote", str(disk.check("C:\\uv\\cpython-3.12\\python.exe")))
                self.assertFalse(any(path.upper().startswith("Z:") for path in disk.looked_at()))

    def test_relative_symlink_is_resolved_from_its_directory(self) -> None:
        disk = self.uv_disk()
        disk.add("C:\\uv\\cpython-3.12", _SYMLINK, "cpython-3.12.13")
        self.assertIsNone(disk.check("C:\\uv\\cpython-3.12\\python.exe"))
        disk.add("C:\\uv\\up", _SYMLINK, "..\\uv\\cpython-3.12.13")
        self.assertIsNone(disk.check("C:\\uv\\up\\python.exe"))

    def test_links_to_remote_targets_are_refused(self) -> None:
        for target in ("\\\\?\\UNC\\host\\share\\py", "\\\\host\\share\\py", "//host/share/py", "\\\\.\\pipe\\py", "\\\\?\\Volume{0}\\py", "Z:\\py"):
            with self.subTest(target=target):
                disk = self.uv_disk()
                disk.drives["Z:\\"] = DRIVE_REMOTE
                disk.add("C:\\uv\\cpython-3.12", _JUNCTION, target)
                problem = disk.check("C:\\uv\\cpython-3.12\\python.exe")
                self.assertIsNotNone(problem)
                self.assertTrue(str(problem).startswith("link target "), problem)
                self.assertFalse(any(path.startswith(("\\\\", "//", "Z:")) for path in disk.looked_at()))

    def test_nt_namespace_and_rooted_targets_are_refused_on_sight(self) -> None:
        targets = (
            "\\Device\\Mup\\host\\share\\py",
            "\\device\\NamedPipe\\py",
            "\\Device\\HarddiskVolume3\\uv\\cpython-3.12.13",
            "\\??\\UNC\\host\\share",
            "\\??\\Volume{0}\\py",
            "\\??\\C:",
            "\\??\\C:x",
            "\\??\\C:\\uv\\..\\uv\\cpython-3.12.13",
            "\\??\\C:/uv/cpython-3.12.13",
            "\\\\?\\C:\\uv\\.\\cpython-3.12.13",
            "\\GLOBAL??\\C:\\uv\\cpython-3.12.13",
            "\\DosDevices\\C:\\uv\\cpython-3.12.13",
            "\\uv\\cpython-3.12.13",
            "/uv/cpython-3.12.13",
            "C:uv\\cpython-3.12.13",
        )
        for target in targets:
            with self.subTest(target=target):
                disk = self.uv_disk()
                disk.add("C:\\Device")  # a local C:\Device must not make \Device\... acceptable
                disk.add("C:\\Device\\HarddiskVolume3")
                disk.add("C:\\uv\\cpython-3.12", _JUNCTION, target)
                problem = disk.check("C:\\uv\\cpython-3.12\\python.exe")
                self.assertIsNotNone(problem)
                self.assertTrue(str(problem).startswith("link target "), problem)
                looked = disk.looked_at()
                self.assertEqual(looked[-1], "C:\\uv\\cpython-3.12")  # the readlink; nothing after it
                self.assertFalse(any("device" in path.lower() or "??" in path for path in looked), looked)

    def test_rewritten_names_are_refused(self) -> None:
        for path in (
            "C:\\uv\\cpython-3.12.13.\\python.exe",
            "C:\\uv\\cpython-3.12.13 \\python.exe",
            "C:\\uv\\...\\python.exe",
            "C:\\uv\\.. \\python.exe",
            "C:\\uv\\cpython-3.12.13\\python.exe.",
            "C:\\uv\\cpython-3.12.13\\python.exe::$DATA",
        ):
            with self.subTest(path=path):
                disk = self.uv_disk()
                self.assertIsNotNone(disk.check(path))
                self.assertEqual(disk.looked_at(), [])
        for target in ("C:\\uv\\cpython-3.12.13.", "cpython-3.12.13 ", "\\\\?\\C:\\uv\\cpython-3.12.13.", "C:\\uv\\a:b\\..\\cpython-3.12.13"):
            with self.subTest(target=target):
                disk = self.uv_disk()
                disk.add("C:\\uv\\cpython-3.12", _SYMLINK, target)
                problem = disk.check("C:\\uv\\cpython-3.12\\python.exe")
                self.assertTrue(str(problem).startswith("link target "), problem)

    def test_link_on_the_last_component(self) -> None:
        disk = self.uv_disk()
        disk.add("C:\\uv\\cpython-3.12.13\\python.exe", _SYMLINK, "\\\\host\\share\\python.exe")
        self.assertIsNotNone(disk.check("C:\\uv\\cpython-3.12.13\\python.exe"))

    def test_loop(self) -> None:
        disk = self.uv_disk()
        disk.add("C:\\a", _JUNCTION, "C:\\b")
        disk.add("C:\\b", _JUNCTION, "C:\\a")
        self.assertIn("loop", str(disk.check("C:\\a\\python.exe")))

    def test_hop_limit(self) -> None:
        disk = self.uv_disk()
        for index in range(HOP_LIMIT + 2):
            disk.add(f"C:\\l{index}", _SYMLINK, f"C:\\l{index + 1}")
        self.assertIn(f"more than {HOP_LIMIT} links", str(disk.check("C:\\l0\\python.exe")))
        short = self.uv_disk()
        for index in range(HOP_LIMIT):
            short.add(f"C:\\l{index}", _SYMLINK, f"C:\\l{index + 1}")
        short.add(f"C:\\l{HOP_LIMIT}")
        short.add(f"C:\\l{HOP_LIMIT}\\python.exe", _FILE)
        self.assertIsNone(short.check("C:\\l0\\python.exe"))

    def test_other_reparse_point_and_unreadable_component(self) -> None:
        disk = self.uv_disk()
        disk.add("C:\\cloud", _JUNCTION, None)  # e.g. a cloud placeholder: readlink fails
        self.assertIn("not a readable link", str(disk.check("C:\\cloud\\python.exe")))

        def denied(path: str) -> os.stat_result:
            raise PermissionError(path)

        problem = locality_problem(
            "C:\\x\\python.exe", drive_type=disk.drive_type, lstat=denied, readlink=disk.readlink, get_attributes=disk.attributes
        )
        self.assertIn("cannot inspect", str(problem))

    def test_reparse_point_invisible_to_lstat_is_refused(self) -> None:
        disk = self.uv_disk()  # lstat says plain directory (os.lstat followed the reparse point)
        disk.extra_attributes[ntpath.normcase("C:\\uv\\cpython-3.12.13")] = stat.FILE_ATTRIBUTE_REPARSE_POINT
        self.assertIn("is a reparse point that is not a symlink or junction", str(disk.check("C:\\uv\\cpython-3.12.13\\python.exe")))
        self.assertNotIn(("readlink", "C:\\uv\\cpython-3.12.13"), disk.calls)
        self.assertNotIn(("lstat", "C:\\uv\\cpython-3.12.13\\python.exe"), disk.calls)

    def test_offline_or_recall_component_is_refused(self) -> None:
        for flag in (locality.FILE_ATTRIBUTE_OFFLINE, locality.FILE_ATTRIBUTE_RECALL_ON_OPEN, locality.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS):
            with self.subTest(flag=flag):
                disk = self.uv_disk()
                disk.extra_attributes[ntpath.normcase("C:\\uv\\cpython-3.12.13\\python.exe")] = flag
                self.assertIn("offline or recalled", str(disk.check("C:\\uv\\cpython-3.12.13\\python.exe")))

    def test_attributes_unreadable_is_refused(self) -> None:
        disk = self.uv_disk()

        def failing(path: str) -> int:
            raise OSError(None, "GetFileAttributesW failed", path, 5)

        problem = locality_problem(
            "C:\\uv\\cpython-3.12.13\\python.exe", drive_type=disk.drive_type, lstat=disk.lstat, readlink=disk.readlink, get_attributes=failing
        )
        self.assertIn("cannot read the attributes", str(problem))

    def test_not_windows_refuses_everything(self) -> None:
        with mock.patch.object(locality.os, "name", "posix"):
            self.assertIsNotNone(locality.local_path_problem("C:\\uv\\python.exe"))


@unittest.skipUnless(os.name == "nt", "Windows junctions")
class RealJunctionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.real = os.path.join(self.dir, "cpython-3.12.13")
        os.mkdir(self.real)
        with open(os.path.join(self.real, "python.exe"), "wb"):
            pass

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_real_local_junction_is_accepted(self) -> None:
        import _winapi

        junction = os.path.join(self.dir, "cpython-3.12")
        _winapi.CreateJunction(self.real, junction)
        result = locality.local_path_check(os.path.join(junction, "python.exe"))
        self.assertIsNone(result.problem)
        ((link, target),) = result.chain
        self.assertEqual(link.lower(), junction.lower())
        self.assertTrue(target.startswith("\\\\?\\"), target)  # what os.readlink returns for \??\X:\ junctions
        self.assertIsNone(locality.local_path_problem(os.path.join(self.real, "python.exe")))
        self.assertTrue(locality.local_path_check(os.path.join(self.real, "gone.exe")).missing)

    def test_real_attributes_of_a_plain_directory(self) -> None:
        attributes = locality.windows_file_attributes(self.real)
        self.assertTrue(attributes & stat.FILE_ATTRIBUTE_DIRECTORY)
        self.assertFalse(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        with self.assertRaises(OSError):
            locality.windows_file_attributes(os.path.join(self.dir, "gone"))

    def test_real_rooted_symlink_is_refused(self) -> None:
        # The target is local (the same tree without its drive letter), so following it would be harmless;
        # the check must still refuse it instead of joining it onto a drive.
        link = os.path.join(self.dir, "rooted")
        rooted = ntpath.splitdrive(self.real)[1]
        try:
            os.symlink(rooted, link, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"cannot create a symlink here: {error}")
        problem = locality.local_path_problem(os.path.join(link, "python.exe"))
        self.assertIsNotNone(problem)
        self.assertIn("rooted without a drive letter", str(problem))


class ReservedDeviceNameTests(unittest.TestCase):
    """Win32 opens a device for these names, so neither home nor a link target may contain one."""

    NAMES = (
        "CON", "prn", "Aux", "nul", "COM1", "com9", "LPT1", "lpt9",
        "COM\u00b9", "com\u00b2", "LPT\u00b3", "nul.txt", "Con.tar.gz", "COM1 .log", "lpt1. .x", "NUL  .exe",
    )

    def test_reserved_name_in_home_is_refused_without_looking(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                disk = FakeDisk()
                problem = disk.check(ntpath.join(r"C:\uv", name, "python.exe"))
                self.assertIsNotNone(problem)
                self.assertIn("reserved device name", str(problem))
                self.assertEqual(disk.looked_at(), [])

    def test_reserved_name_as_the_last_component_is_refused(self) -> None:
        disk = FakeDisk()
        self.assertIn("reserved device name", str(disk.check(r"C:\uv\NUL")))

    def test_reserved_name_in_a_link_target_is_refused(self) -> None:
        for target in (r"C:\aux\cpython", r"\??\C:\x\COM3.dir", "..\\lpt\u00b2"):
            with self.subTest(target=target):
                disk = FakeDisk()
                disk.add(r"C:\uv")
                disk.add(r"C:\uv\link", _JUNCTION, target)
                problem = disk.check(r"C:\uv\link\python.exe")
                self.assertIsNotNone(problem)
                self.assertTrue(str(problem).startswith("link target "), problem)
                self.assertIn("reserved device name", str(problem))
                self.assertEqual(disk.looked_at(), [r"C:\uv", r"C:\uv", r"C:\uv\link", r"C:\uv\link", r"C:\uv\link"])

    def test_names_that_only_look_alike_are_allowed(self) -> None:
        for name in ("CONSOLE", "COM10", "COM0", "LPT0", "nulls", "xcon", "AUX1", "COM\u2074", "PRN_", ".con"):
            with self.subTest(name=name):
                disk = FakeDisk()
                disk.add(r"C:\uv")
                disk.add(ntpath.join(r"C:\uv", name))
                disk.add(ntpath.join(r"C:\uv", name, "python.exe"), _FILE)
                self.assertIsNone(disk.check(ntpath.join(r"C:\uv", name, "python.exe")))
