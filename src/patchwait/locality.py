"""Decide whether a path is on a local fixed drive, without opening it.

Opening ``\\\\host\\share\\python.exe`` (or a local junction that points there,
or a file on a mapped network drive) makes an outbound SMB connection, which
can leak NTLM credentials; ``\\\\.\\pipe\\x`` can block. So before a path named by
a file we read (``pyvenv.cfg``'s ``home``) is opened, it must pass
:func:`locality_check`:

- the path is ``X:\\...`` with a single ASCII drive letter; UNC (``\\\\`` or
  ``//``), device (``\\\\.\\``), extended (``\\\\?\\``) and rooted forms without a
  drive (``\\x``) are refused;
- ``GetDriveTypeW`` says the drive is fixed or a RAM disk (removable, CD-ROM,
  remote, unknown and no-root drives are refused: none of them is where an
  installed interpreter normally lives, and removable or remote media can block
  or reach the network);
- no component ends in ``.`` or a space (other than ``.`` and ``..`` themselves)
  or has a ``:`` after the drive: Win32 would rewrite such a name, so the object
  checked could differ from the one opened;
- no component is a reserved device name (``CON``, ``PRN``, ``AUX``, ``NUL``,
  ``COM1``-``COM9``, ``LPT1``-``LPT9`` and ``COM¹``-``COM³``, ``LPT¹``-``LPT³``)
  in any case, whatever follows its first dot and with trailing spaces and dots
  ignored (``nul.txt``, ``Com1 .log``): older Windows versions (Windows 10 and
  earlier) open the device, not a file, for these names, and newer builds treat
  some of them as ordinary files; since the behaviour differs between builds,
  they are refused on every version;
- walking from the drive root, every component must exist. It is ``lstat``-ed
  and its attributes are read with ``GetFileAttributesW`` (``lstat`` follows
  reparse points that are not symlinks or junctions, so their reparse attribute
  can be invisible to it). A symlink or junction has its target read with
  ``readlink`` (which opens the link, never the target) and that target is
  checked the same way, up to :data:`HOP_LIMIT` links and without revisiting a
  path. A link target in the NT namespace (``\\Device\\``, ``\\??\\``,
  ``\\GLOBAL??\\``, ``\\DosDevices\\``, ``\\\\?\\UNC\\``, ``\\\\.\\``) or rooted without a
  drive is refused on sight; only ``\\??\\X:\\...`` and ``\\\\?\\X:\\...`` are
  unwrapped to ``X:\\...`` and checked like any other path. Relative targets are
  joined to the link's directory. Any other reparse point (for example a cloud
  placeholder) and any component marked offline or recall-on-access is refused.

``os.path.realpath`` and ``GetFinalPathNameByHandle`` are not used: both open
the path. A component that does not exist is refused (reported as missing).
The check returns the chain of links and targets it walked so that a caller
can run it again after opening the path and see whether anything changed. This
check is Windows-only; elsewhere every path is refused.
"""

from __future__ import annotations

import ntpath
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass

HOP_LIMIT = 16

DRIVE_FIXED = 3
DRIVE_RAMDISK = 6
_LOCAL_DRIVE_TYPES = frozenset({DRIVE_FIXED, DRIVE_RAMDISK})
_DRIVE_TYPE_NAMES = {0: "unknown", 1: "no root directory", 2: "removable", 4: "remote", 5: "cd-rom"}

FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_RECALL_ATTRIBUTES = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

_DRIVE_RE = re.compile(r"[A-Za-z]:")
# The only NT-namespace link targets that are unwrapped: \??\X:\... and \\?\X:\...
_NT_DRIVE_RE = re.compile(r"(?:\\\?\?\\|\\\\\?\\)([A-Za-z]:\\.*)", re.DOTALL)
# Refused when a name's part before the first dot, trailing spaces and dots removed, is one of
# these (any case; the superscript digits are U+00B9, U+00B2 and U+00B3). Older Windows versions
# (Windows 10 and earlier) open the device for such a name; newer builds treat some of them as
# files. The behaviour differs between builds, so they are refused on every version.
_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"{device}{digit}" for device in ("COM", "LPT") for digit in "123456789¹²³"]
)
_NT_PREFIXES = ("\\??\\", "\\\\?\\", "\\\\.\\", "\\device\\", "\\global??\\", "\\dosdevices\\")

DriveType = Callable[[str], int]
Lstat = Callable[[str], os.stat_result]
Readlink = Callable[[str], str]
GetAttributes = Callable[[str], int]


def windows_drive_type(root: str) -> int:
    """``GetDriveTypeW(root)``; ``root`` is ``X:\\``.

    It takes a root path, not a handle; whether it touches the volume (for example
    to ask a network redirector) is up to Windows and is not documented.
    """
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
    get_drive_type = kernel32.GetDriveTypeW  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return int(get_drive_type(root))  # pyright: ignore[reportUnknownArgumentType]


def windows_file_attributes(path: str) -> int:
    """``GetFileAttributesW(path)``: the attributes of ``path`` itself (a link is not followed); OSError on failure."""
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
    get_attributes = kernel32.GetFileAttributesW  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    value = int(get_attributes(path))  # pyright: ignore[reportUnknownArgumentType]
    if value == _INVALID_FILE_ATTRIBUTES:
        code = int(ctypes.get_last_error())  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownArgumentType]
        raise OSError(None, "GetFileAttributesW failed", path, code)
    return value


@dataclass(frozen=True, slots=True)
class Locality:
    """Result of :func:`locality_check`.

    ``problem`` is None when the path is local; ``missing`` is True when the only
    problem is that a component does not exist; ``chain`` is every (link, target)
    pair that was followed, in order.
    """

    problem: str | None
    missing: bool
    chain: tuple[tuple[str, str], ...]


def _is_link_like(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes: object = getattr(info, "st_file_attributes", 0)
    return isinstance(attributes, int) and bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _drive_problem(path: str, drive_type: DriveType) -> str | None:
    if "\0" in path:
        return f"{path!r} contains NUL"
    if len(path) >= 2 and path[0] in "\\/" and path[1] in "\\/":
        return f"{path!r} is a UNC or device path"
    drive, rest = ntpath.splitdrive(path)
    if not _DRIVE_RE.fullmatch(drive) or not rest.startswith(("\\", "/")):
        return f"{path!r} is not an absolute drive-letter path"
    kind = drive_type(drive.upper() + "\\")
    if kind not in _LOCAL_DRIVE_TYPES:
        return f"drive {drive.upper()} is {_DRIVE_TYPE_NAMES.get(kind, f'type {kind}')}, not a local fixed drive"
    return None


def _component_problem(path: str) -> str | None:
    """Names that Win32 would rewrite: trailing dot or space, a ``:`` after the drive, or a device name."""
    _, rest = ntpath.splitdrive(path)
    for part in re.split(r"[\\/]+", rest):
        if part in ("", ".", ".."):
            continue
        if ":" in part:
            return f"{path!r} has a ':' after the drive"
        if part.endswith((".", " ")):
            return f"{path!r} has a component ending in a dot or space ({part!r})"
        if part.split(".", 1)[0].rstrip(" .").upper() in _RESERVED_NAMES:
            return f"{path!r} has a component that is a reserved device name ({part!r})"
    return None


def _link_target(link: str, target: str) -> tuple[str | None, str | None]:
    """A link's target as a plain path to check, or why it is refused on sight."""
    unwrapped = _NT_DRIVE_RE.fullmatch(target)
    if unwrapped is not None:
        plain = unwrapped.group(1)
        if "/" in plain or any(part in (".", "..") for part in plain.split("\\")):
            return None, f"{target!r} is an NT-namespace path with '/', '.' or '..'"  # not normalised by Win32
        return plain, None
    if target.lower().startswith(_NT_PREFIXES):
        return None, f"{target!r} is an NT-namespace or device path"
    if len(target) >= 2 and target[0] in "\\/" and target[1] in "\\/":
        return None, f"{target!r} is a UNC or device path"
    if target.startswith(("\\", "/")):
        return None, f"{target!r} is rooted without a drive letter"
    if ntpath.splitdrive(target)[0] != "":
        return target, None  # X:\... is checked as usual; X:rel is refused by the drive check
    return ntpath.join(ntpath.dirname(link), target), None


def locality_check(
    path: str,
    *,
    drive_type: DriveType,
    lstat: Lstat = os.lstat,
    readlink: Readlink = os.readlink,
    get_attributes: GetAttributes = windows_file_attributes,
    hop_limit: int = HOP_LIMIT,
) -> Locality:
    """Whether ``path`` and every link on the way stay on local fixed drives, and the links walked."""
    chain: list[tuple[str, str]] = []

    def refused(problem: str, *, missing: bool = False) -> Locality:
        return Locality(problem if not chain else f"link target {problem}", missing, tuple(chain))

    current = path
    seen: set[str] = set()
    while True:
        problem = _drive_problem(current, drive_type) or _component_problem(current)
        if problem is not None:
            return refused(problem)
        current = ntpath.normpath(current)
        key = ntpath.normcase(current)
        if key in seen:
            return refused(f"links loop at {current!r}")
        seen.add(key)
        drive, rest = ntpath.splitdrive(current)
        parts = [part for part in re.split(r"[\\/]+", rest) if part != ""]
        prefix = drive.upper() + "\\"
        followed = False
        for index, part in enumerate(parts):
            prefix = ntpath.join(prefix, part)
            try:
                info = lstat(prefix)
            except (FileNotFoundError, NotADirectoryError):
                return refused(f"{prefix!r} does not exist", missing=True)
            except OSError as error:
                return refused(f"cannot inspect {prefix!r}: {type(error).__name__}")
            try:
                attributes = get_attributes(prefix)
            except OSError as error:
                return refused(f"cannot read the attributes of {prefix!r}: {type(error).__name__}")
            if attributes & _RECALL_ATTRIBUTES:
                return refused(f"{prefix!r} is offline or recalled on access")
            link_like = _is_link_like(info)
            if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT and not link_like:
                return refused(f"{prefix!r} is a reparse point that is not a symlink or junction")
            if not link_like:
                continue
            try:
                target = readlink(prefix)
            except OSError as error:
                return refused(f"{prefix!r} is a reparse point that is not a readable link: {type(error).__name__}")
            chain.append((prefix, target))
            if len(chain) > hop_limit:
                return refused(f"more than {hop_limit} links")
            plain, problem = _link_target(prefix, target)
            if plain is None:
                return refused(str(problem))
            current = ntpath.join(plain, *parts[index + 1 :])
            followed = True
            break
        if not followed:
            return Locality(None, False, tuple(chain))


def locality_problem(
    path: str,
    *,
    drive_type: DriveType,
    lstat: Lstat = os.lstat,
    readlink: Readlink = os.readlink,
    get_attributes: GetAttributes = windows_file_attributes,
    hop_limit: int = HOP_LIMIT,
) -> str | None:
    """None when ``path`` and every link on the way stay on local fixed drives; else why not."""
    return locality_check(
        path, drive_type=drive_type, lstat=lstat, readlink=readlink, get_attributes=get_attributes, hop_limit=hop_limit
    ).problem


def local_path_check(path: str) -> Locality:
    """:func:`locality_check` with the real drive type and attributes; every path is refused off Windows."""
    if os.name != "nt":
        return Locality("local-drive check is only available on Windows", False, ())
    return locality_check(path, drive_type=windows_drive_type)


def local_path_problem(path: str) -> str | None:
    """:func:`local_path_check`'s problem, or None."""
    return local_path_check(path).problem
