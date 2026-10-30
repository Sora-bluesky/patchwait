"""Read the version resource of a Windows PE file with the standard library only.

The file is only read, with seeks, never loaded whole into memory, and never
handed to an OS loader API or executed. Every offset and length is checked
against the file size; malformed input yields ``Undetermined``, never an
exception or an unbounded loop.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from typing import BinaryIO

from patchwait.model import (
    Check,
    Component,
    Found,
    NotFound,
    Reason,
    RuntimeKind,
    Undetermined,
)

EVIDENCE = "pe-version-resource"

RT_VERSION = 16
_FIXED_SIGNATURE = 0xFEEF04BD
_MAX_SECTIONS = 96
_MAX_DIR_ENTRIES = 4096
_MAX_VERSION_BLOB = 1 << 20  # VS_VERSIONINFO is a few KiB in practice
_OPT_MAGIC_PE32 = 0x10B
_OPT_MAGIC_PE32_PLUS = 0x20B
_RESOURCE_DIR_INDEX = 2

# ASCII digits only ([0-9], not \d, which also matches Arabic-Indic or fullwidth digits). Runs are
# capped so int() never meets a huge run, and may not be followed by any digit: the lookahead keeps
# \d on purpose, so a non-ASCII digit right after the third part refuses the string too.
_VERSION_RE = re.compile(r"^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(?!\d)")

_EXPECTED_PRODUCT: dict[RuntimeKind, str] = {
    RuntimeKind.NODE: "Node.js",
    RuntimeKind.PYTHON: "Python",
}


@dataclass(frozen=True, slots=True)
class VersionInfo:
    """Parsed contents of a VS_VERSIONINFO resource."""

    product_name: str | None
    product_version: str | None
    file_version: str | None
    fixed_file_version: tuple[int, int, int, int]
    fixed_product_version: tuple[int, int, int, int]


class _Fail(Exception):
    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _malformed(detail: str) -> _Fail:
    return _Fail(Reason.MALFORMED_VERSION_RESOURCE, detail)


class _Reader:
    """Bounded random access over an open file."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        self._stream = stream
        self.size = size

    def read(self, offset: int, length: int, what: str, *, not_pe: bool = False) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            if not_pe:
                raise _Fail(Reason.NOT_PE, f"{what} is outside the file")
            raise _malformed(f"{what} is outside the file")
        self._stream.seek(offset)
        data = self._stream.read(length)
        if len(data) != length:
            raise _malformed(f"short read at {what}")
        return data


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_pointer: int


def _rva_to_offset(sections: list[_Section], rva: int, length: int, what: str) -> int:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            if delta + length > section.raw_size:
                raise _malformed(f"{what} extends past its section's raw data")
            return section.raw_pointer + delta
    raise _malformed(f"{what} RVA is not inside any section")


def _read_sections_and_resource_rva(reader: _Reader) -> tuple[list[_Section], int, int]:
    dos = reader.read(0, 64, "DOS header", not_pe=True)
    if dos[:2] != b"MZ":
        raise _Fail(Reason.NOT_PE, "no MZ signature")
    (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
    if reader.read(e_lfanew, 4, "PE signature", not_pe=True) != b"PE\0\0":
        raise _Fail(Reason.NOT_PE, "no PE signature")
    coff = reader.read(e_lfanew + 4, 20, "COFF header", not_pe=True)
    _machine, n_sections, _ts, _sym, _nsym, opt_size, _chars = struct.unpack("<HHIIIHH", coff)
    if n_sections > _MAX_SECTIONS:
        raise _malformed("too many sections")
    opt_offset = e_lfanew + 24
    opt = reader.read(opt_offset, opt_size, "optional header")
    if len(opt) < 2:
        raise _malformed("optional header too small")
    (magic,) = struct.unpack_from("<H", opt, 0)
    if magic == _OPT_MAGIC_PE32:
        count_at, dirs_at = 92, 96
    elif magic == _OPT_MAGIC_PE32_PLUS:
        count_at, dirs_at = 108, 112
    else:
        raise _Fail(Reason.NOT_PE, "unknown optional header magic")
    if len(opt) < count_at + 4:
        raise _malformed("optional header too small")
    (n_dirs,) = struct.unpack_from("<I", opt, count_at)
    if n_dirs <= _RESOURCE_DIR_INDEX:
        raise _Fail(Reason.NO_VERSION_RESOURCE, "no resource data directory")
    entry_at = dirs_at + 8 * _RESOURCE_DIR_INDEX
    if len(opt) < entry_at + 8:
        raise _malformed("optional header too small for data directories")
    rsrc_rva, rsrc_size = struct.unpack_from("<II", opt, entry_at)
    if rsrc_rva == 0 or rsrc_size == 0:
        raise _Fail(Reason.NO_VERSION_RESOURCE, "empty resource data directory")

    table = reader.read(opt_offset + opt_size, 40 * n_sections, "section table")
    sections: list[_Section] = []
    for i in range(n_sections):
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", table, 40 * i + 8)
        sections.append(_Section(vaddr, vsize, rsize, rptr))
    return sections, rsrc_rva, rsrc_size


def _read_directory(
    reader: _Reader, base: int, rel: int, limit: int, what: str
) -> list[tuple[int, int]]:
    """Return (name_field, offset_field) pairs of one IMAGE_RESOURCE_DIRECTORY."""
    if rel < 0 or rel + 16 > limit:
        raise _malformed(f"{what} directory outside the resource section")
    header = reader.read(base + rel, 16, f"{what} directory")
    n_named, n_ids = struct.unpack_from("<HH", header, 12)
    total = n_named + n_ids
    if total > _MAX_DIR_ENTRIES:
        raise _malformed(f"{what} directory has too many entries")
    if rel + 16 + 8 * total > limit:
        raise _malformed(f"{what} directory entries outside the resource section")
    raw = reader.read(base + rel + 16, 8 * total, f"{what} directory entries")
    return [struct.unpack_from("<II", raw, 8 * i) for i in range(total)]


def _subdirectory(offset_field: int, what: str) -> int:
    if not offset_field & 0x80000000:
        raise _malformed(f"{what} entry is not a directory")
    return offset_field & 0x7FFFFFFF


def _read_version_blob(reader: _Reader) -> bytes:
    sections, rsrc_rva, rsrc_size = _read_sections_and_resource_rva(reader)
    base = _rva_to_offset(sections, rsrc_rva, 16, "resource directory")
    limit = min(rsrc_size, reader.size - base)

    root = _read_directory(reader, base, 0, limit, "root")
    version_type = next(
        (off for name, off in root if name == RT_VERSION), None
    )
    if version_type is None:
        raise _Fail(Reason.NO_VERSION_RESOURCE, "no RT_VERSION resource")
    names = _read_directory(reader, base, _subdirectory(version_type, "type"), limit, "name")
    if not names:
        raise _malformed("RT_VERSION has no entries")
    langs = _read_directory(reader, base, _subdirectory(names[0][1], "name"), limit, "language")
    if not langs:
        raise _malformed("RT_VERSION has no language entries")
    leaf = langs[0][1]
    if leaf & 0x80000000:
        raise _malformed("language entry is not a data entry")
    if leaf + 16 > limit:
        raise _malformed("data entry outside the resource section")
    data_rva, data_size = struct.unpack("<II", reader.read(base + leaf, 8, "data entry"))
    if data_size == 0 or data_size > _MAX_VERSION_BLOB:
        raise _malformed("version resource size out of range")
    data_offset = _rva_to_offset(sections, data_rva, data_size, "version resource data")
    return reader.read(data_offset, data_size, "version resource data")


# --- VS_VERSIONINFO ---------------------------------------------------------


def _align4(value: int) -> int:
    return (value + 3) & ~3


@dataclass(frozen=True, slots=True)
class _Node:
    key: str
    value_start: int
    value_length: int  # in bytes, clamped to the node
    is_text: bool
    children_start: int
    end: int


def _parse_node(blob: bytes, offset: int, end: int) -> _Node:
    if offset + 6 > end:
        raise _malformed("version node header truncated")
    length, value_length, value_type = struct.unpack_from("<HHH", blob, offset)
    if length < 6 or offset + length > end:
        raise _malformed("version node length out of range")
    node_end = offset + length
    key_end = offset + 6
    while True:
        if key_end + 2 > node_end:
            raise _malformed("version node key not terminated")
        if blob[key_end : key_end + 2] == b"\0\0":
            break
        key_end += 2
    try:
        key = blob[offset + 6 : key_end].decode("utf-16-le")
    except UnicodeDecodeError:
        raise _malformed("version node key is not UTF-16") from None
    value_start = min(_align4(key_end + 2), node_end)
    is_text = value_type == 1
    value_bytes = value_length * 2 if is_text else value_length
    value_bytes = min(value_bytes, node_end - value_start)
    children_start = min(_align4(value_start + value_bytes), node_end)
    return _Node(key, value_start, value_bytes, is_text, children_start, node_end)


def _children(blob: bytes, node: _Node) -> list[_Node]:
    result: list[_Node] = []
    offset = node.children_start
    while offset + 6 <= node.end:
        child = _parse_node(blob, offset, node.end)
        result.append(child)
        offset = _align4(child.end)  # child length >= 6, so this always advances
    return result


def _text_value(blob: bytes, node: _Node) -> str:
    # Some writers count wValueLength in bytes, some include the NUL; read to
    # the end of the node and stop at the first NUL instead of trusting it.
    raw = blob[node.value_start : node.end]
    raw = raw[: len(raw) - len(raw) % 2]
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        raise _malformed("version string is not UTF-16") from None
    return text.split("\0", 1)[0].strip()


def _parse_version_info(blob: bytes) -> VersionInfo:
    root = _parse_node(blob, 0, len(blob))
    if root.key != "VS_VERSION_INFO":
        raise _malformed("root key is not VS_VERSION_INFO")
    if root.value_length < 52:
        raise _malformed("VS_FIXEDFILEINFO missing")
    fixed = struct.unpack_from("<13I", blob, root.value_start)
    if fixed[0] != _FIXED_SIGNATURE:
        raise _malformed("VS_FIXEDFILEINFO signature mismatch")
    file_ms, file_ls, prod_ms, prod_ls = fixed[2:6]

    strings: dict[str, str] = {}
    for child in _children(blob, root):
        if child.key != "StringFileInfo":
            continue
        for table in _children(blob, child):
            for entry in _children(blob, table):
                if entry.key not in strings:
                    strings[entry.key] = _text_value(blob, entry)

    def split(ms: int, ls: int) -> tuple[int, int, int, int]:
        return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)

    return VersionInfo(
        product_name=strings.get("ProductName") or None,
        product_version=strings.get("ProductVersion") or None,
        file_version=strings.get("FileVersion") or None,
        fixed_file_version=split(file_ms, file_ls),
        fixed_product_version=split(prod_ms, prod_ls),
    )


# --- public API -------------------------------------------------------------


def read_version_info(path: str | os.PathLike[str]) -> Found[VersionInfo] | Undetermined:
    """Parse the VS_VERSIONINFO resource of ``path`` without executing it."""
    try:
        with open(path, "rb") as stream:
            return read_version_info_from(stream)
    except OSError as error:
        return Undetermined(Reason.FILE_UNREADABLE, type(error).__name__)


def read_version_info_from(stream: BinaryIO) -> Found[VersionInfo] | Undetermined:
    """Parse the VS_VERSIONINFO resource of an already open binary file; the caller closes it."""
    try:
        size = os.fstat(stream.fileno()).st_size
        blob = _read_version_blob(_Reader(stream, size))
    except _Fail as fail:
        return Undetermined(fail.reason, fail.detail)
    except OSError as error:
        return Undetermined(Reason.FILE_UNREADABLE, type(error).__name__)
    try:
        return Found(_parse_version_info(blob))
    except _Fail as fail:
        return Undetermined(fail.reason, fail.detail)


def version_from_info(info: VersionInfo) -> Found[str] | Undetermined:
    """String-table ProductVersion (fallback FileVersion), cross-checked on major.minor."""
    if info.product_version is not None:
        text, fixed = info.product_version, info.fixed_product_version
        label = "ProductVersion"
    elif info.file_version is not None:
        text, fixed = info.file_version, info.fixed_file_version
        label = "FileVersion"
    else:
        return Undetermined(Reason.MALFORMED_VERSION_RESOURCE, "no ProductVersion or FileVersion string")
    # The pattern only anchors the N.N.N prefix (a suffix such as "rc1" is kept), so the
    # whole string is checked separately: a non-ASCII or unprintable suffix is not a version.
    match = _VERSION_RE.match(text) if text.isascii() and text.isprintable() else None
    if match is None:
        return Undetermined(Reason.MALFORMED_VERSION_RESOURCE, f"{label} is not N.N.N: {text!r}")
    major, minor, _ = (int(part) for part in match.group(0).split("."))
    if (major, minor) != fixed[:2]:
        return Undetermined(
            Reason.VERSION_MISMATCH,
            f"{label} {text!r} disagrees with fixed info {'.'.join(map(str, fixed))}",
        )
    return Found(text)


def read_runtime_version(path: str | os.PathLike[str]) -> Found[str] | Undetermined:
    info = read_version_info(path)
    if isinstance(info, Undetermined):
        return info
    return version_from_info(info.value)


def detect_runtime(path: str | os.PathLike[str], expected: RuntimeKind) -> Check[Component]:
    """Identify a bundled runtime at ``path``.

    Absent file -> NotFound. Unreadable or unidentifiable file -> Undetermined.
    Identified product -> Found(Component); its ``version`` may itself be
    Undetermined (for example VERSION_MISMATCH).
    """
    if not os.path.lexists(path):
        return NotFound()
    info = read_version_info(path)
    if isinstance(info, Undetermined):
        return info
    want = _EXPECTED_PRODUCT[expected]
    got = info.value.product_name
    if got != want:
        return Undetermined(Reason.UNEXPECTED_PRODUCT, f"ProductName {got!r}, expected {want!r}")
    return Found(
        Component(
            kind=expected,
            location=os.fspath(path),
            version=version_from_info(info.value),
            evidence=EVIDENCE,
        )
    )
