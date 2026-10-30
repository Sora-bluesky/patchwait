"""Build synthetic minimal PE files with a VS_VERSIONINFO resource.

Everything here is synthetic. No real binary is read or copied.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

FILE_ALIGN = 0x200
RSRC_RVA = 0x1000
RT_VERSION = 16
RT_ICON = 3


def _pad4(buf: bytearray) -> None:
    buf += b"\0" * (-len(buf) % 4)


def vs_node(key: str, value: bytes = b"", *, text: bool = False, children: tuple[bytes, ...] = ()) -> bytes:
    buf = bytearray(6)
    buf += key.encode("utf-16-le") + b"\0\0"
    _pad4(buf)
    buf += value
    for child in children:
        _pad4(buf)
        buf += child
    value_length = len(value) // 2 if text else len(value)
    struct.pack_into("<HHH", buf, 0, len(buf), value_length, 1 if text else 0)
    return bytes(buf)


def vs_string(key: str, value: str) -> bytes:
    return vs_node(key, (value + "\0").encode("utf-16-le"), text=True)


def _split(version: tuple[int, int, int, int]) -> tuple[int, int]:
    a, b, c, d = version
    return (a << 16) | b, (c << 16) | d


def fixed_file_info(file_version: tuple[int, int, int, int], product_version: tuple[int, int, int, int], *, signature: int = 0xFEEF04BD) -> bytes:
    fms, fls = _split(file_version)
    pms, pls = _split(product_version)
    return struct.pack("<13I", signature, 0x10000, fms, fls, pms, pls, 0x3F, 0, 0x40004, 1, 0, 0, 0)


@dataclass
class VersionSpec:
    strings: dict[str, str] = field(default_factory=dict)
    fixed_file: tuple[int, int, int, int] = (1, 0, 0, 0)
    fixed_product: tuple[int, int, int, int] = (1, 0, 0, 0)
    signature: int = 0xFEEF04BD


def version_blob(spec: VersionSpec) -> bytes:
    entries = tuple(vs_string(k, v) for k, v in spec.strings.items())
    table = vs_node("040904B0", children=entries)
    sfi = vs_node("StringFileInfo", text=True, children=(table,))
    var = vs_node("VarFileInfo", text=True, children=(vs_node("Translation", b"\x09\x04\xb0\x04"),))
    fixed = fixed_file_info(spec.fixed_file, spec.fixed_product, signature=spec.signature)
    return vs_node("VS_VERSION_INFO", fixed, children=(sfi, var))


def _directory(entries: list[tuple[int, int]]) -> bytes:
    out = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))
    for name, offset in entries:
        out += struct.pack("<II", name, offset)
    return out


def resource_section(type_id: int, payload: bytes) -> bytes:
    """Root -> type -> name 1 -> lang 0x409 -> data entry -> payload."""
    root_off, type_off, name_off, data_entry_off, payload_off = 0, 24, 48, 72, 88
    buf = bytearray()
    buf += _directory([(type_id, 0x80000000 | type_off)])
    buf += _directory([(1, 0x80000000 | name_off)])
    buf += _directory([(0x409, data_entry_off)])
    assert len(buf) == data_entry_off and root_off == 0
    buf += struct.pack("<IIII", RSRC_RVA + payload_off, len(payload), 0, 0)
    assert len(buf) == payload_off
    buf += payload
    return bytes(buf)


@dataclass
class Layout:
    """Byte offsets inside a built file, for corruption tests."""

    e_lfanew: int
    resource_dir_entry: int  # file offset of the resource data directory (rva, size)
    rsrc_offset: int  # file offset of the .rsrc raw data
    data_entry: int  # file offset of the IMAGE_RESOURCE_DATA_ENTRY
    payload: int  # file offset of the VS_VERSIONINFO blob


def build_pe(
    *,
    version: VersionSpec | None,
    pe32_plus: bool = True,
    resource_type: int = RT_VERSION,
    with_resource_dir: bool = True,
) -> tuple[bytes, Layout]:
    """Return a synthetic PE image. ``version=None`` puts an RT_ICON-only tree."""
    if version is None:
        rsrc = resource_section(RT_ICON, b"\0" * 16)
    else:
        rsrc = resource_section(resource_type, version_blob(version))
    raw_size = len(rsrc) + (-len(rsrc) % FILE_ALIGN)

    e_lfanew = 0x40
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    if pe32_plus:
        magic, machine, dirs_at, opt_len = 0x20B, 0x8664, 112, 112 + 16 * 8
    else:
        magic, machine, dirs_at, opt_len = 0x10B, 0x14C, 96, 96 + 16 * 8
    opt = bytearray(opt_len)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<I", opt, dirs_at - 4, 16)
    if with_resource_dir:
        struct.pack_into("<II", opt, dirs_at + 16, RSRC_RVA, len(rsrc))

    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_len, 0x22)
    section = struct.pack(
        "<8sIIIIIIHHI", b".rsrc", len(rsrc), RSRC_RVA, raw_size, FILE_ALIGN, 0, 0, 0, 0, 0x40000040
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + section
    assert len(headers) <= FILE_ALIGN
    image = headers + b"\0" * (FILE_ALIGN - len(headers)) + rsrc + b"\0" * (raw_size - len(rsrc))
    layout = Layout(
        e_lfanew=e_lfanew,
        resource_dir_entry=e_lfanew + 24 + dirs_at + 16,
        rsrc_offset=FILE_ALIGN,
        data_entry=FILE_ALIGN + 72,
        payload=FILE_ALIGN + 88,
    )
    return image, layout


NODE_LIKE = VersionSpec(
    strings={"ProductName": "Node.js", "FileVersion": "24.19.0", "ProductVersion": "24.19.0"},
    fixed_file=(24, 19, 0, 0),
    fixed_product=(24, 19, 0, 0),
)

PYTHON_LIKE = VersionSpec(
    strings={"ProductName": "Python", "FileVersion": "3.14.6", "ProductVersion": "3.14.6"},
    fixed_file=(3, 14, 6150, 1013),
    fixed_product=(3, 14, 6150, 1013),
)
