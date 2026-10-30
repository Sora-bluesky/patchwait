from __future__ import annotations

import os
import random
import struct
import tempfile
import unittest
from dataclasses import replace

from patchwait.model import Component, Found, NotFound, Reason, RuntimeKind, Undetermined
from patchwait.pe_version import detect_runtime, read_runtime_version, read_version_info
from tests.pe_builder import NODE_LIKE, PYTHON_LIKE, VersionSpec, build_pe


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def assert_undetermined(self, result: object, reason: Reason) -> None:
        self.assertIsInstance(result, Undetermined, result)
        assert isinstance(result, Undetermined)
        self.assertEqual(result.reason, reason, result.detail)
        self.assertNotIn(self.dir, result.detail)


class DetectionTests(TempDirCase):
    def test_node_like_pe32_plus(self) -> None:
        image, _ = build_pe(version=NODE_LIKE)
        path = self.write("node.exe", image)
        self.assertEqual(read_runtime_version(path), Found("24.19.0"))
        result = detect_runtime(path, RuntimeKind.NODE)
        self.assertEqual(
            result,
            Found(Component(RuntimeKind.NODE, path, Found("24.19.0"), "pe-version-resource")),
        )

    def test_node_like_pe32(self) -> None:
        image, _ = build_pe(version=NODE_LIKE, pe32_plus=False)
        path = self.write("node32.exe", image)
        self.assertEqual(read_runtime_version(path), Found("24.19.0"))

    def test_python_like_uses_string_version_not_fixed(self) -> None:
        image, _ = build_pe(version=PYTHON_LIKE)
        path = self.write("python.exe", image)
        info = read_version_info(path)
        assert isinstance(info, Found)
        self.assertEqual(info.value.fixed_product_version, (3, 14, 6150, 1013))
        self.assertEqual(read_runtime_version(path), Found("3.14.6"))
        result = detect_runtime(path, RuntimeKind.PYTHON)
        assert isinstance(result, Found)
        self.assertEqual(result.value.version, Found("3.14.6"))

    def test_file_version_fallback(self) -> None:
        spec = replace(NODE_LIKE, strings={"ProductName": "Node.js", "FileVersion": "24.19.0"})
        path = self.write("node.exe", build_pe(version=spec)[0])
        self.assertEqual(read_runtime_version(path), Found("24.19.0"))

    def test_absent_path_is_not_found(self) -> None:
        self.assertEqual(detect_runtime(os.path.join(self.dir, "missing.exe"), RuntimeKind.NODE), NotFound())

    def test_absent_path_version_is_unreadable(self) -> None:
        result = read_runtime_version(os.path.join(self.dir, "missing.exe"))
        self.assert_undetermined(result, Reason.FILE_UNREADABLE)
        assert isinstance(result, Undetermined)
        self.assertEqual(result.detail, "FileNotFoundError")

    def test_directory_is_unreadable(self) -> None:
        self.assert_undetermined(detect_runtime(self.dir, RuntimeKind.NODE), Reason.FILE_UNREADABLE)

    def test_not_pe(self) -> None:
        path = self.write("text.exe", b"hello, this is not a PE file at all" * 4)
        self.assert_undetermined(detect_runtime(path, RuntimeKind.NODE), Reason.NOT_PE)

    def test_mz_without_pe_signature(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        broken[layout.e_lfanew : layout.e_lfanew + 4] = b"XX\0\0"
        self.assert_undetermined(read_runtime_version(self.write("a.exe", bytes(broken))), Reason.NOT_PE)

    def test_e_lfanew_outside_file(self) -> None:
        image, _ = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<I", broken, 0x3C, 0x7FFFFFF0)
        self.assert_undetermined(read_runtime_version(self.write("a.exe", bytes(broken))), Reason.NOT_PE)

    def test_empty_file(self) -> None:
        self.assert_undetermined(read_runtime_version(self.write("empty.exe", b"")), Reason.NOT_PE)

    def test_no_version_resource(self) -> None:
        path = self.write("icon.exe", build_pe(version=None)[0])
        self.assert_undetermined(detect_runtime(path, RuntimeKind.NODE), Reason.NO_VERSION_RESOURCE)

    def test_no_resource_directory(self) -> None:
        path = self.write("bare.exe", build_pe(version=NODE_LIKE, with_resource_dir=False)[0])
        self.assert_undetermined(read_runtime_version(path), Reason.NO_VERSION_RESOURCE)

    def test_version_mismatch(self) -> None:
        spec = replace(NODE_LIKE, fixed_product=(22, 1, 0, 0))
        path = self.write("node.exe", build_pe(version=spec)[0])
        self.assert_undetermined(read_runtime_version(path), Reason.VERSION_MISMATCH)
        result = detect_runtime(path, RuntimeKind.NODE)
        assert isinstance(result, Found)
        self.assert_undetermined(result.value.version, Reason.VERSION_MISMATCH)

    def test_non_numeric_version_string(self) -> None:
        spec = replace(NODE_LIKE, strings={"ProductName": "Node.js", "ProductVersion": "unknown"})
        path = self.write("node.exe", build_pe(version=spec)[0])
        self.assert_undetermined(read_runtime_version(path), Reason.MALFORMED_VERSION_RESOURCE)

    def test_unexpected_product(self) -> None:
        path = self.write("python.exe", build_pe(version=PYTHON_LIKE)[0])
        self.assert_undetermined(detect_runtime(path, RuntimeKind.NODE), Reason.UNEXPECTED_PRODUCT)
        spec = VersionSpec(strings={"ProductVersion": "24.19.0"}, fixed_product=(24, 19, 0, 0))
        nameless = self.write("nameless.exe", build_pe(version=spec)[0])
        self.assert_undetermined(detect_runtime(nameless, RuntimeKind.NODE), Reason.UNEXPECTED_PRODUCT)


class MalformedTests(TempDirCase):
    def check_malformed(self, data: bytes) -> None:
        self.assert_undetermined(read_runtime_version(self.write("bad.exe", data)), Reason.MALFORMED_VERSION_RESOURCE)

    def test_data_entry_offset_outside_file(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<I", broken, layout.data_entry, 0x7FFF0000)
        self.check_malformed(bytes(broken))

    def test_data_entry_huge_size(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<I", broken, layout.data_entry + 4, 0x7FFFFFFF)
        self.check_malformed(bytes(broken))

    def test_resource_rva_outside_sections(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<I", broken, layout.resource_dir_entry, 0x00900000)
        self.check_malformed(bytes(broken))

    def test_directory_entry_count_huge(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<HH", broken, layout.rsrc_offset + 12, 0xFFFF, 0xFFFF)
        self.check_malformed(bytes(broken))

    def test_truncated_inside_resource(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        self.check_malformed(image[: layout.payload + 20])

    def test_zero_length_version_node(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        broken = bytearray(image)
        struct.pack_into("<H", broken, layout.payload, 0)
        self.check_malformed(bytes(broken))

    def test_bad_fixed_signature(self) -> None:
        spec = replace(NODE_LIKE, signature=0x12345678)
        self.check_malformed(build_pe(version=spec)[0])

    def test_every_truncation_is_handled(self) -> None:
        image, _ = build_pe(version=PYTHON_LIKE)
        for cut in range(0, len(image), 3):
            result = read_runtime_version(self.write("cut.exe", image[:cut]))
            self.assertIsInstance(result, (Found, Undetermined))

    def test_random_corruption_never_raises(self) -> None:
        image, layout = build_pe(version=NODE_LIKE)
        rng = random.Random(20261024)
        for _ in range(400):
            broken = bytearray(image)
            for _ in range(rng.randint(1, 8)):
                position = rng.randrange(0x3C, layout.payload + 200)
                broken[position] = rng.randrange(256)
            result = detect_runtime(self.write("fuzz.exe", bytes(broken)), RuntimeKind.NODE)
            self.assertIsInstance(result, (Found, Undetermined))


class AsciiDigitTests(TempDirCase):
    """Only ASCII digits make a version: a regex \\d and int() also accept Arabic-Indic or fullwidth digits."""

    def test_non_ascii_digits_in_product_version_are_malformed(self) -> None:
        for text in ("\u0662\u0664.\u0661\u0669.\u0660", "\uff12\uff14.\uff11\uff19.\uff10", "24.1\u0669.0", "24.19.0\u0663"):
            with self.subTest(text=text):
                spec = replace(NODE_LIKE, strings=dict(NODE_LIKE.strings, ProductVersion=text))
                path = self.write("node.exe", build_pe(version=spec)[0])
                self.assert_undetermined(read_runtime_version(path), Reason.MALFORMED_VERSION_RESOURCE)


if __name__ == "__main__":
    unittest.main()
