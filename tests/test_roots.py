from __future__ import annotations

import contextlib
import datetime
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import time
import tracemalloc
import unittest
from collections.abc import Sequence

from patchwait.cli import main
from patchwait.der import DerError, parse_certificate
from patchwait.model import Found, JSONObject, NotFound, Reason, Undetermined
from patchwait.roots import (
    AUTHROOT_VALUE,
    DISALLOWED_VALUE,
    MAX_DER_CANDIDATE,
    MAX_DER_FILE,
    MAX_PEM_BODY,
    PEM_BEGIN,
    PEM_END,
    DistrustEntry,
    RootsItem,
    RootsUsageError,
    StoreEntry,
    LocationKind,
    WindowsAccess,
    _BytesReader,  # pyright: ignore[reportPrivateUsage]
    _ignored_details,  # pyright: ignore[reportPrivateUsage]
    _judge_collection,  # pyright: ignore[reportPrivateUsage]
    _parse_identifier,  # pyright: ignore[reportPrivateUsage]
    audit_binary,
    audit_pem,
    load_distrust,
    scan_stream,
)
from tests.cert_builder import (
    build_cert,
    build_ctl,
    disallowed_attribute,
    not_before_attribute,
    pem,
    spki_of,
    subject_for,
)

KEY_BAD = bytes(range(1, 65))
KEY_OTHER = bytes(range(100, 164))
BAD = build_cert("Synthetic Distrusted Root G3", KEY_BAD, serial=3)
REISSUED = build_cert("Synthetic Distrusted Root G3", KEY_BAD, serial=4, issuer="Synthetic Cross Signer")
OTHER = build_cert("Synthetic Other Root", KEY_OTHER, serial=5)
WHEN = datetime.datetime(2026, 4, 15, 0, 0, 0, tzinfo=datetime.timezone.utc)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def binary_details(
    *, pem_blocks: int = 0, certs: int = 0, der_certs: int = 0, malformed: int = 0, ignored: Sequence[object] = ()
) -> dict[str, object]:
    return {
        "pem_blocks": pem_blocks,
        "certs": certs,
        "der_certs": der_certs,
        "malformed": malformed,
        "ignored_pem_blocks": list(ignored),
    }


class FakeWindows:
    """Stub registry values and certificate stores."""

    def __init__(self) -> None:
        self.registry: dict[str, object] = {}
        self.stores: dict[str, list[StoreEntry]] = {"ROOT": [], "Disallowed": []}
        self.keys: dict[str, object] = {}  # "HKLM\\subkey" -> FILETIME ticks or an OSError to raise
        self.calls: list[str] = []

    def read(self, name: str) -> object:
        self.calls.append(f"reg:{name}")
        if name not in self.registry:
            raise FileNotFoundError(name)
        value = self.registry[name]
        if isinstance(value, OSError):
            raise value
        return value

    def enum(self, store: str) -> Sequence[StoreEntry]:
        self.calls.append(f"store:{store}")
        if store not in self.stores:
            raise PermissionError(store)
        return self.stores[store]

    def last_write(self, hive: str, subkey: str) -> object:
        name = f"{hive}\\{subkey}"
        self.calls.append(f"key:{name}")
        if name not in self.keys:
            raise FileNotFoundError(name)
        value = self.keys[name]
        if isinstance(value, OSError):
            raise value
        return value

    def access(self, is_windows: bool = True) -> WindowsAccess:
        return WindowsAccess(is_windows, self.read, self.enum, self.last_write)


class RootsCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.windows = FakeWindows()
        self.list_path = self.write("distrust.txt", f"{sha256(BAD)} Synthetic G3\n".encode())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, data: bytes) -> str:
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_roots(self, *argv: str, is_windows: bool = True) -> tuple[int, dict[str, object]]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["roots", *argv], windows_access=self.windows.access(is_windows))
        payload: dict[str, object] = json.loads(out.getvalue()) if out.getvalue() else {}
        if payload:
            self.assert_consistent(payload)
        return code, payload

    def assert_consistent(self, doc: dict[str, object]) -> None:
        items = doc["items"]
        counts = doc["counts"]
        assert isinstance(items, list) and isinstance(counts, dict)
        tally = {role: {"found": 0, "not_found": 0, "undetermined": 0} for role in ("trust", "distrust")}
        for entry in items:  # pyright: ignore[reportUnknownVariableType]
            tally[entry["role"]][entry["verdict"]["result"]] += 1  # pyright: ignore[reportUnknownArgumentType]
        self.assertEqual(counts, {"items": len(items), **tally})  # pyright: ignore[reportUnknownArgumentType]

    def items(self, doc: dict[str, object]) -> list[dict[str, object]]:
        items = doc["items"]
        assert isinstance(items, list)
        return items  # pyright: ignore[reportUnknownVariableType]

    def verdict(self, item: dict[str, object]) -> dict[str, object]:
        verdict = item["verdict"]
        assert isinstance(verdict, dict)
        return verdict  # pyright: ignore[reportUnknownVariableType]

    def only(self, doc: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        (item,) = self.items(doc)
        return item, self.verdict(item)

    def distrust_pem(self) -> str:
        return self.write("distrust.pem", pem(BAD))


class DistrustListTests(RootsCase):
    def test_trust_store_audit_preset_and_prefixed_forms(self) -> None:
        text = (
            "# preset\n"
            f"{sha256(BAD).upper()} Synthetic G3\n"
            f"sha1:{hashlib.sha1(BAD).hexdigest()} Synthetic G3\n"
            f"spki:{sha256(spki_of(KEY_OTHER))}\tOther key\n"
            "\n"
        )
        entries = load_distrust([self.write("p.txt", text.encode())], [])
        self.assertEqual([e.label for e in entries], ["Synthetic G3", "Other key"])
        first, second = entries
        self.assertEqual(first.sha256, hashlib.sha256(BAD).digest())
        self.assertEqual(first.sha1, hashlib.sha1(BAD).digest())
        self.assertEqual(second.spki_sha256, hashlib.sha256(spki_of(KEY_OTHER)).digest())

    def test_colon_separated_hex_and_no_label(self) -> None:
        colons = ":".join(sha256(BAD)[i : i + 2] for i in range(0, 64, 2))
        (entry,) = load_distrust([self.write("p.txt", f"sha256:{colons}\n".encode())], [])
        self.assertEqual(entry.sha256, hashlib.sha256(BAD).digest())
        self.assertEqual(entry.label, f"sha256:{colons}")

    def test_pem_gives_all_identifiers(self) -> None:
        (entry,) = load_distrust([], [self.distrust_pem()])
        self.assertEqual(entry.label, "Synthetic Distrusted Root G3")
        self.assertEqual(entry.sha1, hashlib.sha1(BAD).digest())
        self.assertEqual(entry.spki_der, spki_of(KEY_BAD))
        self.assertEqual(entry.der, BAD)

    def test_bad_lists_are_usage_errors(self) -> None:
        for text in ("nothex Label\n", "sha1:abcd short\n", f"{sha256(BAD)} L\n{sha256(OTHER)} L\n"):
            with self.assertRaises(RootsUsageError, msg=text):
                load_distrust([self.write("bad.txt", text.encode())], [])
        with self.assertRaises(RootsUsageError):
            load_distrust([], [])
        with self.assertRaises(RootsUsageError):
            load_distrust([], [self.write("bad.pem", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")])

    def test_trailing_newline_hex_token_is_refused(self) -> None:
        # The list reader strips lines, so this only reaches the parser directly; there the
        # newline made 63 hex digits pass the old ^...$ check and crash bytes.fromhex.
        for token in ("a" * 63 + "\n", "sha256:" + "a" * 63 + "\n", "sha1:" + "a" * 39 + "\n"):
            self.assertIsNone(_parse_identifier(token), msg=repr(token))


class PemTests(RootsCase):
    def test_found_by_sha256(self) -> None:
        bundle = self.write("app/cacert.pem", pem(OTHER) + pem(BAD))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", bundle)
        self.assertEqual(code, 10)
        item, verdict = self.only(doc)
        self.assertEqual(verdict, {"result": "found", "value": ["sha256"]})
        self.assertEqual(item["role"], "trust")
        self.assertEqual(item["details"], {"pem_blocks": 2, "certs": 2, "malformed": 0})

    def test_reissued_cert_found_by_spki_only(self) -> None:
        bundle = self.write("roots.pem", pem(REISSUED))
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--pem", bundle)
        self.assertEqual(code, 10)
        item, verdict = self.only(doc)
        self.assertEqual(verdict["value"], ["spki_sha256"])
        matches = item["matches"]
        assert isinstance(matches, list)
        self.assertEqual(matches[0]["cert_sha256"], sha256(REISSUED))  # pyright: ignore[reportUnknownArgumentType]

    def test_not_found_exit_0(self) -> None:
        bundle = self.write("roots.pem", pem(OTHER))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", bundle)
        self.assertEqual(code, 0)
        self.assertEqual(self.only(doc)[1], {"result": "not_found"})

    def test_malformed_block_without_match_is_undetermined(self) -> None:
        broken = b"-----BEGIN CERTIFICATE-----\nMIIBroken!!\n-----END CERTIFICATE-----\n"
        bundle = self.write("roots.pem", pem(OTHER) + broken)
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", bundle)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict["reason"], Reason.MALFORMED_CERT.value)
        self.assertEqual(item["details"], {"pem_blocks": 2, "certs": 1, "malformed": 1})

    def test_malformed_block_with_match_is_found(self) -> None:
        broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n"  # no END
        bundle = self.write("roots.pem", broken + pem(BAD))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", bundle)
        self.assertEqual(code, 10)
        self.assertEqual(self.only(doc)[1]["result"], "found")

    def test_der_cer_and_empty_and_missing(self) -> None:
        cer = self.write("root.cer", BAD)
        empty = self.write("empty.pem", b"no certificates here\n")
        missing = os.path.join(self.dir, "absent.pem")
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", cer, "--pem", empty, "--pem", missing)
        self.assertEqual(code, 10)
        results = [self.verdict(i).get("reason", self.verdict(i)["result"]) for i in self.items(doc)]
        self.assertEqual(results, ["found", Reason.NO_CERTS_RECOGNISED.value, Reason.TARGET_MISSING.value])

    def test_pem_root_walk(self) -> None:
        self.write("tree/a/cacert.pem", pem(OTHER))
        self.write("tree/b/grpc/roots.pem", pem(BAD))
        self.write("tree/c/ca-bundle", pem(OTHER))
        self.write("tree/c/readme.txt", pem(BAD))  # not a bundle name
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", os.path.join(self.dir, "tree"))
        self.assertEqual(code, 10)
        located = {os.path.basename(str(i["location"])): self.verdict(i)["result"] for i in self.items(doc)}
        self.assertEqual(located, {"cacert.pem": "not_found", "roots.pem": "found", "ca-bundle": "not_found"})

    def test_pem_root_empty_and_missing(self) -> None:
        os.makedirs(os.path.join(self.dir, "empty"))
        code, doc = self.run_roots(
            "--distrust", self.list_path,
            "--pem-root", os.path.join(self.dir, "empty"),
            "--pem-root", os.path.join(self.dir, "nope"),
        )
        self.assertEqual(code, 0)
        first, second = self.items(doc)
        self.assertEqual(self.verdict(first), {"result": "not_found"})
        self.assertEqual(first["details"], {"files": 0})
        self.assertEqual(self.verdict(second)["reason"], Reason.TARGET_MISSING.value)


    # Split so secret scanners do not flag this fake key block.
    KEY_BLOCK = b"-----BEGIN PRIVATE" + b" KEY-----\nMIIBkey=\n-----END PRIVATE KEY-----\n"

    def test_pem_root_skips_key_only_files_and_counts_them(self) -> None:
        self.write("tree/privatekey.pem", self.KEY_BLOCK)
        self.write("tree/publickey.pem", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
        self.write("tree/cacert.key", b"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
        self.write("tree/roots.pem", pem(OTHER))
        self.write("tree/notes.pem", b"no markers here\n")
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", os.path.join(self.dir, "tree"))
        self.assertEqual(code, 0)
        located = {
            os.path.basename(str(i["location"])): self.verdict(i).get("reason", self.verdict(i)["result"])
            for i in self.items(doc)
        }
        self.assertEqual(
            located,
            {"notes.pem": Reason.NO_CERTS_RECOGNISED.value, "roots.pem": "not_found", "tree": "not_found"},
        )
        summary = next(i for i in self.items(doc) if os.path.basename(str(i["location"])) == "tree")
        self.assertEqual(summary["details"], {"files": 2, "skipped_key_only": 3})

    def test_explicit_pem_key_only_stays_undetermined(self) -> None:
        path = self.write("privatekey.pem", self.KEY_BLOCK)
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", path)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict["reason"], Reason.NO_CERTS_RECOGNISED.value)
        self.assertEqual(item["details"], {"pem_blocks": 0, "certs": 0, "malformed": 0})

    def test_pem_root_key_plus_certificate_is_audited(self) -> None:
        self.write("tree/combined.pem", self.KEY_BLOCK + pem(BAD))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", os.path.join(self.dir, "tree"))
        self.assertEqual(code, 10)
        item, verdict = self.only(doc)
        self.assertEqual(os.path.basename(str(item["location"])), "combined.pem")
        self.assertEqual(verdict["result"], "found")

    @unittest.skipUnless(sys.platform == "win32", "'/' and '\' are the same separator only on Windows")
    def test_pem_root_forward_slashes_reports_unmixed_paths(self) -> None:
        self.write("tree/a/cacert.pem", pem(OTHER))
        self.write("tree/b/grpc/roots.pem", pem(BAD))
        root = os.path.join(self.dir, "tree")
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", root.replace("\\", "/") + "/")
        self.assertEqual(code, 10)
        locations = sorted(str(i["location"]) for i in self.items(doc))
        self.assertEqual(
            locations,
            sorted([os.path.join(root, "a", "cacert.pem"), os.path.join(root, "b", "grpc", "roots.pem")]),
        )

    def _pem_root_with_link(self, make_link: str) -> None:
        """A cacert.pem behind a directory link below the root is not audited."""
        self.write("tree/real/roots.pem", pem(OTHER))
        self.write("outside/cacert.pem", pem(BAD))
        root = os.path.join(self.dir, "tree")
        link = os.path.join(root, "linked")
        target = os.path.join(self.dir, "outside")
        try:
            if make_link == "junction":
                import _winapi

                _winapi.CreateJunction(target, link)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
            else:
                os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError, ImportError) as error:
            self.skipTest(f"cannot create a directory {make_link}: {type(error).__name__}")
        self.assertTrue(os.path.isfile(os.path.join(link, "cacert.pem")))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", root)
        self.assertEqual(code, 0)
        located = {str(i["location"]): self.verdict(i)["result"] for i in self.items(doc)}
        self.assertEqual(located, {os.path.join(root, "real", "roots.pem"): "not_found", root: "not_found"})
        summary = next(i for i in self.items(doc) if i["location"] == root)
        self.assertEqual(summary["details"], {"files": 1, "skipped_reparse_points": 1})

    @unittest.skipUnless(sys.platform == "win32", "junctions exist only on Windows")
    def test_pem_root_does_not_follow_junction(self) -> None:
        self._pem_root_with_link("junction")

    def test_pem_root_does_not_follow_directory_symlink(self) -> None:
        self._pem_root_with_link("symlink")

    def test_pem_root_root_itself_may_be_a_link(self) -> None:
        self.write("outside/cacert.pem", pem(BAD))
        link = os.path.join(self.dir, "root-link")
        target = os.path.join(self.dir, "outside")
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            if sys.platform != "win32":
                self.skipTest("the OS refused a directory symlink")
            try:
                import _winapi

                _winapi.CreateJunction(target, link)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
            except (OSError, AttributeError, ImportError):
                self.skipTest("the OS refused both a directory symlink and a junction")
        code, doc = self.run_roots("--distrust", self.list_path, "--pem-root", link)
        self.assertEqual(code, 10)
        item, verdict = self.only(doc)
        self.assertEqual(item["location"], os.path.join(link, "cacert.pem"))
        self.assertEqual(verdict["result"], "found")


class BinaryTests(RootsCase):
    def test_pem_with_real_newlines_and_escaped_newlines(self) -> None:
        real = self.write("a.exe", b"MZ\0\0" + os.urandom(500) + pem(BAD) + b"\0" * 100)
        escaped = self.write("b.exe", b'MZ var s="' + pem(BAD, escaped=True) + b'";' + b"\0" * 100)
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", real, "--binary", escaped)
        self.assertEqual(code, 10)
        for item in self.items(doc):
            self.assertEqual(self.verdict(item), {"result": "found", "value": ["sha256"]})
            self.assertEqual(item["details"], binary_details(pem_blocks=1, certs=1))

    def test_raw_der_is_parsed_and_raw_spki_still_searched(self) -> None:
        der = self.write("der.exe", b"\0" * 300 + BAD + b"\0" * 300)
        key = self.write("key.exe", b"\0" * 300 + spki_of(KEY_BAD) + b"\0" * 300)
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--binary", der, "--binary", key)
        self.assertEqual(code, 10)
        first, second = self.items(doc)
        # The raw DER and SPKI hits inside the parsed certificate are the same finding, reported once.
        self.assertEqual(self.verdict(first)["value"], ["sha1", "sha256", "spki_sha256"])
        self.assertIn('"offset": 300', json.dumps(first["matches"]))
        self.assertEqual(json.dumps(first["matches"]).count('"offset"'), 3)  # sha256, sha1, spki at offset 300
        self.assertEqual(first["details"], binary_details(der_certs=1))
        self.assertEqual(self.verdict(second)["value"], ["raw_spki"])
        self.assertEqual(second["details"]["der_certs"], 0)  # pyright: ignore[reportIndexIssue, reportOptionalSubscript, reportArgumentType, reportCallIssue]

    def test_raw_der_roots_and_an_empty_pem_template_are_not_found(self) -> None:
        roots = [build_cert(f"Synthetic Root {n}", bytes([n]) * 256, serial=10 + n) for n in range(1, 6)] + [OTHER]
        self.assertEqual(roots[0][:2] + roots[0][4:6], b"\x30\x82\x30\x82")  # tbs over 256 bytes
        self.assertEqual(OTHER[4:6], b"\x30\x81")  # tbs under 256 bytes
        template = b"-----BEGIN CERTIFICATE-----\n" + b"\0" * 40 + b"-----END CERTIFICATE-----"
        head = b"MZ" + b"\0" * 1000 + b"log: %s\n"
        data = head + template + b"\0" * 77 + b"".join(root + b"\0" * 13 for root in roots)
        path = self.write("runtime.exe", data)
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict, {"result": "not_found"})
        ignored = [{"offset": len(head), "reason": "empty_pem_block"}]
        self.assertEqual(item["details"], binary_details(pem_blocks=1, der_certs=len(roots), ignored=ignored))

    def test_raw_der_distrusted_root_found_by_a_sha256_list(self) -> None:
        offset = 4096 + 7
        path = self.write("rt.exe", random.Random(7).randbytes(4096) + b"\0" * 7 + BAD + b"\0" * 50 + OTHER)
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual(code, 10)
        item, verdict = self.only(doc)
        self.assertEqual(verdict, {"result": "found", "value": ["sha256"]})
        self.assertEqual(
            item["matches"],
            [{"matched_by": "sha256", "cert_sha256": sha256(BAD), "subject_cn": "Synthetic Distrusted Root G3",
              "offset": offset}],
        )
        self.assertEqual(item["details"]["der_certs"], 2)  # pyright: ignore[reportIndexIssue, reportOptionalSubscript, reportArgumentType, reportCallIssue]

    def test_raw_der_straddling_a_chunk_boundary_is_counted_once(self) -> None:
        big = build_cert("Synthetic Big Root", bytes(range(256)) * 4, serial=9)
        filler = 100_000
        data = b"\0" * filler + big + b"\0" * 999 + BAD + b"\0" * 10
        path = self.write("straddle.exe", data)
        entries = load_distrust([self.list_path], [])
        reference = audit_binary(path, entries, chunk_size=len(data) + 1)
        for chunk_size in (977, filler - 3, filler + 2, filler + len(big) // 2, filler + len(big) - 1, 65_536):
            items = audit_binary(path, entries, chunk_size=chunk_size)
            self.assertEqual([i.to_json() for i in items], [i.to_json() for i in reference], chunk_size)
            (item,) = items
            self.assertEqual(item.details["der_certs"], 2, chunk_size)
            self.assertEqual([m["offset"] for m in item.matches], [filler + len(big) + 999], chunk_size)

    def test_random_30_82_noise_is_not_a_certificate(self) -> None:
        rng = random.Random(20261026)
        parts = [b"MZ"]
        for _ in range(3000):
            hi, lo = rng.randrange(256), rng.randrange(256)
            parts.append(bytes([0x30, 0x82, hi, lo, 0x30, rng.choice((0x81, 0x82))]) + rng.randbytes(rng.randrange(40)))
        path = self.write("noise.exe", b"".join(parts))
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict["reason"], Reason.NO_CERTS_RECOGNISED.value)
        self.assertEqual(item["details"], binary_details())

    def test_truncated_der_at_the_end_is_not_counted(self) -> None:
        entries = load_distrust([self.list_path], [])
        for cut in (1, 2, 4, 6, 50, len(BAD) - 1):
            with self.subTest(cut=cut):
                path = self.write("cut.exe", b"\0" * 20 + BAD[:cut])
                (item,) = audit_binary(path, entries, chunk_size=7)
                self.assertEqual(item.details["der_certs"], 0)
                self.assertIsInstance(item.verdict, Undetermined)
        path = self.write("whole.exe", b"\0" * 20 + BAD)  # ends exactly at the end of the file
        (item,) = audit_binary(path, entries, chunk_size=7)
        self.assertEqual((item.details["der_certs"], item.verdict), (1, Found(("sha256",))))

    def test_empty_pem_with_a_malformed_pem_body_is_still_malformed(self) -> None:
        template = b"-----BEGIN CERTIFICATE-----\\n\\n-----END CERTIFICATE-----"
        broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        path = self.write("mixed.exe", b"MZ" + template + b"\0" * 9 + broken + OTHER)
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict["reason"], Reason.MALFORMED_CERT.value)
        self.assertEqual(
            verdict["detail"], "1 PEM certificate(s) could not be parsed; no match among 0 PEM and 1 DER certificate(s) parsed"
        )
        ignored = [{"offset": 2, "reason": "empty_pem_block"}]
        self.assertEqual(item["details"], binary_details(pem_blocks=2, der_certs=1, malformed=1, ignored=ignored))

    def test_ignored_pem_blocks_are_capped_with_a_total(self) -> None:
        template = b"-----BEGIN CERTIFICATE-----\r\n \t-----END CERTIFICATE-----"
        path = self.write("many.exe", (template + b"\0") * 25)
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(
            verdict,
            {"result": "undetermined", "reason": "no_certs_recognised",
             "detail": "no certificate was recognised (25 PEM block(s), 25 ignored as empty, no DER certificate)"},
        )
        listed = [{"offset": n * (len(template) + 1), "reason": "empty_pem_block"} for n in range(20)]
        details = binary_details(pem_blocks=25, ignored=listed)
        details["ignored_pem_blocks_total"] = 25
        self.assertEqual(item["details"], details)

    def test_empty_pem_block_in_a_bundle_and_in_a_distrust_pem(self) -> None:
        template = b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
        bundle = self.write("cacert.pem", template + pem(OTHER))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", bundle)
        self.assertEqual(code, 0)
        item, verdict = self.only(doc)
        self.assertEqual(verdict, {"result": "not_found"})
        self.assertEqual(
            item["details"],
            {"pem_blocks": 2, "certs": 1, "malformed": 0,
             "ignored_pem_blocks": [{"offset": 0, "reason": "empty_pem_block"}]},
        )
        with self.assertRaises(RootsUsageError):  # a distrust list takes well-formed certificates only
            load_distrust([], [self.write("d.pem", template + pem(BAD))])

    def test_no_certs_recognised(self) -> None:
        path = self.write("plain.exe", b"MZ" + bytes(range(256)) * 20)
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--binary", path)
        self.assertEqual(code, 0)
        self.assertEqual(self.only(doc)[1]["reason"], Reason.NO_CERTS_RECOGNISED.value)

    def test_only_unrelated_certs_is_not_found(self) -> None:
        path = self.write("other.exe", b"MZ" + pem(OTHER))
        code, doc = self.run_roots("--distrust", self.list_path, "--binary", path)
        self.assertEqual((code, self.only(doc)[1]), (0, {"result": "not_found"}))

    def test_pem_begin_at_every_offset_around_a_window_edge(self) -> None:
        # A BEGIN marker starting in the last bytes before a window's limit ends past the limit.
        chunk = 4096
        overlap = max(len(PEM_BEGIN) + MAX_PEM_BODY + len(PEM_END), MAX_DER_CANDIDATE)
        edge = -(-(overlap + 1) // chunk) * chunk - overlap  # the limit of the first window
        entries = load_distrust([self.list_path], [])
        blocks = {
            "valid": (pem(BAD), {"certs": 1}, Found(("sha256",))),
            "malformed": (PEM_BEGIN + b"\nAAAA\n" + PEM_END, {"malformed": 1}, None),
            "empty": (PEM_BEGIN + b"\n" + PEM_END, {}, None),
        }
        for name, (block, counts, verdict) in blocks.items():
            for start in range(edge - 30, edge + 3):
                with self.subTest(block=name, start=start):
                    data = b"\0" * start + block + b"\0" * (overlap + 2 * chunk)
                    path = self.write("edge.exe", data)
                    (item,) = audit_binary(path, entries, chunk_size=chunk)
                    (whole,) = audit_binary(path, entries, chunk_size=len(data) + 1)
                    self.assertEqual(item.to_json(), whole.to_json())
                    ignored = [{"offset": start, "reason": "empty_pem_block"}] if name == "empty" else []
                    self.assertEqual(item.details, binary_details(pem_blocks=1, ignored=ignored, **counts))
                    if verdict is not None:
                        self.assertEqual(item.verdict, verdict)

    def test_chunked_scan_matches_a_whole_file_read(self) -> None:
        rng = random.Random(1026)
        pieces = [
            pem(BAD), pem(OTHER), pem(BAD, escaped=True), BAD, OTHER, spki_of(KEY_BAD),
            PEM_BEGIN + b"\nAAAA\n" + PEM_END, PEM_BEGIN + b"\\n\\n" + PEM_END, PEM_BEGIN + PEM_END,
        ]
        entries = load_distrust([self.list_path], [self.distrust_pem()])
        for layout in range(8):
            parts: list[bytes] = []
            while sum(map(len, parts)) < 150_000:
                parts.append(rng.randbytes(rng.choice((0, 1, 7, 26, 300, 5000, 40_000))))
                parts.append(rng.choice(pieces))
            data = b"".join(parts)
            path = self.write("layout.exe", data)
            whole = [item.to_json() for item in audit_binary(path, entries, chunk_size=len(data) + 1)]
            for chunk_size in (1009, 4096, 65_557, 100_003):
                with self.subTest(layout=layout, chunk_size=chunk_size):
                    items = audit_binary(path, entries, chunk_size=chunk_size)
                    self.assertEqual([item.to_json() for item in items], whole)

    def test_raw_hits_inside_many_matching_der_certs_scale_linearly(self) -> None:
        entries = load_distrust([], [self.distrust_pem()])

        def timed(copies: int) -> float:
            path = self.write(f"many{copies}.exe", (BAD + b"\0" * 3) * copies)
            began = time.perf_counter()
            (item,) = audit_binary(path, entries)
            best = time.perf_counter() - began
            began = time.perf_counter()
            audit_binary(path, entries)
            best = min(best, time.perf_counter() - began)
            self.assertEqual(item.details, binary_details(der_certs=copies))
            self.assertEqual(item.verdict, Found(("sha1", "sha256", "spki_sha256")))
            self.assertEqual(len(item.matches), 3 * copies)  # every raw DER and SPKI hit is inside a match
            return best

        small, large = timed(4000), timed(16_000)
        self.assertLess(large, small * 8, (small, large))  # 4x the copies: about 4x linear, 16x quadratic

    def test_memory_does_not_grow_with_unrelated_certs(self) -> None:
        entries = load_distrust([self.list_path], [])

        def peak(copies: int) -> tuple[int, RootsItem]:
            path = self.write(f"unrelated{copies}.exe", (OTHER + b"\0" + pem(OTHER)) * copies)
            tracemalloc.start()
            try:
                (item,) = audit_binary(path, entries, chunk_size=65_536)
                _, top = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            return top, item

        (small, _), (large, item) = peak(500), peak(4000)
        self.assertLess(large - small, 256 * 1024, (small, large))
        self.assertEqual(item.details, binary_details(pem_blocks=4000, certs=4000, der_certs=4000))
        self.assertEqual(item.verdict, NotFound())

    def test_backslash_before_an_escape_is_not_an_empty_body(self) -> None:
        entries = load_distrust([self.list_path], [])
        cases = {
            b"\\\\rn": (1, 0), b"\\\\nt": (1, 0), b"\\\\rt": (1, 0),  # \\ then letters: not an escape
            b"": (0, 1), b" \t\r\n\0": (0, 1), b"\\n\\r\\t": (0, 1), b"\\n\0\\n \r\n": (0, 1),
        }
        for body, (malformed, ignored) in cases.items():
            with self.subTest(body=body):
                path = self.write("body.exe", b"MZ" + PEM_BEGIN + body + PEM_END + b"\0" + OTHER)
                (item,) = audit_binary(path, entries)
                self.assertEqual((item.details["malformed"], len(item.details["ignored_pem_blocks"])), (malformed, ignored))  # pyright: ignore[reportArgumentType]
        # The same single pass decodes a body: "\\" + "rn" is not an escape between base64 lines.
        lines = pem(BAD).split(b"\n")
        joined = lines[0] + b"\n" + lines[1] + b"\\\\rn" + b"\n".join(lines[2:])
        path = self.write("joined.exe", b"MZ" + joined)
        (item,) = audit_binary(path, entries)
        self.assertEqual((item.details["certs"], item.details["malformed"]), (0, 1))

    def test_chunk_boundary_straddling_match_seen_once(self) -> None:
        block = pem(BAD)
        raw = BAD
        filler = 200_000
        data = b"\0" * filler + block + b"\0" * 1000 + raw + b"\0" * filler
        path = self.write("big.exe", data)
        entries = load_distrust([], [self.distrust_pem()])
        reference = audit_binary(path, entries, chunk_size=len(data) + 1)
        for chunk_size in (997, 4096, filler + 11, filler + len(block) // 2):
            items = audit_binary(path, entries, chunk_size=chunk_size)
            self.assertEqual([i.to_json() for i in items], [i.to_json() for i in reference], chunk_size)
            (item,) = items
            self.assertEqual(item.details, binary_details(pem_blocks=1, certs=1, der_certs=1))
            offsets = sorted(int(str(m["offset"])) for m in item.matches)
            # sha256/sha1/spki from the PEM, raw DER twice (PEM-decoded bytes are not raw), raw SPKI once
            self.assertIn(filler + len(block) + 1000, offsets)
            self.assertEqual(len(offsets), len(set((str(m["matched_by"]), str(m["offset"])) for m in item.matches)))

    def test_fuzzed_binaries_never_raise(self) -> None:
        entries = load_distrust([], [self.distrust_pem()])
        base = b"MZ" + pem(BAD) + pem(BAD, escaped=True) + BAD
        rng = random.Random(20261024)
        for _ in range(150):
            broken = bytearray(base)
            for _ in range(rng.randint(1, 12)):
                broken[rng.randrange(len(broken))] = rng.randrange(256)
            cut = rng.randint(0, len(broken))
            path = self.write("fuzz.exe", bytes(broken[:cut]))
            for item in audit_binary(path, entries, chunk_size=rng.randint(1, 4096)):
                self.assertIsInstance(item.verdict, (Found, NotFound, Undetermined))


class WindowsTests(RootsCase):
    def authroot(self, *subjects: bytes) -> None:
        self.windows.registry[AUTHROOT_VALUE] = build_ctl(list(subjects))
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([])

    def by_kind(self, doc: dict[str, object]) -> dict[str, dict[str, object]]:
        return {str(i["location_kind"]): i for i in self.items(doc)}

    def test_listed_in_authroot_is_found_with_this_update(self) -> None:
        self.authroot(subject_for(OTHER), subject_for(BAD))
        self.windows.stores["ROOT"] = [(OTHER, "x509_asn", True)]
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 10)
        kinds = self.by_kind(doc)
        self.assertEqual(list(kinds), ["authroot_ctl", "root_store", "disallowed_ctl", "disallowed_store"])
        authroot = kinds["authroot_ctl"]
        self.assertEqual(self.verdict(authroot), {"result": "found", "value": ["sha256"]})
        self.assertEqual(
            authroot["details"],
            {
                "this_update": "2026-08-25T07:24:34Z",
                "ctl_entries": 2,
                "last_sync": None,
                "last_sync_note": "LastSyncTime not found",
            },
        )
        self.assertEqual(self.verdict(kinds["root_store"]), {"result": "not_found"})
        self.assertEqual(self.verdict(kinds["disallowed_ctl"]), {"result": "not_found"})
        self.assertEqual(kinds["disallowed_ctl"]["role"], "distrust")
        self.assertEqual(self.verdict(kinds["disallowed_store"]), {"result": "not_found"})
        self.assertTrue(str(authroot["location"]).endswith("AuthRoot\\AutoUpdate\\EncodedCtl"))

    def test_listed_with_disallowed_filetime_is_not_found_with_date(self) -> None:
        self.authroot(subject_for(BAD, [disallowed_attribute(WHEN)]))
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        authroot = self.by_kind(doc)["authroot_ctl"]
        self.assertEqual(self.verdict(authroot), {"result": "not_found"})
        matches = authroot["matches"]
        assert isinstance(matches, list)
        self.assertEqual(matches[0]["disallowed"]["filetime"], "2026-04-15T00:00:00Z")  # pyright: ignore[reportUnknownArgumentType]

    def test_not_before_restriction_stays_found(self) -> None:
        self.authroot(subject_for(BAD, [not_before_attribute(WHEN)]))
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 10)
        authroot = self.by_kind(doc)["authroot_ctl"]
        self.assertEqual(self.verdict(authroot)["result"], "found")
        matches = authroot["matches"]
        assert isinstance(matches, list)
        self.assertEqual(matches[0]["not_before"]["filetime"], "2026-04-15T00:00:00Z")  # pyright: ignore[reportUnknownArgumentType]
        self.assertIsNone(matches[0]["disallowed"])  # pyright: ignore[reportUnknownArgumentType]

    def test_sha1_identifier_without_sha256_attribute(self) -> None:
        self.authroot(subject_for(BAD, with_sha256=False))
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--windows")
        self.assertEqual(code, 10)
        self.assertEqual(self.verdict(self.by_kind(doc)["authroot_ctl"])["value"], ["sha1"])

    def test_sha256_only_entry_vs_entries_without_98_is_undetermined(self) -> None:
        self.authroot(subject_for(OTHER, with_sha256=False))
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        verdict = self.verdict(self.by_kind(doc)["authroot_ctl"])
        self.assertEqual(verdict["reason"], Reason.NO_USABLE_IDENTIFIER.value)

    def test_unparsable_ctl(self) -> None:
        self.windows.registry[AUTHROOT_VALUE] = b"\x30\x03\x02\x01"
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([])
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        self.assertEqual(self.verdict(self.by_kind(doc)["authroot_ctl"])["reason"], Reason.MALFORMED_CTL.value)

    def test_registry_and_store_read_failures(self) -> None:
        self.windows.registry[DISALLOWED_VALUE] = PermissionError("denied")
        self.windows.registry[AUTHROOT_VALUE] = "not bytes"
        del self.windows.stores["Disallowed"]
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        kinds = self.by_kind(doc)
        for kind in ("authroot_ctl", "disallowed_ctl", "disallowed_store"):
            self.assertEqual(self.verdict(kinds[kind])["reason"], Reason.STORE_UNREADABLE.value, kind)
        self.assertEqual(self.verdict(kinds["root_store"]), {"result": "not_found"})

    def test_disallowed_role_found_does_not_set_exit_10(self) -> None:
        self.authroot()
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([subject_for(BAD)])
        self.windows.stores["Disallowed"] = [(BAD, "x509_asn", True)]
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        kinds = self.by_kind(doc)
        self.assertEqual(self.verdict(kinds["disallowed_ctl"])["result"], "found")
        self.assertEqual(self.verdict(kinds["disallowed_store"])["result"], "found")
        counts = doc["counts"]
        assert isinstance(counts, dict)
        self.assertEqual(counts["distrust"], {"found": 2, "not_found": 0, "undetermined": 0})

    def test_root_store_spki_and_malformed(self) -> None:
        self.authroot()
        self.windows.stores["ROOT"] = [(REISSUED, "x509_asn", True), (b"\x30\x01", "x509_asn", True)]
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--windows")
        self.assertEqual(code, 10)
        root = self.by_kind(doc)["root_store"]
        self.assertEqual(self.verdict(root)["value"], ["spki_sha256"])
        self.assertEqual(root["details"], {"certs": 1, "malformed": 1})

    def test_root_store_malformed_without_match_is_undetermined(self) -> None:
        self.authroot()
        self.windows.stores["ROOT"] = [(OTHER, "x509_asn", True), (b"junk", "x509_asn", True)]
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        self.assertEqual(self.verdict(self.by_kind(doc)["root_store"])["reason"], Reason.MALFORMED_CERT.value)

    def test_spki_only_entry_vs_ctl(self) -> None:
        self.authroot(subject_for(BAD))
        spki_list = self.write("spki.txt", f"spki:{sha256(spki_of(KEY_BAD))} key\n".encode())
        code, doc = self.run_roots("--distrust", spki_list, "--windows")
        kinds = self.by_kind(doc)
        self.assertEqual(self.verdict(kinds["authroot_ctl"])["reason"], Reason.NO_USABLE_IDENTIFIER.value)
        self.assertEqual(self.verdict(kinds["disallowed_ctl"])["reason"], Reason.NO_USABLE_IDENTIFIER.value)
        self.assertEqual(code, 0)

    def test_not_windows(self) -> None:
        code, doc = self.run_roots("--distrust", self.list_path, "--windows", is_windows=False)
        self.assertEqual(code, 0)
        reasons = {self.verdict(i)["reason"] for i in self.items(doc)}
        self.assertEqual(reasons, {Reason.NOT_WINDOWS.value})
        self.assertEqual(len(self.items(doc)), 4)
        self.assertEqual(self.windows.calls, [])

    def test_ctl_fuzz_never_raises(self) -> None:
        blob = build_ctl([subject_for(BAD, [disallowed_attribute(WHEN)]), subject_for(OTHER)])
        rng = random.Random(7)
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([])
        for _ in range(300):
            broken = bytearray(blob)
            for _ in range(rng.randint(1, 6)):
                broken[rng.randrange(len(broken))] = rng.randrange(256)
            self.windows.registry[AUTHROOT_VALUE] = bytes(broken[: rng.randint(0, len(broken))])
            code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--windows")
            self.assertIn(code, (0, 10))
            self.assertEqual(len(self.items(doc)), 4)


KEY_WRITE_TIME = datetime.datetime(2026, 10, 22, 4, 36, 15, tzinfo=datetime.timezone.utc)
KEY_WRITE_TIME_2 = datetime.datetime(2026, 10, 25, 3, 1, 11, tzinfo=datetime.timezone.utc)
SYSTEM = "SOFTWARE\\Microsoft\\SystemCertificates"
POLICIES = "SOFTWARE\\Policies\\Microsoft\\SystemCertificates"
ENTERPRISE = "SOFTWARE\\Microsoft\\EnterpriseCertificates"
BAD_SHA1 = hashlib.sha1(BAD).hexdigest().upper()


def ticks(moment: datetime.datetime) -> int:
    return (moment - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(microseconds=1) * 10


def cert_key(hive: str, base: str, store: str, sha1: str = BAD_SHA1) -> str:
    return f"{hive}\\{base}\\{store}\\Certificates\\{sha1}"


class RegistryKeyTimeTests(RootsCase):
    def setUp(self) -> None:
        super().setUp()
        self.windows.registry[AUTHROOT_VALUE] = build_ctl([])
        self.windows.registry[DISALLOWED_VALUE] = build_ctl([])

    def kind(self, doc: dict[str, object], kind: str) -> dict[str, object]:
        (item,) = [i for i in self.items(doc) if i["location_kind"] == kind]
        return item

    def matches(self, item: dict[str, object]) -> list[dict[str, object]]:
        matches = item["matches"]
        assert isinstance(matches, list)
        return matches  # pyright: ignore[reportUnknownVariableType]

    def test_root_store_key_found_in_two_locations_sorted(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        self.windows.keys[cert_key("HKLM", SYSTEM, "AuthRoot")] = ticks(KEY_WRITE_TIME)
        self.windows.keys[cert_key("HKCU", SYSTEM, "ROOT")] = ticks(KEY_WRITE_TIME_2)
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 10)
        (match,) = self.matches(self.kind(doc, "root_store"))
        self.assertEqual(
            match["registry_keys"],
            [
                {"key": cert_key("HKCU", SYSTEM, "ROOT"), "last_write": "2026-10-25T03:01:11Z"},
                {"key": cert_key("HKLM", SYSTEM, "AuthRoot"), "last_write": "2026-10-22T04:36:15Z"},
            ],
        )
        self.assertNotIn("registry_keys_note", match)
        self.assertNotIn("registry_keys_errors", match)
        looked = sorted(call[4:] for call in self.windows.calls if call.startswith("key:"))
        expected = sorted(
            [cert_key(h, b, s) for h in ("HKLM", "HKCU") for b in (SYSTEM, POLICIES) for s in ("ROOT", "AuthRoot")]
            + [cert_key("HKLM", ENTERPRISE, "ROOT")]
        )
        self.assertEqual(looked, expected)

    def test_disallowed_store_key_in_one_location_and_exit_unchanged(self) -> None:
        self.windows.stores["Disallowed"] = [(BAD, "x509_asn", True)]
        self.windows.keys[cert_key("HKLM", SYSTEM, "Disallowed")] = ticks(KEY_WRITE_TIME_2)
        code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        self.assertEqual(code, 0)
        (match,) = self.matches(self.kind(doc, "disallowed_store"))
        self.assertEqual(
            match["registry_keys"], [{"key": cert_key("HKLM", SYSTEM, "Disallowed"), "last_write": "2026-10-25T03:01:11Z"}]
        )
        looked = [call[4:] for call in self.windows.calls if call.startswith("key:")]
        self.assertEqual(len(looked), 5)
        self.assertIn(cert_key("HKLM", ENTERPRISE, "Disallowed"), looked)
        self.assertTrue(all("\\Disallowed\\" in key for key in looked))

    def test_not_found_anywhere_gives_empty_list_and_note(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        code, doc = self.run_roots("--distrust-pem", self.distrust_pem(), "--windows")
        self.assertEqual(code, 10)
        matches = self.matches(self.kind(doc, "root_store"))
        self.assertEqual([m["matched_by"] for m in matches], ["sha256", "sha1", "spki_sha256"])
        for match in matches:
            self.assertEqual(match["registry_keys"], [])
            self.assertEqual(match["registry_keys_note"], "not found in the registry locations checked")
            self.assertNotIn("registry_keys_errors", match)
        self.assertEqual(sum(call.startswith("key:") for call in self.windows.calls), 9)  # one lookup per certificate

    def test_access_errors_are_recorded(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        self.windows.keys[cert_key("HKLM", POLICIES, "ROOT")] = PermissionError("denied")
        self.windows.keys[cert_key("HKLM", SYSTEM, "AuthRoot")] = ticks(KEY_WRITE_TIME)
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        (match,) = self.matches(self.kind(doc, "root_store"))
        self.assertEqual(len(match["registry_keys"]), 1)  # pyright: ignore[reportArgumentType]
        self.assertNotIn("registry_keys_note", match)
        self.assertEqual(
            match["registry_keys_errors"], [{"key": cert_key("HKLM", POLICIES, "ROOT"), "error": "PermissionError"}]
        )
        del self.windows.keys[cert_key("HKLM", SYSTEM, "AuthRoot")]
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        (match,) = self.matches(self.kind(doc, "root_store"))
        self.assertEqual(match["registry_keys"], [])
        self.assertEqual(match["registry_keys_note"], "not found in the registry locations that could be read")

    def test_bad_filetime_is_null_with_note(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        self.windows.keys[cert_key("HKLM", SYSTEM, "ROOT")] = 0
        self.windows.keys[cert_key("HKLM", SYSTEM, "AuthRoot")] = 2**64 - 1
        self.windows.keys[cert_key("HKCU", SYSTEM, "ROOT")] = "not ticks"
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        (match,) = self.matches(self.kind(doc, "root_store"))
        keys = match["registry_keys"]
        assert isinstance(keys, list)
        self.assertEqual(len(keys), 3)  # pyright: ignore[reportUnknownArgumentType]
        notes = {key["key"]: key["last_write_note"] for key in keys}  # pyright: ignore[reportUnknownVariableType]
        self.assertTrue(all(key["last_write"] is None for key in keys))  # pyright: ignore[reportUnknownVariableType]
        self.assertEqual(
            notes,
            {
                cert_key("HKLM", SYSTEM, "ROOT"): "the time is zero or out of range",
                cert_key("HKLM", SYSTEM, "AuthRoot"): "the time is zero or out of range",
                cert_key("HKCU", SYSTEM, "ROOT"): "the time is not an integer FILETIME",
            },
        )

    def test_unparsed_store_certificate_gets_its_keys(self) -> None:
        bad_der = b"\x30\x03\x02\x01\x05 not a certificate"
        sha1 = hashlib.sha1(bad_der).hexdigest().upper()
        distrust = self.write("unparsed.txt", f"{sha256(bad_der)} Synthetic unparsed\n".encode())
        for encoding in ("pkcs_7_asn", "x509_asn"):
            with self.subTest(encoding=encoding):
                self.windows.stores["ROOT"] = [(bad_der, encoding, True)]
                self.windows.keys = {cert_key("HKLM", SYSTEM, "ROOT", sha1): 134371173750000000}
                code, doc = self.run_roots("--distrust", distrust, "--windows")
                self.assertEqual(code, 10)
                item = self.kind(doc, "root_store")
                self.assertEqual(self.verdict(item), {"result": "found", "value": ["sha256"]})
                (match,) = self.matches(item)
                self.assertEqual(match["cert_sha1"], sha1.lower())
                self.assertEqual(
                    match["registry_keys"],
                    [{"key": cert_key("HKLM", SYSTEM, "ROOT", sha1), "last_write": "2026-10-22T04:36:15Z"}],
                )

    def test_a_lookup_that_raises_another_error_is_recorded(self) -> None:
        def broken(hive: str, subkey: str) -> object:
            if "\\Policies\\" in subkey:
                raise KeyError(hive)
            return self.windows.last_write(hive, subkey)

        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        self.windows.keys[cert_key("HKLM", SYSTEM, "AuthRoot")] = ticks(KEY_WRITE_TIME)
        access = WindowsAccess(True, self.windows.read, self.windows.enum, broken)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["roots", "--distrust", self.list_path, "--windows"], windows_access=access)
        self.assertEqual(code, 10)
        (match,) = self.matches(self.kind(json.loads(out.getvalue()), "root_store"))
        self.assertEqual(len(match["registry_keys"]), 1)  # pyright: ignore[reportArgumentType]
        errors = match["registry_keys_errors"]
        assert isinstance(errors, list)
        self.assertEqual(len(errors), 4)  # pyright: ignore[reportUnknownArgumentType]
        self.assertTrue(all(error["error"] == "KeyError" for error in errors))  # pyright: ignore[reportUnknownVariableType]

    def test_default_key_lookup_reads_nothing(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        access = WindowsAccess(True, self.windows.read, self.windows.enum)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["roots", "--distrust", self.list_path, "--windows"], windows_access=access)
        self.assertEqual(code, 10)
        (match,) = self.matches(self.kind(json.loads(out.getvalue()), "root_store"))
        self.assertEqual(match["registry_keys"], [])
        self.assertEqual(match["registry_keys_note"], "not found in the registry locations that could be read")
        errors = match["registry_keys_errors"]
        assert isinstance(errors, list)
        self.assertEqual({error["error"] for error in errors}, {"OSError"})  # pyright: ignore[reportUnknownVariableType]

    def test_ctl_last_sync(self) -> None:
        self.windows.registry["LastSyncTime"] = ticks(KEY_WRITE_TIME).to_bytes(8, "little")
        self.windows.registry["DisallowedCertLastSyncTime"] = b"\x01\x02\x03\x04"
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        authroot = self.kind(doc, "authroot_ctl")["details"]
        disallowed = self.kind(doc, "disallowed_ctl")["details"]
        assert isinstance(authroot, dict) and isinstance(disallowed, dict)
        self.assertEqual(authroot["last_sync"], "2026-10-22T04:36:15Z")
        self.assertNotIn("last_sync_note", authroot)
        self.assertIsNone(disallowed["last_sync"])
        self.assertEqual(disallowed["last_sync_note"], "DisallowedCertLastSyncTime is not an 8-byte FILETIME")

    def test_disallowed_ctl_last_sync(self) -> None:
        self.windows.registry["DisallowedCertLastSyncTime"] = ticks(KEY_WRITE_TIME_2).to_bytes(8, "little")
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        disallowed = self.kind(doc, "disallowed_ctl")["details"]
        assert isinstance(disallowed, dict)
        self.assertEqual(disallowed["last_sync"], "2026-10-25T03:01:11Z")
        self.assertNotIn("last_sync_note", disallowed)

    def test_ctl_last_sync_missing_zero_unreadable(self) -> None:
        self.windows.registry["LastSyncTime"] = bytes(8)
        self.windows.registry["DisallowedCertLastSyncTime"] = PermissionError("denied")
        self.windows.registry[AUTHROOT_VALUE] = b"\x30\x03\x02\x01"  # an unparsable CTL keeps last_sync
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        authroot = self.kind(doc, "authroot_ctl")
        self.assertEqual(self.verdict(authroot)["reason"], Reason.MALFORMED_CTL.value)
        self.assertEqual(
            authroot["details"], {"last_sync": None, "last_sync_note": "LastSyncTime: the time is zero or out of range"}
        )
        disallowed = self.kind(doc, "disallowed_ctl")["details"]
        assert isinstance(disallowed, dict)
        self.assertEqual(disallowed["last_sync_note"], "DisallowedCertLastSyncTime could not be read: PermissionError")
        del self.windows.registry["LastSyncTime"]
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows")
        details = self.kind(doc, "authroot_ctl")["details"]
        assert isinstance(details, dict)
        self.assertEqual(details["last_sync_note"], "LastSyncTime not found")

    def test_not_windows_has_no_registry_fields(self) -> None:
        self.windows.stores["ROOT"] = [(BAD, "x509_asn", True)]
        _code, doc = self.run_roots("--distrust", self.list_path, "--windows", is_windows=False)
        for item in self.items(doc):
            self.assertEqual(item["matches"], [])
            self.assertEqual(item["details"], {})
        self.assertEqual(self.windows.calls, [])

    def test_access_exposes_reads_only(self) -> None:
        fields = set(WindowsAccess.__dataclass_fields__)  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        self.assertEqual(fields, {"is_windows", "read_registry", "enum_store", "key_last_write"})
        import inspect

        import patchwait.roots as roots_module

        source = inspect.getsource(roots_module)
        for forbidden in ("SetValue", "CreateKey", "DeleteKey", "DeleteValue", "KEY_WRITE", "KEY_ALL_ACCESS", "KEY_SET_VALUE"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count("winreg.OpenKey("), source.count("winreg.KEY_READ)"))


class DocumentTests(RootsCase):
    def test_shape_counts_and_nothing_dropped(self) -> None:
        self.windows.registry[AUTHROOT_VALUE] = build_ctl([subject_for(BAD)])
        list_path = self.write(
            "two.txt", f"{sha256(BAD)} G3\nspki:{sha256(spki_of(KEY_OTHER))} other\n".encode()
        )
        bundle = self.write("roots.pem", pem(OTHER))
        code, doc = self.run_roots(
            "--distrust", list_path, "--windows", "--pem", bundle,
            "--binary", os.path.join(self.dir, "none.exe"),
        )
        self.assertEqual(code, 10)
        self.assertEqual(
            sorted(doc), ["check", "counts", "distrust", "generated", "items", "schema", "tool"]
        )
        self.assertEqual((doc["tool"], doc["schema"], doc["check"]), ("patchwait", 1, "roots"))
        self.assertEqual(len(self.items(doc)), 6 * 2)  # 6 locations x 2 entries
        distrust = doc["distrust"]
        assert isinstance(distrust, list)
        self.assertEqual([d["label"] for d in distrust], ["G3", "other"])  # pyright: ignore[reportUnknownArgumentType]

    def test_usage_errors_exit_2(self) -> None:
        code, doc = self.run_roots("--distrust", self.list_path)
        self.assertEqual((code, doc), (2, {}))
        code, doc = self.run_roots("--pem", self.list_path)
        self.assertEqual((code, doc), (2, {}))

    def test_never_writes_inputs(self) -> None:
        bundle = self.write("roots.pem", pem(BAD))

        def state() -> tuple[int, bytes]:
            with open(bundle, "rb") as handle:
                return os.stat(bundle).st_mtime_ns, handle.read()

        before = state()
        self.run_roots("--distrust", self.list_path, "--pem", bundle, "--binary", bundle)
        self.assertEqual(state(), before)

    def test_entry_round_trip_json(self) -> None:
        entry = DistrustEntry("x", sha256=b"\1" * 32)
        self.assertEqual(entry.to_json()["sha256"], "01" * 32)


def _audit_pem_kept(path: str, entries: Sequence[DistrustEntry]) -> list[RootsItem]:
    """``audit_pem`` as it was before matching moved into the scan: every parsed certificate kept, then judged."""
    with open(path, "rb") as handle:
        data = handle.read()
    scanned = scan_stream(_BytesReader(data), ())
    if scanned.blocks == 0 and os.path.getsize(path) <= MAX_DER_FILE:
        if data[:1] == b"\x30":
            try:
                scanned.certs.append((parse_certificate(data), 0))
            except DerError:
                scanned.malformed += 1
    details: JSONObject = {"pem_blocks": scanned.blocks, "certs": len(scanned.certs), "malformed": scanned.malformed}
    if scanned.ignored_total:
        details.update(_ignored_details(scanned))
    certs = [(cert, None) for cert, _offset in scanned.certs]
    return _judge_collection(path, LocationKind.PEM, entries, certs, (), scanned.malformed, details, require_certs=True)


class PemStreamingTests(RootsCase):
    def entries(self) -> list[DistrustEntry]:
        other_list = self.write("other.txt", f"sha1:{hashlib.sha1(OTHER).hexdigest()} Synthetic other\n".encode())
        return load_distrust([self.list_path, other_list], [self.distrust_pem()])

    def test_matching_as_parsed_gives_the_same_items(self) -> None:
        broken = b"-----BEGIN CERTIFICATE-----\nMIIBroken!!\n-----END CERTIFICATE-----\n"
        empty = b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"
        unrelated = [pem(build_cert(f"Synthetic Filler {n}", bytes([n]) * 64, serial=10 + n)) for n in range(5)]
        bundles = {
            "mixed.pem": b"".join(unrelated[:2]) + pem(BAD) + broken + empty + pem(OTHER) + pem(REISSUED) + b"".join(unrelated[2:]),
            "matches-only.pem": pem(REISSUED) + pem(BAD) + pem(BAD),
            "unrelated.pem": b"".join(unrelated),
            "broken.pem": broken + empty,
            "empty-only.pem": empty,
            "single.cer": BAD,
            "bad.cer": b"\x30\x03\x02\x01\x01",
            "text.crt": b"not a certificate\n",
        }
        entries = self.entries()
        for name, data in bundles.items():
            with self.subTest(name=name):
                path = self.write(name, data)
                old = [item.to_json() for item in _audit_pem_kept(path, entries)]
                new = [item.to_json() for item in audit_pem(path, entries)]
                self.assertEqual(new, old)
                for chunk_size in (1, 97, 4096):
                    small = [item.to_json() for item in audit_pem(path, entries, chunk_size=chunk_size)]
                    self.assertEqual(small, old, chunk_size)

    def test_peak_memory_does_not_grow_with_unrelated_certificates(self) -> None:
        entries = self.entries()
        filler = pem(build_cert("Synthetic Filler", KEY_OTHER[::-1], serial=99))

        def peak(copies: int) -> tuple[int, list[RootsItem]]:
            path = self.write(f"bundle{copies}.pem", filler * copies + pem(BAD))
            tracemalloc.start()
            try:
                items = audit_pem(path, entries, chunk_size=65_536)
                _, top = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            return top, items

        (small, _), (large, items) = peak(200), peak(3000)
        self.assertLess(large - small, 256 * 1024, (small, large))
        self.assertEqual({str(item.details) for item in items}, {str({"pem_blocks": 3001, "certs": 3001, "malformed": 0})})
        self.assertIn(Found(("sha256",)), [item.verdict for item in items])
        old = _audit_pem_kept(os.path.join(self.dir, "bundle3000.pem"), entries)
        self.assertEqual([item.to_json() for item in items], [item.to_json() for item in old])


if __name__ == "__main__":
    unittest.main()
