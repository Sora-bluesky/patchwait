"""Preserve legacy certificate matching when optional Disallowed hashes fail."""

from __future__ import annotations

import hashlib
import os
from unittest import mock

from patchwait.der import DerError, parse_certificate
from tests import test_roots
from tests.cert_builder import build_cert, build_ctl, ctl_subject, explicit, octets, oid, pem, seq, spki_of, tlv
from tests.test_disallowed_ctl import DISALLOWED_HASH, PSS, algorithm, tbs_bytes
from tests.test_roots import KEY_BAD, OTHER

LABEL = "Synthetic legacy certificate " + "X" * 32


def legacy_certificate(spki_der: bytes = b"\x30\x00", *, outer_algorithm: bytes | None = None) -> bytes:
    with mock.patch("tests.cert_builder.spki", return_value=spki_der):
        return build_cert(LABEL, KEY_BAD, outer_signature_algorithm=outer_algorithm)


def malformed_spkis() -> tuple[bytes, ...]:
    return (
        seq(),
        seq(seq()),
        seq(seq(), octets(KEY_BAD)),
        seq(seq(), tlv(0x03, b"")),
        seq(seq(), tlv(0x03, b"\x08" + KEY_BAD)),
        seq(seq(), tlv(0x03, b"\0" + KEY_BAD), seq()),
        seq(b"\x03\x02\0"),
    )


def malformed_signature_algorithms() -> tuple[bytes, ...]:
    return (
        seq(),
        seq(octets(b"synthetic")),
        seq(tlv(0x06, b"")),
        seq(tlv(0x06, b"\x80")),
        seq(tlv(0x06, b"\x81" * 10 + b"\x01")),
        seq(oid("1.2.840.113549.1.1.11"), b"\x05\0", b"\x05\0"),
        seq(b"\x06\x02\x2a"),
        algorithm(PSS, seq(b"\xa0")),
        algorithm(PSS, seq(explicit(0, b"\x30\x02\x06"))),
        algorithm(PSS, seq(explicit(0, seq()))),
        algorithm(PSS, seq(explicit(0, seq(tlv(0x06, b"\x80"))))),
    )


class LegacyCertificateTests(test_roots.RootsCase):
    """These behaviors also hold with the production modules from origin/main."""

    def assert_existing_fields(self, der: bytes, spki_der: bytes) -> None:
        try:
            info = parse_certificate(der)
        except DerError as error:
            self.fail(f"a previously accepted certificate was rejected: {error}")
        self.assertEqual(info.der, der)
        self.assertEqual(info.sha256, hashlib.sha256(der).digest())
        self.assertEqual(info.sha1, hashlib.sha1(der).digest())
        self.assertEqual(info.spki_der, spki_der)
        self.assertEqual(info.spki_sha256, hashlib.sha256(spki_der).digest())
        self.assertEqual(info.subject_cn, LABEL)

    def legacy_list(self, prefix: str) -> str:
        der = legacy_certificate()
        digest = hashlib.sha1(der) if prefix == "sha1" else hashlib.sha256(seq() if prefix == "spki" else der)
        return self.write("legacy.txt", f"{prefix}:{digest.hexdigest()} Synthetic legacy\n".encode("utf-8"))

    def assert_found(self, code: int, doc: dict[str, object], prefix: str) -> dict[str, object]:
        self.assertEqual(code, 10)
        row, verdict = self.only(doc)
        self.assertEqual(verdict, {"result": "found", "value": ["spki_sha256" if prefix == "spki" else prefix]})
        return row

    def test_malformed_spki_preserves_existing_identifiers(self) -> None:
        for spki_der in malformed_spkis():
            with self.subTest(spki=spki_der.hex()):
                self.assert_existing_fields(legacy_certificate(spki_der), spki_der)

    def test_malformed_signature_metadata_preserves_existing_identifiers(self) -> None:
        for outer in malformed_signature_algorithms():
            with self.subTest(algorithm=outer.hex()):
                self.assert_existing_fields(build_cert(LABEL, KEY_BAD, outer_signature_algorithm=outer), spki_of(KEY_BAD))

    def test_pem_bundle_keeps_legacy_matches(self) -> None:
        bundle = self.write("cacert.pem", pem(OTHER) + pem(legacy_certificate()))
        for prefix in ("sha256", "sha1", "spki"):
            with self.subTest(identifier=prefix):
                code, doc = self.run_roots("--distrust", self.legacy_list(prefix), "--pem", bundle)
                row = self.assert_found(code, doc, prefix)
                self.assertEqual(row["details"], {"pem_blocks": 2, "certs": 2, "malformed": 0})

    def test_single_der_keeps_legacy_matches(self) -> None:
        path = self.write("legacy.cer", legacy_certificate())
        for prefix in ("sha256", "sha1", "spki"):
            with self.subTest(identifier=prefix):
                code, doc = self.run_roots("--distrust", self.legacy_list(prefix), "--pem", path)
                self.assert_found(code, doc, prefix)

    def test_pem_root_keeps_legacy_matches(self) -> None:
        bundle = self.write("tree/cacert.pem", pem(legacy_certificate()))
        for prefix in ("sha256", "sha1", "spki"):
            with self.subTest(identifier=prefix):
                code, doc = self.run_roots("--distrust", self.legacy_list(prefix), "--pem-root", os.path.dirname(bundle))
                self.assert_found(code, doc, prefix)

    def test_binary_with_an_unrelated_certificate_keeps_legacy_matches(self) -> None:
        path = self.write("synthetic.dll", b"MZ" + legacy_certificate() + b"synthetic padding" + OTHER)
        for prefix in ("sha256", "sha1", "spki"):
            with self.subTest(identifier=prefix):
                code, doc = self.run_roots("--distrust", self.legacy_list(prefix), "--binary", path)
                row = self.assert_found(code, doc, prefix)
                self.assertEqual(row["details"], test_roots.binary_details(der_certs=2))

    def test_distrust_pem_accepts_legacy_certificate(self) -> None:
        source = self.write("distrust.pem", pem(legacy_certificate()))
        target = self.write("cacert.pem", pem(legacy_certificate()))
        code, doc = self.run_roots("--distrust-pem", source, "--pem", target)
        self.assertEqual(code, 10)
        self.assertEqual(self.only(doc)[1], {"result": "found", "value": ["sha1", "sha256", "spki_sha256"]})

    def test_root_and_disallowed_store_keep_spki_only_matches(self) -> None:
        for store, kind, expected_code in (("ROOT", "root_store", 10), ("Disallowed", "disallowed_store", 0)):
            with self.subTest(store=store):
                self.windows.stores["ROOT"] = []
                self.windows.stores["Disallowed"] = []
                self.windows.stores[store] = [(legacy_certificate(), "x509_asn", True)]
                code, doc = self.run_roots("--windows", "--distrust", self.legacy_list("spki"))
                self.assertEqual(code, expected_code)
                row = next(row for row in self.items(doc) if row["location_kind"] == kind)
                self.assertEqual(self.verdict(row), {"result": "found", "value": ["spki_sha256"]})
                self.assertEqual(row["details"], {"certs": 1, "malformed": 0})


class OptionalDisallowedHashTests(test_roots.RootsCase):
    def audit(self, der: bytes, identifiers: tuple[bytes, ...]) -> dict[str, object]:
        self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl(
            [ctl_subject(value) for value in identifiers], subject_algorithm=DISALLOWED_HASH
        )
        path = self.write("distrust.pem", pem(der))
        code, doc = self.run_roots("--windows", "--distrust-pem", path)
        self.assertEqual(code, 0)
        row = next(row for row in self.items(doc) if row["location_kind"] == "disallowed_ctl")
        return self.verdict(row)

    def assert_missing(self, verdict: dict[str, object], *, signature: bool, public_key: bool) -> None:
        self.assertEqual(verdict["result"], "undetermined")
        self.assertEqual(verdict["reason"], "no_usable_identifier")
        detail = str(verdict["detail"])
        self.assertEqual("signature hash could not be computed" in detail, signature)
        self.assertEqual("public-key MD5 could not be computed" in detail, public_key)

    def test_missing_public_key_md5_still_allows_signature_match(self) -> None:
        for spki_der in malformed_spkis():
            with self.subTest(spki=spki_der.hex()):
                der = legacy_certificate(spki_der)
                digest = hashlib.sha256(tbs_bytes(der)).digest()
                info = parse_certificate(der)
                self.assertIsNone(info.public_key_md5)
                self.assertEqual(info.signature_hash, digest)
                self.assertEqual(self.audit(der, (digest,)), {"result": "found", "value": ["signature_hash"]})
                for identifiers in ((b"x" * 16,), ()):
                    self.assert_missing(self.audit(der, identifiers), signature=False, public_key=True)

    def test_missing_signature_hash_still_allows_public_key_match(self) -> None:
        digest = hashlib.md5(KEY_BAD, usedforsecurity=False).digest()
        for outer in malformed_signature_algorithms():
            with self.subTest(algorithm=outer.hex()):
                der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=outer)
                info = parse_certificate(der)
                self.assertIsNone(info.signature_hash)
                self.assertEqual(info.public_key_md5, digest)
                self.assertEqual(self.audit(der, (digest,)), {"result": "found", "value": ["public_key_md5"]})
                for identifiers in ((b"x" * 16,), ()):
                    verdict = self.audit(der, identifiers)
                    self.assert_missing(verdict, signature=True, public_key=False)
                    if info.signature_algorithm is not None:
                        self.assertIn(info.signature_algorithm, str(verdict["detail"]))

    def test_both_missing_hashes_are_named(self) -> None:
        der = legacy_certificate(outer_algorithm=seq())
        info = parse_certificate(der)
        self.assertIsNone(info.signature_hash)
        self.assertIsNone(info.public_key_md5)
        for identifiers in ((b"x" * 16,), ()):
            self.assert_missing(self.audit(der, identifiers), signature=True, public_key=True)

    def test_unavailable_hash_implementation_preserves_existing_identifiers(self) -> None:
        der = build_cert(LABEL, KEY_BAD)
        for name, missing in (("md5", "public_key_md5"), ("new", "signature_hash")):
            with self.subTest(hash=name), mock.patch(f"patchwait.der.hashlib.{name}", side_effect=ValueError("unavailable")):
                info = parse_certificate(der)
                self.assertEqual(info.sha256, hashlib.sha256(der).digest())
                self.assertEqual(info.sha1, hashlib.sha1(der).digest())
                self.assertEqual(info.spki_sha256, hashlib.sha256(spki_of(KEY_BAD)).digest())
                self.assertIsNone(getattr(info, missing))
