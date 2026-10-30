"""Synthetic Disallowed-hash CTLs, certificate properties and saved-result consumers."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os

from patchwait.cli import main
from patchwait.der import parse_certificate, parse_ctl
from patchwait.ledger import render_document
from patchwait.model import Found, RootsLink
from patchwait.waitlist import saved_result_from_document
from tests.cert_builder import (
    build_cert,
    build_ctl,
    ctl_subject,
    explicit,
    oid,
    pem,
    seq,
    sha256_attribute,
)
from tests import test_roots
from tests.test_roots import KEY_BAD
from tests.test_waitlist import document, item

DISALLOWED_HASH = "1.3.6.1.4.1.311.10.11.15"
PSS = "1.2.840.113549.1.1.10"
UNKNOWN = "1.2.3.4.5"
LABEL = "Synthetic Disallowed Root"


def algorithm(name: str, parameters: bytes = b"\x05\x00") -> bytes:
    return seq(oid(name), parameters)


def tbs_bytes(der: bytes) -> bytes:
    """Slice the first child without using the production DER reader."""
    start = 2 + ((der[1] & 0x7F) if der[1] & 0x80 else 0)
    length_byte = der[start + 1]
    count = (length_byte & 0x7F) if length_byte & 0x80 else 0
    size = int.from_bytes(der[start + 2 : start + 2 + count], "big") if count else length_byte
    return der[start : start + 2 + count + size]


class DisallowedHashTests(test_roots.RootsCase):
    def authroot(self) -> None:
        self.windows.registry["EncodedCtl"] = build_ctl([])

    def by_kind(self, doc: dict[str, object]) -> dict[str, dict[str, object]]:
        return {str(row["location_kind"]): row for row in self.items(doc)}

    def audit(self, der: bytes, subjects: list[bytes]) -> tuple[dict[str, object], dict[str, object]]:
        self.authroot()
        self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl(
            subjects, subject_algorithm=DISALLOWED_HASH, subject_algorithm_parameters=b"\x05\x00"
        )
        path = self.write("synthetic.pem", pem(der))
        code, doc = self.run_roots("--windows", "--distrust-pem", path)
        self.assertEqual(code, 0)
        return doc, self.by_kind(doc)["disallowed_ctl"]

    def assert_match(self, der: bytes, identifier: bytes, method: str) -> dict[str, object]:
        doc, row = self.audit(der, [ctl_subject(identifier)])
        self.assertEqual(self.verdict(row), {"result": "found", "value": [method]})
        self.assertEqual(row["matches"], [{"matched_by": method, "identifier": identifier.hex()}])
        return doc

    def test_md5_signature_hash(self) -> None:
        der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=algorithm("1.2.840.113549.1.1.4"))
        digest = hashlib.md5(tbs_bytes(der), usedforsecurity=False).digest()
        self.assert_match(der, digest, "signature_hash")

    def test_sha384_signature_hash(self) -> None:
        for name in ("1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3"):
            with self.subTest(algorithm=name):
                der = build_cert(LABEL, KEY_BAD, signature_algorithm=algorithm(name))
                self.assert_match(der, hashlib.sha384(tbs_bytes(der)).digest(), "signature_hash")

    def test_public_key_md5_even_with_unknown_signature(self) -> None:
        for name in ("1.2.840.113549.1.1.11", UNKNOWN):
            with self.subTest(algorithm=name):
                der = build_cert(LABEL, KEY_BAD, signature_algorithm=algorithm(name))
                self.assert_match(der, hashlib.md5(KEY_BAD, usedforsecurity=False).digest(), "public_key_md5")

    def test_no_match_is_not_found_after_both_hashes_were_compared(self) -> None:
        der = build_cert(LABEL, KEY_BAD)
        for subjects in (
            [ctl_subject(b"x" * 16), ctl_subject(b"y" * 48)],
            [ctl_subject(hashlib.sha1(der).digest(), [sha256_attribute(der)])],
            [],
        ):
            with self.subTest(subjects=subjects):
                _, row = self.audit(der, subjects)
                self.assertEqual(self.verdict(row), {"result": "not_found"})
                self.assertEqual(row["matches"], [])

    def test_unknown_signature_nonmatch_stays_undetermined(self) -> None:
        der = build_cert(LABEL, KEY_BAD, signature_algorithm=algorithm(UNKNOWN))
        for subjects in ([ctl_subject(b"x" * 16)], []):
            with self.subTest(subjects=subjects):
                _, row = self.audit(der, subjects)
                verdict = self.verdict(row)
                self.assertEqual(verdict["result"], "undetermined")
                self.assertEqual(verdict["reason"], "no_usable_identifier")
                self.assertIn(UNKNOWN, str(verdict["detail"]))

    def test_text_identifiers_need_a_certificate(self) -> None:
        self.authroot()
        for prefix, size in (("sha256", 32), ("sha1", 20), ("spki", 32)):
            for subjects in ([ctl_subject(b"x" * size)], []):
                with self.subTest(prefix=prefix, subjects=subjects):
                    self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl(subjects, subject_algorithm=DISALLOWED_HASH)
                    path = self.write("synthetic.txt", f"{prefix}:{'78' * size} {LABEL}\n".encode("utf-8"))
                    _, doc = self.run_roots("--windows", "--distrust", path)
                    verdict = self.verdict(self.by_kind(doc)["disallowed_ctl"])
                    self.assertEqual(verdict["result"], "undetermined")
                    self.assertEqual(verdict["reason"], "no_usable_identifier")
                    self.assertIn("signature hash or public-key MD5 of a certificate", str(verdict["detail"]))

    def test_subject_algorithm_controls_disallowed_only(self) -> None:
        der = build_cert(LABEL, KEY_BAD)
        identifier = hashlib.md5(KEY_BAD, usedforsecurity=False).digest()
        self.assert_match(der, identifier, "public_key_md5")
        for name in ("1.3.14.3.2.26", UNKNOWN):
            self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl([ctl_subject(identifier)], subject_algorithm=name)
            _, doc = self.run_roots("--windows", "--distrust-pem", os.path.join(self.dir, "synthetic.pem"))
            verdict = self.verdict(self.by_kind(doc)["disallowed_ctl"])
            self.assertEqual(verdict["result"], "undetermined")
        self.windows.registry["EncodedCtl"] = build_ctl([ctl_subject(identifier)], subject_algorithm=DISALLOWED_HASH)
        _, doc = self.run_roots("--windows", "--distrust-pem", os.path.join(self.dir, "synthetic.pem"))
        self.assertEqual(self.verdict(self.by_kind(doc)["authroot_ctl"])["result"], "undetermined")

    def test_signature_digests_use_the_outer_algorithm_and_complete_tbs(self) -> None:
        algorithms = {
            "1.2.840.113549.1.1.4": "md5",
            "1.2.840.113549.1.1.5": "sha1",
            "1.2.840.113549.1.1.11": "sha256",
            "1.2.840.113549.1.1.12": "sha384",
            "1.2.840.113549.1.1.13": "sha512",
            "1.2.840.10045.4.1": "sha1",
            "1.2.840.10045.4.3.2": "sha256",
            "1.2.840.10045.4.3.3": "sha384",
            "1.2.840.10045.4.3.4": "sha512",
        }
        for name, digest in algorithms.items():
            with self.subTest(algorithm=name):
                der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=algorithm(name))
                info = parse_certificate(der)
                self.assertEqual(getattr(info, "signature_hash", None), hashlib.new(digest, tbs_bytes(der)).digest())
                self.assertEqual(getattr(info, "public_key_md5", None), hashlib.md5(KEY_BAD, usedforsecurity=False).digest())

    def test_pss_uses_only_an_explicit_known_hash(self) -> None:
        for name, digest in (("1.3.14.3.2.26", "sha1"), ("2.16.840.1.101.3.4.2.1", "sha256"),
                             ("2.16.840.1.101.3.4.2.2", "sha384"), ("2.16.840.1.101.3.4.2.3", "sha512")):
            with self.subTest(hash=name):
                params = seq(explicit(0, algorithm(name)))
                der = build_cert(LABEL, KEY_BAD, signature_algorithm=algorithm(PSS, params))
                self.assert_match(der, hashlib.new(digest, tbs_bytes(der)).digest(), "signature_hash")
        for params in (b"", seq(), seq(explicit(0, algorithm(UNKNOWN)))):
            with self.subTest(parameters=params):
                der = build_cert(LABEL, KEY_BAD, signature_algorithm=algorithm(PSS, params))
                _, row = self.audit(der, [ctl_subject(b"x" * 16)])
                self.assertEqual(self.verdict(row)["result"], "undetermined")
                self.assertIn(PSS, str(self.verdict(row)["detail"]))

    def test_identifiers_are_exposed_and_survive_label_merging(self) -> None:
        der = build_cert(LABEL, KEY_BAD)
        path = self.write("synthetic.txt", f"sha256:{hashlib.sha256(der).hexdigest()} {LABEL}\n".encode("utf-8"))
        doc, _ = self.audit(der, [])
        _, merged = self.run_roots("--windows", "--distrust", path, "--distrust-pem", os.path.join(self.dir, "synthetic.pem"))
        self.assertEqual(merged["distrust"], doc["distrust"])
        expected = {
            "signature_hash": hashlib.sha256(tbs_bytes(der)).hexdigest(),
            "public_key_md5": hashlib.md5(KEY_BAD, usedforsecurity=False).hexdigest(),
        }
        entries = doc["distrust"]
        assert isinstance(entries, list)
        for key, value in expected.items():
            self.assertEqual(entries[0].get(key), value)
        ctl = parse_ctl(build_ctl([], subject_algorithm=DISALLOWED_HASH))
        self.assertEqual(getattr(ctl, "subject_algorithm", None), DISALLOWED_HASH)

    def test_new_matches_round_trip_through_ledger_and_waitlist_record_from(self) -> None:
        der = build_cert(LABEL, KEY_BAD)
        for method, digest in (("signature_hash", hashlib.sha256(tbs_bytes(der)).digest()),
                               ("public_key_md5", hashlib.md5(KEY_BAD, usedforsecurity=False).digest())):
            with self.subTest(method=method):
                doc = self.assert_match(der, digest, method)
                self.assertIn(f"matched_by `{method}`", render_document(doc, "synthetic").markdown)
                row = self.by_kind(doc)["disallowed_ctl"]
                link = RootsLink("disallowed_ctl", str(row["location"]), LABEL)
                self.assertEqual(saved_result_from_document(doc, "synthetic").rows[link], [Found(method)])
                waitlist = self.write("waitlist.json", json.dumps(document(item(
                    "disallowed-ctl", "2026-10-01", result_link={"check": "roots", "location_kind": link.location_kind,
                                                    "location": link.location, "distrust": link.distrust},
                ))).encode("utf-8"))
                result = self.write("result.json", json.dumps(doc).encode("utf-8"))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(["waitlist", "record", waitlist, "--from", result])
                self.assertEqual(code, 0)
                with open(waitlist, encoding="utf-8") as handle:
                    recorded = json.load(handle)
                self.assertEqual(recorded["items"][0]["last_result"], {"result": "found", "value": method})
