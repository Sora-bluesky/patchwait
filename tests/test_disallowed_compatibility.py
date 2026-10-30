"""Legacy outcomes for every optional read added by Disallowed-hash support.

The same tests run against origin/main's production modules loaded in memory;
they require no new Disallowed fields to exist on that version.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from unittest import mock

from patchwait.der import CertInfo, Ctl, DerError, parse_certificate, parse_ctl
from patchwait.cli import main
from patchwait.ledger import render_document
from patchwait.model import Found, RootsLink
from patchwait.roots import RootsUsageError, load_distrust
from patchwait.waitlist import saved_result_from_document
from tests import test_roots
from tests.cert_builder import (
    build_cert, build_ctl, ctl_subject, disallowed_attribute, explicit, not_before_attribute,
    octets, oid, pem, seq, spki_of, subject_for, tlv,
)
from tests.test_certificate_compatibility import malformed_signature_algorithms, malformed_spkis
from tests.test_disallowed_ctl import DISALLOWED_HASH, PSS, UNKNOWN, algorithm
from tests.test_roots import KEY_BAD, OTHER, WHEN
from tests.test_waitlist import document, item

LABEL = "Synthetic compatibility root " + "X" * 32
CERT = build_cert(LABEL, KEY_BAD)
OLD_FIELDS = ("der", "sha256", "sha1", "spki_der", "spki_sha256", "subject_cn")


class DisallowedCompatibilityTests(test_roots.RootsCase):
    def assert_old_fields(self, der: bytes, spki: bytes) -> None:
        info = parse_certificate(der)
        self.assertEqual(
            tuple(getattr(info, name) for name in OLD_FIELDS),
            (der, hashlib.sha256(der).digest(), hashlib.sha1(der).digest(), spki,
             hashlib.sha256(spki).digest(), LABEL),
        )

    def legacy_journey(self, der: bytes, spki: bytes) -> dict[str, object]:
        """Exercise input loading and every legacy certificate/CTL entry point."""
        self.assert_old_fields(der, spki)
        source = self.write("distrust.pem", pem(der))
        listing = self.write("legacy.txt", (
            f"sha256:{hashlib.sha256(der).hexdigest()} {LABEL}\n"
            f"sha1:{hashlib.sha1(der).hexdigest()} {LABEL}\n"
            f"spki:{hashlib.sha256(spki).hexdigest()} {LABEL}\n"
        ).encode("utf-8"))
        bundle = self.write("bundle.pem", pem(OTHER) + pem(der))
        single = self.write("single.cer", der)
        binary = self.write("synthetic.dll", b"MZ" + der + b"synthetic padding" + OTHER)
        tree = os.path.dirname(self.write("tree/cacert.pem", pem(der)))
        for store in ("ROOT", "Disallowed"):
            self.windows.stores[store] = [(der, "x509_asn", True)]
        for name in ("EncodedCtl", "DisallowedCertEncodedCtl"):
            self.windows.registry[name] = build_ctl([subject_for(der)])
        code, doc = self.run_roots(
            "--windows", "--distrust", listing, "--distrust-pem", source,
            "--pem", bundle, "--pem", single, "--binary", binary, "--pem-root", tree,
        )
        self.assertEqual(code, 10)
        self.assertEqual(doc["counts"], {
            "items": 8,
            "trust": {"found": 6, "not_found": 0, "undetermined": 0},
            "distrust": {"found": 2, "not_found": 0, "undetermined": 0},
        })
        for row in self.items(doc):
            ctl = row["location_kind"] in ("authroot_ctl", "disallowed_ctl")
            self.assertEqual(self.verdict(row), {
                "result": "found", "value": ["sha1", "sha256"] if ctl else ["sha1", "sha256", "spki_sha256"],
            })
            matches = row["matches"]
            assert isinstance(matches, list)
            self.assertEqual(len(matches), 2 if ctl else 3)
            details = row["details"]
            assert isinstance(details, dict)
            self.assertEqual(details.get("malformed", 0), 0)
            if ctl:
                self.assertEqual(details["ctl_entries"], 1)
            elif row["location"] == binary:
                self.assertEqual(details["certs"], 0)
                self.assertEqual(details["der_certs"], 2)
            else:
                count = 2 if row["location"] == bundle else 1
                self.assertEqual(details["certs"], count)
        return doc

    def test_outer_algorithm_failure_preserves_legacy_results(self) -> None:
        for outer in (*malformed_signature_algorithms()[:7], algorithm(UNKNOWN)):
            with self.subTest(outer=outer.hex()):
                der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=outer)
                self.legacy_journey(der, spki_of(KEY_BAD))
                self.assertIsNone(getattr(parse_certificate(der), "signature_hash", None))

    def test_pss_parameters_failure_preserves_legacy_results(self) -> None:
        for parameters in (
            b"", octets(b"synthetic"), seq(), seq(b"\xa0"),
            seq(explicit(0, seq())), seq(explicit(0, seq(tlv(0x06, b"\x80")))),
            seq(explicit(0, algorithm(UNKNOWN))),
            seq(explicit(0, algorithm("1.3.14.3.2.26")), explicit(0, algorithm("1.3.14.3.2.26"))),
        ):
            with self.subTest(parameters=parameters.hex()):
                der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=algorithm(PSS, parameters))
                self.legacy_journey(der, spki_of(KEY_BAD))
                self.assertIsNone(getattr(parse_certificate(der), "signature_hash", None))

    def test_unavailable_signature_digest_preserves_legacy_results(self) -> None:
        for name in ("1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.11"):
            der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=algorithm(name))
            with self.subTest(algorithm=name), mock.patch("hashlib.new", side_effect=ValueError("unavailable")):
                self.legacy_journey(der, spki_of(KEY_BAD))
                self.assertIsNone(getattr(parse_certificate(der), "signature_hash", None))

    def test_spki_or_md5_failure_preserves_legacy_results(self) -> None:
        for spki in malformed_spkis():
            with self.subTest(spki=spki.hex()), mock.patch("tests.cert_builder.spki", return_value=spki):
                der = build_cert(LABEL, KEY_BAD)
                self.legacy_journey(der, spki)
                self.assertIsNone(getattr(parse_certificate(der), "public_key_md5", None))
        with mock.patch("hashlib.md5", side_effect=ValueError("unavailable")):
            self.legacy_journey(CERT, spki_of(KEY_BAD))
            self.assertIsNone(getattr(parse_certificate(CERT), "public_key_md5", None))
        for unused in (0, 7):
            spki = seq(seq(), tlv(0x03, bytes([unused]) + KEY_BAD))
            with self.subTest(unused_bits=unused), mock.patch("tests.cert_builder.spki", return_value=spki):
                self.legacy_journey(build_cert(LABEL, KEY_BAD), spki)

    def test_unreadable_subject_algorithm_preserves_legacy_results(self) -> None:
        algorithms = (
            seq(), seq(oid("1.2.3." + str(2**70))), seq(tlv(0x06, b"")),
            seq(tlv(0x06, b"\x80")), seq(octets(b"synthetic")), seq(b"\x06\x02\x2a"),
            seq(oid("1.3.14.3.2.26"), b"\x05\x00" * 2),
            seq(oid(DISALLOWED_HASH), b"\x05\x00" * 2), seq(oid(DISALLOWED_HASH), b"\x05"),
        )
        listing = self.write("legacy.txt", f"sha256:{hashlib.sha256(CERT).hexdigest()} {LABEL}\n".encode("utf-8"))
        cases = (
            ([subject_for(CERT)], "found", "found"),
            ([subject_for(OTHER)], "not_found", "not_found"),
            ([ctl_subject(b"x" * 16)], "undetermined", "undetermined"),
            ([], "not_found", "not_found"),
            ([subject_for(CERT, [disallowed_attribute(WHEN), not_before_attribute(WHEN)])], "not_found", "found"),
        )
        for raw in algorithms:
            for cms in (False, True):
                for subjects, trust, distrust in cases:
                    with self.subTest(algorithm=raw.hex(), cms=cms, result=trust, entries=len(subjects)):
                        blob = build_ctl(subjects, cms=cms, subject_algorithm_der=raw)
                        ctl = parse_ctl(blob)
                        self.assertIsNone(getattr(ctl, "subject_algorithm", None))
                        for name in ("EncodedCtl", "DisallowedCertEncodedCtl"):
                            self.windows.registry[name] = blob
                        code, doc = self.run_roots("--windows", "--distrust", listing)
                        self.assertEqual(code, 10 if trust == "found" else 0)
                        rows = {str(row["location_kind"]): row for row in self.items(doc)}
                        for kind, expected in (("authroot_ctl", trust), ("disallowed_ctl", distrust)):
                            row = rows[kind]
                            self.assertEqual(self.verdict(row)["result"], expected)
                            if expected == "undetermined":
                                self.assertEqual(self.verdict(row)["reason"], "no_usable_identifier")
                            details = row["details"]
                            assert isinstance(details, dict)
                            self.assertEqual(details["ctl_entries"], len(subjects))

    def test_duplicate_input_with_missing_hashes_still_merges(self) -> None:
        path = self.write("duplicate.pem", pem(CERT) + pem(CERT))
        listing = self.write("legacy.txt", f"sha256:{hashlib.sha256(CERT).hexdigest()} {LABEL}\n".encode("utf-8"))
        original_new, original_md5 = hashlib.new, hashlib.md5
        for target, original in (("new", original_new), ("md5", original_md5)):
            for unavailable in (0, 1):
                calls = 0

                def intermittent(*args: object, **kwargs: object) -> object:
                    nonlocal calls
                    calls += 1
                    if (calls - 1) % 2 == unavailable:
                        raise ValueError("unavailable")
                    return original(*args, **kwargs)  # pyright: ignore[reportArgumentType]

                with self.subTest(hash=target, unavailable=unavailable), mock.patch(f"hashlib.{target}", side_effect=intermittent):
                    (entry,) = load_distrust([listing], [path, path])
                    self.assertEqual(tuple(getattr(entry, name) for name in OLD_FIELDS[:-1]), (
                        CERT, hashlib.sha256(CERT).digest(), hashlib.sha1(CERT).digest(),
                        spki_of(KEY_BAD), hashlib.sha256(spki_of(KEY_BAD)).digest(),
                    ))
                    code, doc = self.run_roots("--distrust", listing, "--distrust-pem", path, "--distrust-pem", path, "--pem", path)
                    self.assertEqual(code, 10)
                    self.assertEqual(len(self.items(doc)), 1)
        other = self.write("conflict.pem", pem(build_cert(LABEL, KEY_BAD, serial=2)))
        with self.assertRaises(RootsUsageError):
            load_distrust([], [path, other])

    def test_optional_json_fields_preserve_saved_result_consumers(self) -> None:
        unknown = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=seq())
        for der, missing_md5 in ((CERT, False), (unknown, False), (unknown, True)):
            unavailable = mock.patch("hashlib.md5", side_effect=ValueError("unavailable"))
            with self.subTest(certificate=hashlib.sha256(der).hexdigest(), missing_md5=missing_md5), \
                    unavailable if missing_md5 else contextlib.nullcontext():
                doc = self.legacy_journey(der, spki_of(KEY_BAD))
                legacy = json.loads(json.dumps(doc))
                for entry in legacy["distrust"]:
                    entry.pop("signature_hash", None)
                    entry.pop("public_key_md5", None)
                self.assertEqual(render_document(doc, "synthetic"), render_document(legacy, "synthetic"))
                self.assertEqual(saved_result_from_document(doc, "synthetic"), saved_result_from_document(legacy, "synthetic"))
                row = self.items(doc)[0]
                link = RootsLink(str(row["location_kind"]), str(row["location"]), LABEL)
                expected = Found("sha1, sha256")
                self.assertEqual(saved_result_from_document(doc, "synthetic").rows[link], [expected])
                waitlist = self.write("waitlist.json", json.dumps(document(item(
                    "disallowed-ctl", "2026-10-01", result_link={"check": "roots", "location_kind": link.location_kind,
                                                    "location": link.location, "distrust": LABEL},
                ))).encode("utf-8"))
                result = self.write("result.json", json.dumps(doc).encode("utf-8"))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["waitlist", "record", waitlist, "--from", result]), 0)
                with open(waitlist, encoding="utf-8") as handle:
                    recorded = json.load(handle)
                self.assertEqual(recorded["items"][0]["last_result"], {"result": "found", "value": expected.value})

    def test_subject_algorithm_dispatch_preserves_other_ctl_results(self) -> None:
        listing = self.write("legacy.txt", f"sha256:{hashlib.sha256(CERT).hexdigest()} {LABEL}\n".encode("utf-8"))
        for name in ("1.3.14.3.2.26", UNKNOWN):
            for subjects in ([subject_for(CERT)], [subject_for(OTHER)], [ctl_subject(b"x" * 16)], []):
                with self.subTest(algorithm=name, subjects=subjects):
                    self.windows.registry["EncodedCtl"] = build_ctl(subjects, subject_algorithm=DISALLOWED_HASH)
                    self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl(subjects, subject_algorithm=name)
                    code, doc = self.run_roots("--windows", "--distrust", listing)
                    expected = "found" if subjects == [subject_for(CERT)] else "undetermined" if subjects == [ctl_subject(b"x" * 16)] else "not_found"
                    self.assertEqual(code, 10 if expected == "found" else 0)
                    for row in self.items(doc):
                        if row["location_kind"] in ("authroot_ctl", "disallowed_ctl"):
                            self.assertEqual(self.verdict(row)["result"], expected)

    def test_legacy_constructors_allow_missing_optional_metadata(self) -> None:
        parsed = parse_certificate(CERT)
        with self.subTest(constructor="CertInfo"):
            info = CertInfo(*(getattr(parsed, name) for name in OLD_FIELDS))
            self.assertEqual(tuple(getattr(info, name) for name in OLD_FIELDS), tuple(getattr(parsed, name) for name in OLD_FIELDS))
            for name in ("signature_algorithm", "signature_hash", "public_key_md5"):
                self.assertIsNone(getattr(info, name, None))
        parsed_ctl = parse_ctl(build_ctl([subject_for(CERT)]))
        with self.subTest(constructor="Ctl"):
            ctl = Ctl(parsed_ctl.this_update, parsed_ctl.entries)
            self.assertEqual(ctl.this_update, parsed_ctl.this_update)
            self.assertEqual(ctl.entries, parsed_ctl.entries)
            self.assertIsNone(getattr(ctl, "subject_algorithm", None))

    def test_unknown_hashes_stay_local_to_disallowed_judgment(self) -> None:
        der = build_cert(LABEL, KEY_BAD, outer_signature_algorithm=algorithm(UNKNOWN))
        with mock.patch("hashlib.md5", side_effect=ValueError("unavailable")):
            self.legacy_journey(der, spki_of(KEY_BAD))
            self.windows.registry["DisallowedCertEncodedCtl"] = build_ctl(
                [ctl_subject(b"x" * 16)], subject_algorithm=DISALLOWED_HASH,
            )
            path = os.path.join(self.dir, "distrust.pem")
            code, doc = self.run_roots("--windows", "--distrust-pem", path)
            self.assertEqual(code, 10)
            self.assertEqual(doc["counts"], {
                "items": 4,
                "trust": {"found": 2, "not_found": 0, "undetermined": 0},
                "distrust": {"found": 1, "not_found": 0, "undetermined": 1},
            })
            for row in self.items(doc):
                verdict = self.verdict(row)
                if row["location_kind"] == "disallowed_ctl":
                    self.assertEqual(verdict["result"], "undetermined")
                    self.assertEqual(verdict["reason"], "no_usable_identifier")
                    self.assertEqual(row["matches"], [])
                else:
                    self.assertEqual(verdict["result"], "found")

    def test_legacy_structure_checks_still_reject_bad_ctl(self) -> None:
        for raw in (octets(b"synthetic"), oid("1.3.14.3.2.26")):
            with self.subTest(algorithm=raw.hex()), self.assertRaises(DerError):
                parse_ctl(build_ctl([], subject_algorithm_der=raw))
        with self.assertRaises(DerError):
            parse_ctl(build_ctl([octets(b"not a TrustedSubject")], subject_algorithm_der=seq()))
