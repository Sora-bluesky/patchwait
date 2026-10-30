"""Structural keystore auditing using only synthetic fixtures."""

from __future__ import annotations

import copy
import datetime
import hashlib
import io
import json
import os
from unittest import mock

from patchwait.ledger import LedgerInputError, render_document
from patchwait.waitlist import WaitlistInputError, saved_result_from_document
from tests.cert_builder import explicit, integer, octets, oid, pem, seq, set_of, tlv
from tests.keystore_builder import (
    DATA, ENCRYPTED, ENVELOPED, JCEKS_MAGIC, bag, cert_bag, content_info,
    encrypted_info, jks, mac_data, pfx, private_entry, safe, trusted_entry, u32, utf,
)
from tests.test_roots import BAD, OTHER, REISSUED, RootsCase, binary_details
from tests.test_waitlist import document, item


class KeystoreTests(RootsCase):
    def audit(self, data: bytes, *, result: str = "undetermined", name: str = "input.store") -> dict[str, object]:
        path = self.write(name, data)
        try:
            code, doc = self.run_roots("--distrust", self.list_path, "--keystore", path)
        except SystemExit as error:
            self.fail(f"roots must accept --keystore, but argparse exited {error.code}")
        self.assertEqual(code, 10 if result == "found" else 0)
        row, verdict = self.only(doc)
        self.assertEqual((row["location_kind"], row["role"], verdict["result"]), ("java_keystore", "trust", result))
        return row

    def test_detection(self) -> None:
        for data, fmt in ((pfx(safe(cert_bag(BAD))), "pkcs12"), (jks(trusted_entry(BAD)), "jks")):
            with self.subTest(fmt=fmt):
                row = self.audit(data, result="found", name="misleading.pem")
                self.assertEqual(row["details"]["format"], fmt)  # type: ignore[index]
        for data in (b"", b"not a keystore", b"\xff\xed\xfe\xed", pem(BAD)):
            with self.subTest(data=data[:8]):
                row = self.audit(data)
                self.assertEqual(self.verdict(row)["reason"], "malformed_keystore")

    def test_found_not_found(self) -> None:
        for cert in (BAD, OTHER):
            for data in (pfx(safe(cert_bag(cert))), jks(trusted_entry(cert)), jks(trusted_entry(cert, version=1), version=1)):
                with self.subTest(cert=cert[:8], data=data[:8]):
                    row = self.audit(data, result="found" if cert == BAD else "not_found")
                    self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
        for data in (pfx(), jks()):
            self.audit(data, result="not_found")

    def test_matching_uses_existing_identifiers(self) -> None:
        from patchwait.der import parse_certificate
        from patchwait.model import Found
        from patchwait.roots import DistrustEntry, audit_keystore
        parsed = parse_certificate(BAD)
        entries = [DistrustEntry("SHA-256", sha256=parsed.sha256), DistrustEntry("SHA-1", sha1=parsed.sha1),
                   DistrustEntry("SPKI", spki_sha256=parsed.spki_sha256)]
        for data in (pfx(safe(cert_bag(BAD))), jks(trusted_entry(BAD))):
            path = self.write("identifiers.store", data)
            results = audit_keystore(path, entries)
            self.assertEqual([r.verdict for r in results], [Found(("sha256",)), Found(("sha1",)), Found(("spki_sha256",))])
        path = self.write("reissued.store", pfx(safe(cert_bag(REISSUED))))
        self.assertEqual(audit_keystore(path, entries)[2].verdict, Found(("spki_sha256",)))

    def test_only_certificate_fields_scanned(self) -> None:
        attrs = set_of(seq(oid("1.2.3.4"), set_of(octets(BAD))))
        self.audit(pfx(safe(bag(1, seq(octets(BAD))), cert_bag(OTHER, attributes=attrs))), result="not_found")
        self.audit(jks(private_entry(key=BAD), trusted_entry(OTHER, alias=BAD)), result="not_found")

    def test_pfx_boundaries(self) -> None:
        data = pfx(safe(cert_bag(OTHER)))
        for damaged in (data[:-1], data + b"trailing", b"\x30\x84\x7f\xff\xff\xff", b"\x30\x80\x00\x00"):
            self.audit(damaged)
        self.audit(pfx(safe(cert_bag(BAD))) + b"trailing", result="found")

    def test_pfx_version(self) -> None:
        for version in (0, 1, 2, 4, 2**40):
            self.audit(pfx(safe(cert_bag(OTHER)), version=version))

    def test_authsafe_type(self) -> None:
        for kind in (ENCRYPTED, ENVELOPED, "1.2.3.4"):
            row = self.audit(pfx(auth_type=kind))
            self.assertEqual(self.verdict(row)["reason"], "keystore_unreadable")

    def test_content_wrappers(self) -> None:
        for auth in (seq(oid(DATA)), seq(oid(DATA), octets(b"")), content_info(b"\x30\x04"), content_info(octets(b"")),
                     seq(oid(DATA), seq(octets(seq()))), seq(oid(DATA), explicit(0, seq(seq())))):
            self.audit(seq(integer(3), auth))
        for ci in (seq(oid(DATA), explicit(0, integer(0))), seq(oid(DATA), explicit(0, octets(b""),) + b"\x00"),
                   seq(oid(DATA), seq(octets(seq(cert_bag(OTHER))))),
                   seq(oid(DATA), explicit(0, seq(seq(cert_bag(OTHER)))))):
            self.audit(pfx(ci))

    def test_authenticated_safe_trailing_data(self) -> None:
        for cert in (OTHER, BAD):
            for tail in (b"\x00", seq(safe(cert_bag(BAD)))):
                with self.subTest(matching=cert == BAD, tail=tail[:2]):
                    auth = content_info(seq(safe(cert_bag(cert))) + tail)
                    row = self.audit(seq(integer(3), auth), result="found" if cert == BAD else "undetermined")
                    self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
                    self.assertGreater(row["details"]["unreadable_parts"], 0)  # type: ignore[index]
                    if cert == OTHER:
                        self.assertEqual(self.verdict(row)["reason"], "malformed_keystore")

    def test_safe_contents_trailing_data(self) -> None:
        for cert in (OTHER, BAD):
            for tail in (b"\x00", seq(cert_bag(BAD))):
                with self.subTest(matching=cert == BAD, tail=tail[:2]):
                    row = self.audit(pfx(content_info(seq(cert_bag(cert)) + tail)),
                                     result="found" if cert == BAD else "undetermined")
                    self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
                    self.assertGreater(row["details"]["unreadable_parts"], 0)  # type: ignore[index]
                    if cert == OTHER:
                        self.assertEqual(self.verdict(row)["reason"], "malformed_keystore")

    def test_readable_prefix_with_extra_fields(self) -> None:
        from tests.keystore_builder import BAG_BASE, X509
        for cert in (OTHER, BAD):
            for tail in (integer(1), b"\x00"):
                value = seq(oid(X509), explicit(0, octets(cert)))
                infos = seq(safe(cert_bag(cert)))
                cases = (
                    seq(integer(3), seq(oid(DATA), explicit(0, octets(infos)), tail)),
                    seq(integer(3), seq(oid(DATA), explicit(0, octets(infos) + tail))),
                    pfx(seq(oid(DATA), explicit(0, octets(seq(cert_bag(cert)))), tail)),
                    pfx(seq(oid(DATA), explicit(0, octets(seq(cert_bag(cert))) + tail))),
                    pfx(safe(seq(oid(BAG_BASE + "3"), explicit(0, value + tail)))),
                    pfx(safe(bag(3, seq(oid(X509), explicit(0, octets(cert)), tail)))),
                    pfx(safe(bag(3, seq(oid(X509), explicit(0, octets(cert) + tail))))),
                )
                for index, data in enumerate(cases):
                    with self.subTest(matching=cert == BAD, tail=tail, wrapper=index):
                        row = self.audit(data, result="found" if cert == BAD else "undetermined")
                        self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
                        self.assertGreater(row["details"]["unreadable_parts"], 0)  # type: ignore[index]

    def test_oid_and_certificate_boundaries(self) -> None:
        for bad_oid in (octets(b""), tlv(6, b""), tlv(6, b"\x80"), tlv(6, b"\x81" * 10 + b"\x01")):
            self.audit(seq(integer(3), seq(bad_oid, explicit(0, octets(seq())))))
            self.audit(pfx(safe(seq(bad_oid, explicit(0, seq())))))
            self.audit(pfx(safe(bag(3, seq(bad_oid, explicit(0, octets(OTHER)))))))
        for value in (integer(1), octets(OTHER) + integer(1)):
            self.audit(pfx(safe(bag(3, seq(oid("1.2.840.113549.1.9.22.1"), explicit(0, value))))))
        for version in (tlv(2, b""), tlv(2, b"\xff"), octets(b"\x03")):
            self.audit(seq(version, content_info(seq())))

    def test_encrypted_content(self) -> None:
        for kind in (ENCRYPTED, ENVELOPED):
            for cert in (None, OTHER, BAD):
                with self.subTest(kind=kind, matching=cert == BAD):
                    infos = [encrypted_info(kind)] + ([safe(cert_bag(cert))] if cert is not None else [])
                    row = self.audit(pfx(*infos), result="found" if cert == BAD else "undetermined")
                    self.assertEqual(row["details"]["encrypted_content_infos"], 1)  # type: ignore[index]
                    if cert != BAD:
                        self.assertIn("1 encrypted ContentInfo not read", str(self.verdict(row)["detail"]))
        self.audit(pfx(content_info(seq(), "1.2.3.4")))
        self.audit(pfx(safe(cert_bag(BAD)), encrypted_info()), result="found")

    def test_verdict_is_per_distrust_entry(self) -> None:
        path = self.write("partial.pfx", pfx(encrypted_info(), safe(cert_bag(BAD))))
        distrust = self.write("two.txt", f"{hashlib.sha256(BAD).hexdigest()} Bad\n{hashlib.sha256(OTHER).hexdigest()} Other\n".encode())
        code, doc = self.run_roots("--distrust", distrust, "--keystore", path)
        self.assertEqual(code, 10)
        self.assertEqual([self.verdict(row)["result"] for row in self.items(doc)], ["found", "undetermined"])

    def test_safe_boundaries(self) -> None:
        for safe_bytes in (octets(b""), seq(tlv(4, b"")), seq(cert_bag(OTHER), b"\x30\x84\xff\xff\xff\xff")):
            self.audit(pfx(content_info(safe_bytes)))
        self.audit(pfx(content_info(seq(b"\x30\x00", cert_bag(BAD)))), result="found")
        self.audit(pfx(content_info(seq(cert_bag(BAD), b"\x30\x84\xff\xff\xff\xff"))), result="found")

    def test_bag_types(self) -> None:
        row = self.audit(pfx(safe(*(bag(kind) for kind in (1, 2, 4, 5)))), result="not_found")
        self.assertEqual(row["details"]["bags"], {"keyBag": 1, "pkcs8ShroudedKeyBag": 1, "crlBag": 1, "secretBag": 1})  # type: ignore[index]
        row = self.audit(pfx(safe(bag(99))))
        self.assertEqual(row["details"]["bags"], {"unknown": 1})  # type: ignore[index]
        self.audit(pfx(safe(bag(99), cert_bag(BAD))), result="found")

    def test_bag_attributes(self) -> None:
        attrs = set_of(seq(oid("1.2.840.113549.1.9.20"), set_of(tlv(0x1E, "synthetic".encode("utf-16-be")))))
        self.audit(pfx(safe(cert_bag(OTHER, attributes=attrs))), result="not_found")
        for attrs in (octets(b""), set_of(seq(oid("1.2.3"))), set_of(seq(oid("1.2.3"), octets(b"")))):
            self.audit(pfx(safe(cert_bag(OTHER, attributes=attrs))))
        self.audit(pfx(safe(cert_bag(BAD, attributes=octets(b"")))), result="found")

    def test_readable_bags_with_malformed_attributes(self) -> None:
        for attrs in (octets(b""), set_of(seq(integer(7), set_of())),
                      set_of(seq(oid("1.2.3"), octets(b""))), set_of(b"\x00"),
                      b"\x00", set_of() + integer(1)):
            for cert in (OTHER, BAD):
                for nested in (False, True):
                    with self.subTest(attrs=attrs, matching=cert == BAD, nested=nested):
                        value = bag(6, seq(cert_bag(cert)), attributes=attrs) if nested else cert_bag(cert, attributes=attrs)
                        row = self.audit(pfx(safe(value)), result="found" if cert == BAD else "undetermined")
                        self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
                        self.assertGreater(row["details"]["unreadable_parts"], 0)  # type: ignore[index]
                        if cert == OTHER:
                            self.assertEqual(self.verdict(row)["reason"], "malformed_keystore")

    def test_nested_bags(self) -> None:
        row = self.audit(pfx(safe(bag(6, seq(cert_bag(BAD))))), result="found")
        self.assertEqual(row["details"]["bags"], {"safeContentsBag": 1, "certBag": 1})  # type: ignore[index]
        nested = cert_bag(OTHER)
        for _ in range(1100):
            nested = bag(6, seq(nested))
        self.audit(pfx(safe(nested)), result="not_found")

    def test_cert_id(self) -> None:
        self.audit(pfx(safe(cert_bag(OTHER, cert_id="1.2.3.4"))))
        self.audit(pfx(safe(cert_bag(OTHER, cert_id="1.2.3.4"), cert_bag(BAD))), result="found")

    def test_unparsable_cert(self) -> None:
        for build in (lambda *certs: pfx(safe(*(cert_bag(c) for c in certs))), lambda *certs: jks(*(trusted_entry(c) for c in certs))):
            row = self.audit(build(b"broken certificate"))
            self.assertEqual(self.verdict(row)["reason"], "malformed_cert")
            self.assertEqual(row["details"]["malformed"], 1)  # type: ignore[index]
            self.audit(build(b"broken certificate", BAD), result="found")
        self.write("raw-hash.txt", f"{hashlib.sha256(b'broken certificate').hexdigest()} Broken\n".encode())
        path = self.write("raw.store", pfx(safe(cert_bag(b"broken certificate"))))
        code, doc = self.run_roots("--distrust", os.path.join(self.dir, "raw-hash.txt"), "--keystore", path)
        self.assertEqual((code, self.only(doc)[1]["result"]), (10, "found"))

    def test_mac_data(self) -> None:
        for mac, present in ((b"", False), (mac_data(), True)):
            row = self.audit(pfx(safe(cert_bag(OTHER)), mac=mac), result="not_found")
            self.assertEqual(row["details"]["mac_data"], present)  # type: ignore[index]
        for mac in (octets(b""), seq(), seq(seq(), octets(b"salt")), mac_data() + mac_data(), mac_data()[:-1] + b"\x00"):
            self.audit(pfx(safe(cert_bag(OTHER)), mac=mac))
        self.audit(pfx(safe(cert_bag(BAD)), mac=seq()), result="found")

    def test_mac_algorithm_oid(self) -> None:
        for algorithm in (integer(7), octets(b""), tlv(6, b""), tlv(6, b"\x80")):
            for cert in (OTHER, BAD):
                with self.subTest(algorithm=algorithm, matching=cert == BAD):
                    mac = seq(seq(seq(algorithm), octets(b"d")), octets(b"s"), integer(1))
                    row = self.audit(pfx(safe(cert_bag(cert)), mac=mac), result="found" if cert == BAD else "undetermined")
                    self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
                    self.assertGreater(row["details"]["unreadable_parts"], 0)  # type: ignore[index]
                    if cert == OTHER:
                        self.assertEqual(self.verdict(row)["reason"], "malformed_keystore")

    def test_jks_header(self) -> None:
        for data in (jks(version=0), jks(version=3), jks(count=2**32-1), jks()[:8], b"\xfe\xed\xfe\xed"):
            self.audit(data)

    def test_entry_tags(self) -> None:
        for tag in (0, 3, 2**32-1):
            self.audit(jks(u32(tag)))
        self.audit(jks(trusted_entry(BAD), u32(9)), result="found")

    def test_entry_metadata(self) -> None:
        for entry in (u32(2) + b"\xff\xff", u32(2) + utf(b"alias") + b"\x00" * 7):
            self.audit(jks(entry, integrity=b""))
        self.audit(jks(trusted_entry(OTHER, alias=b"synthetic\xc0\x80\xed\xa0\x80")), result="not_found")

    def test_certificate_type(self) -> None:
        self.audit(jks(trusted_entry(OTHER, cert_type=b"unknown")))
        self.audit(jks(trusted_entry(OTHER, cert_type=b"unknown"), trusted_entry(BAD)), result="found")
        self.audit(jks(trusted_entry(OTHER, cert_type=b"X509")), result="not_found")
        self.audit(jks(u32(2) + utf(b"alias") + b"\x00" * 8 + b"\xff\xff", integrity=b""))

    def test_jks_lengths(self) -> None:
        prefix = u32(2) + utf(b"alias") + b"\x00" * 8 + utf(b"X.509")
        for length in (0, 2**31, 2**32-1):
            self.audit(jks(prefix + u32(length)))
        for data in (pfx(safe(cert_bag(OTHER))), jks(trusted_entry(OTHER))):
            self.audit(data, result="not_found")
            for end in range(len(data)):
                with self.subTest(prefix=end, format=data[:4]):
                    self.audit(data[:end])

    def test_private_key_chain(self) -> None:
        for version in (1, 2):
            row = self.audit(jks(private_entry([OTHER], version=version), version=version), result="not_found")
            self.assertEqual(row["details"]["entries"], {"private_key": 1})  # type: ignore[index]
            self.assertEqual(row["details"]["certs"], 1)  # type: ignore[index]
            self.audit(jks(private_entry([OTHER, BAD], version=version), version=version), result="found")
        self.audit(jks(private_entry()), result="not_found")
        for suffix in (u32(2**32-1), u32(0) + u32(2**32-1)):
            self.audit(jks(u32(1) + utf(b"alias") + b"\x00" * 8 + suffix, integrity=b""))

    def test_jceks(self) -> None:
        for cert in (BAD, OTHER):
            self.audit(jks(trusted_entry(cert), magic=JCEKS_MAGIC), result="found" if cert == BAD else "not_found")
        for entry in (private_entry(), u32(3)):
            self.audit(jks(entry, magic=JCEKS_MAGIC))

    def test_jks_trailing(self) -> None:
        data = jks(trusted_entry(OTHER))
        for damaged in (data[:-1], data + b"extra", jks(trusted_entry(OTHER), count=0)):
            self.audit(damaged)
        self.audit(jks(trusted_entry(OTHER), integrity=b"\xff" * 20), result="not_found")
        self.audit(jks(trusted_entry(BAD)) + b"extra", result="found")

    def test_file_limits(self) -> None:
        from patchwait.keystore import MAX_KEYSTORE_FILE
        from patchwait.roots import DistrustEntry, audit_keystore
        entry = DistrustEntry("Synthetic", sha256=hashlib.sha256(BAD).digest())
        path = self.write("large.store", b"")
        with open(path, "r+b") as handle:
            handle.truncate(MAX_KEYSTORE_FILE + 1)
        with mock.patch("builtins.open", side_effect=AssertionError("must reject before open")):
            (row,) = audit_keystore(path, [entry])
        self.assertEqual(row.to_json()["verdict"]["reason"], "file_unreadable")  # type: ignore[index]
        self.assertIn(str(MAX_KEYSTORE_FILE), str(row.to_json()["verdict"]["detail"]))  # type: ignore[index]
        for target, reason in (("missing.store", "target_missing"), (".", "file_unreadable")):
            (row,) = audit_keystore(os.path.join(self.dir, target), [entry])
            self.assertEqual(row.to_json()["verdict"]["reason"], reason)  # type: ignore[index]

    def test_file_grows_before_open(self) -> None:
        from patchwait.keystore import MAX_KEYSTORE_FILE
        from patchwait.roots import DistrustEntry, audit_keystore
        path = self.write("growing.store", b"")
        entry = DistrustEntry("Synthetic", sha256=hashlib.sha256(BAD).digest())
        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        with mock.patch("builtins.open", return_value=handle) as opened, \
             mock.patch("patchwait.roots.os.fstat", return_value=mock.Mock(st_size=MAX_KEYSTORE_FILE + 1)):
            (row,) = audit_keystore(path, [entry])
        opened.assert_called_once_with(path, "rb")
        handle.read.assert_not_called()
        self.assertEqual(row.to_json()["verdict"]["reason"], "file_unreadable")  # type: ignore[index]

    def test_file_grows_after_fstat(self) -> None:
        from patchwait.roots import DistrustEntry, audit_keystore
        data = pfx(safe(cert_bag(BAD)))
        limit = len(data)
        path = self.write("growing.store", b"")
        entry = DistrustEntry("Synthetic", sha256=hashlib.sha256(BAD).digest())
        for extra in (b"", b"\x00" * 20):
            with self.subTest(oversized=bool(extra)):
                handle = mock.MagicMock()
                handle.__enter__.return_value = handle
                handle.read.side_effect = io.BytesIO(data + extra).read
                with mock.patch("builtins.open", return_value=handle), \
                     mock.patch("patchwait.roots.os.fstat", return_value=mock.Mock(st_size=0)), \
                     mock.patch("patchwait.roots.MAX_KEYSTORE_FILE", limit):
                    (row,) = audit_keystore(path, [entry])
                handle.read.assert_called_once_with(limit + 1)
                verdict = row.to_json()["verdict"]
                self.assertEqual(verdict["result"], "undetermined" if extra else "found")  # type: ignore[index]
                if extra:
                    self.assertEqual(verdict["reason"], "file_unreadable")  # type: ignore[index]

    def test_repeated_option(self) -> None:
        a = self.write("one.pfx", pfx(safe(cert_bag(BAD))))
        b = self.write("two.jks", jks(trusted_entry(OTHER)))
        code, doc = self.run_roots("--distrust", self.list_path, "--keystore", a, "--keystore", b)
        self.assertEqual(code, 10)
        self.assertEqual([self.verdict(row)["result"] for row in self.items(doc)], ["found", "not_found"])

    def keystore_document(self, cert: bytes = BAD, *, encrypted: bool = False) -> dict[str, object]:
        infos = [safe(cert_bag(cert))] + ([encrypted_info()] if encrypted else [])
        path = self.write("ledger.pfx", pfx(*infos))
        _, doc = self.run_roots("--distrust", self.list_path, "--keystore", path)
        doc["generated"] = "2026-10-24T09:00:00+09:00"
        return doc

    def test_details_validation(self) -> None:
        doc = self.keystore_document()
        row, _ = self.only(doc)
        details = row["details"]
        assert isinstance(details, dict)
        bad_fields = {"format": "other", "version": True, "certs": -1, "malformed": True,
                      "encrypted_content_infos": "1", "unreadable_parts": -1, "declared_entries": False,
                      "mac_data": 1, "bags": {"certBag": -1}, "entries": {"unknown": True},
                      "content_infos": {"data": "1"}}
        for field, bad in bad_fields.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(doc)
                changed["items"][0]["details"][field] = bad  # type: ignore[index]
                with self.assertRaises(LedgerInputError):
                    render_document(changed, "synthetic")
                with self.assertRaises(WaitlistInputError):
                    saved_result_from_document(changed, "synthetic")

    def test_unknown_detail_kinds(self) -> None:
        doc = self.keystore_document()
        for field in ("bags", "entries", "content_infos"):
            with self.subTest(field=field):
                changed = copy.deepcopy(doc)
                changed["items"][0]["details"][field] = {"made_up_bag": 1}  # type: ignore[index]
                with self.assertRaisesRegex(LedgerInputError, field):
                    render_document(changed, "synthetic")
                with self.assertRaisesRegex(WaitlistInputError, field):
                    saved_result_from_document(changed, "synthetic")

    def test_ledger_counts(self) -> None:
        for cert in (BAD, OTHER):
            for brief in (False, True):
                rendered = render_document(self.keystore_document(cert), "synthetic", brief=brief)
                self.assertIn("certs 1", rendered.markdown)
                self.assertIn("certBag 1", rendered.markdown)
                self.assertIn("encrypted_content_infos 0", rendered.markdown)

    def test_waitlist_import(self) -> None:
        from patchwait.waitlist import record_from
        for cert, encrypted in ((BAD, False), (OTHER, False), (OTHER, True)):
            doc = self.keystore_document(cert, encrypted=encrypted)
            row, verdict = self.only(doc)
            link = {"check": "roots", "location_kind": "java_keystore", "location": row["location"], "distrust": "Synthetic G3"}
            wait_path = self.write("waitlist.json", json.dumps(document(item("java-keystore", "2026-10-01", result_link=link))).encode())
            result_path = self.write("result.json", json.dumps(doc).encode())
            record_from(wait_path, result_path, [], datetime.date(2026, 10, 28))
            with open(wait_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            expected = {"result": "found", "value": "sha256"} if cert == BAD else verdict
            self.assertEqual(saved["items"][0]["last_result"], expected)
            with open(wait_path, "rb") as handle:
                before = handle.read()
            row["details"]["certs"] = -1  # type: ignore[index]
            self.write("result.json", json.dumps(doc).encode())
            with self.assertRaises(WaitlistInputError):
                record_from(wait_path, result_path, [], datetime.date(2026, 10, 28))
            with open(wait_path, "rb") as handle:
                self.assertEqual(handle.read(), before)

    def test_existing_options_unchanged(self) -> None:
        path = self.write("legacy.pem", pem(BAD))
        code, doc = self.run_roots("--distrust", self.list_path, "--pem", path, "--binary", path)
        self.assertEqual(code, 10)
        a, b = self.items(doc)
        self.assertEqual(a["details"], {"pem_blocks": 1, "certs": 1, "malformed": 0})
        self.assertEqual(b["details"], binary_details(pem_blocks=1, certs=1))
        self.assertEqual([a["location_kind"], b["location_kind"]], ["pem", "binary"])
