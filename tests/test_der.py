from __future__ import annotations

import datetime
import hashlib
import random
import unittest

from patchwait.der import (
    DerError,
    Tlv,
    children,
    ctl_sha256,
    decode_filetime,
    decode_oid,
    parse_certificate,
    parse_ctl,
    read_tlv,
    single_octet_string,
)
from tests.cert_builder import (
    build_cert,
    build_ctl,
    disallowed_attribute,
    filetime,
    octets,
    oid,
    spki_of,
    subject_for,
)

KEY = bytes(range(64))
WHEN = datetime.datetime(2026, 8, 25, 7, 24, 34, tzinfo=datetime.timezone.utc)


class DerReaderTests(unittest.TestCase):
    def test_short_and_long_lengths(self) -> None:
        self.assertEqual(read_tlv(b"\x04\x02ab", 0), Tlv(0x04, 0, 2, 4))
        long_value = b"\x04\x82\x01\x00" + b"x" * 256
        self.assertEqual(read_tlv(long_value, 0), Tlv(0x04, 0, 4, 260))

    def test_rejects_malformed_headers(self) -> None:
        for bad in (b"", b"\x04", b"\x04\x05ab", b"\x04\x80ab", b"\x04\x85\0\0\0\0\1", b"\x1f\x01a", b"\x04\x82\x01"):
            with self.assertRaises(DerError, msg=bad.hex()):
                read_tlv(bad, 0)

    def test_child_cannot_escape_parent(self) -> None:
        # The outer SEQUENCE claims 3 bytes; its child claims 4.
        data = b"\x30\x03\x04\x04abcd"
        with self.assertRaises(DerError):
            children(data, read_tlv(data, 0))

    def test_oid_round_trip(self) -> None:
        for dotted in ("1.3.6.1.4.1.311.10.11.98", "2.5.4.3", "1.2.840.113549.1.7.2"):
            encoded = oid(dotted)
            self.assertEqual(decode_oid(encoded[2:]), dotted)

    def test_certificate_fields(self) -> None:
        der = build_cert("Synthetic Root G9", KEY)
        info = parse_certificate(der)
        self.assertEqual(info.sha256, hashlib.sha256(der).digest())
        self.assertEqual(info.sha1, hashlib.sha1(der).digest())
        self.assertEqual(info.spki_der, spki_of(KEY))
        self.assertEqual(info.spki_sha256, hashlib.sha256(spki_of(KEY)).digest())
        self.assertEqual(info.subject_cn, "Synthetic Root G9")

    def test_certificate_rejects_trailing_bytes(self) -> None:
        with self.assertRaises(DerError):
            parse_certificate(build_cert("X", KEY) + b"\0")

    def test_ctl_entries_and_this_update(self) -> None:
        der = build_cert("Synthetic Root G9", KEY)
        for cms in (False, True):
            ctl = parse_ctl(build_ctl([subject_for(der, [disallowed_attribute(WHEN)])], cms=cms))
            self.assertEqual(ctl.this_update, WHEN)
            (entry,) = ctl.entries
            self.assertEqual(entry.identifier, hashlib.sha1(der).digest())
            self.assertEqual(ctl_sha256(entry), hashlib.sha256(der).digest())
            values = entry.attributes["1.3.6.1.4.1.311.10.11.104"]
            self.assertEqual(decode_filetime(values), WHEN)

    def test_sha256_attribute_nesting_matches_windows_bytes(self) -> None:
        der = build_cert("X", KEY)
        blob = build_ctl([subject_for(der)])
        digest = hashlib.sha256(der).digest()
        self.assertIn(b"\x31\x22\x04\x20" + digest, blob)
        # A doubly wrapped value is accepted too.
        self.assertEqual(single_octet_string(octets(octets(digest))), digest)

    def test_filetime_must_be_8_bytes(self) -> None:
        self.assertEqual(decode_filetime(octets(filetime(WHEN))), WHEN)
        with self.assertRaises(DerError):
            decode_filetime(octets(b"\0" * 7))

    def test_not_a_ctl(self) -> None:
        for blob in (b"", b"\x30\x00", build_cert("X", KEY), b"garbage" * 10):
            with self.assertRaises(DerError):
                parse_ctl(blob)


class DerFuzzTests(unittest.TestCase):
    def test_truncations_never_raise_other_errors(self) -> None:
        der = build_cert("Synthetic Root G9", KEY)
        blob = build_ctl([subject_for(der, [disallowed_attribute(WHEN)]), subject_for(build_cert("Y", KEY[::-1]))])
        for cut in range(len(der)):
            with self.assertRaises(DerError):
                parse_certificate(der[:cut])
        for cut in range(len(blob)):
            with self.assertRaises(DerError):
                parse_ctl(blob[:cut])

    def test_random_corruption_never_raises_other_errors(self) -> None:
        der = build_cert("Synthetic Root G9", KEY)
        blob = build_ctl([subject_for(der, [disallowed_attribute(WHEN)])])
        rng = random.Random(20261024)
        for original, parse in ((der, parse_certificate), (blob, parse_ctl)):
            for _ in range(600):
                broken = bytearray(original)
                for _ in range(rng.randint(1, 8)):
                    broken[rng.randrange(len(broken))] = rng.randrange(256)
                try:
                    parse(bytes(broken))
                except DerError:
                    pass
        for _ in range(300):
            noise = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
            for parse in (parse_certificate, parse_ctl):
                try:
                    parse(noise)
                except DerError:
                    pass


if __name__ == "__main__":
    unittest.main()
