"""Synthetic Java keystores; no JVM, real keys, signatures or host data."""

from __future__ import annotations

from collections.abc import Sequence

from tests.cert_builder import explicit, integer, octets, oid, seq, set_of, tlv

DATA = "1.2.840.113549.1.7.1"
ENVELOPED = "1.2.840.113549.1.7.3"
ENCRYPTED = "1.2.840.113549.1.7.6"
BAG_BASE = "1.2.840.113549.1.12.10.1."
X509 = "1.2.840.113549.1.9.22.1"
JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"


def bag(kind: int, value: bytes = b"\x30\x00", attributes: bytes = b"") -> bytes:
    return seq(oid(BAG_BASE + str(kind)), explicit(0, value), attributes)


def cert_bag(der: bytes, *, cert_id: str = X509, attributes: bytes = b"") -> bytes:
    return bag(3, seq(oid(cert_id), explicit(0, octets(der))), attributes)


def content_info(value: bytes, kind: str = DATA) -> bytes:
    return seq(oid(kind), explicit(0, octets(value) if kind == DATA else value))


def safe(*bags: bytes) -> bytes:
    return content_info(seq(*bags))


def encrypted_info(kind: str = ENCRYPTED) -> bytes:
    algorithm = seq(oid("1.2.840.113549.3.7"), octets(b"\x00" * 8))
    encrypted_content = seq(oid(DATA), algorithm, tlv(0x80, b"synthetic ciphertext"))
    prefix = (integer(0), set_of()) if kind == ENVELOPED else (integer(0),)
    return content_info(seq(*prefix, encrypted_content), kind)


def mac_data() -> bytes:
    digest = seq(seq(oid("2.16.840.1.101.3.4.2.1"), tlv(0x05, b"")), octets(b"\x00" * 32))
    return seq(digest, octets(b"synthetic salt"), integer(1))


def pfx(*infos: bytes, version: int = 3, mac: bytes = b"", auth_type: str = DATA) -> bytes:
    return seq(integer(version), content_info(seq(*infos), auth_type), mac)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def utf(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def jks_certificate(der: bytes, version: int, cert_type: bytes = b"X.509") -> bytes:
    return (utf(cert_type) if version == 2 else b"") + u32(len(der)) + der


def trusted_entry(
    der: bytes, *, version: int = 2, cert_type: bytes = b"X.509", alias: bytes = b"synthetic-root"
) -> bytes:
    return u32(2) + utf(alias) + b"\x00" * 8 + jks_certificate(der, version, cert_type)


def private_entry(chain: Sequence[bytes] = (), *, version: int = 2, key: bytes = b"synthetic protected key") -> bytes:
    return (u32(1) + utf(b"synthetic-key") + b"\x00" * 8 + u32(len(key)) + key
            + u32(len(chain)) + b"".join(jks_certificate(cert, version) for cert in chain))


def jks(
    *entries: bytes, version: int = 2, magic: bytes = JKS_MAGIC,
    count: int | None = None, integrity: bytes = b"\x00" * 20,
) -> bytes:
    return magic + u32(version) + u32(len(entries) if count is None else count) + b"".join(entries) + integrity
