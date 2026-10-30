"""Build synthetic X.509 certificates and Windows CTL blobs in DER.

Everything here is synthetic: names, keys and signatures are made up and no
real certificate or trust list is read or copied.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
from collections.abc import Sequence

from patchwait.der import (
    OID_CTL,
    OID_CTL_CERT_SHA256,
    OID_CTL_DISALLOWED_FILETIME,
    OID_CTL_NOT_BEFORE_FILETIME,
    OID_SIGNED_DATA,
)

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def tlv(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        header = bytes([tag, size])
    else:
        octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(octets)]) + octets
    return header + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(parts))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return tlv(0x02, raw)


def oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def explicit(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


def name(common_name: str) -> bytes:
    return seq(set_of(seq(oid("2.5.4.3"), tlv(0x0C, common_name.encode("utf-8")))))


def spki(key: bytes) -> bytes:
    algorithm = seq(oid("1.2.840.113549.1.1.1"), tlv(0x05, b""))
    return seq(algorithm, tlv(0x03, b"\0" + key))


def build_cert(
    common_name: str,
    key: bytes,
    serial: int = 1,
    issuer: str | None = None,
    *,
    signature_algorithm: bytes | None = None,
    outer_signature_algorithm: bytes | None = None,
) -> bytes:
    """A synthetic self-signed-looking certificate with a fake signature."""
    if signature_algorithm is None:
        signature_algorithm = seq(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    validity = seq(tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z"))
    tbs = seq(
        explicit(0, integer(2)),
        integer(serial),
        signature_algorithm,
        name(issuer or common_name),
        validity,
        name(common_name),
        spki(key),
    )
    return seq(tbs, outer_signature_algorithm or signature_algorithm, tlv(0x03, b"\0" + hashlib.sha256(tbs).digest() * 8))


def spki_of(key: bytes) -> bytes:
    return spki(key)


def pem(der: bytes, *, escaped: bool = False) -> bytes:
    body = base64.b64encode(der)
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    newline = b"\\n" if escaped else b"\n"
    return (
        b"-----BEGIN CERTIFICATE-----"
        + newline
        + newline.join(lines)
        + newline
        + b"-----END CERTIFICATE-----"
        + newline
    )


def filetime(moment: datetime.datetime) -> bytes:
    delta = moment - _FILETIME_EPOCH
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return ticks.to_bytes(8, "little")


def sha256_attribute(der: bytes) -> tuple[str, bytes]:
    """``.11.98`` as Windows writes it: SET { OCTET STRING (32 bytes) }."""
    return OID_CTL_CERT_SHA256, octets(hashlib.sha256(der).digest())


def disallowed_attribute(moment: datetime.datetime) -> tuple[str, bytes]:
    return OID_CTL_DISALLOWED_FILETIME, octets(filetime(moment))


def not_before_attribute(moment: datetime.datetime) -> tuple[str, bytes]:
    return OID_CTL_NOT_BEFORE_FILETIME, octets(filetime(moment))


def ctl_subject(identifier: bytes, attributes: Sequence[tuple[str, bytes]] = ()) -> bytes:
    parts = [octets(identifier)]
    if attributes:
        parts.append(set_of(*(seq(oid(name), set_of(values)) for name, values in attributes)))
    return seq(*parts)


def build_ctl(
    subjects: Sequence[bytes],
    this_update: bytes = b"260825072434Z",
    *,
    cms: bool = False,
    subject_algorithm: str = "1.3.14.3.2.26",
    subject_algorithm_parameters: bytes = b"",
    subject_algorithm_der: bytes | None = None,
) -> bytes:
    """A synthetic PKCS#7 SignedData holding a CertificateTrustList (no signers)."""
    ctl = seq(
        seq(oid("1.3.6.1.4.1.311.10.3.9")),  # subjectUsage
        octets(b"synthetic"),  # listIdentifier
        integer(7),  # sequenceNumber
        tlv(0x17, this_update),
        seq(oid(subject_algorithm), subject_algorithm_parameters) if subject_algorithm_der is None else subject_algorithm_der,
        seq(*subjects),
    )
    content = octets(ctl) if cms else ctl
    signed = seq(
        integer(1),
        set_of(seq(oid("1.3.14.3.2.26"))),
        seq(oid(OID_CTL), explicit(0, content)),
        set_of(),
    )
    return seq(oid(OID_SIGNED_DATA), explicit(0, signed))


def subject_for(der: bytes, attributes: Sequence[tuple[str, bytes]] = (), *, with_sha256: bool = True) -> bytes:
    attrs = ([sha256_attribute(der)] if with_sha256 else []) + list(attributes)
    return ctl_subject(hashlib.sha1(der).digest(), attrs)
