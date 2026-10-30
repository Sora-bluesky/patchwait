"""A minimal, bounded DER reader for X.509 certificates and Windows CTLs.

Only reads; never verifies signatures. Every length is checked against the
enclosing buffer, so malformed input raises ``DerError`` and never
``IndexError``, a hang or unbounded recursion.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_T61_STRING = 0x14
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_BMP_STRING = 0x1E
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_CONTEXT_0 = 0xA0

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CTL = "1.3.6.1.4.1.311.10.1"
OID_COMMON_NAME = "2.5.4.3"
OID_DISALLOWED_HASH = "1.3.6.1.4.1.311.10.11.15"
OID_CTL_CERT_SHA256 = "1.3.6.1.4.1.311.10.11.98"
OID_CTL_DISALLOWED_FILETIME = "1.3.6.1.4.1.311.10.11.104"
OID_CTL_NOT_BEFORE_FILETIME = "1.3.6.1.4.1.311.10.11.126"

_MAX_LENGTH_OCTETS = 4
_ASCII_DIGITS_RE = re.compile(r"[0-9]+")
_MAX_OID_ARC_OCTETS = 9
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


class DerError(Exception):
    """The input is not well-formed DER of the expected shape."""


@dataclass(frozen=True, slots=True)
class Tlv:
    """One element: header at ``buf[pos:start]``, value at ``buf[start:end]``."""

    tag: int
    pos: int
    start: int
    end: int


def read_tlv(buf: bytes, pos: int, limit: int | None = None) -> Tlv:
    """Read the element at ``pos``; it must end at or before ``limit``."""
    end_of_input = len(buf) if limit is None else min(limit, len(buf))
    if pos < 0 or pos + 2 > end_of_input:
        raise DerError("truncated header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")
    first = buf[pos + 1]
    cursor = pos + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise DerError("indefinite length is not DER")
        if count > _MAX_LENGTH_OCTETS:
            raise DerError("length too large")
        if cursor + count > end_of_input:
            raise DerError("truncated length")
        length = int.from_bytes(buf[cursor : cursor + count], "big")
        cursor += count
    if cursor + length > end_of_input:
        raise DerError("value runs past its container")
    return Tlv(tag, pos, cursor, cursor + length)


def expect(buf: bytes, pos: int, tag: int, limit: int | None = None) -> Tlv:
    element = read_tlv(buf, pos, limit)
    if element.tag != tag:
        raise DerError(f"expected tag 0x{tag:02x}, got 0x{element.tag:02x}")
    return element


def children(buf: bytes, parent: Tlv) -> list[Tlv]:
    """The elements directly inside ``parent``; they must fill it exactly."""
    found: list[Tlv] = []
    pos = parent.start
    while pos < parent.end:
        element = read_tlv(buf, pos, parent.end)
        found.append(element)
        pos = element.end
    return found


def encoding(buf: bytes, element: Tlv) -> bytes:
    """The full encoding (header and value) of ``element``."""
    return buf[element.pos : element.end]


def decode_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    arcs: list[int] = []
    current = 0
    octets = 0
    for byte in value:
        current = (current << 7) | (byte & 0x7F)
        octets += 1
        if octets > _MAX_OID_ARC_OCTETS:
            raise DerError("OID arc too long")
        if byte & 0x80 == 0:
            arcs.append(current)
            current = 0
            octets = 0
    if octets != 0:
        raise DerError("truncated OID")
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(arc) for arc in head + arcs[1:])


def _parse_time(tag: int, value: bytes) -> datetime.datetime:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise DerError("time is not ASCII") from error
    if not text.endswith("Z"):
        raise DerError("time without Z")
    digits = text[:-1]
    if _ASCII_DIGITS_RE.fullmatch(digits) is None:  # not str.isdigit, which accepts non-ASCII digits
        raise DerError("time has non-digits")
    try:
        if tag == TAG_UTC_TIME and len(digits) == 12:
            year = int(digits[0:2])
            year += 2000 if year < 50 else 1900
            rest = digits[2:]
        elif tag == TAG_GENERALIZED_TIME and len(digits) == 14:
            year = int(digits[0:4])
            rest = digits[4:]
        else:
            raise DerError("unsupported time form")
        month, day, hour, minute, second = (int(rest[i : i + 2]) for i in range(0, 10, 2))
        return datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    except ValueError as error:
        raise DerError("time out of range") from error


def iso_utc(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_text(tag: int, value: bytes) -> str | None:
    try:
        if tag == TAG_BMP_STRING:
            return value.decode("utf-16-be")
        if tag in (TAG_UTF8_STRING, TAG_PRINTABLE_STRING, TAG_IA5_STRING):
            return value.decode("utf-8")
        if tag == TAG_T61_STRING:
            return value.decode("latin-1")
    except UnicodeDecodeError:
        return None
    return None


# --- X.509 -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CertInfo:
    der: bytes
    sha256: bytes
    sha1: bytes
    spki_der: bytes
    spki_sha256: bytes
    subject_cn: str | None
    signature_algorithm: str | None = None
    signature_hash: bytes | None = None
    public_key_md5: bytes | None = None


_SIGNATURE_DIGESTS = {
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
_PSS_OID = "1.2.840.113549.1.1.10"
_HASH_DIGESTS = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


def _algorithm_identifier(buf: bytes, element: Tlv) -> tuple[str, Tlv | None]:
    parts = children(buf, element)
    if not 1 <= len(parts) <= 2 or parts[0].tag != TAG_OID:
        raise DerError("malformed AlgorithmIdentifier")
    return decode_oid(buf[parts[0].start : parts[0].end]), parts[1] if len(parts) == 2 else None


def _signature_digest(buf: bytes, name: str, parameters: Tlv | None) -> str | None:
    if name != _PSS_OID:
        return _SIGNATURE_DIGESTS.get(name)
    # Do not infer PSS's default SHA-1: only an explicitly named hash is usable.
    if parameters is None or parameters.tag != TAG_SEQUENCE:
        return None
    hashes = [part for part in children(buf, parameters) if part.tag == TAG_CONTEXT_0]
    if len(hashes) != 1:
        return None
    wrapped = children(buf, hashes[0])
    if len(wrapped) != 1 or wrapped[0].tag != TAG_SEQUENCE:
        return None
    hash_oid, _params = _algorithm_identifier(buf, wrapped[0])
    return _HASH_DIGESTS.get(hash_oid)


def _public_key_md5(buf: bytes, spki: Tlv) -> bytes:
    parts = children(buf, spki)
    if len(parts) != 2 or parts[0].tag != TAG_SEQUENCE or parts[1].tag != TAG_BIT_STRING:
        raise DerError("subjectPublicKeyInfo is not algorithm and BIT STRING")
    key = parts[1]
    if key.start == key.end or buf[key.start] > 7:
        raise DerError("subjectPublicKey has invalid unused bits")
    # Windows property 25 hashes the key bits, without the unused-bits octet.
    return hashlib.md5(buf[key.start + 1 : key.end], usedforsecurity=False).digest()


def _common_name(buf: bytes, name: Tlv) -> str | None:
    for rdn in children(buf, name):
        if rdn.tag != TAG_SET:
            raise DerError("RDN is not a SET")
        for attribute in children(buf, rdn):
            if attribute.tag != TAG_SEQUENCE:
                raise DerError("attribute is not a SEQUENCE")
            parts = children(buf, attribute)
            if len(parts) != 2 or parts[0].tag != TAG_OID:
                raise DerError("malformed attribute")
            if decode_oid(buf[parts[0].start : parts[0].end]) == OID_COMMON_NAME:
                return _decode_text(parts[1].tag, buf[parts[1].start : parts[1].end])
    return None


def parse_certificate(der: bytes) -> CertInfo:
    """Parse one certificate; ``der`` must hold exactly one element."""
    outer = expect(der, 0, TAG_SEQUENCE)
    if outer.end != len(der):
        raise DerError("trailing bytes after certificate")
    parts = children(der, outer)
    if len(parts) != 3 or parts[0].tag != TAG_SEQUENCE or parts[1].tag != TAG_SEQUENCE:
        raise DerError("certificate is not tbs, algorithm, signature")
    if parts[2].tag != TAG_BIT_STRING:
        raise DerError("signature is not a BIT STRING")
    fields = children(der, parts[0])
    index = 1 if fields and fields[0].tag == TAG_CONTEXT_0 else 0
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < index + 6:
        raise DerError("tbsCertificate too short")
    serial, algorithm, issuer, validity, subject, spki = fields[index : index + 6]
    if serial.tag != TAG_INTEGER:
        raise DerError("serial is not an INTEGER")
    for element in (algorithm, issuer, validity, subject, spki):
        if element.tag != TAG_SEQUENCE:
            raise DerError("tbsCertificate field is not a SEQUENCE")
    spki_der = encoding(der, spki)
    # Optional Disallowed identifiers must not prevent existing fingerprint matches.
    signature_algorithm: str | None = None
    signature_hash = None
    try:
        signature_algorithm, parameters = _algorithm_identifier(der, parts[1])
        digest = _signature_digest(der, signature_algorithm, parameters)
        if digest is not None:
            # Windows property 15 includes the complete TBSCertificate tag and length.
            signature_hash = hashlib.new(digest, encoding(der, parts[0]), usedforsecurity=False).digest()
    except (DerError, ValueError):
        pass
    try:
        public_key_md5 = _public_key_md5(der, spki)
    except (DerError, ValueError):
        public_key_md5 = None
    return CertInfo(
        der=der,
        sha256=hashlib.sha256(der).digest(),
        sha1=hashlib.sha1(der).digest(),
        spki_der=spki_der,
        spki_sha256=hashlib.sha256(spki_der).digest(),
        subject_cn=_common_name(der, subject),
        signature_algorithm=signature_algorithm,
        signature_hash=signature_hash,
        public_key_md5=public_key_md5,
    )


# --- Windows certificate trust lists ------------------------------------------


@dataclass(frozen=True, slots=True)
class CtlEntry:
    """A TrustedSubject: identifier and ``{attribute OID: encoded values}``.

    The value bytes are the content of the attribute's ``SET OF`` (the
    concatenated encodings of its values).
    """

    identifier: bytes
    attributes: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class Ctl:
    this_update: datetime.datetime
    entries: tuple[CtlEntry, ...]
    subject_algorithm: str | None = None


def _unwrap_explicit(buf: bytes, element: Tlv) -> Tlv:
    inner = children(buf, element)
    if len(inner) != 1:
        raise DerError("explicit tag must hold one element")
    return inner[0]


def parse_ctl(blob: bytes) -> Ctl:
    """Parse a PKCS#7 SignedData whose content is a CertificateTrustList.

    Bytes after the outer ContentInfo are ignored (registry blobs may be padded).
    """
    info = expect(blob, 0, TAG_SEQUENCE)
    info_parts = children(blob, info)
    if len(info_parts) != 2 or info_parts[0].tag != TAG_OID or info_parts[1].tag != TAG_CONTEXT_0:
        raise DerError("not a ContentInfo")
    if decode_oid(blob[info_parts[0].start : info_parts[0].end]) != OID_SIGNED_DATA:
        raise DerError("not SignedData")
    signed = _unwrap_explicit(blob, info_parts[1])
    if signed.tag != TAG_SEQUENCE:
        raise DerError("SignedData is not a SEQUENCE")
    signed_parts = children(blob, signed)
    if len(signed_parts) < 3 or signed_parts[0].tag != TAG_INTEGER or signed_parts[1].tag != TAG_SET:
        raise DerError("malformed SignedData")
    encap = signed_parts[2]
    if encap.tag != TAG_SEQUENCE:
        raise DerError("encapContentInfo is not a SEQUENCE")
    encap_parts = children(blob, encap)
    if len(encap_parts) != 2 or encap_parts[0].tag != TAG_OID or encap_parts[1].tag != TAG_CONTEXT_0:
        raise DerError("encapContentInfo has no content")
    if decode_oid(blob[encap_parts[0].start : encap_parts[0].end]) != OID_CTL:
        raise DerError("content is not a CTL")
    content = _unwrap_explicit(blob, encap_parts[1])
    if content.tag == TAG_OCTET_STRING:  # CMS style wraps the content once more
        inner = expect(blob, content.start, TAG_SEQUENCE, content.end)
        if inner.end != content.end:
            raise DerError("trailing bytes in CTL content")
        content = inner
    if content.tag != TAG_SEQUENCE:
        raise DerError("CTL is not a SEQUENCE")
    return _parse_ctl_body(blob, content)


def _parse_ctl_body(buf: bytes, ctl: Tlv) -> Ctl:
    fields = children(buf, ctl)
    index = 0

    def peek() -> Tlv | None:
        return fields[index] if index < len(fields) else None

    current = peek()
    if current is not None and current.tag == TAG_INTEGER:  # version
        index += 1
    current = peek()
    if current is None or current.tag != TAG_SEQUENCE:  # subjectUsage
        raise DerError("CTL has no subjectUsage")
    index += 1
    current = peek()
    if current is not None and current.tag == TAG_OCTET_STRING:  # listIdentifier
        index += 1
    current = peek()
    if current is not None and current.tag == TAG_INTEGER:  # sequenceNumber
        index += 1
    current = peek()
    if current is None or current.tag not in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
        raise DerError("CTL has no ThisUpdate")
    this_update = _parse_time(current.tag, buf[current.start : current.end])
    index += 1
    current = peek()
    if current is not None and current.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):  # nextUpdate
        index += 1
    current = peek()
    if current is None or current.tag != TAG_SEQUENCE:  # subjectAlgorithm
        raise DerError("CTL has no subjectAlgorithm")
    # Recognition of Disallowed hashes is optional; legacy CTL matching only
    # required this SEQUENCE, without interpreting its contents.
    subject_algorithm = None
    try:
        subject_algorithm, _parameters = _algorithm_identifier(buf, current)
    except DerError:
        pass
    index += 1
    current = peek()
    entries: list[CtlEntry] = []
    if current is not None and current.tag == TAG_SEQUENCE:  # trustedSubjects
        entries = [_parse_subject(buf, subject) for subject in children(buf, current)]
        index += 1
    current = peek()
    if current is not None and current.tag == TAG_CONTEXT_0:  # ctlExtensions
        index += 1
    if index != len(fields):
        raise DerError("unexpected fields in CTL")
    return Ctl(this_update, tuple(entries), subject_algorithm)


def _parse_subject(buf: bytes, subject: Tlv) -> CtlEntry:
    if subject.tag != TAG_SEQUENCE:
        raise DerError("TrustedSubject is not a SEQUENCE")
    parts = children(buf, subject)
    if not parts or len(parts) > 2 or parts[0].tag != TAG_OCTET_STRING:
        raise DerError("TrustedSubject has no identifier")
    attributes: dict[str, bytes] = {}
    if len(parts) == 2:
        if parts[1].tag != TAG_SET:
            raise DerError("subjectAttributes is not a SET")
        for attribute in children(buf, parts[1]):
            if attribute.tag != TAG_SEQUENCE:
                raise DerError("attribute is not a SEQUENCE")
            pair = children(buf, attribute)
            if len(pair) != 2 or pair[0].tag != TAG_OID or pair[1].tag != TAG_SET:
                raise DerError("malformed attribute")
            children(buf, pair[1])  # values must be well-formed
            oid = decode_oid(buf[pair[0].start : pair[0].end])
            attributes[oid] = buf[pair[1].start : pair[1].end]
    return CtlEntry(buf[parts[0].start : parts[0].end], attributes)


def single_octet_string(values: bytes) -> bytes:
    """The content of the one OCTET STRING in an attribute's values.

    One more OCTET STRING layer inside it is unwrapped if the content is
    exactly such an element, so either nesting yields the payload.
    """
    element = expect(values, 0, TAG_OCTET_STRING)
    if element.end != len(values):
        raise DerError("attribute holds more than one value")
    payload = values[element.start : element.end]
    if len(payload) >= 2 and payload[0] == TAG_OCTET_STRING:
        try:
            inner = expect(payload, 0, TAG_OCTET_STRING)
        except DerError:
            return payload
        if inner.end == len(payload):
            return payload[inner.start : inner.end]
    return payload


def ctl_sha256(entry: CtlEntry) -> bytes | None:
    """The certificate SHA-256 from ``.11.98``; None if absent or malformed."""
    values = entry.attributes.get(OID_CTL_CERT_SHA256)
    if values is None:
        return None
    try:
        payload = single_octet_string(values)
    except DerError:
        return None
    return payload if len(payload) == 32 else None


def decode_filetime(values: bytes) -> datetime.datetime:
    payload = single_octet_string(values)
    if len(payload) != 8:
        raise DerError("FILETIME is not 8 bytes")
    ticks = int.from_bytes(payload, "little")
    try:
        return _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)
    except OverflowError as error:
        raise DerError("FILETIME out of range") from error
