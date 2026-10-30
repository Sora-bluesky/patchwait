"""Bounded structural readers for Java PKCS12, JKS and trusted-cert JCEKS.

No passwords, decryption, MAC/integrity verification or byte scanning. Only
certificate fields reach the existing X.509 parser; opaque keys stay opaque.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from patchwait.der import (
    TAG_CONTEXT_0, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
    CertInfo, DerError, Tlv, decode_oid, expect, parse_certificate, read_tlv,
)
from patchwait.model import JSONObject

# The observed Java cacerts is 153,428 bytes; 16 MiB leaves over 100x headroom.
MAX_KEYSTORE_FILE = 16 * 1024 * 1024
JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"
OID_DATA = "1.2.840.113549.1.7.1"
OID_ENVELOPED_DATA = "1.2.840.113549.1.7.3"
OID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6"
OID_X509_CERTIFICATE = "1.2.840.113549.1.9.22.1"
BAG_TYPES = {
    "1.2.840.113549.1.12.10.1.1": "keyBag",
    "1.2.840.113549.1.12.10.1.2": "pkcs8ShroudedKeyBag",
    "1.2.840.113549.1.12.10.1.3": "certBag",
    "1.2.840.113549.1.12.10.1.4": "crlBag",
    "1.2.840.113549.1.12.10.1.5": "secretBag",
    "1.2.840.113549.1.12.10.1.6": "safeContentsBag",
}
CONTENT_TYPES = {OID_DATA: "data", OID_ENCRYPTED_DATA: "encryptedData", OID_ENVELOPED_DATA: "envelopedData"}
ENTRY_TYPES = {1: "private_key", 2: "trusted_cert", 3: "secret_key"}


@dataclass(slots=True)
class KeystoreScan:
    format: str = "unknown"
    version: int | None = None
    certs: list[tuple[CertInfo, int | None]] = field(default_factory=lambda: [])
    unparsed: list[bytes] = field(default_factory=lambda: [])
    bags: dict[str, int] = field(default_factory=lambda: {})
    entries: dict[str, int] = field(default_factory=lambda: {})
    content_infos: dict[str, int] = field(default_factory=lambda: {})
    declared_entries: int | None = None
    encrypted_content_infos: int = 0
    unreadable_parts: int = 0
    mac_data: bool | None = None
    malformed_structure: bool = False
    first_problem: str | None = None

    def unreadable(self, detail: str, *, malformed: bool = False) -> None:
        self.unreadable_parts += 1
        self.malformed_structure |= malformed
        if self.first_problem is None:
            self.first_problem = detail

    def certificate(self, raw: bytes) -> None:
        try:
            cert = parse_certificate(raw)
        except DerError:
            self.unparsed.append(raw)
        else:
            self.certs.append((cert, None))

    def details(self) -> JSONObject:
        return {
            "format": self.format, "version": self.version,
            "certs": len(self.certs), "malformed": len(self.unparsed),
            "bags": {name: count for name, count in self.bags.items()},
            "entries": {name: count for name, count in self.entries.items()},
            "content_infos": {name: count for name, count in self.content_infos.items()},
            "declared_entries": self.declared_entries,
            "encrypted_content_infos": self.encrypted_content_infos,
            "unreadable_parts": self.unreadable_parts, "mac_data": self.mac_data,
        }

    def detail(self) -> str:
        parts = [f"{self.encrypted_content_infos} encrypted ContentInfo not read"] if self.encrypted_content_infos else []
        if self.unreadable_parts:
            parts.append(f"{self.unreadable_parts} unreadable part(s): {self.first_problem}")
        parts.append(f"{len(self.unparsed)} certificate(s) could not be parsed; {len(self.certs)} certificates parsed")
        return "; ".join(parts)


def _count(counts: dict[str, int], name: str) -> None:
    counts[name] = counts.get(name, 0) + 1


def parse_keystore(data: bytes) -> KeystoreScan:
    """Keep readable certificates even when a sibling or trailing structure fails."""
    scan = KeystoreScan()
    try:
        if len(data) > MAX_KEYSTORE_FILE:
            raise DerError(f"keystore exceeds {MAX_KEYSTORE_FILE} bytes")
        if data[:4] in (JKS_MAGIC, JCEKS_MAGIC):
            scan.format = "jks" if data[:4] == JKS_MAGIC else "jceks"
            _jks(data, scan)
        elif data[:1] == bytes([TAG_SEQUENCE]):
            scan.format = "pkcs12"
            _pfx(data, scan)
        else:
            raise DerError("unrecognised keystore format (expected PKCS12, JKS or JCEKS)")
    except DerError as error:
        scan.unreadable(str(error), malformed=True)
    return scan


def _children(buf: bytes, parent: Tlv) -> Iterator[Tlv]:
    pos = parent.start
    while pos < parent.end:
        element = read_tlv(buf, pos, parent.end)
        yield element
        pos = element.end


def _parts(
    buf: bytes, parent: Tlv, minimum: int, maximum: int, tag: int = TAG_SEQUENCE,
    *, scan: KeystoreScan | None = None,
) -> list[Tlv]:
    if parent.tag != tag:
        raise DerError(f"expected container tag 0x{tag:02x}")
    parts: list[Tlv] = []
    try:
        for part in _children(buf, parent):
            if len(parts) == maximum:
                raise DerError("extra field in keystore structure")
            parts.append(part)
    except DerError as error:
        if scan is None or len(parts) < minimum:
            raise
        # Required fields have known boundaries; a broken suffix cannot hide them.
        scan.unreadable(f"keystore structure: {error}", malformed=True)
    if len(parts) < minimum:
        raise DerError("missing field in keystore structure")
    return parts


def _single(buf: bytes, parent: Tlv, scan: KeystoreScan) -> Tlv:
    return _parts(buf, parent, 1, 1, TAG_CONTEXT_0, scan=scan)[0]


def _oid(buf: bytes, element: Tlv) -> str:
    if element.tag != TAG_OID:
        raise DerError("expected OID")
    return decode_oid(buf[element.start:element.end])


def _number(buf: bytes, element: Tlv) -> int:
    if element.tag != TAG_INTEGER or not 1 <= element.end - element.start <= 8 or buf[element.start] & 0x80:
        raise DerError("expected small non-negative INTEGER")
    return int.from_bytes(buf[element.start:element.end], "big")


def _whole_sequence(buf: bytes, scan: KeystoreScan) -> Tlv:
    element = expect(buf, 0, TAG_SEQUENCE)
    if element.end != len(buf):
        scan.unreadable("trailing bytes after keystore SEQUENCE", malformed=True)
    return element


def _content_info(buf: bytes, info: Tlv, scan: KeystoreScan) -> tuple[str, Tlv]:
    fields = _parts(buf, info, 2, 2, scan=scan)
    return _oid(buf, fields[0]), _single(buf, fields[1], scan)


def _data_bytes(buf: bytes, value: Tlv) -> bytes:
    if value.tag != TAG_OCTET_STRING:
        raise DerError("data content must be an OCTET STRING")
    return buf[value.start:value.end]


def _pfx(buf: bytes, scan: KeystoreScan) -> None:
    outer = expect(buf, 0, TAG_SEQUENCE)
    if outer.end != len(buf):
        scan.unreadable("trailing bytes after PFX", malformed=True)
    version = read_tlv(buf, outer.start, outer.end)
    scan.version = _number(buf, version)
    if scan.version != 3:
        raise DerError("PKCS12 version must be 3")
    auth = read_tlv(buf, version.end, outer.end)
    scan.mac_data = auth.end < outer.end
    kind, value = _content_info(buf, auth, scan)
    if kind != OID_DATA:
        if kind in (OID_ENCRYPTED_DATA, OID_ENVELOPED_DATA):
            scan.encrypted_content_infos += 1
        scan.unreadable(f"authSafe content type {kind} not read (requires data)")
    else:
        _authenticated_safe(_data_bytes(buf, value), scan)
    if scan.mac_data:
        mac = read_tlv(buf, auth.end, outer.end)
        _mac_data(buf, mac)
        if mac.end != outer.end:
            raise DerError("extra fields after macData")


def _authenticated_safe(buf: bytes, scan: KeystoreScan) -> None:
    parent = _whole_sequence(buf, scan)
    for info in _children(buf, parent):
        try:
            kind, value = _content_info(buf, info, scan)
            _count(scan.content_infos, CONTENT_TYPES.get(kind, "unknown"))
            if kind == OID_DATA:
                _safe_contents(_data_bytes(buf, value), scan)
            elif kind in (OID_ENCRYPTED_DATA, OID_ENVELOPED_DATA):
                scan.encrypted_content_infos += 1
            else:
                scan.unreadable(f"ContentInfo type {kind} not read")
        except DerError as error:
            scan.unreadable(f"ContentInfo: {error}", malformed=True)


def _safe_contents(buf: bytes, scan: KeystoreScan) -> None:
    parent = _whole_sequence(buf, scan)
    # Positions refer to this same buffer, including nested safeContentsBag values.
    # An explicit stack avoids both recursion limits and repeated nested copies.
    stack = [(parent.start, parent.end)]
    while stack:
        pos, end = stack[-1]
        if pos == end:
            stack.pop()
            continue
        try:
            element = read_tlv(buf, pos, end)
        except DerError as error:
            scan.unreadable(f"SafeContents: {error}", malformed=True)
            stack.pop()
            continue
        stack[-1] = (element.end, end)
        try:
            nested = _bag(buf, element, scan)
            if nested is not None:
                stack.append((nested.start, nested.end))
        except DerError as error:
            scan.unreadable(f"SafeBag: {error}", malformed=True)


def _bag(buf: bytes, element: Tlv, scan: KeystoreScan) -> Tlv | None:
    parts = _parts(buf, element, 2, 3, scan=scan)
    kind = _oid(buf, parts[0])
    name = BAG_TYPES.get(kind, "unknown")
    _count(scan.bags, name)
    value = _single(buf, parts[1], scan)
    if value.tag != TAG_SEQUENCE:
        raise DerError("SafeBag value must be a SEQUENCE")
    if name == "certBag":
        _cert_bag(buf, value, scan)
    elif name == "unknown":
        scan.unreadable(f"SafeBag type {kind} not read")
    if len(parts) == 3:
        try:
            _attributes(buf, parts[2])
        except DerError as error:
            scan.unreadable(f"bagAttributes: {error}", malformed=True)
    return value if name == "safeContentsBag" else None


def _attributes(buf: bytes, attributes: Tlv) -> None:
    if attributes.tag != TAG_SET:
        raise DerError("bagAttributes must be a SET")
    for attr in _children(buf, attributes):
        parts = _parts(buf, attr, 2, 2)
        _oid(buf, parts[0])
        if parts[1].tag != TAG_SET:
            raise DerError("attribute values must be a SET")
        for _value in _children(buf, parts[1]):
            pass  # Attribute values are metadata, not trust-side certificates.


def _cert_bag(buf: bytes, value: Tlv, scan: KeystoreScan) -> None:
    parts = _parts(buf, value, 2, 2, scan=scan)
    kind = _oid(buf, parts[0])
    cert = _single(buf, parts[1], scan)
    if kind != OID_X509_CERTIFICATE:
        scan.unreadable(f"certBag certId {kind} not read")
        return
    scan.certificate(_data_bytes(buf, cert))


def _mac_data(buf: bytes, value: Tlv) -> None:
    parts = _parts(buf, value, 2, 3)
    digest = _parts(buf, parts[0], 2, 2)
    algorithm = _parts(buf, digest[0], 1, 2)
    _oid(buf, algorithm[0])
    _data_bytes(buf, digest[1])
    _data_bytes(buf, parts[1])
    if len(parts) == 3 and _number(buf, parts[2]) == 0:
        raise DerError("macData iterations must be positive")
    # MAC bytes are deliberately not verified.


class _JksReader:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.buf) - self.pos:
            raise DerError("JKS length runs past the buffer")
        start = self.pos
        self.pos += size
        return self.buf[start:self.pos]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def utf(self) -> bytes:
        # Java modified UTF-8: aliases are opaque metadata, never displayed or
        # used for matching. The type name below is compared as ASCII bytes.
        return self.take(int.from_bytes(self.take(2), "big"))

    def certificate(self, scan: KeystoreScan) -> None:
        kind = self.utf() if scan.version == 2 else b"X.509"
        raw = self.take(self.u32())
        if kind.upper() not in (b"X.509", b"X509"):
            scan.unreadable("JKS certificate type is not X.509")
        else:
            scan.certificate(raw)


def _jks(buf: bytes, scan: KeystoreScan) -> None:
    reader = _JksReader(buf)
    reader.take(4)  # magic was checked by content detection
    scan.version = reader.u32()
    if scan.version not in (1, 2):
        raise DerError("JKS/JCEKS version must be 1 or 2")
    scan.declared_entries = reader.u32()
    for _ in range(scan.declared_entries):
        tag = reader.u32()
        _count(scan.entries, ENTRY_TYPES.get(tag, "unknown"))
        if tag not in (1, 2) or (scan.format == "jceks" and tag != 2):
            scan.unreadable(f"{scan.format.upper()} entry tag {tag} not read")
            return  # Unknown/serialized entries have no safe next-entry boundary.
        reader.utf()  # alias bytes, not a path or a matcher input
        reader.take(8)  # signed millisecond timestamp; no date conversion needed
        if tag == 2:
            reader.certificate(scan)
        else:
            reader.take(reader.u32())  # protected key bytes are not certificates
            chain_count = reader.u32()
            for _ in range(chain_count):
                reader.certificate(scan)
    reader.take(20)  # integrity digest is present but deliberately not verified
    if reader.pos != len(buf):
        raise DerError("trailing bytes after JKS integrity hash")
