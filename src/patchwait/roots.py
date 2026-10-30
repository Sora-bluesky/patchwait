"""Audit where distrusted root certificates are still trusted.

The caller gives the distrust list. Each location is read, never modified,
and yields one item per distrust entry: ``found`` (present), ``not_found``
(everything was read and nothing matched) or ``undetermined`` with a reason.
Locations have a role: on the ``trust`` side a match is bad, on the
``distrust`` side (Disallowed) a match is good.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import datetime
import hashlib
import itertools
import os
import re
import ssl
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import BinaryIO

from patchwait.der import (
    OID_CTL_DISALLOWED_FILETIME,
    OID_CTL_NOT_BEFORE_FILETIME,
    OID_DISALLOWED_HASH,
    TAG_BIT_STRING,
    TAG_CONTEXT_0,
    TAG_INTEGER,
    TAG_SEQUENCE,
    CertInfo,
    CtlEntry,
    DerError,
    ctl_sha256,
    decode_filetime,
    iso_utc,
    parse_certificate,
    parse_ctl,
    read_tlv,
)
from patchwait.model import Check, Found, JSONObject, JSONValue, NotFound, Reason, Undetermined, check_to_json
from patchwait.keystore import MAX_KEYSTORE_FILE, parse_keystore
from patchwait.reparse import is_reparse_point

SCHEMA = 1

AUTOUPDATE_KEY = r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate"
AUTHROOT_VALUE = "EncodedCtl"
DISALLOWED_VALUE = "DisallowedCertEncodedCtl"

PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_END = b"-----END CERTIFICATE-----"
MAX_PEM_BODY = 64 * 1024  # a root certificate is a few KiB of base64
CHUNK_SIZE = 4 * 1024 * 1024
MAX_DER_FILE = 1024 * 1024  # a single DER .cer read whole
MAX_DER_CANDIDATE = 4 + 0xFFFF  # SEQUENCE with a two-byte length, header included
MAX_IGNORED_LISTED = 20  # ignored PEM blocks listed by offset in details
EMPTY_PEM_BLOCK = "empty_pem_block"  # the reason given for each of them

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")
_WHITESPACE_RE = re.compile(rb"[ \t\r\n]+")
# Literal backslash escapes as in a string literal (\r, \n, \t, and a JSON \/), read in a
# single pass, so removing one escape never joins the bytes around it into another.
_ESCAPE_RE = re.compile(rb"\\([rnt/])")
_EMPTY_PEM_BODY_RE = re.compile(rb"(?:[ \t\r\n\x00]|\\[rnt])*")
# A certificate SEQUENCE with a two-byte length whose first child (tbsCertificate)
# is a SEQUENCE with a one- or two-byte length (a small EC root's tbs can be
# under 256 bytes). Only the first two bytes are consumed, and no start is lost:
# two starts are never one byte apart, since buf[p + 1] is 0x82, never 0x30.
_DER_CANDIDATE_RE = re.compile(rb"\x30\x82(?=..\x30[\x81\x82])", re.DOTALL)

_PEM_LABEL_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]{1,64})-----")
_PEM_LABEL_OVERLAP = 80  # longer than any label marker the regex accepts
_CERT_LABELS = frozenset({b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE"})

_PEM_SUFFIXES = (".pem", ".crt", ".cer")
_PEM_PREFIXES = ("cacert", "ca-bundle")


class RootsUsageError(Exception):
    """Bad arguments or an unusable distrust list. Maps to exit code 2."""


class Role(StrEnum):
    TRUST = "trust"
    DISTRUST = "distrust"


class LocationKind(StrEnum):
    AUTHROOT_CTL = "authroot_ctl"
    DISALLOWED_CTL = "disallowed_ctl"
    ROOT_STORE = "root_store"
    DISALLOWED_STORE = "disallowed_store"
    PEM = "pem"
    PEM_ROOT = "pem_root"
    BINARY = "binary"
    JAVA_KEYSTORE = "java_keystore"


_ROLE: dict[LocationKind, Role] = {
    LocationKind.AUTHROOT_CTL: Role.TRUST,
    LocationKind.DISALLOWED_CTL: Role.DISTRUST,
    LocationKind.ROOT_STORE: Role.TRUST,
    LocationKind.DISALLOWED_STORE: Role.DISTRUST,
    LocationKind.PEM: Role.TRUST,
    LocationKind.PEM_ROOT: Role.TRUST,
    LocationKind.BINARY: Role.TRUST,
    LocationKind.JAVA_KEYSTORE: Role.TRUST,
}


def role_of(kind: LocationKind) -> Role:
    """The side a location is on: a match is bad on ``trust`` and good on ``distrust``."""
    return _ROLE[kind]


def _hex(value: bytes | None) -> str | None:
    return value.hex() if value is not None else None


# --- distrust list -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DistrustEntry:
    label: str
    sha256: bytes | None = None
    sha1: bytes | None = None
    spki_sha256: bytes | None = None
    der: bytes | None = None
    spki_der: bytes | None = None
    signature_hash: bytes | None = None
    public_key_md5: bytes | None = None
    signature_algorithm: str | None = None

    def to_json(self) -> JSONObject:
        return {
            "label": self.label,
            "sha256": _hex(self.sha256),
            "sha1": _hex(self.sha1),
            "spki_sha256": _hex(self.spki_sha256),
            "signature_hash": _hex(self.signature_hash),
            "public_key_md5": _hex(self.public_key_md5),
            "raw_der": self.der is not None,
        }


_FIELDS = ("sha256", "sha1", "spki_sha256", "der", "spki_der", "signature_hash", "public_key_md5")
_PREFIX_FIELD = {"sha256": ("sha256", 32), "sha1": ("sha1", 20), "spki": ("spki_sha256", 32)}


def _parse_identifier(token: str) -> tuple[str, bytes] | None:
    prefix, sep, rest = token.partition(":")
    if sep and prefix.lower() in _PREFIX_FIELD:
        name, size = _PREFIX_FIELD[prefix.lower()]
        text = rest
    else:
        name, size = "sha256", 32  # trust-store-audit preset: a bare SHA-256
        text = token
    text = text.replace(":", "")
    if not _HEX_RE.fullmatch(text) or len(text) != size * 2:
        return None
    return name, bytes.fromhex(text)


class _Merger:
    """Entries with the same label become one; conflicting values are an error."""

    def __init__(self) -> None:
        self._order: list[str] = []
        self._values: dict[str, dict[str, bytes]] = {}
        self._signature_algorithms: dict[str, str] = {}

    def add(self, label: str, values: dict[str, bytes], where: str, signature_algorithm: str | None = None) -> None:
        if label not in self._values:
            self._order.append(label)
            self._values[label] = {}
        current = self._values[label]
        for name, value in values.items():
            if name in current and current[name] != value:
                raise RootsUsageError(f"{where}: {label!r} has two different {name} values")
            current[name] = value
        if signature_algorithm is not None:
            self._signature_algorithms[label] = signature_algorithm

    def entries(self) -> list[DistrustEntry]:
        result: list[DistrustEntry] = []
        for label in self._order:
            values = self._values[label]
            result.append(DistrustEntry(
                label, **{name: values.get(name) for name in _FIELDS},
                signature_algorithm=self._signature_algorithms.get(label),
            ))
        return result


def _read_text(option: str, path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise RootsUsageError(f"{option} {path!r}: {type(error).__name__}") from error


def _add_list(merger: _Merger, path: str) -> None:
    for number, raw in enumerate(_read_text("--distrust", path).splitlines(), start=1):
        line = raw.strip()
        if line == "" or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        token = parts[0]
        label = parts[1] if len(parts) > 1 else ""
        parsed = _parse_identifier(token)
        where = f"--distrust {os.path.basename(path)}:{number}"
        if parsed is None:
            raise RootsUsageError(f"{where}: {token!r} is not sha256:/sha1:/spki: hex or a bare SHA-256")
        name, value = parsed
        label = label.strip() or token
        merger.add(label, {name: value}, where)


def _add_pem(merger: _Merger, path: str) -> None:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_DER_FILE + 1)
    except OSError as error:
        raise RootsUsageError(f"--distrust-pem {path!r}: {type(error).__name__}") from error
    scanned = scan_stream(_BytesReader(data), ())
    if scanned.malformed or scanned.ignored_total or not scanned.certs:
        raise RootsUsageError(f"--distrust-pem {path!r}: needs well-formed PEM certificates only")
    for index, (cert, _offset) in enumerate(scanned.certs, start=1):
        label = cert.subject_cn or f"{os.path.basename(path)}#{index}"
        values: dict[str, bytes | None] = {
            "sha256": cert.sha256,
            "sha1": cert.sha1,
            "spki_sha256": cert.spki_sha256,
            "der": cert.der,
            "spki_der": cert.spki_der,
            "signature_hash": cert.signature_hash,
            "public_key_md5": cert.public_key_md5,
        }
        merger.add(
            label, {name: value for name, value in values.items() if value is not None},
            f"--distrust-pem {os.path.basename(path)}", cert.signature_algorithm,
        )


def load_distrust(lists: Sequence[str], pems: Sequence[str]) -> list[DistrustEntry]:
    merger = _Merger()
    for path in lists:
        _add_list(merger, path)
    for path in pems:
        _add_pem(merger, path)
    entries = merger.entries()
    if not entries:
        raise RootsUsageError("no distrust entries: give --distrust or --distrust-pem")
    return entries


# --- results -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RootsItem:
    location: str
    kind: LocationKind
    entry: DistrustEntry
    verdict: Check[tuple[str, ...]]  # Found(value) = how it matched
    matches: tuple[JSONObject, ...] = ()
    details: JSONObject = field(default_factory=lambda: {})

    @property
    def role(self) -> Role:
        return _ROLE[self.kind]

    def to_json(self) -> JSONObject:
        return {
            "location": self.location,
            "location_kind": self.kind.value,
            "role": self.role.value,
            "distrust": self.entry.label,
            "verdict": check_to_json(self.verdict, _encode_methods),
            "matches": list(self.matches),
            "details": self.details,
        }


def _encode_methods(value: tuple[str, ...]) -> JSONValue:
    return list(value)


def _all_undetermined(
    location: str, kind: LocationKind, entries: Sequence[DistrustEntry], reason: Reason, detail: str
) -> list[RootsItem]:
    return [RootsItem(location, kind, entry, Undetermined(reason, detail)) for entry in entries]


def _methods(matches: Iterable[JSONObject]) -> tuple[str, ...]:
    return tuple(sorted({str(match["matched_by"]) for match in matches}))


# --- certificate collections (stores, PEM, binaries) -----------------------------


def _cert_matches(entry: DistrustEntry, cert: CertInfo, offset: int | None) -> list[JSONObject]:
    found: list[JSONObject] = []
    for method, mine, theirs in (
        ("sha256", entry.sha256, cert.sha256),
        ("sha1", entry.sha1, cert.sha1),
        ("spki_sha256", entry.spki_sha256, cert.spki_sha256),
    ):
        if mine is not None and mine == theirs:
            match: JSONObject = {
                "matched_by": method,
                "cert_sha256": cert.sha256.hex(),
                "subject_cn": cert.subject_cn,
            }
            if offset is not None:
                match["offset"] = offset
            found.append(match)
    return found


def _judge_collection(
    location: str,
    kind: LocationKind,
    entries: Sequence[DistrustEntry],
    certs: Sequence[tuple[CertInfo, int | None]],
    unparsed: Sequence[bytes],
    malformed: int,
    details: JSONObject,
    require_certs: bool = False,
) -> list[RootsItem]:
    per_entry: list[list[JSONObject]] = []
    for entry in entries:
        matches: list[JSONObject] = []
        for cert, offset in certs:
            matches += _cert_matches(entry, cert, offset)
        for raw in unparsed:  # fingerprints of the raw bytes still compare
            for method, mine, theirs in (
                ("sha256", entry.sha256, hashlib.sha256(raw).digest()),
                ("sha1", entry.sha1, hashlib.sha1(raw).digest()),
            ):
                if mine is not None and mine == theirs:
                    matches.append({"matched_by": method, "cert_sha256": hashlib.sha256(raw).hexdigest()})
        per_entry.append(matches)
    return _collection_items(location, kind, entries, per_entry, len(certs), malformed, details, require_certs)


def _collection_items(
    location: str,
    kind: LocationKind,
    entries: Sequence[DistrustEntry],
    per_entry: Sequence[Sequence[JSONObject]],
    parsed: int,
    malformed: int,
    details: JSONObject,
    require_certs: bool,
) -> list[RootsItem]:
    """One item per entry from its matches, given how many certificates were parsed and how many were not."""
    detail = f"{malformed} certificate(s) could not be parsed; no match among {parsed} parsed"
    none_detail = "no certificate was recognised" if require_certs and parsed == 0 else None
    return [
        RootsItem(location, kind, entry, _verdict(matches, malformed, detail, none_detail), tuple(matches), dict(details))
        for entry, matches in zip(entries, per_entry, strict=True)
    ]


def _verdict(
    matches: Sequence[JSONObject], malformed: int, malformed_detail: str, none_detail: str | None
) -> Check[tuple[str, ...]]:
    """``none_detail`` is given when no certificate was recognised and that leaves the result open."""
    if matches:
        return Found(_methods(matches))
    if malformed > 0:
        return Undetermined(Reason.MALFORMED_CERT, malformed_detail)
    if none_detail is not None:
        return Undetermined(Reason.NO_CERTS_RECOGNISED, none_detail)
    return NotFound()


class _BytesReader:
    """A minimal ``read(n)`` over bytes, so the streaming scan serves both."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, size: int) -> bytes:
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk


CertSink = Callable[[CertInfo, int, bool], None]  # certificate, absolute offset, from raw DER


@dataclass(slots=True)
class StreamScan:
    certs: list[tuple[CertInfo, int]]  # parsed certificates, kept only when no sink was given
    malformed: int
    blocks: int
    needle_hits: dict[int, list[int]]  # needle index -> absolute offsets
    pem_certs: int = 0  # certificates parsed from PEM blocks
    der_certs: int = 0  # raw DER certificates parsed (find_der only)
    ignored: list[int] = field(default_factory=lambda: [])  # offsets of the first empty PEM blocks
    ignored_total: int = 0


def _is_empty_pem_body(body: bytes) -> bool:
    """True if only whitespace, NULs and literal escapes sit between the markers."""
    return _EMPTY_PEM_BODY_RE.fullmatch(body) is not None


def _unescape(match: re.Match[bytes]) -> bytes:
    return b"/" if match.group(1) == b"/" else b""  # a JSON-escaped slash stays a slash


def _decode_pem_body(body: bytes) -> bytes | None:
    body = _ESCAPE_RE.sub(_unescape, body)
    body = _WHITESPACE_RE.sub(b"", body)
    if body == b"" or len(body) % 4 != 0 or not _BASE64_RE.match(body):
        return None
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None


def scan_stream(
    handle: BinaryIO | _BytesReader,
    needles: Sequence[bytes],
    chunk_size: int = CHUNK_SIZE,
    *,
    find_der: bool = False,
    sink: CertSink | None = None,
) -> StreamScan:
    """Find PEM certificate blocks, raw byte ``needles`` and, with ``find_der``,
    raw DER certificates in a stream.

    Chunks overlap by more than the longest block, needle or DER candidate, and
    only matches starting before the overlap are handled in each round, so a
    match that straddles a chunk boundary is seen exactly once.

    Each parsed certificate goes to ``sink`` as soon as it is parsed and is then
    dropped, so memory does not grow with the number of certificates; without a
    sink it is kept in ``certs``.
    """
    overlap = max(
        [len(PEM_BEGIN) + MAX_PEM_BODY + len(PEM_END), MAX_DER_CANDIDATE] + [len(needle) for needle in needles]
    )
    result = StreamScan([], 0, 0, {})
    emit: CertSink = sink if sink is not None else lambda cert, offset, _der: result.certs.append((cert, offset))
    buffer = b""
    base = 0  # absolute offset of buffer[0]
    while True:
        chunk = handle.read(max(1, chunk_size))
        final = chunk == b""
        buffer += chunk
        limit = len(buffer) if final else len(buffer) - overlap
        if limit > 0:
            _scan_window(buffer, base, limit, needles, result, emit)
            if find_der:
                _scan_der(buffer, base, limit, result, emit)
            buffer = buffer[limit:]
            base += limit
        if final:
            return result


def _scan_window(
    buffer: bytes, base: int, limit: int, needles: Sequence[bytes], result: StreamScan, emit: CertSink
) -> None:
    # A marker starting just before ``limit`` ends past it: search that far, keep starts below ``limit``.
    stop = min(len(buffer), limit + len(PEM_BEGIN) - 1)
    pos = buffer.find(PEM_BEGIN, 0, stop)
    while pos != -1:
        result.blocks += 1
        body_start = pos + len(PEM_BEGIN)
        end = buffer.find(PEM_END, body_start, body_start + MAX_PEM_BODY + len(PEM_END))
        if end != -1 and _is_empty_pem_body(buffer[body_start:end]):
            result.ignored_total += 1  # a template, not a certificate
            if len(result.ignored) < MAX_IGNORED_LISTED:
                result.ignored.append(base + pos)
        else:
            der = _decode_pem_body(buffer[body_start:end]) if end != -1 else None
            cert: CertInfo | None = None
            if der is not None:
                try:
                    cert = parse_certificate(der)
                except DerError:
                    cert = None
            if cert is None:
                result.malformed += 1
            else:
                result.pem_certs += 1
                emit(cert, base + pos, False)
        pos = buffer.find(PEM_BEGIN, pos + 1, stop)
    for index, needle in enumerate(needles):
        if not needle:
            continue
        pos = buffer.find(needle, 0)
        while pos != -1 and pos < limit:
            result.needle_hits.setdefault(index, []).append(base + pos)
            pos = buffer.find(needle, pos + 1)


_TBS_FIELDS = (TAG_INTEGER,) + (TAG_SEQUENCE,) * 5  # serial, signature, issuer, validity, subject, spki


def _der_shape(buffer: bytes, start: int, end: int) -> bool:
    """A check in place before copying up to 64 KiB: tbs, algorithm and signature
    fill ``start + 4:end``, and tbs opens with the six fields of a certificate.

    It reads a bounded number of headers, so a file dense with candidates costs
    no more than a few header reads per candidate.
    """
    try:
        tbs = read_tlv(buffer, start + 4, end)
        algorithm = read_tlv(buffer, tbs.end, end)
        signature = read_tlv(buffer, algorithm.end, end)
        if algorithm.tag != TAG_SEQUENCE or signature.tag != TAG_BIT_STRING or signature.end != end:
            return False
        tags: list[int] = []
        pos = tbs.start
        while pos < tbs.end and len(tags) < len(_TBS_FIELDS) + 1:
            element = read_tlv(buffer, pos, tbs.end)
            tags.append(element.tag)
            pos = element.end
    except DerError:
        return False
    if tags[:1] == [TAG_CONTEXT_0]:  # version
        tags = tags[1:]
    return tuple(tags[: len(_TBS_FIELDS)]) == _TBS_FIELDS


def _scan_der(buffer: bytes, base: int, limit: int, result: StreamScan, emit: CertSink) -> None:
    """Raw DER certificates starting before ``limit``.

    A candidate that does not parse is not a certificate, and not a malformed
    one either: ``30 82`` is common in code and data.
    """
    for match in _DER_CANDIDATE_RE.finditer(buffer, 0, min(len(buffer), limit + 5)):
        start = match.start()
        if start >= limit:
            break
        end = start + 4 + int.from_bytes(buffer[start + 2 : start + 4], "big")
        if end > len(buffer) or not _der_shape(buffer, start, end):
            continue  # runs past the end of the file, or is not shaped like a certificate
        try:
            cert = parse_certificate(buffer[start:end])
        except DerError:
            continue
        result.der_certs += 1
        emit(cert, base + start, True)


def _needles(entries: Sequence[DistrustEntry]) -> tuple[list[bytes], list[tuple[int, str]]]:
    needles: list[bytes] = []
    owners: list[tuple[int, str]] = []  # (entry index, method)
    for index, entry in enumerate(entries):
        if entry.der:
            needles.append(entry.der)
            owners.append((index, "raw_der"))
        if entry.spki_der:
            needles.append(entry.spki_der)
            owners.append((index, "raw_spki"))
    return needles, owners


def _outside(hits: Sequence[int], spans: Sequence[tuple[int, int]]) -> list[int]:
    """The hits that fall in none of the ``[start, end)`` spans, in O((hits + spans) log spans)."""
    ordered = sorted(spans)
    starts = [start for start, _end in ordered]
    reach = list(itertools.accumulate((end for _start, end in ordered), max))  # furthest end so far
    kept: list[int] = []
    for hit in hits:
        index = bisect.bisect_right(starts, hit) - 1
        if index < 0 or reach[index] <= hit:
            kept.append(hit)
    return kept


def _file_problem(path: str) -> tuple[Reason, str] | None:
    if not os.path.lexists(path):
        return Reason.TARGET_MISSING, "path does not exist"
    if not os.path.isfile(path):
        return Reason.FILE_UNREADABLE, "path is not a regular file"
    return None


def audit_binary(path: str, entries: Sequence[DistrustEntry], chunk_size: int = CHUNK_SIZE) -> list[RootsItem]:
    kind = LocationKind.BINARY
    problem = _file_problem(path)
    if problem is not None:
        return _all_undetermined(path, kind, entries, *problem)
    needles, owners = _needles(entries)
    # Each certificate is matched as it is parsed; only the matches and the spans of
    # matching DER certificates are kept, never the certificates themselves.
    pem_matches: list[list[JSONObject]] = [[] for _ in entries]
    der_matches: list[list[JSONObject]] = [[] for _ in entries]
    der_spans: list[list[tuple[int, int]]] = [[] for _ in entries]

    def sink(cert: CertInfo, offset: int, from_der: bool) -> None:
        for index, entry in enumerate(entries):
            found = _cert_matches(entry, cert, offset)
            if found and from_der:
                der_matches[index] += found
                der_spans[index].append((offset, offset + len(cert.der)))
            elif found:
                pem_matches[index] += found

    try:
        with open(path, "rb") as handle:
            scanned = scan_stream(handle, needles, chunk_size, find_der=True, sink=sink)
    except OSError as error:
        return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, type(error).__name__)
    raw_matches: list[list[JSONObject]] = [[] for _ in entries]
    for needle_index in sorted(scanned.needle_hits):  # needle order, whatever the chunking
        index, method = owners[needle_index]
        # A raw hit inside a DER certificate that already matched this entry is the same finding.
        hits = _outside(scanned.needle_hits[needle_index], der_spans[index])
        for hit in hits:
            raw: JSONObject = {"matched_by": method, "offset": hit}
            raw_matches[index].append(raw)
    malformed_detail = (
        f"{scanned.malformed} PEM certificate(s) could not be parsed; no match among "
        f"{scanned.pem_certs} PEM and {scanned.der_certs} DER certificate(s) parsed"
    )
    none_detail = (
        f"no certificate was recognised ({scanned.blocks} PEM block(s), "
        f"{scanned.ignored_total} ignored as empty, no DER certificate)"
    )
    recognised = scanned.pem_certs + scanned.der_certs > 0
    details = _binary_details(scanned)
    items: list[RootsItem] = []
    for index, entry in enumerate(entries):
        matches = pem_matches[index] + der_matches[index] + raw_matches[index]
        verdict = _verdict(matches, scanned.malformed, malformed_detail, None if recognised else none_detail)
        items.append(RootsItem(path, kind, entry, verdict, tuple(matches), dict(details)))
    return items


def _ignored_details(scanned: StreamScan) -> JSONObject:
    listed: list[JSONValue] = [{"offset": offset, "reason": EMPTY_PEM_BLOCK} for offset in scanned.ignored]
    details: JSONObject = {"ignored_pem_blocks": listed}
    if scanned.ignored_total > len(scanned.ignored):
        details["ignored_pem_blocks_total"] = scanned.ignored_total
    return details


def _binary_details(scanned: StreamScan) -> JSONObject:
    details: JSONObject = {
        "pem_blocks": scanned.blocks,
        "certs": scanned.pem_certs,
        "der_certs": scanned.der_certs,
        "malformed": scanned.malformed,
    }
    details.update(_ignored_details(scanned))
    return details


def audit_pem(path: str, entries: Sequence[DistrustEntry], chunk_size: int = CHUNK_SIZE) -> list[RootsItem]:
    """A PEM bundle, or a single DER certificate (``.cer``) without PEM blocks.

    Each certificate is matched as it is parsed; only the count and the matches are
    kept, never the certificates themselves, so memory does not grow with the bundle.
    """
    kind = LocationKind.PEM
    problem = _file_problem(path)
    if problem is not None:
        return _all_undetermined(path, kind, entries, *problem)
    matches: list[list[JSONObject]] = [[] for _ in entries]
    parsed = 0

    def sink(cert: CertInfo, _offset: int, _from_der: bool) -> None:
        nonlocal parsed
        parsed += 1
        for index, entry in enumerate(entries):
            matches[index] += _cert_matches(entry, cert, None)

    try:
        with open(path, "rb") as handle:
            scanned = scan_stream(handle, (), chunk_size, sink=sink)
        if scanned.blocks == 0 and os.path.getsize(path) <= MAX_DER_FILE:
            with open(path, "rb") as handle:
                data = handle.read(MAX_DER_FILE + 1)
            if data[:1] == b"0":
                try:
                    cert = parse_certificate(data)
                except DerError:
                    scanned.malformed += 1
                else:
                    sink(cert, 0, True)
    except OSError as error:
        return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, type(error).__name__)
    details: JSONObject = {"pem_blocks": scanned.blocks, "certs": parsed, "malformed": scanned.malformed}
    if scanned.ignored_total:
        details.update(_ignored_details(scanned))
    return _collection_items(path, kind, entries, matches, parsed, scanned.malformed, details, require_certs=True)


def audit_keystore(path: str, entries: Sequence[DistrustEntry]) -> list[RootsItem]:
    """Enumerate certificate fields; only a complete read can prove absence."""
    kind = LocationKind.JAVA_KEYSTORE
    problem = _file_problem(path)
    if problem is not None:
        return _all_undetermined(path, kind, entries, *problem)
    too_large = f"file exceeds MAX_KEYSTORE_FILE ({MAX_KEYSTORE_FILE} bytes)"
    try:
        if os.path.getsize(path) > MAX_KEYSTORE_FILE:
            return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, too_large)
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > MAX_KEYSTORE_FILE:
                return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, too_large)
            data = handle.read(MAX_KEYSTORE_FILE + 1)
        if len(data) > MAX_KEYSTORE_FILE:
            return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, too_large)
    except OSError as error:
        return _all_undetermined(path, kind, entries, Reason.FILE_UNREADABLE, type(error).__name__)
    scanned = parse_keystore(data)
    items = _judge_collection(
        path, kind, entries, scanned.certs, scanned.unparsed, len(scanned.unparsed), scanned.details(),
    )
    if scanned.unreadable_parts or scanned.encrypted_content_infos:
        reason = Reason.MALFORMED_KEYSTORE if scanned.malformed_structure else Reason.KEYSTORE_UNREADABLE
        items = [
            replace(item, verdict=Undetermined(reason, scanned.detail())) if not isinstance(item.verdict, Found) else item
            for item in items
        ]
    return items


def is_bundle_name(name: str) -> bool:
    lower = name.lower()
    return lower.endswith(_PEM_SUFFIXES) or lower.startswith(_PEM_PREFIXES) or lower == "roots.pem"


def find_bundles(root: str) -> tuple[list[str], list[str], int]:
    """Bundle files under ``root``, the directories that could not be listed, and
    how many directory symlinks and junctions were skipped.

    The walk is depth-first with entries sorted by name, and a directory's files
    come before its subdirectories. The root itself is always entered; a symlink
    or junction to a directory below it is not. ``root`` is put in
    ``os.path.normpath`` form first, so the joined paths never mix separators.
    """
    root = os.path.normpath(root)
    files: list[str] = []
    errors: list[str] = []
    skipped = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError:
            errors.append(directory)
            continue
        subdirs: list[str] = []
        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                is_dir = False
            if not is_dir:
                if is_bundle_name(entry.name):
                    files.append(entry.path)
                continue
            try:
                reparse = is_reparse_point(entry)
            except OSError:
                errors.append(entry.path)
                continue
            if reparse:
                skipped += 1
            else:
                subdirs.append(entry.path)
        stack.extend(reversed(subdirs))
    return files, errors, skipped


def is_key_only(path: str, chunk_size: int = CHUNK_SIZE) -> bool:
    """True if the file has PEM blocks and none of them is a certificate.

    An unreadable file is not key-only: it is left to the audit to report.
    """
    labels: set[bytes] = set()
    tail = b""
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(max(1, chunk_size)):
                window = tail + chunk
                labels.update(match.group(1) for match in _PEM_LABEL_RE.finditer(window))
                tail = window[-_PEM_LABEL_OVERLAP:]
    except OSError:
        return False
    return bool(labels) and labels.isdisjoint(_CERT_LABELS)


def audit_pem_root(root: str, entries: Sequence[DistrustEntry]) -> list[RootsItem]:
    kind = LocationKind.PEM_ROOT
    root = os.path.normpath(root)
    if not os.path.isdir(root):
        reason = Reason.TARGET_MISSING if not os.path.lexists(root) else Reason.FILE_UNREADABLE
        return _all_undetermined(root, kind, entries, reason, "not a directory")
    files, errors, skipped_reparse = find_bundles(root)
    audited = [path for path in files if not is_key_only(path)]
    skipped = len(files) - len(audited)
    items: list[RootsItem] = []
    for path in audited:
        items += audit_pem(path, entries)
    for directory in errors:
        items += _all_undetermined(directory, kind, entries, Reason.FILE_UNREADABLE, "directory could not be listed")
    if skipped or skipped_reparse or (not audited and not errors):
        details: JSONObject = {"files": len(audited)}
        if skipped:
            details["skipped_key_only"] = skipped
        if skipped_reparse:
            details["skipped_reparse_points"] = skipped_reparse
        items += [RootsItem(root, kind, entry, NotFound(), (), dict(details)) for entry in entries]
    return items


# --- Windows -------------------------------------------------------------------

StoreEntry = tuple[bytes, str, object]


def _key_unavailable(hive: str, subkey: str) -> object:
    raise OSError(f"no key_last_write was given for {hive}\\{subkey}")


@dataclass(frozen=True, slots=True)
class WindowsAccess:
    """Read-only access to the Windows locations, injectable for tests.

    There is no write function: every registry key is opened with ``KEY_READ``.
    """

    is_windows: bool
    read_registry: Callable[[str], object]  # value name under AUTOUPDATE_KEY
    enum_store: Callable[[str], Sequence[StoreEntry]]
    # (hive "HKLM" or "HKCU", subkey) -> the key's last-write FILETIME ticks;
    # FileNotFoundError when the key does not exist; the default reads nothing and
    # raises OSError, so every key is reported as unreadable
    key_last_write: Callable[[str, str], object] = _key_unavailable


def _read_registry(name: str) -> object:
    if sys.platform != "win32":
        raise OSError("winreg is only available on Windows")
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AUTOUPDATE_KEY, 0, winreg.KEY_READ) as key:
        value, _kind = winreg.QueryValueEx(key, name)
    return value


def _key_last_write(hive: str, subkey: str) -> object:
    if sys.platform != "win32":
        raise OSError("winreg is only available on Windows")
    import winreg

    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    with winreg.OpenKey(hives[hive], subkey, 0, winreg.KEY_READ) as key:
        return winreg.QueryInfoKey(key)[2]


def _enum_store(name: str) -> Sequence[StoreEntry]:
    if sys.platform != "win32":
        raise OSError("ssl.enum_certificates is only available on Windows")
    return [(der, encoding, trust) for der, encoding, trust in ssl.enum_certificates(name)]


def default_windows_access() -> WindowsAccess:
    return WindowsAccess(sys.platform == "win32", _read_registry, _enum_store, _key_last_write)


_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
BAD_FILETIME_NOTE = "the time is zero or out of range"
NOT_TICKS_NOTE = "the time is not an integer FILETIME"
_CERT_BASES = (r"SOFTWARE\Microsoft\SystemCertificates", r"SOFTWARE\Policies\Microsoft\SystemCertificates")
_ENTERPRISE_BASE = r"SOFTWARE\Microsoft\EnterpriseCertificates"
# The registry stores looked up for a store item's match.
_REGISTRY_STORES: dict[LocationKind, tuple[str, ...]] = {
    LocationKind.ROOT_STORE: ("ROOT", "AuthRoot"),
    LocationKind.DISALLOWED_STORE: ("Disallowed",),
}
_ENTERPRISE_STORE: dict[LocationKind, str] = {LocationKind.ROOT_STORE: "ROOT", LocationKind.DISALLOWED_STORE: "Disallowed"}
REGISTRY_KEYS_NOTE = "not found in the registry locations checked"
REGISTRY_KEYS_PARTIAL_NOTE = "not found in the registry locations that could be read"
# The AutoUpdate value holding the last sync time of each CTL.
_LAST_SYNC_VALUE: dict[LocationKind, str] = {
    LocationKind.AUTHROOT_CTL: "LastSyncTime",
    LocationKind.DISALLOWED_CTL: "DisallowedCertLastSyncTime",
}


def filetime_ticks_to_iso(ticks: object) -> str | None:
    """FILETIME ticks (100 ns since 1601 UTC) as ISO 8601 UTC; None when zero, negative or out of range."""
    if type(ticks) is not int or ticks <= 0:
        return None
    try:
        return iso_utc(_FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10))
    except OverflowError:
        return None


def _registry_locations(kind: LocationKind, sha1_hex: str) -> list[tuple[str, str]]:
    """(hive, subkey) pairs where a store item's certificate can have a key."""
    found: list[tuple[str, str]] = []
    for hive in ("HKLM", "HKCU"):
        for base in _CERT_BASES:
            for store in _REGISTRY_STORES[kind]:
                found.append((hive, f"{base}\\{store}\\Certificates\\{sha1_hex}"))
    found.append(("HKLM", f"{_ENTERPRISE_BASE}\\{_ENTERPRISE_STORE[kind]}\\Certificates\\{sha1_hex}"))
    return found


def registry_key_paths(kind: LocationKind, sha1_hex: str) -> list[str]:
    """The full registry key paths a store item's certificate is looked up at."""
    return [f"{hive}\\{subkey}" for hive, subkey in _registry_locations(kind, sha1_hex.upper())]


def _registry_keys(kind: LocationKind, sha1: bytes, access: WindowsAccess) -> JSONObject:
    """The registry keys of one certificate and their last-write times; nothing is guessed."""
    keys: list[JSONObject] = []
    errors: list[JSONObject] = []
    for hive, subkey in _registry_locations(kind, sha1.hex().upper()):
        name = f"{hive}\\{subkey}"
        try:
            ticks = access.key_last_write(hive, subkey)
        except FileNotFoundError:
            continue
        except Exception as error:  # any failure of one key is recorded, not raised
            errors.append({"key": name, "error": type(error).__name__})
            continue
        entry: JSONObject = {"key": name, "last_write": filetime_ticks_to_iso(ticks)}
        if entry["last_write"] is None:
            entry["last_write_note"] = BAD_FILETIME_NOTE if type(ticks) is int else NOT_TICKS_NOTE
        keys.append(entry)
    keys.sort(key=lambda entry: str(entry["key"]))
    result: JSONObject = {"registry_keys": list(keys)}
    if not keys:
        result["registry_keys_note"] = REGISTRY_KEYS_PARTIAL_NOTE if errors else REGISTRY_KEYS_NOTE
    if errors:
        result["registry_keys_errors"] = list(errors)
    return result


def _last_sync(kind: LocationKind, access: WindowsAccess) -> JSONObject:
    name = _LAST_SYNC_VALUE[kind]
    try:
        value = access.read_registry(name)
    except FileNotFoundError:
        return {"last_sync": None, "last_sync_note": f"{name} not found"}
    except OSError as error:
        return {"last_sync": None, "last_sync_note": f"{name} could not be read: {type(error).__name__}"}
    if not isinstance(value, bytes) or len(value) != 8:
        return {"last_sync": None, "last_sync_note": f"{name} is not an 8-byte FILETIME"}
    when = filetime_ticks_to_iso(int.from_bytes(value, "little"))
    if when is None:
        return {"last_sync": None, "last_sync_note": f"{name}: {BAD_FILETIME_NOTE}"}
    return {"last_sync": when}


def _filetime(entry: CtlEntry, oid: str) -> JSONValue:
    values = entry.attributes.get(oid)
    if values is None:
        return None
    try:
        when: str | None = iso_utc(decode_filetime(values))
    except DerError:
        when = None
    return {"filetime": when, "raw": values.hex()}


def audit_ctl(
    kind: LocationKind, value_name: str, entries: Sequence[DistrustEntry], access: WindowsAccess
) -> list[RootsItem]:
    location = "HKLM\\" + AUTOUPDATE_KEY + "\\" + value_name
    if not access.is_windows:
        return _all_undetermined(location, kind, entries, Reason.NOT_WINDOWS, "not running on Windows")
    last_sync = _last_sync(kind, access)

    def unreadable(reason: Reason, detail: str) -> list[RootsItem]:
        return [RootsItem(location, kind, entry, Undetermined(reason, detail), (), dict(last_sync)) for entry in entries]

    try:
        blob = access.read_registry(value_name)
    except OSError as error:
        return unreadable(Reason.STORE_UNREADABLE, type(error).__name__)
    if not isinstance(blob, bytes) or blob == b"":
        return unreadable(Reason.STORE_UNREADABLE, "value is not binary data")
    try:
        ctl = parse_ctl(blob)
    except DerError as error:
        return unreadable(Reason.MALFORMED_CTL, str(error))
    details: JSONObject = {"this_update": iso_utc(ctl.this_update), "ctl_entries": len(ctl.entries), **last_sync}
    if kind is LocationKind.DISALLOWED_CTL and ctl.subject_algorithm == OID_DISALLOWED_HASH:
        return [_judge_disallowed_hash(location, kind, entry, ctl.entries, details) for entry in entries]
    return [_judge_ctl_entry(location, kind, entry, ctl.entries, details) for entry in entries]


def _judge_disallowed_hash(
    location: str, kind: LocationKind, entry: DistrustEntry, subjects: Sequence[CtlEntry], details: JSONObject
) -> RootsItem:
    matches: list[JSONObject] = []
    for subject in subjects:
        for method, identifier in (("signature_hash", entry.signature_hash), ("public_key_md5", entry.public_key_md5)):
            if identifier is not None and subject.identifier == identifier:
                matches.append({"matched_by": method, "identifier": identifier.hex()})
    verdict: Check[tuple[str, ...]]
    if matches:
        verdict = Found(_methods(matches))
    elif entry.signature_hash is not None and entry.public_key_md5 is not None:
        verdict = NotFound()
    else:
        detail = "the Disallowed list is matched by signature hash or public-key MD5 of a certificate"
        if entry.signature_hash is None:
            detail += "; signature hash could not be computed"
            if entry.signature_algorithm is not None:
                detail += f" (signature algorithm {entry.signature_algorithm} or its hash parameters)"
        if entry.public_key_md5 is None:
            detail += "; public-key MD5 could not be computed"
        verdict = Undetermined(Reason.NO_USABLE_IDENTIFIER, detail)
    return RootsItem(location, kind, entry, verdict, tuple(matches), dict(details))


def _judge_ctl_entry(
    location: str, kind: LocationKind, entry: DistrustEntry, subjects: Sequence[CtlEntry], details: JSONObject
) -> RootsItem:
    def item(verdict: Check[tuple[str, ...]], matches: Sequence[JSONObject] = ()) -> RootsItem:
        return RootsItem(location, kind, entry, verdict, tuple(matches), dict(details))

    if entry.sha1 is None and entry.sha256 is None:
        return item(Undetermined(Reason.NO_USABLE_IDENTIFIER, "a CTL is matched by sha1 or sha256 only"))
    matches: list[JSONObject] = []
    active: list[JSONObject] = []  # matches not taken out by .11.104
    undecidable = 0
    for subject in subjects:
        cert_sha256 = ctl_sha256(subject)
        by_sha1 = entry.sha1 is not None and len(subject.identifier) == 20
        by_sha256 = entry.sha256 is not None and cert_sha256 is not None
        if not (by_sha1 or by_sha256):
            undecidable += 1
            continue
        methods: list[str] = []
        if by_sha1 and subject.identifier == entry.sha1:
            methods.append("sha1")
        if by_sha256 and cert_sha256 == entry.sha256:
            methods.append("sha256")
        for method in methods:
            match: JSONObject = {
                "matched_by": method,
                "identifier": subject.identifier.hex(),
                "cert_sha256": _hex(cert_sha256),
                "disallowed": _filetime(subject, OID_CTL_DISALLOWED_FILETIME),
                "not_before": _filetime(subject, OID_CTL_NOT_BEFORE_FILETIME),
            }
            matches.append(match)
            if match["disallowed"] is None:
                active.append(match)
    role = _ROLE[kind]
    if role is Role.TRUST and matches and not active:
        return item(NotFound(), matches)  # listed, but taken out (.11.104)
    if matches:
        return item(Found(_methods(matches)), matches)
    if undecidable:
        detail = f"{undecidable} CTL entries cannot be compared with the identifiers given"
        return item(Undetermined(Reason.NO_USABLE_IDENTIFIER, detail))
    return item(NotFound())


def audit_store(
    kind: LocationKind, store: str, entries: Sequence[DistrustEntry], access: WindowsAccess
) -> list[RootsItem]:
    location = f"cert-store:{store}"
    if not access.is_windows:
        return _all_undetermined(location, kind, entries, Reason.NOT_WINDOWS, "not running on Windows")
    try:
        listed = list(access.enum_store(store))
    except (OSError, ssl.SSLError) as error:
        return _all_undetermined(location, kind, entries, Reason.STORE_UNREADABLE, type(error).__name__)
    certs: list[tuple[CertInfo, int | None]] = []
    unparsed: list[bytes] = []
    for der, encoding, _trust in listed:
        try:
            if encoding != "x509_asn":
                raise DerError(f"encoding {encoding}")
            certs.append((parse_certificate(der), None))
        except DerError:
            unparsed.append(der)
    details: JSONObject = {"certs": len(certs), "malformed": len(unparsed)}
    items = _judge_collection(location, kind, entries, certs, unparsed, len(unparsed), details)
    sha1_of = {cert.sha256.hex(): cert.sha1 for cert, _offset in certs}
    sha1_of.update({hashlib.sha256(raw).hexdigest(): hashlib.sha1(raw).digest() for raw in unparsed})
    looked_up: dict[bytes, JSONObject] = {}  # one lookup per certificate, shared by its matches

    def with_keys(match: JSONObject) -> JSONObject:
        sha1 = sha1_of[str(match["cert_sha256"])]
        if sha1 not in looked_up:
            looked_up[sha1] = _registry_keys(kind, sha1, access)
        return {**match, "cert_sha1": sha1.hex(), **looked_up[sha1]}

    return [replace(item, matches=tuple(with_keys(match) for match in item.matches)) for item in items]


def audit_windows(entries: Sequence[DistrustEntry], access: WindowsAccess) -> list[RootsItem]:
    return (
        audit_ctl(LocationKind.AUTHROOT_CTL, AUTHROOT_VALUE, entries, access)
        + audit_store(LocationKind.ROOT_STORE, "ROOT", entries, access)
        + audit_ctl(LocationKind.DISALLOWED_CTL, DISALLOWED_VALUE, entries, access)
        + audit_store(LocationKind.DISALLOWED_STORE, "Disallowed", entries, access)
    )


# --- document --------------------------------------------------------------------


def roots_document(
    items: Sequence[RootsItem], entries: Sequence[DistrustEntry], generated: datetime.datetime | None = None
) -> JSONObject:
    when = generated if generated is not None else datetime.datetime.now().astimezone()
    tally: dict[str, dict[str, int]] = {
        role.value: {"found": 0, "not_found": 0, "undetermined": 0} for role in Role
    }
    for item in items:
        bucket = tally[item.role.value]
        if isinstance(item.verdict, Found):
            bucket["found"] += 1
        elif isinstance(item.verdict, NotFound):
            bucket["not_found"] += 1
        else:
            bucket["undetermined"] += 1
    counts: JSONObject = {"items": len(items)}
    for role, bucket in tally.items():
        counts[role] = dict(bucket)
    return {
        "tool": "patchwait",
        "schema": SCHEMA,
        "generated": when.isoformat(timespec="seconds"),
        "check": "roots",
        "distrust": [entry.to_json() for entry in entries],
        "counts": counts,
        "items": [item.to_json() for item in items],
    }


def trust_found(items: Sequence[RootsItem]) -> bool:
    return any(item.role is Role.TRUST and isinstance(item.verdict, Found) for item in items)
