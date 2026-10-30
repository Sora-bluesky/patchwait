"""Offline KEV and JVN RSS matching against ScanMux's append-only intel store.

Only bounded, locally checked files are opened. A usable catalog is a Found;
only that catalog can produce NotFound for a CVE. Damaged or absent evidence
stays Undetermined. URLs below identify records; they are never fetched.
"""

from __future__ import annotations

import calendar
import datetime
import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar, cast

from patchwait.locality import Locality, local_path_check
from patchwait.model import Check, Found, JSONObject, NotFound, Reason, Undetermined, is_cve_id
from patchwait.reparse import is_reparse_point

MAX_ATTEMPT_BYTES = 64 * 1024
MAX_KEV_BYTES = 16 * 1024 * 1024
_SCHEMA = "scanmux.intel-attempt/v1"
_ATTEMPT_NAME = re.compile(
    r"([0-9]{8}T[0-9]{9}Z)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json"
)
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}):([0-9]{2})"
    r"(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(?:Z|([+-])([0-9]{2}):([0-9]{2}))"
)
_FAIL_REASONS = frozenset({"http_status", "network", "timeout", "byte_limit", "url_mismatch", "schema_drift"})
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_TERMS = "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt"
T = TypeVar("T")
_PARSE_LIMIT_DETAIL = "patchwait could not parse a copy ScanMux may accept (JSON nesting limit)"


class IntelInputError(Exception):
    """An invalid store argument or layout; maps to exit 2."""


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise ValueError(detail)


def _object(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "expected object")
    return cast(dict[str, object], value)


def _keys(data: dict[str, object], *keys: str) -> None:
    _require(set(data) == set(keys), "unexpected keys")


def _integer(value: object) -> bool:
    """Number.isSafeInteger, including JSON numbers written as 200.0 or 2e2."""
    return (type(value) in (int, float) and isinstance(value, (int, float))
            and abs(value) <= 9_007_199_254_740_991 and math.isfinite(value) and int(value) == value)


def _text(value: object, limit: int | None = None, *, empty: bool = False) -> str:
    _require(isinstance(value, str), "expected text")
    text = cast(str, value)
    # JS strings may contain lone surrogates; string.length counts UTF-16 units.
    _require((empty or bool(text)) and (limit is None or len(text.encode("utf-16-le", errors="surrogatepass")) // 2 <= limit),
             "text length")
    return text


def _day_number(value: str) -> int:
    _require(_DAY.fullmatch(value) is not None, "invalid day")
    year, month, day = (int(part) for part in value.split("-"))
    _require(1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1], "invalid day")
    # JS accepts year 0000, which datetime.date cannot represent.
    if year == 0:
        return -365 + sum(calendar.monthrange(0, m)[1] for m in range(1, month)) + day - 1
    return datetime.date(year, month, day).toordinal()


def _timestamp(value: object) -> str:
    text = _text(value)
    match = _TIMESTAMP.fullmatch(text)
    _require(match is not None, "invalid timestamp")
    assert match is not None
    _day_number(match[1])
    _require(all(int(match[i] or 0) <= limit for i, limit in ((2, 23), (3, 59), (4, 59), (7, 23), (8, 59))),
             "invalid timestamp")
    return text


def _timestamp_ms(text: str) -> int:
    """Date.parse of a checked timestamp: fractions below a millisecond are dropped."""
    match = _TIMESTAMP.fullmatch(_timestamp(text))
    assert match is not None
    offset = (int(match[7]) * 60 + int(match[8])) * 60_000 * (1 if match[6] == "+" else -1) if match[6] else 0
    return (_day_number(match[1]) * 86_400_000 + int(match[2]) * 3_600_000 + int(match[3]) * 60_000
            + int(match[4] or 0) * 1000 + int((match[5] or "").ljust(3, "0")[:3]) - offset)


def _time(value: object) -> int:
    text = _text(value)
    _require(_TIME.fullmatch(text) is not None, "invalid attempt timestamp")
    day = _day_number(text[:10])
    hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
    _require(hour <= 23 and minute <= 59 and second <= 59, "invalid attempt timestamp")
    return day * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000 + int(text[20:23])


def _now_ms(now: datetime.datetime) -> int:
    utc = now.astimezone(datetime.timezone.utc)
    return (utc.toordinal() * 86_400_000 + utc.hour * 3_600_000 + utc.minute * 60_000
            + utc.second * 1000 + utc.microsecond // 1000)


def _json(body: bytes) -> object:
    def reject_constant(name: str) -> object:
        raise ValueError(f"not JSON: {name}")

    # TextDecoder removes one leading BOM; JSON.parse keeps the last duplicate
    # key and accepts escaped lone surrogates, but not NaN or Infinity tokens.
    # JSON.parse reads all numbers as doubles, including very long integers.
    return json.loads(body.decode("utf-8-sig", errors="strict"), parse_int=float, parse_constant=reject_constant)


@dataclass(frozen=True, slots=True)
class KevEntry:
    date_added: str
    due_date: str
    ransomware: str | None

    def to_json(self) -> JSONObject:
        ransomware = (self.ransomware.encode("utf-16-le", errors="surrogatepass").decode("utf-16-le", errors="replace")
                      if self.ransomware is not None else None)
        return {"dateAdded": self.date_added, "dueDate": self.due_date,
                "knownRansomwareCampaignUse": ransomware}


@dataclass(frozen=True, slots=True)
class KevCatalog:
    version: str
    released: str
    entries: dict[str, KevEntry]


def parse_kev(body: bytes) -> KevCatalog:
    """Port ScanMux parseKev's known-field rules; unknown catalog fields are allowed."""
    _require(len(body) <= MAX_KEV_BYTES, "KEV byte limit")
    top = _object(_json(body))
    raw = top.get("vulnerabilities")
    _require(isinstance(raw, list), "vulnerabilities must be an array")
    items = cast(list[object], raw)
    count = top.get("count")
    _require(_integer(count) and count == len(items), "count mismatch")
    version = _text(top.get("catalogVersion"))
    _require(re.fullmatch(r"[0-9A-Za-z._-]{1,64}", version) is not None, "invalid catalogVersion")
    released = _timestamp(top.get("dateReleased"))
    entries: dict[str, KevEntry] = {}
    known: dict[str, tuple[str | None, ...]] = {}
    for raw_item in items:
        item = _object(raw_item)
        cve = item.get("cveID")
        _require(is_cve_id(cve), "invalid CVE ID")
        cve = cast(str, cve)
        texts = tuple(_text(item.get(key), 4096) for key in
                      ("vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction"))
        added, due = _text(item.get("dateAdded")), _text(item.get("dueDate"))
        _day_number(added)
        _day_number(due)
        ransomware = _text(item["knownRansomwareCampaignUse"], empty=True) if "knownRansomwareCampaignUse" in item else None
        full = (*texts, added, due, ransomware)
        _require(cve not in known or known[cve] == full, "conflicting duplicate CVE")
        known[cve] = full
        entries[cve] = KevEntry(added, due, ransomware)
    return KevCatalog(version, released, entries)


# --- JVN RSS (a port of ScanMux parseJvnRss) -------------------------------------

MAX_JVN_BYTES = 1024 * 1024
_JVN_ITEMS = 1000  # ScanMux's bound on a broken or hostile body; the window holds about 20
# JS \s and String.prototype.trim: WhiteSpace and LineTerminator, which differ from Python's.
_JS_SPACE = ("\t\n\x0b\x0c\r              "
             "    　﻿")
_S = f"[{_JS_SPACE}]"
_NOT_XML_CHAR = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")
_ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}
_QUALIFIED = r"[A-Za-z_][A-Za-z0-9_.-]*(?::[A-Za-z_][A-Za-z0-9_.-]*)?"
_ATTRIBUTE = f"{_S}+([A-Za-z_][A-Za-z0-9_.:-]*){_S}*={_S}*(?:\"([^\"<]*)\"|'([^'<]*)')"
_START_TAG = re.compile(f"<({_QUALIFIED})((?:{_ATTRIBUTE})*){_S}*(?P<empty>/?)>")
_ATTRIBUTES = re.compile(_ATTRIBUTE)
_END_TAG = re.compile(f"</({_QUALIFIED}){_S}*>")
_DECLARATION = re.compile(f"﻿?<\\?xml{_S}[^<>?]*\\?>")
_JVN_FIELDS = ("title", "link", "description", "dc:identifier", "dc:date", "dcterms:issued", "dcterms:modified")
_JVN_ID = re.compile(r"JVN[A-Z]*#[0-9A-Za-z-]{1,32}")
_JVN_LINK = re.compile(r"https://jvn\.jp/[\x21-\x7e]{1,500}")
_JVN_CVE = re.compile(r"(?<![A-Za-z0-9_-])CVE-[0-9]{4}-[0-9]{4,}(?![A-Za-z0-9_-])", re.IGNORECASE | re.ASCII)
_DRIFT = "JVN RSS does not match ScanMux's reader"


def _js_trim(text: str) -> str:
    return text.strip(_JS_SPACE)


def _xml_decode(raw: str) -> str:
    def entity(match: re.Match[str]) -> str:
        name = match[1]
        _require(name is not None, _DRIFT)
        assert name is not None
        if name in _ENTITIES:
            return _ENTITIES[name]
        hexadecimal = re.fullmatch(r"#x([0-9a-fA-F]{1,6})", name)
        decimal = re.fullmatch(r"#([0-9]{1,7})", name)
        point = int(hexadecimal[1], 16) if hexadecimal else int(decimal[1]) if decimal else -1
        _require(0 < point <= 0x10FFFF, _DRIFT)
        character = chr(point)
        _require(_NOT_XML_CHAR.search(character) is None, _DRIFT)
        return character

    return re.sub(r"&([^;&]{0,12});|&", entity, raw)


@dataclass(slots=True)
class _Element:
    name: str
    children: list[_Element]
    text: str


def _xml_root(source: str) -> tuple[_Element, int]:
    _require(_NOT_XML_CHAR.search(source) is None, _DRIFT)
    top = _Element("", [], "")
    stack = [top]
    declaration = _DECLARATION.match(source)
    index = declaration.end() if declaration else (1 if source.startswith("﻿") else 0)
    items = 0
    while index < len(source):
        opening = source.find("<", index)
        text = source[index:] if opening < 0 else source[index:opening]
        parent = stack[-1]
        if len(stack) == 1:
            _require(not _js_trim(text), _DRIFT)
        else:
            parent.text += _xml_decode(text)
        if opening < 0:
            break
        index = opening
        if source.startswith("<!--", index):
            close = source.find("-->", index + 4)
            body = source[index + 4:close]
            _require(close >= 0 and "--" not in body and not body.endswith("-"), _DRIFT)
            index = close + 3
            continue
        if source.startswith("<![CDATA[", index):
            close = source.find("]]>", index + 9)
            _require(len(stack) > 1 and close >= 0, _DRIFT)
            parent.text += source[index + 9:close]
            index = close + 3
            continue
        end = _END_TAG.match(source, index)
        if end:
            _require(len(stack) > 1 and parent.name == end[1], _DRIFT)
            stack.pop()
            index = end.end()
            continue
        start = _START_TAG.match(source, index)
        _require(start is not None and (len(stack) > 1 or not top.children), _DRIFT)
        assert start is not None
        names: list[str] = []
        for attribute in _ATTRIBUTES.finditer(start[2]):
            _xml_decode(attribute[2] if attribute[2] is not None else attribute[3])
            names.append(attribute[1])
        _require(len(set(names)) == len(names), _DRIFT)
        element = _Element(start[1], [], "")
        if element.name == "item":
            items += 1
            _require(items <= _JVN_ITEMS, _DRIFT)
        parent.children.append(element)
        if not start["empty"]:
            stack.append(element)
        index = start.end()
    _require(len(stack) == 1 and len(top.children) == 1 and top.children[0].name == "rdf:RDF", _DRIFT)
    return top.children[0], items


def _xml_fields(element: _Element | None) -> dict[str, str]:
    found: dict[str, str] = {}
    for child in element.children if element is not None else []:
        if child.name not in _JVN_FIELDS:
            continue
        _require(child.name not in found and not child.children, _DRIFT)
        found[child.name] = _js_trim(child.text)
    return found


def _rss_time(fields: dict[str, str]) -> str | None:
    """``dcterms:modified``, or ``dc:date`` only when that field is absent; None unless a real timestamp."""
    value = fields["dcterms:modified"] if "dcterms:modified" in fields else fields.get("dc:date")
    try:
        return _timestamp(value) if value is not None else None
    except ValueError:
        return None


def _cve_token(token: str) -> str | None:
    cve = _js_trim(token).upper()
    return cve if len(token) <= 64 and is_cve_id(cve) else None


@dataclass(frozen=True, slots=True)
class JvnItem:
    identifier: str
    link: str
    modified: str
    cves: tuple[str, ...]

    def to_json(self) -> JSONObject:
        return {"identifier": self.identifier, "link": self.link, "modified": self.modified}


@dataclass(frozen=True, slots=True)
class JvnWindow:
    modified: str | None
    items: tuple[JvnItem, ...]
    oldest: str
    newest: str


def parse_jvn_rss(body: bytes) -> JvnWindow:
    """Read the recent-update RSS as ScanMux does: strict XML, required item fields, whole-token CVE IDs."""
    _require(len(body) <= MAX_JVN_BYTES, "JVN byte limit")  # ScanMux applies this as the feed download limit
    try:
        source = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(_DRIFT) from None
    if source.startswith("﻿"):  # TextDecoder removes one leading BOM
        source = source[1:]
    root, total = _xml_root(source)
    blocks = [child for child in root.children if child.name == "item"]
    _require(0 < len(blocks) == total, _DRIFT)
    items: list[JvnItem] = []
    for block in blocks:
        found = _xml_fields(block)
        identifier, link, title = found.get("dc:identifier"), found.get("link"), found.get("title")
        modified = _rss_time(found)
        _require(identifier is not None and _JVN_ID.fullmatch(identifier) is not None and title is not None
                 and modified is not None and link is not None and _JVN_LINK.fullmatch(link) is not None, _DRIFT)
        assert identifier is not None and link is not None and modified is not None
        text = f"{title}\n{found.get('description', '')}"
        cves = {_cve_token(match[0]) for match in _JVN_CVE.finditer(text)}
        items.append(JvnItem(identifier, link, modified, tuple(sorted(cve for cve in cves if cve is not None))))
    channel = next((child for child in root.children if child.name == "channel"), None)
    ordered = sorted((item.modified for item in items), key=_timestamp_ms)
    return JvnWindow(_rss_time(_xml_fields(channel)), tuple(items), ordered[0], ordered[-1])


@dataclass(frozen=True, slots=True)
class Attempt:
    completed: str
    at: int
    feed: str
    outcome: dict[str, object]
    name: str


def _status(value: object) -> bool:
    return value is None or (_integer(value) and 100 <= cast(int, value) <= 599)


def _outcome(value: object, feed: str) -> dict[str, object]:
    data = _object(value)
    kind = data.get("kind")
    if kind == "stored" and feed != "jvndb":
        _keys(data, "kind", "httpStatus", "contentType", "bytes", "sha256", "source")
        _require(_integer(data["httpStatus"]) and data["httpStatus"] == 200, "invalid HTTP status")
        content = data["contentType"]
        _require(content is None or (isinstance(content, str) and re.fullmatch(r"[\x20-\x7e]{1,200}", content) is not None),
                 "invalid contentType")
        size = data["bytes"]
        limit = MAX_KEV_BYTES if feed == "kev" else 1024 * 1024
        _require(_integer(size) and 0 < cast(int, size) <= limit, "invalid blob size")
        digest = data["sha256"]
        _require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) is not None, "invalid digest")
        source = _object(data["source"])
        _keys(source, "version", "date")
        for value in source.values():
            if value is not None:
                _text(value, 64, empty=True)
    elif kind == "failed":
        _keys(data, "kind", "reason", "httpStatus")
        _require(isinstance(data["reason"], str) and data["reason"] in _FAIL_REASONS and _status(data["httpStatus"]),
                 "invalid failure")
    elif kind == "unsupported" and feed == "jvndb":
        _keys(data, "kind", "httpStatus")
        _require(_integer(data["httpStatus"]) and data["httpStatus"] == 200, "invalid HTTP status")
    else:
        raise ValueError("invalid outcome")
    return data


def _attempt(data: dict[str, object], name: str, now: int) -> Attempt:
    _keys(data, "schema", "feed", "url", "termsUrl", "startedAt", "completedAt", "outcome")
    _require(data["schema"] == _SCHEMA, "unknown schema")
    feed = data["feed"]
    _require(isinstance(feed, str) and feed in ("kev", "jvn", "jvndb"), "invalid feed")
    feed = cast(str, feed)
    started, completed = _time(data["startedAt"]), _time(data["completedAt"])
    start_text, end_text = str(data["startedAt"]), str(data["completedAt"])
    _require(started <= completed <= now, "unverified clock")
    stamp = start_text.translate(str.maketrans("", "", "-:."))
    _require(name[:19] == stamp, "filename timestamp mismatch")
    url, terms = {
        "kev": (_KEV_URL, _KEV_TERMS),
        "jvn": ("https://jvn.jp/rss/jvn.rdf", None),
        "jvndb": (f"https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_{start_text[:4]}.rdf", None),
    }[feed]
    _require(data["url"] == url and data["termsUrl"] == terms, "feed URL mismatch")
    return Attempt(end_text, completed, feed, _outcome(data["outcome"], feed), name)


def _local(path: str) -> Locality:
    check = local_path_check(path)
    _require(check.problem is None, "path is not verified local")
    _require(not check.chain and not is_reparse_point(Path(path)), "store paths must not traverse reparse points")
    return check


def _bounded_read(path: str, limit: int) -> bytes:
    before = _local(path)
    with open(path, "rb") as handle:
        info = os.fstat(handle.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "file type or byte limit")
        body = handle.read(limit + 1)
    _require(len(body) <= limit and _local(path) == before, "file changed or byte limit")
    return body


def _store(path: str) -> None:
    try:
        _require(os.path.isabs(path), "store must be an absolute path")
        _require(os.path.abspath(path) == path and os.path.normpath(path) == path, "store path must be normalized")
        _require(os.path.dirname(path) != path, "store must not be a drive root")
        _local(path)
        _require(os.path.isdir(path), "store must be a directory")
        _require(set(os.listdir(path)) == {"attempts", "blobs"}, "store must contain only attempts and blobs")
        for name in ("attempts", "blobs"):
            child = os.path.join(path, name)
            _local(child)
            _require(os.path.isdir(child), "store children must be directories")
    except (OSError, ValueError) as error:
        raise IntelInputError(f"--intel-store: invalid store ({error})") from None


def _blob(store: str, attempt: Attempt) -> bytes:
    outcome = attempt.outcome
    size, digest = int(cast(int, outcome["bytes"])), cast(str, outcome["sha256"])
    body = _bounded_read(os.path.join(store, "blobs", digest), size)
    _require(len(body) == size and hashlib.sha256(body).hexdigest() == digest, "blob size or SHA-256 mismatch")
    return body


def _same_source(attempt: Attempt, version: str | None, date: str | None) -> None:
    _require(list(_object(attempt.outcome["source"]).items()) == [("version", version), ("date", date)],
             "source mismatch")


def _kev_generation(store: str, attempt: Attempt) -> KevCatalog:
    catalog = parse_kev(_blob(store, attempt))
    _same_source(attempt, catalog.version, catalog.released)
    return catalog


def _jvn_generation(store: str, attempt: Attempt) -> JvnWindow:
    window = parse_jvn_rss(_blob(store, attempt))
    _same_source(attempt, None, window.modified)
    return window


@dataclass(frozen=True, slots=True)
class Copy(Generic[T]):
    """The copy of one feed that was used, or why none could be."""

    data: Check[T]
    completed_at: str | None
    days_since_fetch: int | None
    latest_attempt: str
    invalid_attempts: int

    def header(self) -> JSONObject:
        encoded: JSONObject = {"completedAt": self.completed_at, "days_since_fetch": self.days_since_fetch,
                               "latest_attempt": self.latest_attempt, "invalid_attempts": self.invalid_attempts}
        if isinstance(self.data, Undetermined):
            encoded.update({"result": "undetermined", "reason": self.data.reason.value, "detail": self.data.detail})
        return encoded


def _undetermined_json(check: Undetermined) -> JSONObject:
    return {"result": "undetermined", "reason": check.reason.value, "detail": check.detail}


@dataclass(frozen=True, slots=True)
class Intel:
    store: str
    kev: Copy[KevCatalog]
    jvn: Copy[JvnWindow]

    def kev_check(self, cve: str) -> Check[KevEntry]:
        if isinstance(self.kev.data, Undetermined):
            return self.kev.data
        if isinstance(self.kev.data, NotFound):
            return Undetermined(Reason.SOURCE_MISSING, "no usable KEV copy")
        entry = self.kev.data.value.entries.get(cve)
        return NotFound() if entry is None else Found(entry)

    def kev_to_json(self, cve: str) -> JSONObject:
        check = self.kev_check(cve)
        if isinstance(check, Found):
            return {"result": "listed", **check.value.to_json()}
        if isinstance(check, NotFound):
            return {"result": "not_listed"}
        return _undetermined_json(check)

    def jvn_check(self, cve: str) -> Check[list[JvnItem]]:
        """Found: the window items that name ``cve``. NotFound means only "not in this window"."""
        if isinstance(self.jvn.data, Undetermined):
            return self.jvn.data
        if isinstance(self.jvn.data, NotFound):
            return Undetermined(Reason.SOURCE_MISSING, "no usable JVN RSS copy")
        items = [item for item in self.jvn.data.value.items if cve in item.cves]
        return Found(items) if items else NotFound()

    def jvn_to_json(self, cve: str) -> JSONObject:
        check = self.jvn_check(cve)
        if isinstance(check, Found):
            return {"result": "observed", "items": [item.to_json() for item in check.value]}
        if isinstance(check, NotFound):
            assert isinstance(self.jvn.data, Found)
            window = self.jvn.data.value
            return {"result": "not_observed_in_window", "oldest": window.oldest, "newest": window.newest,
                    "items": len(window.items)}
        return _undetermined_json(check)

    def to_json(self) -> JSONObject:
        catalog = self.kev.data.value if isinstance(self.kev.data, Found) else None
        window = self.jvn.data.value if isinstance(self.jvn.data, Found) else None
        return {
            "store": self.store,
            "kev": {"catalogVersion": catalog.version if catalog else None,
                    "dateReleased": catalog.released if catalog else None, **self.kev.header()},
            "jvn": {"modified": window.modified if window else None, "oldest": window.oldest if window else None,
                    "newest": window.newest if window else None, "items": len(window.items) if window else None,
                    **self.jvn.header()},
        }


def _select(
    store: str, attempts: list[Attempt], read: Callable[[str, Attempt], T], label: str, clock: int,
    invalid: int, malformed: bool, blocked: Undetermined | None,
) -> Copy[T]:
    """The newest stored copy that reads back; a damaged copy falls back to the one before it."""
    attempts = sorted(attempts, key=lambda attempt: (attempt.at, attempt.outcome["kind"] == "failed", attempt.name),
                      reverse=True)
    latest = str(attempts[0].outcome["kind"]) if attempts else "none"
    if blocked is not None:
        return Copy(blocked, None, None, latest, invalid)
    for attempt in attempts:
        if attempt.outcome["kind"] != "stored":
            continue
        try:
            data = read(store, attempt)
            return Copy(Found(data), attempt.completed, (clock - attempt.at) // 86_400_000, latest, invalid)
        except RecursionError:
            return Copy(Undetermined(Reason.SOURCE_MALFORMED, _PARSE_LIMIT_DETAIL), None, None, latest, invalid + 1)
        except (OSError, ValueError):
            invalid += 1
            malformed = True
    reason = Reason.SOURCE_MALFORMED if malformed else Reason.SOURCE_MISSING
    return Copy(Undetermined(reason, f"no usable {label} copy"), None, None, latest, invalid)


def load_intel(store: str, now: datetime.datetime | None = None) -> Intel:
    """Read every matching attempt; select the newest usable KEV and JVN RSS generations.

    An invalid record counts against every feed. It makes a feed's result malformed rather
    than missing unless the record names a different feed.
    """
    _store(store)
    clock = _now_ms(now if now is not None else datetime.datetime.now(datetime.timezone.utc))
    invalid = 0
    kev_malformed = False
    jvn_malformed = False
    unknown_schema = False
    parse_limit = False
    attempts: dict[str, list[Attempt]] = {"kev": [], "jvn": [], "jvndb": []}
    try:
        _local(os.path.join(store, "attempts"))
        names = os.listdir(os.path.join(store, "attempts"))
    except (OSError, ValueError):
        unreadable = Undetermined(Reason.SOURCE_MALFORMED, "cannot read attempts")
        return Intel(store, Copy(unreadable, None, None, "none", 0), Copy(unreadable, None, None, "none", 0))
    for name in names:
        if _ATTEMPT_NAME.fullmatch(name) is None:
            continue
        feed: object = None
        try:
            data = _object(_json(_bounded_read(os.path.join(store, "attempts", name), MAX_ATTEMPT_BYTES)))
            feed = data.get("feed")
            if "schema" in data and data["schema"] != _SCHEMA:
                unknown_schema = True
            attempt = _attempt(data, name, clock)
            attempts[attempt.feed].append(attempt)
        except RecursionError:
            invalid += 1
            parse_limit = True
        except (OSError, ValueError):
            invalid += 1
            if feed not in ("jvn", "jvndb"):
                kev_malformed = True
            if feed not in ("kev", "jvndb"):
                jvn_malformed = True
    blocked: Undetermined | None = None
    if parse_limit:
        blocked = Undetermined(Reason.SOURCE_MALFORMED, _PARSE_LIMIT_DETAIL)
    elif unknown_schema:
        blocked = Undetermined(Reason.SOURCE_MALFORMED, "unknown schema in attempt record")
    return Intel(
        store,
        _select(store, attempts["kev"], _kev_generation, "KEV", clock, invalid, kev_malformed, blocked),
        _select(store, attempts["jvn"], _jvn_generation, "JVN RSS", clock, invalid, jvn_malformed, blocked),
    )
