"""Data model: three-valued check results, inventory components, matches and ledger items.

Every check is ``Found[T] | NotFound | Undetermined``. Invalid combinations
("found but with a reason", "undetermined without a reason") cannot be built:
the dataclasses are frozen and ``__post_init__`` rejects empty values.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeAlias, TypeVar, Union

T = TypeVar("T")

JSONValue: TypeAlias = Union[
    str, int, float, bool, None, list["JSONValue"], dict[str, "JSONValue"]
]
JSONObject: TypeAlias = dict[str, JSONValue]


class Reason(StrEnum):
    """Why a check could not be determined."""

    # File side
    FILE_UNREADABLE = "file_unreadable"
    NOT_PE = "not_pe"
    NO_VERSION_RESOURCE = "no_version_resource"
    MALFORMED_VERSION_RESOURCE = "malformed_version_resource"
    VERSION_MISMATCH = "version_mismatch"
    UNEXPECTED_PRODUCT = "unexpected_product"
    TARGET_MISSING = "target_missing"
    DUPLICATE_KEY = "duplicate_key"
    # Trust store side
    STORE_UNREADABLE = "store_unreadable"
    MALFORMED_CTL = "malformed_ctl"
    MALFORMED_KEYSTORE = "malformed_keystore"
    KEYSTORE_UNREADABLE = "keystore_unreadable"
    MALFORMED_CERT = "malformed_cert"
    NO_CERTS_RECOGNISED = "no_certs_recognised"
    NO_USABLE_IDENTIFIER = "no_usable_identifier"
    NOT_WINDOWS = "not_windows"
    # Comparison side
    NO_BASELINE = "no_baseline"
    # Source side
    SOURCE_MISSING = "source_missing"
    SOURCE_AUTH_EXPIRED = "source_auth_expired"
    SOURCE_HTTP_ERROR = "source_http_error"
    SOURCE_RATE_LIMITED = "source_rate_limited"
    SOURCE_UNREACHABLE = "source_unreachable"
    SOURCE_MALFORMED = "source_malformed"


def _is_empty(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (tuple, list, frozenset, set, dict)):
        return len(value) == 0  # pyright: ignore[reportUnknownArgumentType]
    return False


def _require_text(owner: str, field: str, value: object) -> None:
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{owner}.{field} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class Found(Generic[T]):
    """The thing was found; ``value`` is never empty."""

    value: T

    def __post_init__(self) -> None:
        if _is_empty(self.value):
            raise ValueError("Found.value must not be empty")


@dataclass(frozen=True, slots=True)
class NotFound:
    """The thing was looked for and is definitely absent."""


@dataclass(frozen=True, slots=True)
class Undetermined:
    """The check could not be completed. Never to be read as "not found"."""

    reason: Reason
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, Reason):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Undetermined.reason must be a Reason")
        _require_text("Undetermined", "detail", self.detail)


Check: TypeAlias = Union[Found[T], NotFound, Undetermined]


class RuntimeKind(StrEnum):
    NODE = "node"
    PYTHON = "python"


@dataclass(frozen=True, slots=True)
class Component:
    """An inventory item: a runtime found at ``location``."""

    kind: RuntimeKind
    location: str
    version: Found[str] | Undetermined
    evidence: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RuntimeKind):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Component.kind must be a RuntimeKind")
        _require_text("Component", "location", self.location)
        _require_text("Component", "evidence", self.evidence)
        if not isinstance(self.version, (Found, Undetermined)):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Component.version must be Found[str] or Undetermined")
        if isinstance(self.version, Found):
            _require_text("Component", "version.value", self.version.value)


@dataclass(frozen=True, slots=True)
class Match:
    """Result of matching one component against one source."""

    component: Component
    source: str
    advisories: Check[tuple[str, ...]]

    def __post_init__(self) -> None:
        _require_text("Match", "source", self.source)
        if isinstance(self.advisories, Found):
            ids: object = self.advisories.value
            if not isinstance(ids, tuple):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise TypeError("Match.advisories must hold a tuple of IDs")
            for advisory_id in ids:  # pyright: ignore[reportUnknownVariableType]
                _require_text("Match", "advisories[]", advisory_id)
        elif not isinstance(self.advisories, (NotFound, Undetermined)):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Match.advisories must be a Check")


@dataclass(frozen=True, slots=True)
class WaitingOnVendor:
    vendor: str

    def __post_init__(self) -> None:
        _require_text("WaitingOnVendor", "vendor", self.vendor)


@dataclass(frozen=True, slots=True)
class InProgress:
    owner: str

    def __post_init__(self) -> None:
        _require_text("InProgress", "owner", self.owner)


@dataclass(frozen=True, slots=True)
class AwaitingDecision:
    question: str

    def __post_init__(self) -> None:
        _require_text("AwaitingDecision", "question", self.question)


@dataclass(frozen=True, slots=True)
class Done:
    resolution: str

    def __post_init__(self) -> None:
        _require_text("Done", "resolution", self.resolution)


LedgerStatus: TypeAlias = Union[WaitingOnVendor, InProgress, AwaitingDecision, Done]


@dataclass(frozen=True, slots=True)
class ScanLink:
    """Links a ledger item to the ``scan`` row with this ``kind`` and ``path``, compared exactly."""

    kind: RuntimeKind
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RuntimeKind):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("ScanLink.kind must be a RuntimeKind")
        _require_text("ScanLink", "path", self.path)


@dataclass(frozen=True, slots=True)
class RootsLink:
    """Links a ledger item to the ``roots`` row with these three fields, compared exactly."""

    location_kind: str
    location: str
    distrust: str

    def __post_init__(self) -> None:
        _require_text("RootsLink", "location_kind", self.location_kind)
        _require_text("RootsLink", "location", self.location)
        _require_text("RootsLink", "distrust", self.distrust)


ResultLink: TypeAlias = Union[ScanLink, RootsLink]

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def is_cve_id(value: object) -> bool:
    """An exact ScanMux CVE ID: ASCII, uppercase, at most 64 characters."""
    return isinstance(value, str) and len(value) <= 64 and _CVE_ID.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class LedgerItem:
    id: str
    title: str
    status: LedgerStatus
    recheck_command: str
    last_checked: datetime.date
    last_result: Check[str]
    result_link: ResultLink | None = None  # which row of a saved scan/roots result this item follows
    cves: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        _require_text("LedgerItem", "id", self.id)
        _require_text("LedgerItem", "title", self.title)
        _require_text("LedgerItem", "recheck_command", self.recheck_command)
        if not isinstance(self.status, (WaitingOnVendor, InProgress, AwaitingDecision, Done)):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("LedgerItem.status must be a ledger status")
        if not isinstance(self.last_checked, datetime.date):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("LedgerItem.last_checked must be a date")
        if not isinstance(self.last_result, (Found, NotFound, Undetermined)):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("LedgerItem.last_result must be a Check")
        if self.result_link is not None and not isinstance(self.result_link, (ScanLink, RootsLink)):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("LedgerItem.result_link must be a ScanLink, a RootsLink or None")
        if self.cves is not None:
            if not isinstance(self.cves, tuple) or not self.cves or not all(is_cve_id(cve) for cve in self.cves):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ValueError("LedgerItem.cves must be a non-empty tuple of exact CVE IDs")
            if len(set(self.cves)) != len(self.cves):
                raise ValueError("LedgerItem.cves must not contain duplicates")


# --- JSON -------------------------------------------------------------------


def check_to_json(check: Check[T], encode: Callable[[T], JSONValue]) -> JSONObject:
    """Encode a check as ``{"result": "found" | "not_found" | "undetermined", ...}``."""
    if isinstance(check, Found):
        return {"result": "found", "value": encode(check.value)}
    if isinstance(check, NotFound):
        return {"result": "not_found"}
    return {"result": "undetermined", "reason": check.reason.value, "detail": check.detail}


def _encode_str(value: str) -> JSONValue:
    return value


def _encode_ids(value: tuple[str, ...]) -> JSONValue:
    return list(value)


def component_to_json(component: Component) -> JSONObject:
    return {
        "kind": component.kind.value,
        "location": component.location,
        "version": check_to_json(component.version, _encode_str),
        "evidence": component.evidence,
    }


def match_to_json(match: Match) -> JSONObject:
    return {
        "component": component_to_json(match.component),
        "source": match.source,
        "advisories": check_to_json(match.advisories, _encode_ids),
    }


def status_to_json(status: LedgerStatus) -> JSONObject:
    match status:
        case WaitingOnVendor(vendor=vendor):
            return {"state": "waiting_on_vendor", "vendor": vendor}
        case InProgress(owner=owner):
            return {"state": "in_progress", "owner": owner}
        case AwaitingDecision(question=question):
            return {"state": "awaiting_decision", "question": question}
        case Done(resolution=resolution):
            return {"state": "done", "resolution": resolution}


def result_link_to_json(link: ResultLink) -> JSONObject:
    match link:
        case ScanLink(kind=kind, path=path):
            return {"check": "scan", "kind": kind.value, "path": path}
        case RootsLink(location_kind=location_kind, location=location, distrust=distrust):
            return {"check": "roots", "location_kind": location_kind, "location": location, "distrust": distrust}


def ledger_item_to_json(item: LedgerItem) -> JSONObject:
    """``result_link`` is written only when the item has one, so items without it keep their shape."""
    encoded: JSONObject = {
        "id": item.id,
        "title": item.title,
        "status": status_to_json(item.status),
        "recheck_command": item.recheck_command,
        "last_checked": item.last_checked.isoformat(),
        "last_result": check_to_json(item.last_result, _encode_str),
    }
    if item.result_link is not None:
        encoded["result_link"] = result_link_to_json(item.result_link)
    if item.cves is not None:
        encoded["cves"] = list(item.cves)
    return encoded


# --- JSON back to the model (strict) -------------------------------------------

_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_LEDGER_ITEM_KEYS = frozenset({"id", "title", "status", "recheck_command", "last_checked", "last_result"})
_LINK_KEYS: dict[str, frozenset[str]] = {
    "scan": frozenset({"check", "kind", "path"}),
    "roots": frozenset({"check", "location_kind", "location", "distrust"}),
}
_KIND_VALUES = frozenset(kind.value for kind in RuntimeKind)
_STATUS_FIELDS: dict[str, tuple[str, Callable[[str], LedgerStatus]]] = {
    "waiting_on_vendor": ("vendor", WaitingOnVendor),
    "in_progress": ("owner", InProgress),
    "awaiting_decision": ("question", AwaitingDecision),
    "done": ("resolution", Done),
}
_RESULT_KEYS: dict[str, frozenset[str]] = {
    "found": frozenset({"result", "value"}),
    "not_found": frozenset({"result"}),
    "undetermined": frozenset({"result", "reason", "detail"}),
}
_REASON_VALUES = frozenset(reason.value for reason in Reason)


def _json_object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: must be an object")
    return {str(key): item for key, item in value.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]


def _exact_keys(data: dict[str, object], expected: frozenset[str], where: str) -> None:
    keys = frozenset(data)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        parts = ([f"missing {', '.join(missing)}"] if missing else []) + ([f"unknown {', '.join(extra)}"] if extra else [])
        raise ValueError(f"{where}: {'; '.join(parts)}")


def _json_text(value: object, where: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{where}: must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # a JSON escape such as "\ud800" decodes to a lone surrogate
        raise ValueError(f"{where}: must be valid Unicode (lone surrogate)") from None
    return value


def parse_iso_date(value: object, where: str) -> datetime.date:
    """``YYYY-MM-DD`` only: the basic and week forms that ``fromisoformat`` also takes are rejected."""
    if not isinstance(value, str) or _ISO_DATE.fullmatch(value) is None:
        raise ValueError(f"{where}: must be a date as YYYY-MM-DD")
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{where}: not a valid date: {value!r}") from None


def status_from_json(value: object, where: str = "status") -> LedgerStatus:
    data = _json_object(value, where)
    state = data.get("state")
    if not isinstance(state, str) or state not in _STATUS_FIELDS:
        raise ValueError(f"{where}.state: must be one of {', '.join(_STATUS_FIELDS)}")
    field, build = _STATUS_FIELDS[state]
    _exact_keys(data, frozenset({"state", field}), where)
    return build(_json_text(data[field], f"{where}.{field}"))


def text_check_from_json(value: object, where: str = "last_result") -> Check[str]:
    """Inverse of ``check_to_json`` for a check whose found value is a string."""
    data = _json_object(value, where)
    result = data.get("result")
    if not isinstance(result, str) or result not in _RESULT_KEYS:
        raise ValueError(f"{where}.result: must be one of {', '.join(_RESULT_KEYS)}")
    _exact_keys(data, _RESULT_KEYS[result], where)
    if result == "found":
        return Found(_json_text(data["value"], f"{where}.value"))
    if result == "not_found":
        return NotFound()
    reason = _json_text(data["reason"], f"{where}.reason")
    if reason not in _REASON_VALUES:
        raise ValueError(f"{where}.reason: unknown reason {reason!r}")
    return Undetermined(Reason(reason), _json_text(data["detail"], f"{where}.detail"))


def result_link_from_json(value: object, where: str = "result_link") -> ResultLink:
    """Inverse of ``result_link_to_json``. ``location_kind`` is checked against the roots names by the caller."""
    data = _json_object(value, where)
    check = data.get("check")
    if not isinstance(check, str) or check not in _LINK_KEYS:
        raise ValueError(f"{where}.check: must be one of {', '.join(_LINK_KEYS)}")
    _exact_keys(data, _LINK_KEYS[check], where)
    if check == "scan":
        kind = _json_text(data["kind"], f"{where}.kind")
        if kind not in _KIND_VALUES:
            raise ValueError(f"{where}.kind: must be one of {', '.join(sorted(_KIND_VALUES))}")
        return ScanLink(RuntimeKind(kind), _json_text(data["path"], f"{where}.path"))
    return RootsLink(
        _json_text(data["location_kind"], f"{where}.location_kind"),
        _json_text(data["location"], f"{where}.location"),
        _json_text(data["distrust"], f"{where}.distrust"),
    )


def ledger_item_from_json(value: object, where: str = "item") -> LedgerItem:
    """Inverse of ``ledger_item_to_json``. Exact keys (``result_link`` optional); raises ``ValueError`` naming the field."""
    data = _json_object(value, where)
    link = result_link_from_json(data.pop("result_link"), f"{where}.result_link") if "result_link" in data else None
    cves: tuple[str, ...] | None = None
    if "cves" in data:
        raw = data.pop("cves")
        if not isinstance(raw, list) or not raw:
            raise ValueError(f"{where}.cves: must be a non-empty list of exact CVE IDs")
        values: list[object] = list(raw)  # pyright: ignore[reportUnknownArgumentType]
        if not all(is_cve_id(cve) for cve in values):
            raise ValueError(f"{where}.cves: must contain exact CVE IDs")
        cves = tuple(str(cve) for cve in values)
        if len(set(cves)) != len(cves):
            raise ValueError(f"{where}.cves: duplicate CVE ID")
    _exact_keys(data, _LEDGER_ITEM_KEYS, where)
    return LedgerItem(
        id=_json_text(data["id"], f"{where}.id"),
        title=_json_text(data["title"], f"{where}.title"),
        status=status_from_json(data["status"], f"{where}.status"),
        recheck_command=_json_text(data["recheck_command"], f"{where}.recheck_command"),
        last_checked=parse_iso_date(data["last_checked"], f"{where}.last_checked"),
        last_result=text_check_from_json(data["last_result"], f"{where}.last_result"),
        result_link=link,
        cves=cves,
    )
