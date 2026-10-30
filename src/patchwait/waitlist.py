"""A waitlist: items waiting on a vendor fix, kept in a JSON file on the user's PC.

The file is ``{"tool": "patchwait", "schema": 1, "kind": "waitlist", "items": [...]}``
with each item in the ``ledger_item_to_json`` shape. It is read strictly: a
malformed file, an unknown state or reason, a future ``last_checked`` or a
duplicate id is rejected as a whole.

``show`` reports, per item, how many days have passed since the last check.
Only when a stale threshold is given does it mark items: an item that is not
``done`` and was last checked more than N days ago is stale. There is no
default N.

``record_from`` updates items from a saved ``scan`` or ``roots`` result. An
item follows the row named by its optional ``result_link``: for ``scan`` the
document's ``kind`` and the row's ``path``, for ``roots`` the row's
``location_kind``, ``location`` and ``distrust`` label, all compared as exact
strings. Nothing else is used to match, so an item without a link, or whose
row is absent or ambiguous, is left as it is and reported. The row's verdict
is copied as it is; an ``undetermined`` row stays ``undetermined``.

The recheck command is data. This module prints it and never runs it.
"""

from __future__ import annotations

import datetime
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from patchwait.intel import Intel

from patchwait.ledger import LedgerInputError, _code, _plain, render_document  # pyright: ignore[reportPrivateUsage]
from patchwait.model import (
    AwaitingDecision,
    Check,
    Done,
    Found,
    InProgress,
    JSONObject,
    JSONValue,
    LedgerItem,
    NotFound,
    Reason,
    ResultLink,
    RootsLink,
    RuntimeKind,
    ScanLink,
    Undetermined,
    WaitingOnVendor,
    ledger_item_from_json,
    ledger_item_to_json,
    parse_iso_date,
    text_check_from_json,
)
from patchwait.roots import LocationKind
from patchwait.scan import write_atomic

SCHEMA = 1
KIND = "waitlist"
STATES: tuple[str, ...] = ("waiting_on_vendor", "in_progress", "awaiting_decision", "done")
RESULTS: tuple[str, ...] = ("found", "not_found", "undetermined")
_FILE_KEYS = frozenset({"tool", "schema", "kind", "items"})
_REASONS = frozenset(reason.value for reason in Reason)
_DIGITS = re.compile(r"[0-9]+")
_LOCATION_KINDS = frozenset(kind.value for kind in LocationKind)
# Why ``record_from`` left an item as it was.
NO_RESULT_LINK = "no_result_link"
NOT_FOUND_IN_RESULT = "not_found_in_result"
AMBIGUOUS_IN_RESULT = "ambiguous_in_result"
CHECKED_AFTER_RESULT = "checked_after_result"


class WaitlistInputError(Exception):
    """Bad file or bad arguments. Maps to exit code 2."""


@dataclass(frozen=True, slots=True)
class Row:
    item: LedgerItem
    days_since_check: int
    stale: bool | None  # None when no threshold was given


# --- reading ---------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WaitlistInputError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> object:
    raise WaitlistInputError(f"not JSON: {name}")


def strict_json_loads(text: str) -> object:
    """JSON without duplicate object keys or non-finite constants."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)


def parse_date_arg(text: str, option: str) -> datetime.date:
    try:
        return parse_iso_date(text, option)
    except ValueError as error:
        raise WaitlistInputError(str(error)) from None


def parse_stale_days(text: str) -> int:
    """A non-negative decimal integer in ASCII digits (``int`` would also take ``+5``, `` 5`` and ``５``)."""
    if _DIGITS.fullmatch(text) is None:
        raise WaitlistInputError(f"--stale-days: must be a non-negative integer, not {text!r}")
    return int(text)


def items_from_document(document: object, today: datetime.date) -> list[LedgerItem]:
    if not isinstance(document, dict):
        raise WaitlistInputError("not a patchwait waitlist: must be an object")
    data: dict[str, object] = {str(key): value for key, value in document.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    if frozenset(data) != _FILE_KEYS:
        raise WaitlistInputError(f"not a patchwait waitlist: keys must be {', '.join(sorted(_FILE_KEYS))}")
    if data["tool"] != "patchwait" or data["kind"] != KIND:
        raise WaitlistInputError("not a patchwait waitlist: tool must be patchwait and kind waitlist")
    if type(data["schema"]) is not int or data["schema"] != SCHEMA:
        raise WaitlistInputError(f"unsupported schema {data['schema']!r} (expected {SCHEMA})")
    if not isinstance(data["items"], list):
        raise WaitlistInputError("items: must be a list")
    raw_items: list[object] = list(data["items"])  # pyright: ignore[reportUnknownArgumentType]
    items: list[LedgerItem] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_items):
        where = f"items[{index}]"
        try:
            item = ledger_item_from_json(raw, where)
        except (ValueError, TypeError) as error:
            raise WaitlistInputError(str(error)) from None
        if isinstance(item.result_link, RootsLink) and item.result_link.location_kind not in _LOCATION_KINDS:
            raise WaitlistInputError(
                f"{where}.result_link.location_kind: unknown location_kind {_plain(item.result_link.location_kind)!r}"
            )
        if item.id in seen:
            raise WaitlistInputError(f"{where}.id: duplicate id {item.id!r}")
        seen.add(item.id)
        if item.last_checked > today:
            raise WaitlistInputError(
                f"{where}.last_checked: {item.last_checked.isoformat()} is after today {today.isoformat()}"
            )
        items.append(item)
    return items


def _load_json(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise WaitlistInputError(f"{path}: cannot read: {type(error).__name__}") from None
    try:
        return strict_json_loads(text)
    except WaitlistInputError as error:
        raise WaitlistInputError(f"{path}: {error}") from None
    except ValueError as error:
        raise WaitlistInputError(f"{path}: not JSON: {error}") from None


def load_waitlist(path: str, today: datetime.date) -> list[LedgerItem]:
    document = _load_json(path)
    try:
        return items_from_document(document, today)
    except WaitlistInputError as error:
        raise WaitlistInputError(f"{path}: {error}") from None


# --- show ------------------------------------------------------------------------


def rows(items: Sequence[LedgerItem], today: datetime.date, stale_days: int | None) -> list[Row]:
    result: list[Row] = []
    for item in items:
        days = (today - item.last_checked).days
        stale = None if stale_days is None else (not isinstance(item.status, Done) and days > stale_days)
        result.append(Row(item, days, stale))
    return result


def any_stale(table: Sequence[Row]) -> bool:
    return any(row.stale for row in table)


def _state(item: LedgerItem) -> str:
    match item.status:
        case WaitingOnVendor():
            return "waiting_on_vendor"
        case InProgress():
            return "in_progress"
        case AwaitingDecision():
            return "awaiting_decision"
        case Done():
            return "done"


def _result(check: Check[str]) -> str:
    if isinstance(check, Found):
        return "found"
    if isinstance(check, NotFound):
        return "not_found"
    return "undetermined"


def show_document(
    items: Sequence[LedgerItem],
    today: datetime.date,
    stale_days: int | None,
    generated: datetime.datetime | None = None,
    intel: Intel | None = None,
) -> JSONObject:
    when = generated if generated is not None else datetime.datetime.now().astimezone()
    table = rows(items, today, stale_days)
    states = {state: 0 for state in STATES}
    results = {result: 0 for result in RESULTS}
    out_items: list[JSONValue] = []
    for row in table:
        states[_state(row.item)] += 1
        results[_result(row.item.last_result)] += 1
        encoded = ledger_item_to_json(row.item)
        encoded["days_since_check"] = row.days_since_check
        if row.stale is not None:
            encoded["stale"] = row.stale
        if intel is not None and row.item.cves is not None:
            encoded["kev"] = {cve: intel.kev_to_json(cve) for cve in row.item.cves}
            encoded["jvn"] = {cve: intel.jvn_to_json(cve) for cve in row.item.cves}
        out_items.append(encoded)
    counts: JSONObject = {"items": len(table), "state": dict(states), "last_result": dict(results)}
    if stale_days is not None:
        counts["stale"] = sum(1 for row in table if row.stale)
    document: JSONObject = {
        "tool": "patchwait",
        "schema": SCHEMA,
        "generated": when.isoformat(timespec="seconds"),
        "today": today.isoformat(),
        "stale_days": stale_days,
        "counts": counts,
        "items": out_items,
    }
    return document if intel is None else {"intel": intel.to_json(), **document}


def _status_md(item: LedgerItem) -> str:
    match item.status:
        case WaitingOnVendor(vendor=vendor):
            return f"vendor {_code(vendor)}"
        case InProgress(owner=owner):
            return f"owner {_code(owner)}"
        case AwaitingDecision(question=question):
            return f"question {_code(question)}"
        case Done(resolution=resolution):
            return f"resolution {_code(resolution)}"


def _result_md(check: Check[str]) -> str:
    if isinstance(check, Found):
        return f"found {_code(check.value)}"
    if isinstance(check, NotFound):
        return "not_found"
    return f"undetermined {check.reason.value}: {_code(check.detail)}"


def render_markdown(
    items: Sequence[LedgerItem], today: datetime.date, stale_days: int | None, intel: Intel | None = None
) -> str:
    """A summary line, then one line per item. Free text goes into code spans (see ``ledger``)."""
    table = rows(items, today, stale_days)
    states = {state: 0 for state in STATES}
    for row in table:
        states[_state(row.item)] += 1
    summary = f"{today.isoformat()}: patchwait waitlist: {len(table)} items (" + ", ".join(
        f"{state} {count}" for state, count in states.items()
    ) + ")"
    if stale_days is not None:
        summary += f"; stale {sum(1 for row in table if row.stale)} (more than {stale_days} days, not done)"
    lines = [summary, ""]
    if intel is not None:
        lines = [f"intel {_code(json.dumps(intel.to_json(), ensure_ascii=False))}", "", *lines]
    for row in table:
        item = row.item
        mark = "" if not row.stale else " — stale"
        lines.append(
            f"- {_state(item)}: {_code(item.id)} {_code(item.title)} — {_status_md(item)}"
            f" — last checked {item.last_checked.isoformat()} ({row.days_since_check} days){mark}"
            f" — last result {_result_md(item.last_result)}"
            f" — recheck {_code(item.recheck_command)}"
        )
        if intel is not None and item.cves is not None:
            for cve in item.cves:
                lines.append(f"  - {_code(cve)} kev {_code(json.dumps(intel.kev_to_json(cve), ensure_ascii=False))}")
                lines.append(f"  - {_code(cve)} jvn {_code(json.dumps(intel.jvn_to_json(cve), ensure_ascii=False))}")
    return "\n".join(lines) + "\n"


# --- record ----------------------------------------------------------------------


def check_from_args(result: str, value: str | None, reason: str | None, detail: str | None) -> Check[str]:
    """The three-valued result of ``record``, refusing options that do not belong to it."""
    if result == "found":
        if reason is not None or detail is not None:
            raise WaitlistInputError("--result found takes --value only, not --reason or --detail")
        if value is None or value.strip() == "":
            raise WaitlistInputError("--result found needs a non-empty --value")
        return Found(value)
    if result == "not_found":
        if value is not None or reason is not None or detail is not None:
            raise WaitlistInputError("--result not_found takes no --value, --reason or --detail")
        return NotFound()
    if result == "undetermined":
        if value is not None:
            raise WaitlistInputError("--result undetermined takes --reason and --detail, not --value")
        if reason is None or reason not in _REASONS:
            raise WaitlistInputError(f"--result undetermined needs --reason, one of: {', '.join(sorted(_REASONS))}")
        if detail is None or detail.strip() == "":
            raise WaitlistInputError("--result undetermined needs a non-empty --detail")
        return Undetermined(Reason(reason), detail)
    raise WaitlistInputError(f"--result must be one of {', '.join(RESULTS)}")


def waitlist_text(items: Sequence[LedgerItem]) -> str:
    document: JSONObject = {
        "tool": "patchwait",
        "schema": SCHEMA,
        "kind": KIND,
        "items": [ledger_item_to_json(item) for item in items],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def record(
    path: str, item_id: str, result: Check[str], when: datetime.date, today: datetime.date
) -> LedgerItem:
    """Set ``last_checked`` and ``last_result`` of one item and replace ``path`` atomically."""
    if when > today:
        raise WaitlistInputError(f"--date: {when.isoformat()} is after today {today.isoformat()}")
    items = load_waitlist(path, today)
    positions = [index for index, item in enumerate(items) if item.id == item_id]
    if not positions:
        raise WaitlistInputError(f"{path}: no item with id {_plain(item_id)!r}")
    index = positions[0]  # ids are unique once loaded
    if when < items[index].last_checked:
        raise WaitlistInputError(
            f"--date: {when.isoformat()} is before the item's last_checked {items[index].last_checked.isoformat()}"
        )
    updated = replace(items[index], last_checked=when, last_result=result)
    items[index] = updated
    write_atomic(path, waitlist_text(items))
    return updated


# --- record --from ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SavedResult:
    """The rows of a saved ``scan`` or ``roots`` document, keyed by the link an item would carry."""

    check: str  # "scan" or "roots"
    checked: datetime.date  # the local date in the document's ``generated``
    rows: dict[ResultLink, list[Check[str]]]
    walk: list[JSONValue] | None = None


@dataclass(frozen=True, slots=True)
class Recorded:
    result: SavedResult
    updated: list[tuple[LedgerItem, bool]]  # the item as written, and whether it changed
    unchanged: list[tuple[LedgerItem, str]]  # the item, and why it was left as it was


def _row_check(verdict: object, where: str) -> Check[str]:
    """The waitlist form of a row's verdict: a roots ``found`` lists its match methods, joined by ``, ``."""
    data: object = verdict
    if isinstance(verdict, dict):
        fields: dict[str, object] = {str(key): value for key, value in verdict.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
        value = fields.get("value")
        if fields.get("result") == "found" and isinstance(value, list):
            methods: list[object] = list(value)  # pyright: ignore[reportUnknownArgumentType]
            fields["value"] = ", ".join(str(method) for method in methods)  # checked as text by render_document
        data = fields
    try:
        return text_check_from_json(data, where)
    except (ValueError, TypeError) as error:
        raise WaitlistInputError(str(error)) from None


def saved_result_from_document(document: object, where: str) -> SavedResult:
    """Validate ``document`` as ``ledger`` does, then index its rows. Anything else is refused."""
    try:
        render_document(document, where)
    except LedgerInputError as error:
        raise WaitlistInputError(f"not a saved scan or roots result: {error}") from None
    assert isinstance(document, dict)  # render_document accepted it
    top: dict[str, object] = {str(key): value for key, value in document.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    checked = datetime.datetime.fromisoformat(str(top["generated"])).date()  # checked by render_document
    listed = top["items"]
    assert isinstance(listed, list)
    raw_items: list[object] = list(listed)  # pyright: ignore[reportUnknownArgumentType]
    check = "roots" if "check" in top else "scan"
    rows: dict[ResultLink, list[Check[str]]] = {}
    for index, raw in enumerate(raw_items):
        assert isinstance(raw, dict)
        row: dict[str, object] = {str(key): value for key, value in raw.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
        link: ResultLink
        if check == "scan":
            link = ScanLink(RuntimeKind(str(top["kind"])), str(row["path"]))
        else:
            link = RootsLink(str(row["location_kind"]), str(row["location"]), str(row["distrust"]))
        rows.setdefault(link, []).append(_row_check(row["verdict"], f"{where}.items[{index}].verdict"))
    walk: list[JSONValue] | None = None
    if check == "scan":
        raw_walk = cast("list[JSONValue]", top["walk"])  # already validated by render_document
        if any(isinstance(entry, dict) and any(name in entry for name in (
            "package_root", "package_root_error", "skipped_protected"
        )) for entry in raw_walk):
            walk = raw_walk
    return SavedResult(check, checked, rows, walk)


def load_saved_result(path: str) -> SavedResult:
    document = _load_json(path)
    try:
        return saved_result_from_document(document, path)
    except WaitlistInputError as error:
        raise WaitlistInputError(f"{path}: {error}") from None


def record_from(path: str, result_path: str, ids: Sequence[str], today: datetime.date) -> Recorded:
    """Update every linked item (or only ``ids``) from a saved result and replace ``path`` atomically.

    The file is written only when an item changed, and the same input gives the same file again.
    """
    saved = load_saved_result(result_path)
    if saved.checked > today:
        raise WaitlistInputError(f"{result_path}: generated {saved.checked.isoformat()} is after today {today.isoformat()}")
    items = load_waitlist(path, today)
    known = {item.id for item in items}
    for item_id in ids:
        if item_id not in known:
            raise WaitlistInputError(f"{path}: no item with id {_plain(item_id)!r}")
    wanted = set(ids)
    updated: list[tuple[LedgerItem, bool]] = []
    unchanged: list[tuple[LedgerItem, str]] = []
    for index, item in enumerate(items):
        if wanted and item.id not in wanted:
            continue
        why: str | None = None
        checks = saved.rows.get(item.result_link, []) if item.result_link is not None else []
        if item.result_link is None:
            why = NO_RESULT_LINK
        elif not checks:
            why = NOT_FOUND_IN_RESULT
        elif any(check != checks[0] for check in checks):
            why = AMBIGUOUS_IN_RESULT
        elif item.last_checked > saved.checked:
            why = CHECKED_AFTER_RESULT
        if why is not None:
            unchanged.append((item, why))
            continue
        new = replace(item, last_checked=saved.checked, last_result=checks[0])
        updated.append((new, new != item))
        items[index] = new
    if any(changed for _, changed in updated):
        write_atomic(path, waitlist_text(items))
    return Recorded(saved, updated, unchanged)


def record_from_document(recorded: Recorded, result_path: str) -> JSONObject:
    updated: list[JSONValue] = []
    for item, changed in recorded.updated:
        encoded = ledger_item_to_json(item)
        encoded["changed"] = changed
        updated.append(encoded)
    unchanged: list[JSONValue] = [{"id": item.id, "why": why} for item, why in recorded.unchanged]
    document: JSONObject = {
        "tool": "patchwait",
        "schema": SCHEMA,
        "from": result_path,
        "check": recorded.result.check,
        "checked": recorded.result.checked.isoformat(),
        "counts": {
            "updated": len(recorded.updated),
            "changed": sum(1 for _, changed in recorded.updated if changed),
            "unchanged": len(recorded.unchanged),
        },
        "updated": updated,
        "unchanged": unchanged,
    }
    if recorded.result.walk is not None:
        document["walk"] = recorded.result.walk
    return document
