"""Turn ``scan`` and ``roots`` documents into Markdown for a ledger.

For each document: one summary line meant for a ledger's evidence cell, then a
list of the items. ``found`` and ``undetermined`` items are always listed one
per line; ``not_found`` items are too, unless ``brief`` collapses them into a
count. The JSON tokens (``found``, ``not_found``, ``undetermined``, reason
names) are used verbatim.

Counts are recomputed from the items and must agree with the document's own
``counts``; a document that disagrees is rejected rather than summarised.
Nothing is stored and nothing is compared with earlier runs.

Every free-text value (paths, locations, labels, versions, product names,
details, match methods) is written inside a code span, so a crafted value
cannot inject Markdown or HTML. Control and format characters in it become
``\\uXXXX`` escapes (``\\UXXXXXXXX`` above U+FFFF), and a backslash that would
read as the start of such an escape becomes ``\\u005c``, so distinct values stay
distinct. An email-shaped part of a path becomes ``<email>``.
"""

from __future__ import annotations

import datetime
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from patchwait.model import Reason, RuntimeKind
from patchwait import windows_walk
from patchwait.keystore import BAG_TYPES, CONTENT_TYPES, ENTRY_TYPES
from patchwait.pyvenv import EVIDENCE_HOME, EVIDENCE_TARGET, EVIDENCE_VERSION_INFO, EVIDENCES
from patchwait.roots import EMPTY_PEM_BLOCK, MAX_IGNORED_LISTED, LocationKind, registry_key_paths, role_of

SCHEMA = 1
RESULTS: tuple[str, ...] = ("found", "not_found", "undetermined")
ROLES: tuple[str, ...] = ("trust", "distrust")
_REASONS = frozenset(reason.value for reason in Reason)
_KINDS = frozenset(kind.value for kind in RuntimeKind)
_LOCATION_ROLES = {kind.value: role_of(kind).value for kind in LocationKind}
# Trust-side Windows locations that a Disallowed store entry overrides.
_OVERRIDDEN_BY_DISALLOWED = frozenset({LocationKind.ROOT_STORE.value, LocationKind.AUTHROOT_CTL.value})
DISALLOWED_NOTE = "note: Disallowed also lists this certificate; Windows does not trust it while it is in Disallowed"
# local@label.label...tld inside a path segment; separators and spaces end it.
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+)[A-Za-z]{2,}(?![A-Za-z0-9-])"
)
# controls, format characters (bidi, zero-width), line and paragraph separators, lone surrogates
_ESCAPED = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})
# A backslash the reader could take for the start of an escape.
_ESCAPE_LIKE = re.compile(r"\\(?=u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})")
_WALK_SKIPS: tuple[str, ...] = ("skipped_reparse_points", "excluded_dirs")
_SCAN_LOCATION_KINDS = frozenset({"file", "directory"})
_VERSION_SOURCE_FIELDS = frozenset({"evidence", "pyvenv_cfg", "home", "version_info"})
_TARGET_SOURCE_FIELDS = frozenset({"evidence", "target_file", "target"})
_PEM_ROOT_SKIPS: tuple[str, ...] = ("skipped_reparse_points", "skipped_key_only")
# Certificate counts of a file read for certificates; each is optional, a stated one is checked.
_CERT_COUNTS: tuple[str, ...] = ("pem_blocks", "certs", "der_certs", "malformed")
_CERT_FILE_KINDS = frozenset({LocationKind.BINARY.value, LocationKind.PEM.value})
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
_ISO_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SHA1_HEX = re.compile(r"[0-9a-fA-F]{40}")
_REGISTRY_EXTRAS: tuple[str, ...] = ("cert_sha1", "registry_keys_note", "registry_keys_errors")
_REGISTRY_FIELDS: tuple[str, ...] = ("registry_keys", *_REGISTRY_EXTRAS)
_STORE_KINDS = frozenset({LocationKind.ROOT_STORE.value, LocationKind.DISALLOWED_STORE.value})
_CTL_KINDS = frozenset({LocationKind.AUTHROOT_CTL.value, LocationKind.DISALLOWED_CTL.value})
_LAST_SYNC_FIELDS: tuple[str, ...] = ("last_sync", "last_sync_note")
SHORT_SHA1 = 12  # hex digits of the SHA-1 that prefix registry parts when an item matches several certificates


class LedgerInputError(Exception):
    """An input file is unreadable or is not a patchwait document. Maps to exit code 2."""


@dataclass(frozen=True, slots=True)
class Rendered:
    markdown: str
    bad_found: bool  # scan: any found; roots: found on the trust side


# --- validation helpers ---------------------------------------------------------


def _fail(where: str, problem: str) -> LedgerInputError:
    return LedgerInputError(f"{where}: {problem}")


def _object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _fail(where, "must be an object")
    return {str(key): item for key, item in value.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]


def _list(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise _fail(where, "must be a list")
    return list(value)  # pyright: ignore[reportUnknownArgumentType]


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise _fail(where, "must be a non-empty string")
    return value


def _optional_text(value: object, where: str) -> str | None:
    if value is None:
        return None
    return _text(value, where)


def _count(value: object, where: str) -> int:
    if type(value) is not int or value < 0:
        raise _fail(where, "must be a non-negative integer")
    return value


def _verdict(item: dict[str, object], where: str) -> dict[str, object]:
    verdict = _object(item.get("verdict"), f"{where}.verdict")
    result = verdict.get("result")
    if result not in RESULTS:
        raise _fail(f"{where}.verdict.result", f"must be one of {', '.join(RESULTS)}")
    if result == "found" and "value" not in verdict:
        raise _fail(f"{where}.verdict", "found without a value")
    if result == "undetermined":
        reason = _text(verdict.get("reason"), f"{where}.verdict.reason")
        if reason not in _REASONS:
            raise _fail(f"{where}.verdict.reason", f"unknown reason {reason!r}")
        _text(verdict.get("detail"), f"{where}.verdict.detail")
    return verdict


def _check_counts(stated: dict[str, object], tally: dict[str, int], where: str) -> None:
    for result in RESULTS:
        claimed = _count(stated.get(result), f"{where}.{result}")
        if claimed != tally[result]:
            raise _fail(where, f"{result} is {claimed} but the items give {tally[result]}")


# --- Markdown helpers --------------------------------------------------------------


def _escape(ch: str) -> str:
    code = ord(ch)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _plain(text: str) -> str:
    """One line: control and format characters (newlines and tabs included) become escapes.

    ``\\uXXXX`` (``\\UXXXXXXXX`` above U+FFFF). A literal backslash followed by
    what reads as such an escape becomes ``\\u005c`` first, so a path holding the
    text ``\\u000a`` and a path holding a newline render differently. Spaces,
    Unicode spaces included, are kept as they are, so distinct values stay distinct.
    """
    text = _ESCAPE_LIKE.sub(lambda _: "\\u005c", text)
    return "".join(_escape(ch) if unicodedata.category(ch) in _ESCAPED else ch for ch in text)


def _code(text: str) -> str:
    """A code span showing ``text`` (after ``_plain``) literally: no Markdown, no HTML."""
    text = _plain(text)
    if text == "":
        raise ValueError("empty code span")  # _text rejects empty values before rendering
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * (longest + 1)
    # CommonMark strips one space from each end when both ends have one; pad so none is lost.
    padded = text.startswith("`") or text.endswith("`") or (text.startswith(" ") and text.endswith(" "))
    pad = " " if padded else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _email_or_kept(match: re.Match[str]) -> str:
    labels = match.group(1).split(".")[:-1]  # the domain labels before the TLD
    if not any(ch.isalpha() for label in labels for ch in label):
        return match.group(0)  # all-digit labels: a version such as pkg@1.0.0.tgz, not a domain
    return "<email>"


def _mask_emails(path: str) -> str:
    """Email-shaped text inside a path segment becomes ``<email>``; the rest is verbatim.

    The domain needs a dot, a letter TLD and a letter somewhere before the TLD,
    so ``first.last@example.com (1)`` is masked and ``pkg@1.0.0.tgz`` is kept.
    """
    return _EMAIL.sub(_email_or_kept, path)


def _location(path: str) -> str:
    return _code(_mask_emails(path))


def _reason_counts(reasons: Sequence[str]) -> str:
    if not reasons:
        return ""
    ordered = sorted(Counter(reasons).items(), key=lambda pair: (-pair[1], pair[0]))
    return " (" + ", ".join(f"{name} {count}" for name, count in ordered) + ")"


def _triple(tally: dict[str, int], reasons: Sequence[str]) -> str:
    text = " / ".join(f"{result} {tally[result]}" for result in RESULTS)
    return text + _reason_counts(reasons)


def _date(document: dict[str, object], where: str) -> str:
    generated = _text(document.get("generated"), f"{where}.generated")
    try:
        when = datetime.datetime.fromisoformat(generated)
    except ValueError:
        raise _fail(f"{where}.generated", f"not an ISO date: {generated!r}") from None
    return when.strftime("%m-%d")  # the document's own date, not today's


def _undetermined_tail(verdict: dict[str, object]) -> str:
    return f" — {verdict['reason']}: {_code(str(verdict['detail']))}"


# --- scan --------------------------------------------------------------------------


def _version_source(item: dict[str, object], location_kind: str, version: str | None, result: str, where: str) -> str:
    """Python fallback evidence as one part, or "" when the item has none."""
    if "version_source" not in item:
        return ""
    at = f"{where}.version_source"
    if location_kind != "file":
        raise _fail(at, "is only for file items")
    source = _object(item["version_source"], at)
    if frozenset(source) == _TARGET_SOURCE_FIELDS:
        evidence = _optional_text(source["evidence"], f"{at}.evidence")
        target_file = _text(source["target_file"], f"{at}.target_file")
        target = _optional_text(source["target"], f"{at}.target")
        if evidence not in (None, EVIDENCE_TARGET):
            raise _fail(f"{at}.evidence", f"must be {EVIDENCE_TARGET!r} or null")
        if evidence is None and result != "undetermined":
            raise _fail(f"{at}.evidence", "is null but the verdict is not undetermined")
        if evidence == EVIDENCE_TARGET and target is None:
            raise _fail(f"{at}.target", f"must be given for {EVIDENCE_TARGET}")
        parts = [f"version from {_code(evidence)}" if evidence is not None else "no version taken",
                 f"__target__ {_location(target_file)}"]
        if target is not None:
            parts.append(f"target {_location(target)}")
        return ", ".join(parts)
    if frozenset(source) != _VERSION_SOURCE_FIELDS:
        raise _fail(at, f"must have exactly the keys {{{', '.join(sorted(_VERSION_SOURCE_FIELDS))}}} "
                    f"or {{{', '.join(sorted(_TARGET_SOURCE_FIELDS))}}}")
    evidence = _optional_text(source["evidence"], f"{at}.evidence")
    cfg = _text(source["pyvenv_cfg"], f"{at}.pyvenv_cfg")
    home = _optional_text(source["home"], f"{at}.home")
    version_info = _optional_text(source["version_info"], f"{at}.version_info")
    if evidence is not None and evidence not in EVIDENCES:
        raise _fail(f"{at}.evidence", f"unknown evidence {evidence!r}")
    if evidence is None and result != "undetermined":
        raise _fail(f"{at}.evidence", "is null but the verdict is not undetermined")
    if evidence == EVIDENCE_HOME and home is None:
        raise _fail(f"{at}.home", f"must be given for {EVIDENCE_HOME}")
    if evidence == EVIDENCE_VERSION_INFO and (version_info is None or version_info != version):
        raise _fail(f"{at}.version_info", f"must equal product_version for {EVIDENCE_VERSION_INFO}")
    parts = [f"version from {_code(evidence)}" if evidence is not None else "no version taken", f"pyvenv.cfg {_location(cfg)}"]
    if home is not None:
        parts.append(f"home {_location(home)}")
    if version_info is not None:
        parts.append(f"version_info {_code(version_info)}")
    return ", ".join(parts)


def _scan_line(item: dict[str, object], verdict: dict[str, object], where: str) -> str:
    path = _text(item.get("path"), f"{where}.path")
    location_kind = _text(item.get("location_kind"), f"{where}.location_kind")
    if location_kind not in _SCAN_LOCATION_KINDS:
        raise _fail(f"{where}.location_kind", f"unknown location_kind {location_kind!r}")
    product = _object(item.get("product"), f"{where}.product")
    name = _text(product.get("name"), f"{where}.product.name")
    inferred = product.get("inferred")
    if not isinstance(inferred, bool):
        raise _fail(f"{where}.product.inferred", "must be true or false")
    version = _optional_text(item.get("product_version"), f"{where}.product_version")
    checked = _object(item.get("checked_against"), f"{where}.checked_against")
    minimum = _optional_text(checked.get("minimum"), f"{where}.checked_against.minimum")
    result = str(verdict["result"])
    source = _version_source(item, location_kind, version, result, where)
    head = f"- {result}: {_location(path)}"
    if location_kind == "directory":
        head += " (directory)"
    if result == "undetermined":
        return head + (f" — {source}" if source else "") + _undetermined_tail(verdict)
    if result == "found":
        shown = _text(verdict["value"], f"{where}.verdict.value")  # the unfixed version that is present
        if shown != version:
            raise _fail(f"{where}.verdict.value", "does not match product_version")
    else:
        shown = version
    product_text = f"product {_code(name)}" + (" (inferred)" if inferred else "")
    sign = "<" if result == "found" else ">="
    compared = f"{_code(shown or '?')} {sign} {_code(minimum or '?')}"
    return f"{head} — {compared}, {product_text}" + (f", {source}" if source else "")


def _exact_fields(fields: dict[str, object], names: set[str], where: str) -> None:
    if fields.keys() != names:
        raise _fail(where, f"must have exactly the keys {{{', '.join(sorted(names))}}}")


def _protected_walk(walk: dict[str, object], at: str) -> tuple[int, list[str]]:
    if "skipped_protected" not in walk and "skipped_protected_count" not in walk:
        return 0, []
    count = _count(walk.get("skipped_protected_count"), f"{at}.skipped_protected_count")
    entries = _list(walk.get("skipped_protected"), f"{at}.skipped_protected")
    if count != len(entries):
        raise _fail(at, "skipped_protected_count disagrees with skipped_protected")
    lines: list[str] = []
    for index, raw in enumerate(entries):
        entry_at = f"{at}.skipped_protected[{index}]"
        entry = _object(raw, entry_at)
        _exact_fields(entry, {"path", "reason"}, entry_at)
        path = _text(entry["path"], f"{entry_at}.path")
        if entry["reason"] != windows_walk.PROTECTED_REASON:
            raise _fail(f"{entry_at}.reason", f"must be {windows_walk.PROTECTED_REASON!r}")
        lines.append(f"- not walked: skipped_protected {_location(path)} — {windows_walk.PROTECTED_REASON}; "
                     + windows_walk.PROTECTED_NOTE)
    return count, lines


def _package_walk(walk: dict[str, object], at: str) -> tuple[dict[str, int], list[str]]:
    totals: dict[str, int] = dict.fromkeys(("package_absent", "package_unreadable", "package_refused"), 0)
    if "package_root_error" in walk:
        error = _text(walk["package_root_error"], f"{at}.package_root_error")
        if "package_root" in walk:
            raise _fail(at, "package_root and package_root_error cannot both be present")
        return totals, [f"- package_root unavailable: {_code(error)}; original unreadable items retained"]
    if "package_root" not in walk:
        return totals, []
    package = _object(walk["package_root"], f"{at}.package_root")
    count_fields = ("packages_registered", "walked", "unreadable", "absent", "excluded", "skipped_reparse_points")
    _exact_fields(package, {"path", *count_fields, "refused", "note"}, f"{at}.package_root")
    path = _text(package["path"], f"{at}.package_root.path")
    note = _text(package["note"], f"{at}.package_root.note")
    counts = {name: _count(package[name], f"{at}.package_root.{name}") for name in count_fields}
    refused = [_text(name, f"{at}.package_root.refused[{index}]") for index, name in enumerate(
        _list(package["refused"], f"{at}.package_root.refused"))]
    if counts["packages_registered"] != sum(counts[name] for name in count_fields[1:]) + len(refused):
        raise _fail(f"{at}.package_root", "package counts do not account for every registered package")
    totals.update(package_absent=counts["absent"], package_unreadable=counts["unreadable"], package_refused=len(refused))
    count_text = ", ".join(f"{name} {counts[name]}" for name in count_fields)
    lines = [f"- package_root {_location(path)}: {count_text}, refused {len(refused)}; {_code(note)}"]
    lines += [f"- not walked: refused package name {_code(name)}" for name in refused]
    return totals, lines


def _not_walked(document: dict[str, object], where: str) -> tuple[str, list[str]]:
    totals = dict.fromkeys(_WALK_SKIPS, 0)
    details: list[str] = []
    for index, entry in enumerate(_list(document.get("walk"), f"{where}.walk")):
        at = f"{where}.walk[{index}]"
        walk = _object(entry, at)
        for name in _WALK_SKIPS:
            totals[name] += _count(walk.get(name), f"{at}.{name}")
        protected, protected_lines = _protected_walk(walk, at)
        if "skipped_protected" in walk:
            totals["skipped_protected"] = totals.get("skipped_protected", 0) + protected
        package, package_lines = _package_walk(walk, at)
        for name, count in package.items():
            if count:
                totals[name] = totals.get(name, 0) + count
        details += protected_lines + package_lines
    if not any(totals.values()):
        return "", details
    return "; not walked: " + ", ".join(f"{name} {count}" for name, count in totals.items()), details


def _render_scan(document: dict[str, object], items: list[dict[str, object]], where: str, brief: bool) -> Rendered:
    kind = _text(document.get("kind"), f"{where}.kind")
    if kind not in _KINDS:
        raise _fail(f"{where}.kind", f"unknown kind {kind!r}")
    tally = dict.fromkeys(RESULTS, 0)
    reasons: list[str] = []
    lines: dict[str, list[str]] = {result: [] for result in RESULTS}
    for index, item in enumerate(items):
        at = f"{where}.items[{index}]"
        verdict = _verdict(item, at)
        result = str(verdict["result"])
        tally[result] += 1
        if result == "undetermined":
            reasons.append(str(verdict["reason"]))
        lines[result].append(_scan_line(item, verdict, at))
    counts = _object(document.get("counts"), f"{where}.counts")
    targets = _count(counts.get("targets"), f"{where}.counts.targets")
    if targets != len(items):
        raise _fail(f"{where}.counts", f"targets is {targets} but there are {len(items)} items")
    _check_counts(counts, tally, f"{where}.counts")
    not_walked, walk_details = _not_walked(document, where)
    summary = f"{_date(document, where)}: patchwait scan {kind}: {_triple(tally, reasons)}{not_walked}"
    not_found = [f"- not_found: {tally['not_found']} items"] if brief else lines["not_found"]
    body = lines["found"] + lines["undetermined"] + not_found + walk_details
    return Rendered(_block(summary, body), tally["found"] > 0)


# --- roots -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RootsItem:
    location: str
    role: str
    location_kind: str
    label: str
    result: str
    text: str  # the rendered line, without the Disallowed note
    cert_sha256: frozenset[str]  # lower-case cert_sha256 values of the matches that state one
    skips: tuple[int, ...]  # pem_root: counts for _PEM_ROOT_SKIPS (zeros elsewhere)
    keystore_parts: tuple[str, ...] = ()


def _match_certs(item: dict[str, object], where: str) -> frozenset[str]:
    """The cert_sha256 values stated by the item's matches; null or absent ones are left out."""
    found: set[str] = set()
    for index, entry in enumerate(_list(item.get("matches", []), f"{where}.matches")):
        match = _object(entry, f"{where}.matches[{index}]")
        value = match.get("cert_sha256")
        if value is None:
            continue
        if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
            raise _fail(f"{where}.matches[{index}].cert_sha256", "must be 64 hex digits or null")
        found.add(value.lower())
    return frozenset(found)


def _iso_time(value: object, where: str) -> str | None:
    """An ISO 8601 UTC time as written by ``roots`` (``YYYY-MM-DDTHH:MM:SSZ``), or null."""
    if value is None:
        return None
    if not isinstance(value, str) or _ISO_UTC.fullmatch(value) is None:
        raise _fail(where, "must be an ISO 8601 UTC time (YYYY-MM-DDTHH:MM:SSZ) or null")
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _fail(where, f"not a valid time: {value!r}") from None
    return value


def _time_text(value: str | None, note: object, where: str) -> str:
    """A time in a code span, or ``unknown`` with the note that a null time must carry."""
    if value is not None:
        if note is not None:
            raise _fail(where, "has a note but the time is given")
        return _code(value)
    return f"unknown ({_code(_text(note, where))})"


def _last_sync_parts(details: dict[str, object], location_kind: str, where: str) -> list[str]:
    if location_kind not in _CTL_KINDS:
        for name in _LAST_SYNC_FIELDS:
            if name in details:
                raise _fail(f"{where}.{name}", "is only for authroot_ctl and disallowed_ctl details")
        return []
    if "last_sync" not in details:
        if "last_sync_note" in details:
            raise _fail(f"{where}.last_sync_note", "needs last_sync")
        return []
    when = _iso_time(details["last_sync"], f"{where}.last_sync")
    return ["last_sync " + _time_text(when, details.get("last_sync_note"), f"{where}.last_sync_note")]


def _registry_key(value: object, allowed: frozenset[str], where: str) -> str:
    """A key name that is one of the paths looked up for the match's certificate and store."""
    name = _text(value, where)
    if name.casefold() not in allowed:
        raise _fail(where, "is not a registry key looked up for this certificate and store")
    return name


def _registry_parts(match: dict[str, object], kind: LocationKind, where: str) -> tuple[str | None, list[str]]:
    """The certificate's SHA-1 and the registry parts of one match: each key with
    its last write, the not-found note, the errors."""
    if "registry_keys" not in match:
        for name in _REGISTRY_EXTRAS:
            if name in match:
                raise _fail(f"{where}.{name}", "needs registry_keys")
        return None, []
    sha1 = match.get("cert_sha1")
    if not isinstance(sha1, str) or _SHA1_HEX.fullmatch(sha1) is None:
        raise _fail(f"{where}.cert_sha1", "must be 40 hex digits when registry_keys is given")
    allowed = frozenset(path.casefold() for path in registry_key_paths(kind, sha1))
    parts: list[str] = []
    keys = _list(match["registry_keys"], f"{where}.registry_keys")
    for index, entry in enumerate(keys):
        at = f"{where}.registry_keys[{index}]"
        key = _object(entry, at)
        name = _registry_key(key.get("key"), allowed, f"{at}.key")
        if "last_write" not in key:
            raise _fail(f"{at}.last_write", "is missing (a time or null)")
        when = _iso_time(key["last_write"], f"{at}.last_write")
        written = _time_text(when, key.get("last_write_note"), f"{at}.last_write_note")
        parts.append(f"registry {_code(name)} last write {written}")
    note = match.get("registry_keys_note")
    if keys and note is not None:
        raise _fail(f"{where}.registry_keys_note", "is only for an empty registry_keys")
    if not keys:
        parts.append(f"registry {_code(_text(note, f'{where}.registry_keys_note'))}")
    if "registry_keys_errors" in match:
        errors = _list(match["registry_keys_errors"], f"{where}.registry_keys_errors")
        if not errors:
            raise _fail(f"{where}.registry_keys_errors", "must not be empty when given")
        for index, entry in enumerate(errors):
            at = f"{where}.registry_keys_errors[{index}]"
            error = _object(entry, at)
            name = _registry_key(error.get("key"), allowed, f"{at}.key")
            parts.append(f"registry {_code(name)} unreadable {_code(_text(error.get('error'), f'{at}.error'))}")
    return sha1.upper(), parts


def _match_registry_parts(item: dict[str, object], location_kind: str, where: str) -> list[str]:
    """Registry parts of all matches, each distinct part once (a certificate matched two ways repeats them).

    When the matches are of two or more certificates, each part starts with the
    certificate's short SHA-1 so that a note or an error can be told apart.
    """
    found: list[tuple[str | None, list[str]]] = []
    for index, entry in enumerate(_list(item.get("matches", []), f"{where}.matches")):
        at = f"{where}.matches[{index}]"
        match = _object(entry, at)
        if location_kind not in _STORE_KINDS:
            for name in _REGISTRY_FIELDS:
                if name in match:
                    raise _fail(f"{at}.{name}", "is only for root_store and disallowed_store matches")
            continue
        found.append(_registry_parts(match, LocationKind(location_kind), at))
    several = len({sha1 for sha1, _parts in found if sha1 is not None}) >= 2
    parts: list[str] = []
    for sha1, own in found:
        for part in own:
            text = f"{_code(sha1[:SHORT_SHA1])} {part}" if several and sha1 is not None else part
            if text not in parts:
                parts.append(text)
    return parts


def _ignored_pem_blocks(details: dict[str, object], where: str) -> int:
    """How many PEM blocks were ignored: the listed ones, or the stated total when the list was capped."""
    if "ignored_pem_blocks" not in details:
        if "ignored_pem_blocks_total" in details:
            raise _fail(f"{where}.ignored_pem_blocks_total", "needs ignored_pem_blocks")
        return 0
    listed = _list(details["ignored_pem_blocks"], f"{where}.ignored_pem_blocks")
    for index, entry in enumerate(listed):
        at = f"{where}.ignored_pem_blocks[{index}]"
        block = _object(entry, at)
        _count(block.get("offset"), f"{at}.offset")
        if block.get("reason") != EMPTY_PEM_BLOCK:
            raise _fail(f"{at}.reason", f"must be {EMPTY_PEM_BLOCK!r}")
    if "ignored_pem_blocks_total" not in details:
        return len(listed)
    total = _count(details["ignored_pem_blocks_total"], f"{where}.ignored_pem_blocks_total")
    if len(listed) != MAX_IGNORED_LISTED:
        raise _fail(f"{where}.ignored_pem_blocks", f"must list exactly {MAX_IGNORED_LISTED} when a total is given")
    if total <= len(listed):
        raise _fail(f"{where}.ignored_pem_blocks_total", "must be more than the blocks listed")
    return total


def _cert_file_parts(details: dict[str, object], location_kind: str, where: str) -> list[str]:
    """``der_certs`` and the ignored PEM blocks of a binary or PEM file, after checking the counts."""
    if location_kind not in _CERT_FILE_KINDS:
        return []
    counts = {name: _count(details[name], f"{where}.{name}") for name in _CERT_COUNTS if name in details}
    ignored = _ignored_pem_blocks(details, where)
    parts: list[str] = []
    if location_kind == LocationKind.BINARY.value and "der_certs" in counts:
        parts.append(f"der_certs {counts['der_certs']}")
    if ignored > 0:
        parts.append(f"ignored_pem_blocks {ignored}")
    return parts


def _keystore_parts(details: dict[str, object], location_kind: str, where: str) -> list[str]:
    if location_kind != LocationKind.JAVA_KEYSTORE.value or not details:
        return []
    fmt = details.get("format")
    if fmt not in ("pkcs12", "jks", "jceks", "unknown"):
        raise _fail(f"{where}.format", "must be pkcs12, jks, jceks or unknown")
    parts = [f"format {fmt}"]
    for name in ("version", "declared_entries"):
        value = details.get(name)
        if value is not None:
            parts.append(f"{name} {_count(value, f'{where}.{name}')}")
    for name in ("certs", "malformed", "encrypted_content_infos", "unreadable_parts"):
        parts.append(f"{name} {_count(details.get(name), f'{where}.{name}')}")
    for name, allowed in (("bags", BAG_TYPES.values()), ("entries", ENTRY_TYPES.values()), ("content_infos", CONTENT_TYPES.values())):
        counts = _object(details.get(name), f"{where}.{name}")
        for kind, value in counts.items():
            if kind != "unknown" and kind not in allowed:
                raise _fail(f"{where}.{name}.{kind}", "unknown count type")
            count = _count(value, f"{where}.{name}.{kind}")
            parts.append(f"{name} {kind} {count}")
    mac = details.get("mac_data")
    if mac is not None and type(mac) is not bool:
        raise _fail(f"{where}.mac_data", "must be a boolean or null")
    if mac is not None:
        parts.append("mac_data " + ("present" if mac else "absent"))
    return parts


def _roots_item(item: dict[str, object], verdict: dict[str, object], where: str) -> _RootsItem:
    location = _text(item.get("location"), f"{where}.location")
    location_kind = _text(item.get("location_kind"), f"{where}.location_kind")
    if location_kind not in _LOCATION_ROLES:
        raise _fail(f"{where}.location_kind", f"unknown location_kind {location_kind!r}")
    role = item.get("role")
    if role != _LOCATION_ROLES[location_kind]:
        raise _fail(f"{where}.role", f"must be {_LOCATION_ROLES[location_kind]} for {location_kind}")
    role = str(role)
    label = _text(item.get("distrust"), f"{where}.distrust")
    details = _object(item.get("details", {}), f"{where}.details")
    result = str(verdict["result"])
    parts = [f"role {role}", f"location_kind {location_kind}", f"distrust {_code(label)}"]
    if result == "found":
        methods = _list(verdict["value"], f"{where}.verdict.value")
        if not methods:
            raise _fail(f"{where}.verdict.value", "must be a non-empty list")
        names = [_text(method, f"{where}.verdict.value[{index}]") for index, method in enumerate(methods)]
        parts.append("matched_by " + ", ".join(_code(name) for name in names))
    this_update = details.get("this_update")
    if isinstance(this_update, str) and this_update.strip() != "":
        parts.append(f"this_update {_code(this_update)}")
    parts += _last_sync_parts(details, location_kind, f"{where}.details")
    parts += _match_registry_parts(item, location_kind, where)
    skips = tuple(
        _count(details.get(name, 0), f"{where}.details.{name}") if location_kind == LocationKind.PEM_ROOT.value else 0
        for name in _PEM_ROOT_SKIPS
    )
    parts += [f"{name} {count}" for name, count in zip(_PEM_ROOT_SKIPS, skips, strict=True) if count > 0]
    parts += _cert_file_parts(details, location_kind, f"{where}.details")
    keystore_parts = _keystore_parts(details, location_kind, f"{where}.details")
    parts += keystore_parts
    text = f"- {result}: {_location(location)} — " + ", ".join(parts)
    if result == "undetermined":
        text += _undetermined_tail(verdict)
    certs = _match_certs(item, where)
    return _RootsItem(location, role, location_kind, label, result, text, certs, skips, tuple(keystore_parts))


def _roots_lines(rendered: Sequence[_RootsItem]) -> dict[str, list[str]]:
    """Lines by result; a trust-side Windows found that Disallowed overrides gets a note.

    The note needs the same certificate on both sides: a cert_sha256 of the
    trust-side match equal to one of a Disallowed store found for the same
    label. A shared label alone (Disallowed may hold another certificate,
    matched by its key only) or a match without a cert_sha256 gives no note.
    """
    disallowed: dict[str, set[str]] = {}
    for item in rendered:
        if item.location_kind == LocationKind.DISALLOWED_STORE.value and item.result == "found":
            disallowed.setdefault(item.label, set()).update(item.cert_sha256)
    lines: dict[str, list[str]] = {result: [] for result in RESULTS}
    for item in rendered:
        overridden = item.result == "found" and item.location_kind in _OVERRIDDEN_BY_DISALLOWED
        same_cert = not item.cert_sha256.isdisjoint(disallowed.get(item.label, set()))
        note = f" — {DISALLOWED_NOTE}" if overridden and same_cert else ""
        lines[item.result].append(item.text + note)
    return lines


def _roots_not_walked(rendered: Sequence[_RootsItem]) -> str:
    """Skip counts of the pem_root directories, once per directory (each is repeated per label)."""
    per_root = {item.location: item.skips for item in rendered if any(item.skips)}
    if not per_root:
        return ""
    totals = [sum(counts[index] for counts in per_root.values()) for index in range(len(_PEM_ROOT_SKIPS))]
    return "; not walked: " + ", ".join(f"{name} {total}" for name, total in zip(_PEM_ROOT_SKIPS, totals, strict=True))


def _render_roots(document: dict[str, object], items: list[dict[str, object]], where: str, brief: bool) -> Rendered:
    tally = {role: dict.fromkeys(RESULTS, 0) for role in ROLES}
    reasons: dict[str, list[str]] = {role: [] for role in ROLES}
    rendered: list[_RootsItem] = []
    for index, item in enumerate(items):
        at = f"{where}.items[{index}]"
        verdict = _verdict(item, at)
        line = _roots_item(item, verdict, at)
        tally[line.role][line.result] += 1
        if line.result == "undetermined":
            reasons[line.role].append(str(verdict["reason"]))
        rendered.append(line)
    counts = _object(document.get("counts"), f"{where}.counts")
    total = _count(counts.get("items"), f"{where}.counts.items")
    if total != len(items):
        raise _fail(f"{where}.counts", f"items is {total} but there are {len(items)} items")
    for role in ROLES:
        _check_counts(_object(counts.get(role), f"{where}.counts.{role}"), tally[role], f"{where}.counts.{role}")
    sides = "; ".join(f"{role} {_triple(tally[role], reasons[role])}" for role in ROLES)
    summary = f"{_date(document, where)}: patchwait roots: {sides}{_roots_not_walked(rendered)}"
    lines = _roots_lines(rendered)
    if brief:
        split = ", ".join(f"{role} {tally[role]['not_found']}" for role in ROLES)
        total_not_found = sum(tally[role]["not_found"] for role in ROLES)
        not_found = [f"- not_found: {total_not_found} items ({split})"]
        keystores = dict.fromkeys(
            (item.location, item.keystore_parts) for item in rendered
            if item.result == "not_found" and item.keystore_parts
        )
        not_found += [f"- java_keystore: {_location(location)} — " + ", ".join(parts) for location, parts in keystores]
    else:
        not_found = lines["not_found"]
    body = lines["found"] + lines["undetermined"] + not_found
    return Rendered(_block(summary, body), tally["trust"]["found"] > 0)


# --- documents -----------------------------------------------------------------------


def _block(summary: str, body: Sequence[str]) -> str:
    return summary + "\n" + ("\n" + "\n".join(body) + "\n" if body else "")


def render_document(document: object, where: str, *, brief: bool = False) -> Rendered:
    top = _object(document, where)
    if top.get("tool") != "patchwait":
        raise _fail(f"{where}.tool", "is not \"patchwait\"")
    schema = top.get("schema")
    if type(schema) is not int or schema != SCHEMA:
        raise _fail(f"{where}.schema", f"must be {SCHEMA}")
    if "counts" not in top:
        raise _fail(where, "has no counts")
    items = [_object(item, f"{where}.items[{index}]") for index, item in enumerate(_list(top.get("items"), f"{where}.items"))]
    has_kind, has_check = "kind" in top, "check" in top
    if has_check and not has_kind:
        if top.get("check") != "roots":
            raise _fail(f"{where}.check", "is not \"roots\"")
        return _render_roots(top, items, where, brief)
    if has_kind and not has_check:
        return _render_scan(top, items, where, brief)
    raise _fail(where, "needs exactly one of kind (scan) or check (roots)")


def load_document(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise LedgerInputError(f"{path}: cannot read: {type(error).__name__}") from None
    try:
        return json.loads(text)
    except ValueError as error:
        raise LedgerInputError(f"{path}: not JSON: {error}") from None


def ledger(paths: Sequence[str], *, brief: bool = False) -> Rendered:
    """Render every document in order. Any bad input raises before anything is returned."""
    rendered = [render_document(load_document(path), path, brief=brief) for path in paths]
    markdown = "\n".join(part.markdown for part in rendered)
    return Rendered(markdown, any(part.bad_found for part in rendered))
