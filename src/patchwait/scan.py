"""Scan bundled runtimes against caller-supplied minimum versions.

The fix-version baselines and their source URLs always come from the caller;
nothing about them is built in. Every target yields exactly one item:
``found`` (a version below the series minimum is present), ``not_found``
(the version is at or above the minimum) or ``undetermined`` with a reason.

``--root`` directories are walked for the kind's executable name. Symlinks
and junctions (reparse points) are not followed. A directory that cannot be
listed, or a root that does not exist, becomes an undetermined item of its
own (``location_kind`` ``directory``). Windows Store roots and folders that also
deny reading their permissions have explicit walk evidence instead.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from patchwait import pyvenv, windows_walk
from patchwait.model import (
    Check,
    Found,
    JSONObject,
    JSONValue,
    NotFound,
    Reason,
    RuntimeKind,
    Undetermined,
    check_to_json,
)
from patchwait.pyvenv import InstallManagerSource, VersionSource
from patchwait.reparse import is_reparse_point as _is_reparse_point

SCHEMA = 1

# ASCII digits only ([0-9], not \d, which also matches Arabic-Indic or fullwidth digits). Runs are
# capped so int() never meets a huge run (a crafted PE string must not raise).
# Matched with fullmatch: "$" would also accept a trailing newline.
_PLAIN_VERSION_RE = re.compile(r"([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})")
_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Python versions differ per minor series (3.13.x, 3.14.x); Node per major.
_SERIES_WIDTH: dict[RuntimeKind, int] = {
    RuntimeKind.NODE: 1,
    RuntimeKind.PYTHON: 2,
}

# A path token that starts with the key names the product.
_PRODUCT_HINTS: tuple[tuple[str, str], ...] = (
    ("cursor", "Cursor"),
    ("codex", "Codex"),
    ("hermes", "Hermes"),
    ("playwright", "Playwright"),
    ("logi", "Logi Options+"),
)

UNKNOWN_PRODUCT = "unknown"

RUNTIME_FILE_NAMES: dict[RuntimeKind, str] = {
    RuntimeKind.NODE: "node.exe",
    RuntimeKind.PYTHON: "python.exe",
}

LOCATION_FILE = "file"
LOCATION_DIRECTORY = "directory"

Version = tuple[int, int, int]


class ScanUsageError(Exception):
    """Bad arguments or an unusable targets file. Maps to exit code 2."""


def parse_version(text: str) -> Version | None:
    match = _PLAIN_VERSION_RE.fullmatch(text)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _series(kind: RuntimeKind, version: Version) -> tuple[int, ...]:
    return version[: _SERIES_WIDTH[kind]]


@dataclass(frozen=True, slots=True)
class Baseline:
    """Series minimums and their source for one runtime kind, as given."""

    minimums: tuple[str, ...]
    source: str | None

    def to_json(self) -> JSONObject:
        return {"minimums": list(self.minimums), "source": self.source}


def _split_assignment(option: str, text: str) -> tuple[str, str]:
    name, sep, value = text.partition("=")
    name, value = name.strip(), value.strip()
    if sep == "" or name == "" or value == "":
        raise ScanUsageError(f"{option} expects KIND=VALUE, got {text!r}")
    if name not in {kind.value for kind in RuntimeKind}:
        raise ScanUsageError(f"{option}: unknown kind {name!r}")
    return name, value


def parse_baselines(mins: Sequence[str], sources: Sequence[str]) -> dict[str, Baseline]:
    """Parse ``--min node=24.22.1,26.12.1`` and ``--source node=<URL>``."""
    minimums: dict[str, tuple[str, ...]] = {}
    for text in mins:
        name, value = _split_assignment("--min", text)
        kind = RuntimeKind(name)
        parts = tuple(part.strip() for part in value.split(","))
        seen: set[tuple[int, ...]] = set()
        for part in minimums.get(name, ()) + parts:
            version = parse_version(part)
            if version is None:
                raise ScanUsageError(f"--min {name}: {part!r} is not N.N.N")
            series = _series(kind, version)
            if series in seen:
                raise ScanUsageError(f"--min {name}: two minimums for series {'.'.join(map(str, series))}")
            seen.add(series)
        minimums[name] = minimums.get(name, ()) + parts
    source_of: dict[str, str] = {}
    for text in sources:
        name, value = _split_assignment("--source", text)
        if name in source_of:
            raise ScanUsageError(f"--source {name} given twice")
        source_of[name] = value
    names = sorted(set(minimums) | set(source_of))
    return {name: Baseline(minimums.get(name, ()), source_of.get(name)) for name in names}


def _minimum_for(kind: RuntimeKind, baseline: Baseline | None, version: Version) -> str | None:
    if baseline is None:
        return None
    for text in baseline.minimums:
        minimum = parse_version(text)
        if minimum is not None and _series(kind, minimum) == _series(kind, version):
            return text
    return None


@dataclass(frozen=True, slots=True)
class Product:
    name: str
    inferred: bool

    def to_json(self) -> JSONObject:
        return {"name": self.name, "inferred": self.inferred}


def infer_product(path: str) -> Product:
    """Guess the product from path segments, case-insensitively."""
    for segment in re.split(r"[\\/]+", path):
        for token in _TOKEN_RE.findall(segment.lower()):
            for key, name in _PRODUCT_HINTS:
                if token.startswith(key):
                    return Product(name, inferred=True)
    return Product(UNKNOWN_PRODUCT, inferred=True)


@dataclass(frozen=True, slots=True)
class Target:
    path: str
    product: Product


def targets_from_paths(paths: Sequence[str]) -> list[Target]:
    return [Target(path, infer_product(path)) for path in paths]


def load_targets_file(path: str) -> list[Target]:
    """Read ``[{"path": ..., "product": optional str}, ...]``."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data: object = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScanUsageError(f"--targets {path!r}: {type(error).__name__}") from error
    if not isinstance(data, list):
        raise ScanUsageError("--targets must hold a JSON list")
    targets: list[Target] = []
    for index, entry in enumerate(data):  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
        if not isinstance(entry, dict):
            raise ScanUsageError(f"--targets[{index}] must be an object")
        fields = cast("dict[str, object]", entry)
        target_path = fields.get("path")
        product = fields.get("product")
        if not isinstance(target_path, str) or target_path.strip() == "":
            raise ScanUsageError(f"--targets[{index}].path must be a non-empty string")
        if product is None:
            targets.append(Target(target_path, infer_product(target_path)))
        elif isinstance(product, str) and product.strip() != "":
            targets.append(Target(target_path, Product(product, inferred=False)))
        else:
            raise ScanUsageError(f"--targets[{index}].product must be a non-empty string")
    return targets


@dataclass(frozen=True, slots=True)
class ScanItem:
    target: Target
    product_version: str | None
    minimum: str | None
    source: str | None
    verdict: Check[str]  # Found(value) = the unfixed version that is present
    location_kind: str = LOCATION_FILE
    version_source: VersionSource | InstallManagerSource | None = None

    def to_json(self) -> JSONObject:
        document: JSONObject = {
            "path": self.target.path,
            "location_kind": self.location_kind,
            "product": self.target.product.to_json(),
            "product_version": self.product_version,
            "checked_against": {"minimum": self.minimum, "source": self.source},
            "verdict": check_to_json(self.verdict, _encode_str),
        }
        if self.version_source is not None:
            document["version_source"] = self.version_source.to_json()
        return document


def _encode_str(value: str) -> JSONValue:
    return value


def scan_target(target: Target, kind: RuntimeKind, baseline: Baseline | None) -> ScanItem:
    source = baseline.source if baseline is not None else None
    version_source: VersionSource | InstallManagerSource | None = None

    def item(version: str | None, minimum: str | None, verdict: Check[str]) -> ScanItem:
        return ScanItem(target, version, minimum, source, verdict, version_source=version_source)

    detected, version_source = pyvenv.detect_runtime_with_venv(target.path, kind)
    if isinstance(detected, NotFound):
        return item(None, None, Undetermined(Reason.TARGET_MISSING, "target path does not exist"))
    if isinstance(detected, Undetermined):
        return item(None, None, detected)
    read = detected.value.version
    if isinstance(read, Undetermined):
        return item(None, None, read)
    text = read.value
    version = parse_version(text)
    if version is None:
        detail = f"version {text!r} is not plain N.N.N; not compared"
        return item(text, None, Undetermined(Reason.MALFORMED_VERSION_RESOURCE, detail))
    minimum = _minimum_for(kind, baseline, version)
    if minimum is None:
        series = ".".join(map(str, _series(kind, version)))
        detail = f"no --min for {kind.value} series {series}"
        return item(text, None, Undetermined(Reason.NO_BASELINE, detail))
    minimum_version = parse_version(minimum)
    assert minimum_version is not None  # validated by parse_baselines
    if version < minimum_version:
        return item(text, minimum, Found(text))
    return item(text, minimum, NotFound())


def scan(targets: Sequence[Target], kind: RuntimeKind, baselines: dict[str, Baseline]) -> list[ScanItem]:
    baseline = baselines.get(kind.value)
    return [scan_target(target, kind, baseline) for target in targets]


@dataclass(slots=True)
class PackageWalk:
    path: str
    packages_registered: int
    walked: int = 0
    unreadable: int = 0
    absent: int = 0
    excluded: int = 0
    skipped_reparse_points: int = 0
    refused: tuple[str, ...] = ()

    def to_json(self) -> JSONObject:
        return {"path": self.path, "packages_registered": self.packages_registered,
                "walked": self.walked, "unreadable": self.unreadable, "absent": self.absent,
                "excluded": self.excluded, "skipped_reparse_points": self.skipped_reparse_points,
                # JSON literals remain nonempty even for empty names and safely
                # preserve every refused character without joining a path.
                "refused": [json.dumps(name, ensure_ascii=True) for name in self.refused],
                "note": windows_walk.PACKAGE_NOTE}


@dataclass(frozen=True, slots=True)
class WalkResult:
    """What walking one ``--root`` saw. ``matched_files`` is before de-duplication."""

    root: str
    missing: bool
    matched_files: tuple[str, ...]
    unreadable_dirs: tuple[tuple[str, str], ...]  # (directory, OS error type)
    skipped_reparse_points: int
    excluded_dirs: int
    package_root: PackageWalk | None = None
    package_root_error: str | None = None
    skipped_protected: tuple[str, ...] = ()

    def to_json(self) -> JSONObject:
        result: JSONObject = {
            "root": self.root,
            "matched_files": len(self.matched_files),
            "unreadable_dirs": len(self.unreadable_dirs),
            "skipped_reparse_points": self.skipped_reparse_points,
            "excluded_dirs": self.excluded_dirs,
        }
        if self.package_root is not None:
            result["package_root"] = self.package_root.to_json()
        if self.package_root_error is not None:
            result["package_root_error"] = self.package_root_error
        if self.skipped_protected:
            result["skipped_protected"] = [
                {"path": path, "reason": windows_walk.PROTECTED_REASON} for path in self.skipped_protected
            ]
            result["skipped_protected_count"] = len(self.skipped_protected)
        return result


def _points_to_directory(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir()
    except OSError:
        return False


_SEPARATORS = tuple(sep for sep in (os.sep, os.altsep) if sep)


def _comparable(path: str) -> str:
    """``path`` with this OS's separators and case folded, so spellings compare equal.

    A trailing separator is kept: ``\\Temp\\`` still means "a component named Temp".
    """
    folded = os.path.normcase(os.path.normpath(path)).lower()
    if path.endswith(_SEPARATORS) and not folded.endswith(os.sep):
        folded += os.sep
    return folded


def _package_directories(
    package: PackageWalk, names: Sequence[str], needles: Sequence[str], unreadable: list[tuple[str, str]]
) -> list[tuple[str, str | None, bool]]:
    directories: list[tuple[str, str | None, bool]] = []
    refused: list[str] = []
    for name in sorted(names):
        if not windows_walk.valid_package_name(name):
            refused.append(name)
            continue
        path = os.path.join(package.path, name)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            package.absent += 1
            continue
        except OSError as error:
            package.unreadable += 1
            unreadable.append((path, f"{type(error).__name__}: Store package {name!r}"))
            continue
        try:
            if _is_reparse_point(Path(path)):
                package.skipped_reparse_points += 1
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise NotADirectoryError()
        except OSError as error:
            package.unreadable += 1
            unreadable.append((path, f"{type(error).__name__}: Store package {name!r}"))
            continue
        candidate = _comparable(path) + os.sep
        if any(needle in candidate for needle in needles):
            package.excluded += 1
        else:
            directories.append((path, name, True))
    package.refused = tuple(refused)
    return directories


def walk_root(root: str, file_name: str, excludes: Sequence[str]) -> WalkResult:
    """Depth-first, entries sorted by name in each directory, links not followed.

    ``excludes`` are case-insensitive substrings of a subdirectory's full path,
    compared after normalising separators on both sides (on Windows ``/`` and
    ``\\`` are the same); a matching subdirectory is not entered. The root itself
    is always entered. ``root`` and every reported path are in ``os.path.normpath``
    form, so they never mix separators.
    """
    root = os.path.normpath(root)
    if not os.path.lexists(root):
        return WalkResult(root, True, (), (), 0, 0)
    wanted = file_name.lower()
    needles = [_comparable(text) for text in excludes if text != ""]
    matched: list[str] = []
    unreadable: list[tuple[str, str]] = []
    skipped = 0
    excluded = 0
    protected: list[str] = []
    package: PackageWalk | None = None
    package_error: str | None = None
    registry_checked = False
    root_identity_unavailable = False
    registry_root: str | None = None
    stack: list[tuple[str, str | None, bool]] = [(root, None, False)]
    while stack:
        directory, package_name, package_entry = stack.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError as error:
            detail = type(error).__name__
            if package_name is not None:
                detail += f": Store package {package_name!r}"
            if package_entry:
                assert package is not None
                package.unreadable += 1
                unreadable.append((directory, detail))
                continue
            if not registry_checked:
                registry_checked = True
                try:
                    registry_root = windows_walk.read_package_root()
                except windows_walk.PackageReadError as registry_error:
                    package_error = str(registry_error)
                    root_identity_unavailable = True
            if registry_root is not None and _path_key(directory) == _path_key(registry_root):
                try:
                    names = windows_walk.registered_packages()
                except windows_walk.PackageReadError as registry_error:
                    package_error = str(registry_error)
                else:
                    package = PackageWalk(directory, len(names))
                    directories = _package_directories(package, names, needles, unreadable)
                    skipped += package.skipped_reparse_points
                    excluded += package.excluded
                    stack.extend(reversed(directories))
                    continue
            elif not root_identity_unavailable and isinstance(error, PermissionError) and windows_walk.permissions_access_denied(directory):
                protected.append(directory)
                continue
            unreadable.append((directory, detail))
            continue
        if package_entry:
            assert package is not None
            package.walked += 1
        subdirs: list[str] = []
        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                name_matches = entry.name.lower() == wanted
                if not (is_dir or name_matches or entry.is_symlink()):
                    continue
                if _is_reparse_point(entry):
                    if is_dir or name_matches or _points_to_directory(entry):
                        skipped += 1
                    continue
                is_file = entry.is_file(follow_symlinks=False)
            except OSError as error:
                unreadable.append((entry.path, type(error).__name__))
                continue
            if is_dir:
                candidate = _comparable(entry.path) + os.sep
                if any(needle in candidate for needle in needles):
                    excluded += 1
                else:
                    subdirs.append(entry.path)
            elif name_matches and is_file:
                matched.append(entry.path)
        stack.extend((path, package_name, False) for path in reversed(subdirs))
    return WalkResult(root, False, tuple(matched), tuple(unreadable), skipped, excluded,
                      package, package_error, tuple(protected))


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def scan_with_walks(
    targets: Sequence[Target],
    walks: Sequence[WalkResult],
    kind: RuntimeKind,
    baselines: dict[str, Baseline],
) -> list[ScanItem]:
    """Explicit targets first, then per root its new files and its directory items.

    A walked file already given by ``--targets`` or ``--path`` (or by an earlier
    root) is not scanned again; the explicit target keeps its product name.
    """
    baseline = baselines.get(kind.value)
    source = baseline.source if baseline is not None else None
    items = [scan_target(target, kind, baseline) for target in targets]
    seen = {_path_key(target.path) for target in targets}
    for walk in walks:
        for path in walk.matched_files:
            key = _path_key(path)
            if key in seen:
                continue
            seen.add(key)
            items.append(scan_target(Target(path, infer_product(path)), kind, baseline))
        problems: list[tuple[str, Undetermined]] = []
        if walk.missing:
            problems.append((walk.root, Undetermined(Reason.TARGET_MISSING, "root does not exist")))
        problems += [(path, Undetermined(Reason.FILE_UNREADABLE, error)) for path, error in walk.unreadable_dirs]
        for path, verdict in problems:
            target = Target(path, infer_product(path))
            items.append(ScanItem(target, None, None, source, verdict, LOCATION_DIRECTORY))
    return items


def scan_document(
    items: Sequence[ScanItem],
    kind: RuntimeKind,
    baselines: dict[str, Baseline],
    generated: datetime.datetime | None = None,
    walks: Sequence[WalkResult] = (),
) -> JSONObject:
    when = generated if generated is not None else datetime.datetime.now().astimezone()
    counts = {"targets": len(items), "found": 0, "not_found": 0, "undetermined": 0}
    for scanned in items:
        if isinstance(scanned.verdict, Found):
            counts["found"] += 1
        elif isinstance(scanned.verdict, NotFound):
            counts["not_found"] += 1
        else:
            counts["undetermined"] += 1
    return {
        "tool": "patchwait",
        "schema": SCHEMA,
        "generated": when.isoformat(timespec="seconds"),
        "kind": kind.value,
        "baselines": {name: baseline.to_json() for name, baseline in baselines.items()},
        "counts": dict(counts),
        "walk": [walk.to_json() for walk in walks],
        "items": [scanned.to_json() for scanned in items],
    }


def write_atomic(path: str, text: str) -> None:
    """Write UTF-8 next to ``path``, then replace it; escape lone surrogates.

    Windows filenames can contain lone surrogates. Backslash escapes keep JSON
    values intact when read back, while ordinary Unicode keeps its UTF-8 bytes.
    """
    directory = os.path.dirname(os.path.abspath(path))
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", errors="backslashreplace", newline="\n", dir=directory,
        prefix=".patchwait-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
