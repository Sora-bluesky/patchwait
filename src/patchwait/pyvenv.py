"""Python fallback versions from ``pyvenv.cfg`` or an install-manager ``.__target__``.

Both commands enter through ``detect_runtime_with_venv``. A file's own usable
version wins, then the existing venv route, then (only without an applicable cfg)
the exact filename's ``.__target__`` sidecar. The latter names one runtime PE;
it never follows another sidecar or uses version text from a configuration file.

A venv's ``python.exe`` (for example uv's trampoline) often carries no version
resource. The interpreter it starts is ``<home>\\python.exe`` named in the
venv's ``pyvenv.cfg``. This module only reads: ``pyvenv.cfg`` (bounded) and the
version resource of ``<home>\\python.exe``. Nothing is executed, and ``home``'s
own ``pyvenv.cfg`` is not followed.

Order: (1) the version resource of ``<home>\\python.exe`` with ProductName
``Python``; if ``version_info`` disagrees with it on major.minor the version is
``version_mismatch``. (2) Otherwise ``version_info`` when it is exactly
``N.N.N``. (3) Otherwise still ``no_version_resource``, with what was missing.

Only a target named ``python.exe`` is looked at. ``pyvenv.cfg`` must be a
regular file, not a link or reparse point, must not give a key twice and must
name ``home`` on at most one line, as lowercase ``home = ...`` (``duplicate_key``).
``<home>\\python.exe`` is opened only when it and every link on its way stay on a
local fixed drive (:mod:`patchwait.locality`); otherwise the item is undetermined
and nothing under ``home`` is opened. The locality check runs again after the
read; if the links it walked changed, or the open file's volume, file number, size
or write time changed while it was read, no version is taken.
When the home ``python.exe`` is read and has a version resource that gives no
usable version, or disagrees with ``version_info``, no version is taken
(``evidence`` is None). ``version_info`` is used instead only when the home
``python.exe`` is missing, unreadable, not a PE, has no version resource or is
another product.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import BinaryIO

from patchwait.locality import (
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    Locality,
    local_path_check,
    windows_file_attributes,
)
from patchwait.model import Check, Component, Found, JSONObject, Reason, RuntimeKind, Undetermined
from patchwait.pe_version import VersionInfo, detect_runtime, read_version_info_from, version_from_info

CFG_NAME = "pyvenv.cfg"
PYTHON_EXE = "python.exe"
MAX_CFG_BYTES = 64 * 1024
TARGET_SUFFIX = ".__target__"
MAX_TARGET_BYTES = 4096
EVIDENCE_TARGET = "install-manager-target-pe-version-resource"
EVIDENCE_HOME = "pyvenv-home-pe-version-resource"
EVIDENCE_VERSION_INFO = "pyvenv-cfg-version-info"
EVIDENCES = frozenset({EVIDENCE_HOME, EVIDENCE_VERSION_INFO})

# Digit runs are capped so int() never meets a huge run (CPython refuses > 4300 digits).
_PLAIN_VERSION_RE = re.compile(r"[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}")
_MAJOR_MINOR_ONLY_RE = re.compile(r"[0-9]{1,9}\.[0-9]{1,9}")
_MAJOR_MINOR_RE = re.compile(r"([0-9]{1,9})\.([0-9]{1,9})(?:\.[0-9]{1,9})?")
_ASCII_BLANKS = " \t"
# Reasons from reading the home python.exe after which version_info may still be used:
# nothing read from the file says it is an interpreter with a broken version resource.
_HOME_FALLBACK_REASONS = frozenset({Reason.FILE_UNREADABLE, Reason.NOT_PE, Reason.NO_VERSION_RESOURCE})
_PYTHON_PRODUCT = "Python"


@dataclass(frozen=True, slots=True)
class VersionSource:
    """What a venv version came from. ``evidence`` is None when no version was taken."""

    evidence: str | None
    pyvenv_cfg: str
    home: str | None
    version_info: str | None

    def to_json(self) -> JSONObject:
        return {
            "evidence": self.evidence,
            "pyvenv_cfg": self.pyvenv_cfg,
            "home": self.home,
            "version_info": self.version_info,
        }


@dataclass(frozen=True, slots=True)
class InstallManagerSource:
    """The sidecar and runtime path inspected; no evidence when no version was taken."""

    evidence: str | None
    target_file: str
    target: str | None

    def to_json(self) -> JSONObject:
        return {"evidence": self.evidence, "target_file": self.target_file, "target": self.target}


def detect_runtime_with_venv(
    path: str, kind: RuntimeKind,
) -> tuple[Check[Component], VersionSource | InstallManagerSource | None]:
    """Own version first, existing venv handling next, then an install-manager target."""
    detected = detect_runtime(path, kind)
    if kind is not RuntimeKind.PYTHON:
        return detected, None
    if isinstance(detected, Undetermined) and detected.reason is Reason.NO_VERSION_RESOURCE:
        from_venv = venv_runtime(path, detected)
        if from_venv is not None:
            return from_venv
    undetermined = isinstance(detected, Undetermined) or (
        isinstance(detected, Found) and isinstance(detected.value.version, Undetermined)
    )
    if undetermined:
        # A cfg applies only to python.exe. Keep venv eligibility and failure
        # results unchanged, including when its own PE names another product.
        if os.path.basename(path).lower() == PYTHON_EXE and find_cfg(path) is not None:
            return detected, None
        from_target = install_manager_runtime(path)
        if from_target is not None:
            return from_target
    return detected, None


def find_cfg(python_exe: str) -> str | None:
    """``pyvenv.cfg`` next to ``python.exe``, else one directory up (``<venv>\\Scripts``)."""
    directory = os.path.dirname(os.path.abspath(python_exe))
    for candidate in (os.path.join(directory, CFG_NAME), os.path.join(os.path.dirname(directory), CFG_NAME)):
        if os.path.lexists(candidate):
            return candidate
    return None


class DuplicateKeyError(ValueError):
    """A key appears more than once in ``pyvenv.cfg`` (keys compared case-insensitively), or ``home`` is ambiguous."""

    def __init__(self, key: str, detail: str | None = None) -> None:
        super().__init__(key)
        self.key = key
        self.detail = detail if detail is not None else f"pyvenv.cfg gives the key {key!r} more than once"


class MalformedCfgError(ValueError):
    """A key or value in ``pyvenv.cfg`` starts or ends with whitespace other than ASCII space or tab."""


def _odd_edge(text: str) -> bool:
    return text != "" and any(char.isspace() and char not in _ASCII_BLANKS for char in (text[0], text[-1]))


def _home_key(line: str) -> str | None:
    """The key of a line that looks like ``home`` in any case (also inside a ``#``/``;`` comment, ``=`` optional)."""
    body = line.strip(_ASCII_BLANKS).lstrip("#;").strip(_ASCII_BLANKS)
    key = body.partition("=")[0].strip(_ASCII_BLANKS)
    return key if key.lower() == "home" else None


def parse_cfg(text: str) -> dict[str, str]:
    """``key = value`` lines; keys are lower-cased; blanks, comments and lines without ``=`` are skipped.

    Lines end only at ``\\n`` (an ``\\r`` before it is dropped); U+2028, U+0085, ``\\v``
    and ``\\f`` stay inside the line. Only ASCII space and tab are trimmed around keys and
    values; other whitespace at their start or end raises :class:`MalformedCfgError`. A key
    given twice raises :class:`DuplicateKeyError`, and so do two or more lines that look like
    ``home`` (comments counted) or a single one that is not exactly ``home = ...``: neither
    value is trusted.
    """
    lines = [line.removesuffix("\r") for line in text.split("\n")]
    homes = [line for line in lines if _home_key(line) is not None]
    if len(homes) > 1 or (len(homes) == 1 and not re.fullmatch(r"[ \t]*home[ \t]*=.*", homes[0], re.DOTALL)):
        raise DuplicateKeyError("home", "pyvenv.cfg mentions home more than once or in another form")
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip(_ASCII_BLANKS)
        if stripped == "" or stripped.startswith(("#", ";")):
            continue
        raw_key, sep, raw_value = stripped.partition("=")
        if sep == "":
            continue
        key, value = raw_key.strip(_ASCII_BLANKS), raw_value.strip(_ASCII_BLANKS)
        if _odd_edge(key) or _odd_edge(value):
            raise MalformedCfgError(f"pyvenv.cfg key or value of {key.strip()!r} starts or ends with non-ASCII whitespace")
        key = key.lower()
        if key == "":
            continue
        if key in values:
            raise DuplicateKeyError(key)
        values[key] = value
    return values


def cfg_file_problem(mode: int, attributes: int, name: str = CFG_NAME) -> str | None:
    """Why an ``lstat`` result is not a plain regular file, or None."""
    if stat.S_ISLNK(mode) or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return f"{name} is a link or reparse point; not read"
    if not stat.S_ISREG(mode):
        return f"{name} is not a regular file; not read"
    return None


def _attributes(info: os.stat_result) -> int:
    attributes: object = getattr(info, "st_file_attributes", 0)
    return attributes if isinstance(attributes, int) else 0


def _read_plain_file(path: str, name: str, limit: int, *, strict: bool = False) -> bytes | Undetermined:
    """Shared bounded regular-file read; strict sidecars also refuse changes."""
    def unreadable(error: OSError) -> Undetermined:
        return Undetermined(Reason.NO_VERSION_RESOURCE, f"{name} is unreadable: {type(error).__name__}")

    try:
        before = os.lstat(path)
        attributes = _attributes(before)
        if os.name == "nt":
            # lstat can hide reparse points that are not symlinks or junctions.
            attributes |= windows_file_attributes(path)
    except OSError as error:
        return unreadable(error)
    problem = cfg_file_problem(before.st_mode, attributes, name)
    if problem is not None:
        return Undetermined(Reason.NO_VERSION_RESOURCE, problem)
    recall = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    if attributes & recall:
        return Undetermined(Reason.NO_VERSION_RESOURCE, f"{name} is offline or recalled on access; not read")
    try:
        with open(path, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return Undetermined(Reason.NO_VERSION_RESOURCE, f"{name} changed while being opened; not read")
            data = handle.read(limit + 1)
            if strict and (
                _file_state(os.fstat(handle.fileno())) != _file_state(opened)
                or _file_state(os.lstat(path)) != _file_state(before)
            ):
                return Undetermined(Reason.NO_VERSION_RESOURCE, f"{name} changed while it was read; not used")
    except OSError as error:
        return unreadable(error)
    if len(data) > limit:
        return Undetermined(Reason.NO_VERSION_RESOURCE, f"{name} is larger than {limit} bytes; not read")
    return data


def _read_cfg(path: str) -> str | Undetermined:
    data = _read_plain_file(path, CFG_NAME, MAX_CFG_BYTES)
    if isinstance(data, Undetermined):
        return data
    return data.decode("utf-8-sig", errors="replace")


class _Stop(str):
    """A ``_home_version`` text that ends the lookup: ``home`` is not trusted, so nothing else is."""


def _file_state(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _handle_state(stream: BinaryIO) -> tuple[int, int, int, int]:
    return _file_state(os.fstat(stream.fileno()))


def _read_home_exe(exe: str) -> tuple[Found[VersionInfo] | Undetermined, bool]:
    """The version info of ``exe``, opened once, and whether the open file changed while it was read."""
    try:
        stream = open(exe, "rb")
    except OSError as error:
        return Undetermined(Reason.FILE_UNREADABLE, type(error).__name__), False
    with stream:
        try:
            before = _handle_state(stream)
            info = read_version_info_from(stream)
            after = _handle_state(stream)
        except OSError as error:
            return Undetermined(Reason.FILE_UNREADABLE, type(error).__name__), True
    return info, before != after


def _read_local_exe(exe: str) -> tuple[Found[VersionInfo] | Undetermined | None, Locality, bool]:
    """Check locality, read a local executable, and check for changes afterward."""
    checked = local_path_check(exe)
    if checked.problem is not None:
        return None, checked, False
    info, changed = _read_home_exe(exe)
    return info, checked, changed or local_path_check(exe) != checked


def _home_version(home: str | None) -> Found[str] | Undetermined | str:
    """The home python.exe's version check, or a text saying why it is not usable.

    ``<home>\\python.exe`` is checked for locality (see :mod:`patchwait.locality`) before it is
    opened and again after it is read; it is opened once and read through that one handle. That
    narrows, but does not close, the window in which a writer in the scanned tree can swap a link
    between the check and the open.
    """
    if home is None:
        return "pyvenv.cfg has no home"
    exe = os.path.join(home, PYTHON_EXE)
    info, checked, changed = _read_local_exe(exe)
    if checked.missing:
        return f"home python.exe is missing ({checked.problem}); not read"
    if checked.problem is not None:
        return _Stop(f"pyvenv.cfg home is not a local fixed-drive path ({checked.problem}); home not read")
    if changed:
        return _Stop("home changed while it was read; no version taken")
    assert info is not None
    if isinstance(info, Undetermined):
        if info.reason not in _HOME_FALLBACK_REASONS:
            return info
        if info.reason is Reason.FILE_UNREADABLE:
            return f"home python.exe is unreadable: {info.detail}"
        return f"home python.exe gives {info.reason.value}: {info.detail}"
    product = info.value.product_name
    if product != _PYTHON_PRODUCT:
        return f"home python.exe ProductName {product!r}, expected {_PYTHON_PRODUCT!r}"
    return version_from_info(info.value)


def install_manager_runtime(python_exe: str) -> tuple[Found[Component] | Undetermined, InstallManagerSource] | None:
    """Read one exact-name sidecar and one local runtime PE; never recurse or execute."""
    sidecar = os.path.abspath(python_exe) + TARGET_SUFFIX
    if not os.path.lexists(sidecar):
        return None
    target: str | None = None

    def refused(reason: Reason, detail: str) -> tuple[Undetermined, InstallManagerSource]:
        shown_target = target if target and target.strip() else None
        return Undetermined(reason, f"__target__ route: {detail}"), InstallManagerSource(None, sidecar, shown_target)

    data = _read_plain_file(sidecar, "__target__ sidecar", MAX_TARGET_BYTES, strict=True)
    if isinstance(data, Undetermined):
        return refused(data.reason, data.detail)
    if data.startswith(b"\xef\xbb\xbf"):
        return refused(Reason.NO_VERSION_RESOURCE, "sidecar has a UTF-8 BOM; not used")
    try:
        target = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return refused(Reason.NO_VERSION_RESOURCE, "sidecar is not valid UTF-8; not used")
    if not target:
        return refused(Reason.NO_VERSION_RESOURCE, "sidecar is empty; not used")
    if "\0" in target:
        return refused(Reason.NO_VERSION_RESOURCE, "sidecar contains NUL; not used")
    if "\r" in target or "\n" in target:
        return refused(Reason.NO_VERSION_RESOURCE, "sidecar contains CR or LF; not used")
    info, checked, changed = _read_local_exe(target)
    if checked.missing:
        return refused(Reason.NO_VERSION_RESOURCE, f"target is missing ({checked.problem}); not read")
    if checked.problem is not None:
        return refused(Reason.NO_VERSION_RESOURCE, f"target is not a local fixed-drive path ({checked.problem}); not read")
    if changed:
        return refused(Reason.NO_VERSION_RESOURCE, "target changed while it was read; no version taken")
    assert info is not None
    if isinstance(info, Undetermined):
        return refused(info.reason, f"target gives {info.reason.value}: {info.detail}")
    if info.value.product_name != _PYTHON_PRODUCT:
        return refused(Reason.UNEXPECTED_PRODUCT, f"target ProductName {info.value.product_name!r}, expected {_PYTHON_PRODUCT!r}")
    version = version_from_info(info.value)
    if isinstance(version, Undetermined):
        return refused(version.reason, f"target: {version.detail}")
    component = Component(RuntimeKind.PYTHON, python_exe, version, EVIDENCE_TARGET)
    return Found(component), InstallManagerSource(EVIDENCE_TARGET, sidecar, target)


def _version_info_problem(version_info: str | None) -> str:
    if version_info is None or version_info == "":
        return "pyvenv.cfg has no version_info"
    if _MAJOR_MINOR_ONLY_RE.fullmatch(version_info):
        return f"pyvenv.cfg version_info is {version_info} (major.minor only)"
    return f"pyvenv.cfg version_info {version_info!r} is not N.N.N"


def _major_minor(text: str) -> tuple[int, int] | None:
    """Major and minor of exactly ``N.N`` or ``N.N.N`` (parts of 1 to 9 ASCII digits), else None."""
    match = _MAJOR_MINOR_RE.fullmatch(text)
    return None if match is None else (int(match.group(1)), int(match.group(2)))


def venv_runtime(
    python_exe: str, no_resource: Undetermined
) -> tuple[Found[Component] | Undetermined, VersionSource] | None:
    """For a ``python.exe`` without a version resource: the runtime from its ``pyvenv.cfg``.

    None when the file is not named ``python.exe`` or there is no ``pyvenv.cfg``; the caller keeps ``no_resource``.
    """
    if os.path.basename(python_exe).lower() != PYTHON_EXE:
        return None
    cfg = find_cfg(python_exe)
    if cfg is None:
        return None
    text = _read_cfg(cfg)
    if isinstance(text, Undetermined):
        detail = f"{no_resource.detail}; {text.detail}"
        return Undetermined(Reason.NO_VERSION_RESOURCE, detail), VersionSource(None, cfg, None, None)
    try:
        values = parse_cfg(text)
    except DuplicateKeyError as error:
        detail = f"{no_resource.detail}; {error.detail}; neither value used"
        return Undetermined(Reason.DUPLICATE_KEY, detail), VersionSource(None, cfg, None, None)
    except MalformedCfgError as error:
        detail = f"{no_resource.detail}; {error}; pyvenv.cfg not used"
        return Undetermined(Reason.MALFORMED_VERSION_RESOURCE, detail), VersionSource(None, cfg, None, None)
    home = values.get("home")
    version_info = values.get("version_info") or None

    def component(version: Found[str], evidence: str) -> tuple[Found[Component], VersionSource]:
        found = Component(RuntimeKind.PYTHON, python_exe, version, evidence)
        return Found(found), VersionSource(evidence, cfg, home, version_info)

    def no_version(reason: Reason, detail: str) -> tuple[Undetermined, VersionSource]:
        return Undetermined(reason, detail), VersionSource(None, cfg, home or None, version_info)

    home_version = _home_version(home)
    if isinstance(home_version, _Stop):
        return no_version(Reason.NO_VERSION_RESOURCE, f"{no_resource.detail}; {home_version}")
    if isinstance(home_version, Undetermined):
        return no_version(home_version.reason, f"home python.exe: {home_version.detail}")
    if isinstance(home_version, Found):
        if version_info is not None:
            want = _major_minor(version_info)
            got = _major_minor(home_version.value)
            if want is None:
                detail = (
                    f"pyvenv.cfg version_info {version_info!r} is not N.N or N.N.N; "
                    f"not compared with home python.exe {home_version.value!r}"
                )
                return no_version(Reason.MALFORMED_VERSION_RESOURCE, detail)
            if got is None:
                detail = (
                    f"home python.exe version {home_version.value!r} is not N.N.N; "
                    f"not compared with pyvenv.cfg version_info {version_info!r}"
                )
                return no_version(Reason.MALFORMED_VERSION_RESOURCE, detail)
            if want != got:
                detail = f"pyvenv.cfg version_info {version_info!r} disagrees with home python.exe {home_version.value!r}"
                return no_version(Reason.VERSION_MISMATCH, detail)
        return component(home_version, EVIDENCE_HOME)
    if version_info is not None and _PLAIN_VERSION_RE.fullmatch(version_info):
        return component(Found(version_info), EVIDENCE_VERSION_INFO)
    detail = f"{no_resource.detail}; {_version_info_problem(version_info)} and {home_version}"
    return no_version(Reason.NO_VERSION_RESOURCE, detail)
