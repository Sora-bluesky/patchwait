"""Reject commits and pushes that would publish internal files, markers or identities.

Subcommands:
  staged            check the index and the new commit's author/committer
                    ident (pre-commit)
  message FILE      check a commit message file (commit-msg)
  range [--remote NAME] [--url URL] OLD NEW
                    check commits reachable from NEW and not from OLD (pre-push).
                    When OLD is zero or unknown here, check what NAME's
                    remote-tracking refs do not have, but only when those refs
                    describe the push target (see below); otherwise the whole
                    history of NEW
  revs [--remote NAME] [--url URL] OLD NEW
                    print the rev-list arguments range would check, on one
                    line (pre-push passes them to gitleaks as --log-opts)
  all               check every commit reachable from any ref

Remote-tracking refs (refs/remotes/NAME/*) reflect NAME's fetch URL, so they
stand for "what the push target already has" only when all of these hold:
NAME matches [A-Za-z0-9._-]+ and does not start with "-"; NAME has exactly one
push URL and it equals its fetch URL; URL (pre-push $2, where the push really
goes) equals that URL; no other remote is named NAME/...; and NAME has at least
one remote-tracking ref. Stale
tracking refs still count as published: run `git fetch --prune` first.

For range and all, each commit's tree paths and blobs are checked, and so is
the commit object itself (author and committer ident lines, full message).

Paths must match the allowlist (tools/publish-allowlist.txt) and must not match
any `internal_paths` glob of the guard file (case-insensitive). Blob contents
must not contain any marker from the markers file. Author and committer emails
must be listed in the guard file's `allowed_identities`. For range, no pushed
commit may be reachable from a ref listed in `local_only_refs` (refs that do
not exist locally are ignored).

Both files are untracked and are read from the repository top level:
  .local/publish-markers.txt  one literal per line, or `re:<regex>`
  .local/publish-guard.json   {"internal_paths": [glob, ...],
                               "allowed_identities": [email, ...],
                               "local_only_refs": [full ref name, ...]}
A missing, unreadable, empty or invalid markers or guard file fails closed.

Exit codes: 0 clean, 1 violations found, 2 usage or internal error.
Matched marker text and line contents are never printed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

ZERO_SHA_RE = re.compile(r"^0+$")

DEFAULT_ALLOWLIST = "tools/publish-allowlist.txt"
DEFAULT_MARKERS = ".local/publish-markers.txt"
DEFAULT_GUARD = ".local/publish-guard.json"


class CheckError(Exception):
    """Usage or environment problem; reported with exit code 2."""


# ---------------------------------------------------------------- git helpers


def git(args: list[str], *, stdin: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            ["git", *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise CheckError(f"cannot run git: {exc}") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise CheckError(f"git {' '.join(args)} failed: {err}")
    return proc.stdout


def git_ok(args: list[str]) -> bool:
    try:
        proc = subprocess.run(
            ["git", *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0


def decode_path(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


class BlobReader:
    """Reads objects (blobs, commits) by sha through one `git cat-file --batch` process."""

    def __init__(self) -> None:
        try:
            self._proc = subprocess.Popen(
                ["git", "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
        except OSError as exc:
            raise CheckError(f"cannot run git: {exc}") from exc

    def read(self, sha: str) -> bytes:
        stdin = self._proc.stdin
        stdout = self._proc.stdout
        if stdin is None or stdout is None:
            raise CheckError("git cat-file pipes are not available")
        stdin.write(sha.encode("ascii") + b"\n")
        stdin.flush()
        header = stdout.readline()
        parts = header.split()
        if len(parts) != 3:
            raise CheckError(f"cannot read blob {sha}")
        size = int(parts[2])
        data = stdout.read(size)
        stdout.read(1)  # trailing newline
        if len(data) != size:
            raise CheckError(f"short read for blob {sha}")
        return data

    def close(self) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        self._proc.wait()


# ------------------------------------------------------------------ allowlist


def glob_match(pattern: str, path: str) -> bool:
    """Match a slash-separated path against a glob with `**` segments.

    `*` and `?` stay inside one segment; a `**` segment matches zero or more
    whole segments. Matching is case-sensitive.
    """
    return _match_segments(pattern.split("/"), path.split("/"))


def _match_segments(pat: list[str], parts: list[str]) -> bool:
    if not pat:
        return not parts
    head = pat[0]
    if head == "**":
        rest = pat[1:]
        for i in range(len(parts) + 1):
            if _match_segments(rest, parts[i:]):
                return True
        return False
    if not parts:
        return False
    if not fnmatch.fnmatchcase(parts[0], head):
        return False
    return _match_segments(pat[1:], parts[1:])


def load_allowlist(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise CheckError(f"cannot read allowlist {path}: {exc.__class__.__name__}") from exc
    patterns = [ln.strip() for ln in lines]
    patterns = [p for p in patterns if p and not p.startswith("#")]
    if not patterns:
        raise CheckError(f"allowlist {path} has no patterns")
    return patterns


def is_internal(path: str, internal_paths: list[str]) -> bool:
    lower = path.lower()
    return any(glob_match(p.lower(), lower) for p in internal_paths)


def path_reason(path: str, allowlist: list[str], internal_paths: list[str]) -> str | None:
    if is_internal(path, internal_paths):
        return "internal path"
    if not any(glob_match(p, path) for p in allowlist):
        return "not in allowlist"
    return None


# ---------------------------------------------------------------------- guard


@dataclass(frozen=True)
class Guard:
    internal_paths: list[str]
    allowed_identities: frozenset[str]  # lower-cased emails
    local_only_refs: list[str]


GUARD_KEYS = ("internal_paths", "allowed_identities", "local_only_refs")


def load_guard(path: str) -> Guard:
    def fail(why: str) -> CheckError:
        return CheckError(f"guard file {path} {why}; refusing to continue (fail closed)")

    try:
        with open(path, encoding="utf-8-sig") as fh:
            data: object = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise fail(f"is missing or unreadable ({exc.__class__.__name__})") from exc
    except ValueError as exc:
        raise fail("is not valid JSON") from exc
    if not isinstance(data, dict):
        raise fail("is not a JSON object")
    values: dict[str, list[str]] = {}
    for key in GUARD_KEYS:
        value: object = data.get(key)  # pyright: ignore[reportUnknownMemberType]
        if not isinstance(value, list):
            raise fail(f"has no list `{key}`")
        items: list[str] = []
        for item in value:  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(item, str) or not item.strip():
                raise fail(f"has a non-string or empty entry in `{key}`")
            items.append(item.strip())
        values[key] = items
    if not values["allowed_identities"]:
        raise fail("has an empty `allowed_identities`")
    return Guard(
        internal_paths=values["internal_paths"],
        allowed_identities=frozenset(e.lower() for e in values["allowed_identities"]),
        local_only_refs=values["local_only_refs"],
    )


IDENT_EMAIL_RE = re.compile(r"<([^<>]*)>")


def ident_email(ident: str) -> str | None:
    m = IDENT_EMAIL_RE.search(ident)
    return m.group(1).strip().lower() if m is not None else None


def identity_allowed(ident: str, guard: Guard) -> bool:
    email = ident_email(ident)
    return email is not None and email in guard.allowed_identities


def existing_refs(refs: list[str]) -> list[str]:
    return [r for r in refs if git_ok(["rev-parse", "--verify", "-q", f"{r}^{{commit}}"])]


# -------------------------------------------------------------------- markers


@dataclass(frozen=True)
class Marker:
    index: int  # 1-based among marker lines
    line: int  # line number in the markers file
    regex: re.Pattern[str]


def load_markers(path: str) -> list[Marker]:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckError(
            f"markers file {path} is missing or unreadable ({exc.__class__.__name__}); "
            "refusing to continue (fail closed)"
        ) from exc
    markers: list[Marker] = []
    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        index = len(markers) + 1
        if raw.startswith("re:"):
            source = raw[3:]
        else:
            source = re.escape(raw)
        try:
            compiled = re.compile(source, re.IGNORECASE)
        except re.error as exc:
            raise CheckError(
                f"markers file {path}: marker #{index} (line {lineno}) is not a valid regex: {exc.msg}"
            ) from exc
        markers.append(Marker(index, lineno, compiled))
    if not markers:
        raise CheckError(f"markers file {path} has no markers; refusing to continue (fail closed)")
    return markers


def _decodings(data: bytes) -> list[tuple[str, str]]:
    views = [("utf-8", data.decode("utf-8", "replace"))]
    # UTF-16-LE at both byte alignments, so a marker in any wide string is seen.
    for offset in (0, 1):
        chunk = data[offset:]
        chunk = chunk[: len(chunk) - (len(chunk) % 2)]
        if chunk:
            views.append(("utf-16-le", chunk.decode("utf-16-le", "replace")))
    return views


def scan_blob(data: bytes, markers: list[Marker]) -> list[tuple[Marker, str, int]]:
    """Return (marker, encoding, line) for the first hit of each marker."""
    hits: list[tuple[Marker, str, int]] = []
    views = _decodings(data)
    for marker in markers:
        for encoding, text in views:
            m = marker.regex.search(text)
            if m is not None:
                line = text.count("\n", 0, m.start()) + 1
                hits.append((marker, encoding, line))
                break
    return hits


SCISSORS_RE = re.compile(r"^. -{24} >8 -{24}$", re.MULTILINE)


def scan_text(text: str, markers: list[Marker]) -> list[tuple[Marker, int]]:
    """Return (marker, line) for the first hit of each marker in text."""
    hits: list[tuple[Marker, int]] = []
    for marker in markers:
        m = marker.regex.search(text)
        if m is not None:
            hits.append((marker, text.count("\n", 0, m.start()) + 1))
    return hits


def commit_parts(raw: bytes) -> list[tuple[str, str]]:
    """Split a raw commit object into (part, text) for author, committer, message."""
    header, _, message = raw.partition(b"\n\n")
    parts: list[tuple[str, str]] = []
    for line in header.split(b"\n"):
        for name in ("author", "committer"):
            if line.startswith(name.encode("ascii") + b" "):
                parts.append((name, line.decode("utf-8", "replace")))
    parts.append(("message", message.decode("utf-8", "replace")))
    return parts


def scan_commit(raw: bytes, markers: list[Marker]) -> list[tuple[Marker, str]]:
    """Return (marker, part) for every part of the commit object a marker hits."""
    hits: list[tuple[Marker, str]] = []
    for part, text in commit_parts(raw):
        for marker, _line in scan_text(text, markers):
            if (marker, part) not in hits:
                hits.append((marker, part))
    hits.sort(key=lambda h: h[0].index)
    return hits


# --------------------------------------------------------------------- checks


@dataclass
class Report:
    violations: list[str]

    def add(self, text: str) -> None:
        self.violations.append(text)


def check_entries(
    entries: list[tuple[str, str, str]],
    where: str,
    allowlist: list[str],
    guard: Guard,
    markers: list[Marker],
    reader: BlobReader,
    seen_paths: set[tuple[str, str]],
    seen_blobs: set[str],
    report: Report,
    scan: set[str] | None = None,
) -> None:
    """entries: (mode, sha, path). scan: paths whose content is scanned (None = all)."""
    for mode, sha, path in entries:
        reason = path_reason(path, allowlist, guard.internal_paths)
        if reason is not None and (path, reason) not in seen_paths:
            seen_paths.add((path, reason))
            report.add(f"{path}: {reason} ({where})")
        if mode == "160000":  # submodule: no blob to read
            continue
        if scan is not None and path not in scan:
            continue
        if sha in seen_blobs:
            continue
        seen_blobs.add(sha)
        for marker, encoding, line in scan_blob(reader.read(sha), markers):
            enc = "" if encoding == "utf-8" else f", {encoding}"
            report.add(f"{path}: contains marker #{marker.index} ({where}, line {line}{enc})")


def parse_ls_files(raw: bytes) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        fields = meta.split()
        out.append((fields[0].decode(), fields[1].decode(), decode_path(path)))
    return out


def parse_ls_tree(raw: bytes) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, _kind, sha = meta.split()
        out.append((mode.decode(), sha.decode(), decode_path(path)))
    return out


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def run_staged(allowlist: list[str], guard: Guard, markers: list[Marker], report: Report) -> None:
    entries = parse_ls_files(git(["ls-files", "-s", "-z"]))
    base = "HEAD" if git_ok(["rev-parse", "--verify", "-q", "HEAD^{commit}"]) else EMPTY_TREE
    changed_raw = git(["diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=AM", base])
    changed = {decode_path(p) for p in changed_raw.split(b"\0") if p}
    reader = BlobReader()
    try:
        check_entries(entries, "index", allowlist, guard, markers, reader, set(), set(), report, changed)
    finally:
        reader.close()
    for part, var in (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT")):
        ident = git(["var", var]).decode("utf-8", "replace")
        if not identity_allowed(ident, guard):
            report.add(f"new commit: {part} email not allowed")
        for marker, _line in scan_text(ident, markers):
            report.add(f"new commit: contains marker #{marker.index} ({part})")


def run_message(path: str, markers: list[Marker], report: Report) -> None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise CheckError(f"cannot read message file {path}: {exc.__class__.__name__}") from exc
    text = raw.decode("utf-8", "replace")
    cut = SCISSORS_RE.search(text)  # git drops everything below the scissors line
    if cut is not None:
        text = text[: cut.start()]
    for marker, line in scan_text(text, markers):
        report.add(f"commit message: contains marker #{marker.index} (message, line {line})")


def run_commits(
    commits: list[str],
    allowlist: list[str],
    guard: Guard,
    markers: list[Marker],
    report: Report,
    *,
    check_local_only: bool = False,
) -> None:
    local_only = existing_refs(guard.local_only_refs) if check_local_only else []
    reader = BlobReader()
    seen_paths: set[tuple[str, str]] = set()
    seen_blobs: set[str] = set()
    try:
        for commit in commits:
            entries = parse_ls_tree(git(["ls-tree", "-r", "-z", "--full-tree", commit]))
            where = f"commit {commit[:10]}"
            raw = reader.read(commit)
            for part, text in commit_parts(raw):
                if part != "message" and not identity_allowed(text, guard):
                    report.add(f"{where}: {part} email not allowed")
            if any(git_ok(["merge-base", "--is-ancestor", commit, ref]) for ref in local_only):
                report.add(f"{where}: reachable from a local-only ref")
            for marker, part in scan_commit(raw, markers):
                report.add(f"{where}: contains marker #{marker.index} ({part})")
            check_entries(entries, where, allowlist, guard, markers, reader, seen_paths, seen_blobs, report)
    finally:
        reader.close()


def rev_list(args: list[str]) -> list[str]:
    raw = git(["rev-list", *args]).decode("ascii", "replace")
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def has_tracking_refs(remote: str) -> bool:
    return git(["for-each-ref", "--count=1", "--format=%(refname)", f"refs/remotes/{remote}/"]).strip() != b""


REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]*")


def git_lines(args: list[str]) -> list[str] | None:
    """Output lines of a git command, or None when it fails."""
    try:
        proc = subprocess.run(["git", *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return [ln.rstrip("\r") for ln in proc.stdout.decode("utf-8", "surrogateescape").split("\n") if ln.strip()]


def tracking_refs_describe_target(remote: str | None, url: str | None) -> bool:
    """Whether refs/remotes/<remote>/* say what the push target already has.

    They reflect the fetch URL, so they count only when the push goes to that
    same single URL. Anything else (a separate or extra push URL, a push to a
    URL, a name that is not a plain remote name) gets no exclusion.
    """
    if not remote or not url or REMOTE_NAME_RE.fullmatch(remote) is None:
        return False
    fetch = git_lines(["remote", "get-url", remote])
    push = git_lines(["remote", "get-url", "--push", "--all", remote])
    if fetch is None or push is None or len(fetch) != 1 or len(push) != 1:
        return False
    if not (push[0] == fetch[0] == url):
        return False
    # --remotes=NAME also takes refs/remotes/NAME/x/* of a remote named NAME/x.
    names = git_lines(["remote"])
    if names is None or any(name.startswith(remote + "/") for name in names):
        return False
    return has_tracking_refs(remote)


def range_args(old: str, new: str, remote: str | None = None, url: str | None = None) -> list[str]:
    """rev-list arguments for the commits a push of OLD -> NEW publishes ([] for a delete)."""
    if ZERO_SHA_RE.match(new):
        return []  # deleting a remote ref publishes nothing
    if not git_ok(["cat-file", "-e", f"{new}^{{commit}}"]):
        raise CheckError(f"unknown commit {new}")
    if ZERO_SHA_RE.match(old) or not git_ok(["cat-file", "-e", f"{old}^{{commit}}"]):
        # New remote ref, or the remote tip is not known locally: check what the
        # push target's remote-tracking refs do not have, when they describe the
        # push target. Commits only on another remote (a mirror, a backup) or
        # only on the fetch side are not on the target yet, so they count.
        # Otherwise (first push, a push to a URL, a different push URL): the
        # whole history.
        if remote is not None and tracking_refs_describe_target(remote, url):
            return [new, "--not", f"--remotes={remote}"]
        return [new]
    return [new, "--not", old]


def commits_for_range(old: str, new: str, remote: str | None = None, url: str | None = None) -> list[str]:
    args = range_args(old, new, remote, url)
    return rev_list(args) if args else []


# ----------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="publish_check.py", description="Reject commits and pushes that would publish internal files or markers.")
    parser.add_argument("--markers", help="markers file (default: <toplevel>/.local/publish-markers.txt)")
    parser.add_argument("--allowlist", help="allowlist file (default: <toplevel>/tools/publish-allowlist.txt)")
    parser.add_argument("--guard", help="guard file (default: <toplevel>/.local/publish-guard.json)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("staged", help="check the index and the new commit's idents (pre-commit)")
    msg = sub.add_parser("message", help="check a commit message file (commit-msg)")
    msg.add_argument("file")
    rng = sub.add_parser("range", help="check commits in NEW not in OLD (pre-push)")
    revs = sub.add_parser("revs", help="print the rev-list arguments range would check")
    for cmd in (rng, revs):
        cmd.add_argument("--remote", help="the push target's remote name (pre-push $1)")
        cmd.add_argument("--url", help="the URL the push goes to (pre-push $2)")
        cmd.add_argument("old")
        cmd.add_argument("new")
    sub.add_parser("all", help="check every commit reachable from any ref")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")
    args = sys.argv[1:] if argv is None else argv
    args = ["all" if a == "--all" else a for a in args]  # accept --all as an alias
    try:
        ns = build_parser().parse_args(args)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    try:
        markers_arg = os.path.abspath(ns.markers) if ns.markers else None
        allowlist_arg = os.path.abspath(ns.allowlist) if ns.allowlist else None
        guard_arg = os.path.abspath(ns.guard) if ns.guard else None
        message_arg = os.path.abspath(ns.file) if ns.command == "message" else None
        top = decode_path(git(["rev-parse", "--show-toplevel"]).strip())
        os.chdir(top)  # git path output is relative to the cwd; anchor it at the top
        if ns.command == "revs":
            print(" ".join(range_args(ns.old, ns.new, ns.remote, ns.url)))
            return 0
        markers = load_markers(markers_arg or os.path.join(top, DEFAULT_MARKERS))
        allowlist = load_allowlist(allowlist_arg or os.path.join(top, DEFAULT_ALLOWLIST))
        guard = load_guard(guard_arg or os.path.join(top, DEFAULT_GUARD))
        report = Report([])
        if ns.command == "staged":
            run_staged(allowlist, guard, markers, report)
        elif ns.command == "message":
            assert message_arg is not None
            run_message(message_arg, markers, report)
        elif ns.command == "range":
            commits = commits_for_range(ns.old, ns.new, ns.remote, ns.url)
            run_commits(commits, allowlist, guard, markers, report, check_local_only=True)
        else:
            run_commits(rev_list(["--all"]), allowlist, guard, markers, report)
    except CheckError as exc:
        print(f"publish_check: {exc}", file=sys.stderr)
        return 2
    if report.violations:
        for line in report.violations:
            print(line)
        print(f"publish_check: {len(report.violations)} violation(s); rejected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
