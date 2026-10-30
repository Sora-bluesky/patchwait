"""Tests for tools/publish_check.py and the .githooks scripts, in throwaway repos."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import ModuleType

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "publish_check.py")
HOOKS = os.path.join(ROOT, ".githooks")
ZERO = "0" * 40

# Built at runtime so this file does not itself match the session-id marker.
SYNTH_ID = "local_" + "0123abcd"
MARKERS = "# synthetic markers\nsynthuser\n\nre:local_[0-9a-f]{8}\n"
ALLOWLIST = "# synthetic\nsrc/**/*.py\nREADME.md\nbin/*\ntools/*\n"
ALLOWED_EMAIL = "test@example.invalid"
OTHER_EMAIL = "someone-else@example.invalid"
LOCAL_ONLY = "refs/heads/local-only"
GUARD: dict[str, list[str]] = {
    "internal_paths": ["**/SYNTH-NOTES.md", "**/.synthdir/**", "docs/synth-inner.md"],
    "allowed_identities": [ALLOWED_EMAIL],
    "local_only_refs": [LOCAL_ONLY, "refs/heads/does-not-exist"],
}
# A GitHub-token-shaped fake, built at runtime so this file holds no match.
FAKE_TOKEN = "ghp_" + "Zq8xLm3Rt7Vb2Nc9" + "Kp4Wd6Hs1Fg5Jy0Ua"
HAS_GIT = shutil.which("git") is not None
HAS_GITLEAKS = shutil.which("gitleaks") is not None


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("publish_check", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["publish_check"] = module
    spec.loader.exec_module(module)
    return module


class GlobTests(unittest.TestCase):
    def test_double_star(self) -> None:
        tool = _load_tool()
        self.assertTrue(tool.glob_match("src/**/*.py", "src/a.py"))
        self.assertTrue(tool.glob_match("src/**/*.py", "src/x/y/a.py"))
        self.assertFalse(tool.glob_match("src/**/*.py", "src/a.txt"))
        self.assertFalse(tool.glob_match(".githooks/*", ".githooks/x/y"))
        self.assertTrue(tool.glob_match(".githooks/*", ".githooks/pre-push"))
        self.assertFalse(tool.glob_match("README.md", "readme.md"))
        self.assertTrue(tool.glob_match("**", "a/b/c"))


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="publish-check-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        global_cfg = os.path.join(self.tmp, "global.gitconfig")
        with open(global_cfg, "w", encoding="utf-8", newline="\n"):
            pass
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_CONFIG_GLOBAL"] = global_cfg
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["HOME"] = self.tmp
        self.env = env
        self.global_cfg = global_cfg
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", ALLOWED_EMAIL)
        self.git("config", "commit.gpgsign", "false")
        self.markers = self.write_file(os.path.join(self.tmp, "markers.txt"), MARKERS)
        self.allowlist = self.write_file(os.path.join(self.tmp, "allow.txt"), ALLOWLIST)
        self.guard = self.write_file(os.path.join(self.tmp, "guard.json"), json.dumps(GUARD))

    # helpers -------------------------------------------------------------

    def write_file(self, path: str, text: str) -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return path

    def git(self, *args: str, stdin: bytes | None = None, env: dict[str, str] | None = None) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            input=stdin,
            capture_output=True,
            env=env or self.env,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"git {args} failed: {proc.stderr.decode('utf-8', 'replace')}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def check(self, *args: str, markers: str | None = None, guard: str | None = None) -> tuple[int, str]:
        opts = ["--markers", markers or self.markers, "--allowlist", self.allowlist, "--guard", guard or self.guard]
        proc = subprocess.run(
            [sys.executable, "-I", TOOL, *opts, *args],
            cwd=self.repo,
            capture_output=True,
            env=self.env,
            check=False,
        )
        out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        return proc.returncode, out

    def stage(self, path: str, data: bytes) -> None:
        full = os.path.join(self.repo, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
        self.git("add", "-f", "--", path)

    def blob(self, data: bytes) -> str:
        return self.git("hash-object", "-w", "--stdin", stdin=data)

    def tree(self, files: dict[str, bytes]) -> str:
        index = os.path.join(self.tmp, "plumbing.index")
        if os.path.exists(index):
            os.remove(index)
        env = dict(self.env, GIT_INDEX_FILE=index)
        for path, data in files.items():
            self.git("update-index", "--add", "--cacheinfo", f"100644,{self.blob(data)},{path}", env=env)
        return self.git("write-tree", env=env)

    def commit(
        self, files: dict[str, bytes], *parents: str, message: str = "c", env: dict[str, str] | None = None
    ) -> str:
        args = ["commit-tree", self.tree(files), "-m", message]
        for p in parents:
            args += ["-p", p]
        return self.git(*args, env=dict(self.env, **(env or {})))

    def publish(self, sha: str, name: str = "origin") -> None:
        """Put sha on a bare remote `name` as main and fetch it back as <name>/main.

        The remote pulls the commit, so no push (and no pre-push hook) runs.
        """
        remote = os.path.join(self.tmp, f"{name}.git")
        if not os.path.isdir(remote):
            self.git("init", "-q", "--bare", remote)
            # What `git remote add` writes, without its check that names do not nest.
            self.git("config", f"remote.{name}.url", remote.replace("\\", "/"))
            self.git("config", f"remote.{name}.fetch", f"+refs/heads/*:refs/remotes/{name}/*")
        self.git("update-ref", "refs/heads/published", sha)
        self.git("--git-dir", remote, "fetch", "-q", self.repo.replace("\\", "/"), "+published:refs/heads/main")
        self.git("update-ref", "-d", "refs/heads/published")
        self.git("fetch", "-q", name)
        self.assertEqual(self.git("rev-parse", f"refs/remotes/{name}/main"), sha)

    def url(self, name: str) -> str:
        return self.git("remote", "get-url", name)

    def bare(self, name: str) -> str:
        """A bare repository that is not a remote here; returns its URL."""
        path = os.path.join(self.tmp, f"{name}.git")
        self.git("init", "-q", "--bare", path)
        return path.replace("\\", "/")

    def assert_no_leak(self, out: str) -> None:
        self.assertNotIn("synthuser", out.lower())
        self.assertNotIn(SYNTH_ID, out)
        self.assertNotIn("secret line", out)
        self.assertNotIn(OTHER_EMAIL, out)
        self.assertNotIn(FAKE_TOKEN, out)


@unittest.skipUnless(HAS_GIT, "git is not on PATH")
class StagedTests(RepoCase):
    def test_allowed_clean_passes(self) -> None:
        self.stage("src/pkg/a.py", b"print('ok')\n")
        self.stage("README.md", b"# demo\n")
        self.assertEqual(self.check("staged"), (0, ""))

    def test_path_not_in_allowlist(self) -> None:
        self.stage("notes.txt", b"hello\n")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("notes.txt: not in allowlist", out)

    def test_internal_path_rejected_even_if_allowlisted(self) -> None:
        self.write_file(self.allowlist, "**\n")
        self.stage("synth-notes.md", b"x\n")
        self.stage("src/deep/Synth-Notes.MD", b"x\n")
        self.stage("docs/synth-inner.md", b"x\n")
        self.stage(".synthdir/thing.txt", b"x\n")
        self.stage("a/.SynthDir/b/c.txt", b"x\n")
        self.stage("other/docs/synth-inner.md", b"x\n")
        self.stage("src/ok.py", b"x\n")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        for path in ("synth-notes.md", "src/deep/Synth-Notes.MD", "docs/synth-inner.md",
                     ".synthdir/thing.txt", "a/.SynthDir/b/c.txt"):
            self.assertIn(f"{path}: internal path (index)", out)
        self.assertNotIn("other/docs/synth-inner.md", out)
        self.assertNotIn("src/ok.py", out)

    def test_missing_guard_fails_closed(self) -> None:
        self.stage("src/a.py", b"ok\n")
        rc, out = self.check("staged", guard=os.path.join(self.tmp, "nope.json"))
        self.assertEqual(rc, 2)
        self.assertIn("fail closed", out)

    def test_invalid_guard_fails_closed(self) -> None:
        self.stage("src/a.py", b"ok\n")
        broken = dict(GUARD)
        del broken["local_only_refs"]
        cases = {
            "not json": "{",
            "not an object": "[]",
            "missing key": json.dumps(broken),
            "not a list": json.dumps(dict(GUARD, internal_paths="**")),
            "non-string entry": json.dumps(dict(GUARD, allowed_identities=[1])),
            "no identities": json.dumps(dict(GUARD, allowed_identities=[])),
        }
        for name, text in cases.items():
            path = self.write_file(os.path.join(self.tmp, "bad-guard.json"), text)
            rc, out = self.check("staged", guard=path)
            self.assertEqual(rc, 2, name)
            self.assertIn("fail closed", out, name)

    def test_disallowed_author_and_committer_email(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.git("config", "user.email", OTHER_EMAIL)
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("new commit: author email not allowed", out)
        self.assertIn("new commit: committer email not allowed", out)
        self.assert_no_leak(out)

    def test_disallowed_committer_email_only(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.env["GIT_COMMITTER_EMAIL"] = OTHER_EMAIL
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("new commit: committer email not allowed", out)
        self.assertNotIn("author", out)
        self.assert_no_leak(out)

    def test_allowed_email_is_case_insensitive(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.git("config", "user.email", ALLOWED_EMAIL.upper())
        self.assertEqual(self.check("staged"), (0, ""))

    def test_marker_in_content_not_printed(self) -> None:
        self.stage("src/a.py", b"x = 1\n# secret line SynthUser here\n")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("src/a.py: contains marker #1", out)
        self.assertIn("line 2", out)
        self.assert_no_leak(out)

    def test_utf16_marker_in_binary(self) -> None:
        self.stage("bin/tool.exe", b"MZ\x00\x01\xff" + "synthuser".encode("utf-16-le") + b"\x00\x00")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("bin/tool.exe: contains marker #1", out)
        self.assertIn("utf-16-le", out)
        self.assert_no_leak(out)

    def test_regex_marker(self) -> None:
        self.stage("src/a.py", b"id = '" + SYNTH_ID.encode() + b"'\n")
        self.stage("src/b.py", b"id = 'local_xyz'\n")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("src/a.py: contains marker #2", out)
        self.assertNotIn("src/b.py", out)
        self.assert_no_leak(out)

    def test_unchanged_staged_content_not_rescanned(self) -> None:
        commit = self.commit({"src/a.py": b"synthuser\n"})
        self.git("update-ref", "refs/heads/main", commit)
        self.git("read-tree", "HEAD")
        self.stage("src/b.py", b"ok\n")
        self.assertEqual(self.check("staged"), (0, ""))

    def test_marker_in_author_ident(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.git("config", "user.email", "synthuser@example.invalid")
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("new commit: contains marker #1 (author)", out)
        self.assertIn("new commit: contains marker #1 (committer)", out)
        self.assert_no_leak(out)

    def test_marker_in_committer_ident_only(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.env["GIT_COMMITTER_NAME"] = SYNTH_ID
        rc, out = self.check("staged")
        self.assertEqual(rc, 1)
        self.assertIn("new commit: contains marker #2 (committer)", out)
        self.assertNotIn("(author)", out)
        self.assert_no_leak(out)

    def test_missing_markers_fails_closed(self) -> None:
        self.stage("src/a.py", b"ok\n")
        rc, out = self.check("staged", markers=os.path.join(self.tmp, "nope.txt"))
        self.assertEqual(rc, 2)
        self.assertIn("fail closed", out)

    def test_empty_markers_fails_closed(self) -> None:
        self.stage("src/a.py", b"ok\n")
        empty = self.write_file(os.path.join(self.tmp, "empty.txt"), "# only comments\n\n")
        rc, out = self.check("staged", markers=empty)
        self.assertEqual(rc, 2)
        self.assertIn("no markers", out)

    def test_default_markers_path_is_toplevel(self) -> None:
        self.stage("src/a.py", b"ok\n")
        proc = subprocess.run(
            [sys.executable, "-I", TOOL, "--allowlist", self.allowlist, "--guard", self.guard, "staged"],
            cwd=os.path.join(self.repo, "src"),
            capture_output=True,
            env=self.env,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.write_file(os.path.join(self.repo, ".local", "publish-markers.txt"), MARKERS)
        proc = subprocess.run(
            [sys.executable, "-I", TOOL, "--allowlist", self.allowlist, "--guard", self.guard, "staged"],
            cwd=os.path.join(self.repo, "src"),
            capture_output=True,
            env=self.env,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)

    def test_default_guard_path_is_toplevel(self) -> None:
        self.stage("src/a.py", b"ok\n")
        cmd = [sys.executable, "-I", TOOL, "--allowlist", self.allowlist, "--markers", self.markers, "staged"]
        cwd = os.path.join(self.repo, "src")
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, env=self.env, check=False)
        self.assertEqual(proc.returncode, 2)
        self.write_file(os.path.join(self.repo, ".local", "publish-guard.json"), json.dumps(GUARD))
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, env=self.env, check=False)
        self.assertEqual(proc.returncode, 0)


@unittest.skipUnless(HAS_GIT, "git is not on PATH")
class HistoryTests(RepoCase):
    def make_history(self) -> tuple[str, str, str]:
        base = self.commit({"src/a.py": b"ok\n"})
        bad = self.commit({"src/a.py": b"ok\n", "notes.txt": b"x\n", "src/b.py": b"secret line synthuser\n"}, base)
        fixed = self.commit({"src/a.py": b"ok\n"}, bad)
        return base, bad, fixed

    def test_range_finds_deleted_bad_file(self) -> None:
        base, _bad, fixed = self.make_history()
        rc, out = self.check("range", base, fixed)
        self.assertEqual(rc, 1)
        self.assertIn("notes.txt: not in allowlist", out)
        self.assertIn("src/b.py: contains marker #1", out)
        self.assert_no_leak(out)

    def test_range_excludes_old(self) -> None:
        _base, bad, fixed = self.make_history()
        self.assertEqual(self.check("range", bad, fixed), (0, ""))

    def test_range_zero_old_means_all_history(self) -> None:
        _base, _bad, fixed = self.make_history()
        rc, out = self.check("range", ZERO, fixed)
        self.assertEqual(rc, 1)
        self.assertIn("notes.txt", out)

    def test_range_unknown_old_checks_all_history(self) -> None:
        _base, _bad, fixed = self.make_history()
        rc, _out = self.check("range", "1" * 40, fixed)
        self.assertEqual(rc, 1)

    def test_delete_push_passes(self) -> None:
        _base, _bad, fixed = self.make_history()
        self.assertEqual(self.check("range", fixed, ZERO), (0, ""))

    def test_all_mode(self) -> None:
        base, bad, _fixed = self.make_history()
        self.git("update-ref", "refs/heads/main", base)
        self.assertEqual(self.check("all"), (0, ""))
        self.git("update-ref", "refs/heads/side", bad)
        rc, out = self.check("all")
        self.assertEqual(rc, 1)
        self.assertIn("notes.txt", out)
        self.assertEqual(self.check("--all")[0], 1)

    def test_range_marker_in_commit_message(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        bad = self.commit({"src/a.py": b"ok\n"}, base, message="subject\n\nsecret line SynthUser\n")
        fixed = self.commit({"src/a.py": b"ok\n"}, bad)
        rc, out = self.check("range", base, fixed)
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {bad[:10]}: contains marker #1 (message)", out)
        self.assertNotIn(fixed[:10], out)
        self.assert_no_leak(out)

    def test_range_marker_in_author_email(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        bad = self.commit({"src/a.py": b"ok\n"}, base, env={"GIT_AUTHOR_EMAIL": "synthuser@example.invalid"})
        rc, out = self.check("range", base, bad)
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {bad[:10]}: contains marker #1 (author)", out)
        self.assertNotIn("(committer)", out)
        self.assertNotIn("(message)", out)
        self.assert_no_leak(out)

    def test_all_mode_marker_in_committer(self) -> None:
        bad = self.commit({"src/a.py": b"ok\n"}, env={"GIT_COMMITTER_NAME": SYNTH_ID})
        self.git("update-ref", "refs/heads/main", bad)
        rc, out = self.check("all")
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {bad[:10]}: contains marker #2 (committer)", out)
        self.assert_no_leak(out)

    def test_range_clean_idents_and_message_pass(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"}, message="clean subject\n\nclean body\n")
        self.assertEqual(self.check("range", ZERO, base), (0, ""))

    def test_all_mode_empty_repo(self) -> None:
        self.assertEqual(self.check("all"), (0, ""))

    def test_range_disallowed_author_email(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        bad = self.commit({"src/a.py": b"ok\n"}, base, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL})
        rc, out = self.check("range", base, bad)
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines()[0], f"commit {bad[:10]}: author email not allowed")
        self.assertNotIn("committer", out)
        self.assert_no_leak(out)

    def test_range_disallowed_committer_email(self) -> None:
        bad = self.commit({"src/a.py": b"ok\n"}, env={"GIT_COMMITTER_EMAIL": OTHER_EMAIL})
        rc, out = self.check("range", ZERO, bad)
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {bad[:10]}: committer email not allowed", out)
        self.assertNotIn("author", out)
        self.assert_no_leak(out)

    def test_new_branch_skips_commits_already_on_remote(self) -> None:
        # A squash merge on the remote: committed by an identity not allowed here.
        merged = self.commit({"src/a.py": b"ok\n"}, env={"GIT_COMMITTER_EMAIL": OTHER_EMAIL})
        self.publish(merged)
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, merged)
        url = self.url("origin")
        self.assertEqual(self.check("range", "--remote", "origin", "--url", url, ZERO, feat), (0, ""))
        self.assertEqual(self.check("range", "--remote", "origin", "--url", url, "1" * 40, feat), (0, ""))
        bad = self.commit({"src/a.py": b"ok\n"}, feat, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL})
        rc, out = self.check("range", "--remote", "origin", "--url", url, ZERO, bad)
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines()[0], f"commit {bad[:10]}: author email not allowed")
        self.assertNotIn(merged[:10], out)
        self.assertNotIn(feat[:10], out)
        self.assert_no_leak(out)

    def test_new_branch_checks_commits_only_on_another_remote(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        self.publish(base, "public")
        mirrored = self.commit({"src/a.py": b"ok\n"}, base, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL})
        self.publish(mirrored, "private")
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, mirrored)
        expected = f"commit {mirrored[:10]}: author email not allowed"
        for old in (ZERO, "1" * 40):
            with self.subTest(old=old):
                rc, out = self.check("range", "--remote", "public", "--url", self.url("public"), old, feat)
                self.assertEqual(rc, 1)
                self.assertEqual(out.splitlines()[0], expected)
                self.assertNotIn(base[:10], out)
                self.assertNotIn(feat[:10], out)
                private = ("range", "--remote", "private", "--url", self.url("private"), old, feat)
                self.assertEqual(self.check(*private), (0, ""))
        # No name, a URL, or a name without tracking refs: the whole history of feat.
        for args in ((), ("--remote", "https://example.invalid/r.git"), ("--remote", "nothing")):
            with self.subTest(args=args):
                rc, out = self.check("range", *args, ZERO, feat)
                self.assertEqual(rc, 1)
                self.assertIn(expected, out)
                self.assert_no_leak(out)

    def fetch_side_only(self, name: str = "origin") -> tuple[str, str, str]:
        """A disallowed commit on `name` (fetched as name/main) and a clean branch on top."""
        merged = self.commit({"src/a.py": b"ok\n"}, env={"GIT_COMMITTER_EMAIL": OTHER_EMAIL})
        self.publish(merged, name)
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, merged)
        return merged, feat, f"commit {merged[:10]}: committer email not allowed"

    def assert_whole_history(self, *args: str) -> None:
        merged, feat = args[-2], args[-1]
        rc, out = self.check("range", *args[:-2], ZERO, feat)
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {merged[:10]}: committer email not allowed", out)
        self.assert_no_leak(out)
        code, revs = self.check("revs", *args[:-2], ZERO, feat)
        self.assertEqual((code, revs.strip()), (0, feat))

    def test_tracking_refs_count_only_when_push_and_fetch_url_agree(self) -> None:
        merged, feat, _ = self.fetch_side_only()
        url = self.url("origin")
        other = self.bare("elsewhere")
        self.assertEqual(self.check("range", "--remote", "origin", "--url", url, ZERO, feat), (0, ""))
        code, revs = self.check("revs", "--remote", "origin", "--url", url, ZERO, feat)
        self.assertEqual((code, revs.strip()), (0, f"{feat} --not --remotes=origin"))
        # The hook's $2 is not the fetch URL, or is not given.
        self.assert_whole_history("--remote", "origin", "--url", other, merged, feat)
        self.assert_whole_history("--remote", "origin", merged, feat)
        # A push URL other than the fetch URL: the tracking refs say nothing about it.
        self.git("remote", "set-url", "--push", "origin", other)
        self.assert_whole_history("--remote", "origin", "--url", other, merged, feat)
        self.assert_whole_history("--remote", "origin", "--url", url, merged, feat)
        # Several push URLs, the fetch URL among them.
        self.git("remote", "set-url", "--push", "origin", url)
        self.git("remote", "set-url", "--add", "--push", "origin", other)
        self.assert_whole_history("--remote", "origin", "--url", url, merged, feat)
        # One push URL equal to the fetch URL is the same as none.
        self.git("config", "--unset-all", "remote.origin.pushurl")
        self.git("remote", "set-url", "--push", "origin", url)
        self.assertEqual(self.check("range", "--remote", "origin", "--url", url, ZERO, feat), (0, ""))

    def test_remote_name_with_a_slash_gets_the_whole_history(self) -> None:
        merged, feat, _ = self.fetch_side_only("team/pub")
        self.assert_whole_history("--remote", "team/pub", "--url", self.url("team/pub"), merged, feat)

    def test_remote_named_under_the_target_gets_the_whole_history(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        self.publish(base, "pub")
        mirrored = self.commit({"src/a.py": b"ok\n"}, base, env={"GIT_COMMITTER_EMAIL": OTHER_EMAIL})
        self.publish(mirrored, "pub/mirror")  # refs/remotes/pub/mirror/main matches --remotes=pub
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, mirrored)
        self.assert_whole_history("--remote", "pub", "--url", self.url("pub"), mirrored, feat)

    def test_all_mode_checks_every_commit_identity(self) -> None:
        bad = self.commit({"src/a.py": b"ok\n"}, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL})
        good = self.commit({"src/a.py": b"ok\n"}, bad)
        self.git("update-ref", "refs/heads/main", good)
        rc, out = self.check("all")
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {bad[:10]}: author email not allowed", out)
        self.assertNotIn(good[:10], out)
        self.assert_no_leak(out)

    def test_range_allowed_identity_passes(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"}, env={"GIT_AUTHOR_EMAIL": ALLOWED_EMAIL.upper()})
        self.assertEqual(self.check("range", ZERO, base), (0, ""))

    def test_range_rejects_commit_reachable_from_local_only_ref(self) -> None:
        files = {"src/a.py": b"ok\n"}
        base = self.commit(files)
        private = self.commit(files, base, message="private")
        self.git("update-ref", LOCAL_ONLY, private)
        public = self.commit(files, base, message="public")
        rc, out = self.check("range", ZERO, public)
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines()[0], f"commit {base[:10]}: reachable from a local-only ref")
        self.assertNotIn(public[:10], out)
        rc, out = self.check("range", base, private)
        self.assertEqual(rc, 1)
        self.assertIn(f"commit {private[:10]}: reachable from a local-only ref", out)
        # An orphan commit with the same tree shares no history with the ref.
        orphan = self.commit(files, message="orphan")
        self.assertEqual(self.git("rev-parse", f"{orphan}^{{tree}}"), self.git("rev-parse", f"{private}^{{tree}}"))
        self.assertEqual(self.check("range", ZERO, orphan), (0, ""))

    def test_missing_local_only_ref_is_ignored(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        self.assertEqual(self.check("range", ZERO, base), (0, ""))


@unittest.skipUnless(HAS_GIT, "git is not on PATH")
class MessageTests(RepoCase):
    def test_marker_in_message_file(self) -> None:
        path = self.write_file(os.path.join(self.tmp, "MSG"), "subject\n\nbody\nsecret line " + SYNTH_ID + "\n")
        rc, out = self.check("message", path)
        self.assertEqual(rc, 1)
        self.assertIn("commit message: contains marker #2 (message, line 4)", out)
        self.assertNotIn("marker #1", out)
        self.assert_no_leak(out)

    def test_clean_message_passes(self) -> None:
        path = self.write_file(os.path.join(self.tmp, "MSG"), "subject\n\n# comment\n")
        self.assertEqual(self.check("message", path), (0, ""))

    def test_below_scissors_is_ignored(self) -> None:
        text = "subject\n# " + "-" * 24 + " >8 " + "-" * 24 + "\n+synthuser\n"
        path = self.write_file(os.path.join(self.tmp, "MSG"), text)
        self.assertEqual(self.check("message", path), (0, ""))

    def test_missing_message_file(self) -> None:
        rc, _out = self.check("message", os.path.join(self.tmp, "nope"))
        self.assertEqual(rc, 2)


class AllowlistTests(unittest.TestCase):
    def test_repo_allowlist_covers_hooks(self) -> None:
        tool = _load_tool()
        allow = tool.load_allowlist(os.path.join(ROOT, "tools", "publish-allowlist.txt"))
        for name in ("commit-msg", "pre-commit", "pre-push", "chain.sh"):
            self.assertIsNone(tool.path_reason(f".githooks/{name}", allow, []), name)


SH = shutil.which("sh")


@unittest.skipUnless(HAS_GIT and SH and HAS_GITLEAKS, "git, sh or gitleaks is not on PATH")
class HookTests(RepoCase):
    def setUp(self) -> None:
        super().setUp()
        hooks = os.path.join(self.tmp, "repo-hooks")
        shutil.copytree(HOOKS, hooks)
        self.hooks = hooks
        os.makedirs(os.path.join(self.repo, "tools"))
        shutil.copy(TOOL, os.path.join(self.repo, "tools", "publish_check.py"))
        shutil.copy(self.allowlist, os.path.join(self.repo, "tools", "publish-allowlist.txt"))
        self.write_file(os.path.join(self.repo, ".local", "publish-markers.txt"), MARKERS)
        self.write_file(os.path.join(self.repo, ".local", "publish-guard.json"), json.dumps(GUARD))
        self.git("config", "core.hooksPath", hooks.replace("\\", "/"))
        gdir = os.path.join(self.tmp, "fake-global")
        self.log = os.path.join(self.tmp, "global.log").replace("\\", "/")
        for name in ("pre-commit", "pre-push", "commit-msg"):
            path = self.write_file(
                os.path.join(gdir, name),
                "#!/bin/sh\n"
                f'echo "{name}" >> "{self.log}"\n'
                f'[ "{name}" = pre-push ] && cat >> "{self.log}"\n'
                'echo "fake-global-hook ran" >&2\n'
                "exit ${FAKE_GLOBAL_RC:-0}\n",
            )
            os.chmod(path, 0o755)
        self.write_file(self.global_cfg, f"[core]\n\thooksPath = {gdir.replace(chr(92), '/')}\n")

    def commit_with_hook(self, rc: str, message: str = "msg", env: dict[str, str] | None = None) -> tuple[int, str]:
        env = dict(env or self.env, FAKE_GLOBAL_RC=rc)
        proc = subprocess.run(
            ["git", "commit", "-q", "-m", message], cwd=self.repo, capture_output=True, env=env, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")

    def read_log(self) -> str:
        if not os.path.exists(self.log):
            return ""
        with open(self.log, encoding="utf-8") as fh:
            return fh.read()

    def test_pre_commit_chains_global_first(self) -> None:
        self.stage("src/a.py", b"ok\n")
        rc, out = self.commit_with_hook("0")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.read_log().split(), ["pre-commit", "commit-msg"])

        self.stage("src/b.py", b"secret line synthuser\n")
        rc, out = self.commit_with_hook("0")
        self.assertNotEqual(rc, 0)
        self.assertIn("fake-global-hook ran", out)
        self.assertIn("src/b.py: contains marker #1", out)
        self.assert_no_leak(out)

        # Global failure stops the commit before the publish check runs.
        rc, out = self.commit_with_hook("7")
        self.assertNotEqual(rc, 0)
        self.assertIn("fake-global-hook ran", out)
        self.assertNotIn("contains marker", out)
        self.assertEqual(self.read_log().split(), ["pre-commit", "commit-msg", "pre-commit", "pre-commit"])

    def test_commit_msg_chains_global_then_checks_message(self) -> None:
        self.stage("src/a.py", b"ok\n")
        rc, out = self.commit_with_hook("0", message="subject\n\nsecret line synthuser")
        self.assertNotEqual(rc, 0)
        self.assertIn("commit message: contains marker #1 (message, line 3)", out)
        self.assert_no_leak(out)
        self.assertEqual(self.read_log().split(), ["pre-commit", "commit-msg"])

        # Global commit-msg failure stops the commit before the message check.
        self.write_file(os.path.join(self.tmp, "fake-global", "pre-commit"), "#!/bin/sh\nexit 0\n")
        rc, out = self.commit_with_hook("5", message="secret line synthuser")
        self.assertNotEqual(rc, 0)
        self.assertNotIn("contains marker", out)

        rc, out = self.commit_with_hook("0", message="clean subject")
        self.assertEqual(rc, 0, out)

    def push(self, line: str, rc: str = "0", remote: str = "origin", url: str | None = None) -> tuple[int, str]:
        """Run pre-push; url ($2) defaults to the remote's own URL, as git passes it."""
        if url is None:
            names = self.git("remote").split()
            url = self.url(remote) if remote in names else "https://example.invalid/r.git"
        env = dict(self.env, FAKE_GLOBAL_RC=rc)
        proc = subprocess.run(
            [SH or "sh", os.path.join(self.hooks, "pre-push"), remote, url],
            cwd=self.repo,
            input=line.encode(),
            capture_output=True,
            env=env,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")

    def test_pre_commit_gitleaks_rejects_fake_token(self) -> None:
        self.stage("src/a.py", b"ok\n")
        self.stage("src/c.py", f'token = "{FAKE_TOKEN}"\n'.encode())
        rc, out = self.commit_with_hook("0")
        self.assertNotEqual(rc, 0)
        self.assertIn("leaks found", out)
        self.assert_no_leak(out)
        self.assertEqual(self.read_log().split(), ["pre-commit"])  # stopped before commit-msg
        self.git("rm", "-q", "--cached", "src/c.py")
        rc, out = self.commit_with_hook("0")
        self.assertEqual(rc, 0, out)

    def test_pre_push_gitleaks_scans_pushed_range(self) -> None:
        leaky = self.commit({"src/a.py": f'token = "{FAKE_TOKEN}"\n'.encode()})
        fixed = self.commit({"src/a.py": b"ok\n"}, leaky)
        rc, out = self.push(f"refs/heads/main {fixed} refs/heads/main {ZERO}\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("leaks found", out)
        self.assert_no_leak(out)
        # Remote already has the leaky commit: only fixed is pushed.
        rc, out = self.push(f"refs/heads/main {fixed} refs/heads/main {leaky}\n")
        self.assertEqual(rc, 0, out)
        # Remote tip unknown here: the whole history of fixed is scanned.
        rc, out = self.push(f"refs/heads/main {fixed} refs/heads/main {'1' * 40}\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("leaks found", out)

    def test_pre_push_gitleaks_skips_commits_already_on_remote(self) -> None:
        leaky = self.commit({"src/a.py": f'token = "{FAKE_TOKEN}"\n'.encode()})
        fixed = self.commit({"src/a.py": b"ok\n"}, leaky)
        self.publish(fixed)
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, fixed)
        rc, out = self.push(f"refs/heads/feat {feat} refs/heads/feat {ZERO}\n")
        self.assertEqual(rc, 0, out)
        rc, out = self.push(f"refs/heads/feat {feat} refs/heads/feat {'1' * 40}\n")
        self.assertEqual(rc, 0, out)
        new_leak = self.commit({"src/a.py": b"ok\n", "src/c.py": f'token = "{FAKE_TOKEN}"\n'.encode()}, feat)
        rc, out = self.push(f"refs/heads/feat {new_leak} refs/heads/feat {ZERO}\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("leaks found", out)
        self.assert_no_leak(out)

    def test_pre_push_checks_commits_only_on_another_remote(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        self.publish(base, "public")
        leaky = self.commit(
            {"src/a.py": f'token = "{FAKE_TOKEN}"\n'.encode()}, base, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL}
        )
        fixed = self.commit({"src/a.py": b"ok\n"}, leaky)
        self.publish(fixed, "private")
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, fixed)
        line = f"refs/heads/feat {feat} refs/heads/feat {ZERO}\n"
        rc, out = self.push(line, remote="public")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"commit {leaky[:10]}: author email not allowed", out)
        self.assertIn("leaks found", out)
        self.assert_no_leak(out)
        rc, out = self.push(line, remote="private")
        self.assertEqual(rc, 0, out)
        # Pushing to a URL: no tracking refs, so the whole history is checked.
        rc, out = self.push(line, remote="https://example.invalid/r.git")
        self.assertNotEqual(rc, 0)
        self.assertIn("leaks found", out)

    def test_pre_push_ignores_tracking_refs_that_do_not_describe_the_push_target(self) -> None:
        leaky = self.commit(
            {"src/a.py": f'token = "{FAKE_TOKEN}"\n'.encode()}, env={"GIT_AUTHOR_EMAIL": OTHER_EMAIL}
        )
        fixed = self.commit({"src/a.py": b"ok\n"}, leaky)
        self.publish(fixed)  # leaky is on the fetch side only
        feat = self.commit({"src/a.py": b"ok\n", "src/b.py": b"ok\n"}, fixed)
        line = f"refs/heads/feat {feat} refs/heads/feat {ZERO}\n"
        self.assertEqual(self.push(line)[0], 0)  # push URL = fetch URL = $2: skipped as before
        other = self.bare("elsewhere")

        def assert_rejected(**kwargs: str) -> None:
            rc, out = self.push(line, **kwargs)
            self.assertNotEqual(rc, 0)
            self.assertIn(f"commit {leaky[:10]}: author email not allowed", out)
            self.assertIn("leaks found", out)
            self.assert_no_leak(out)

        assert_rejected(url=other)  # $2 is not the fetch URL
        self.git("remote", "set-url", "--push", "origin", other)
        assert_rejected(url=other)  # pushurl differs from url
        self.git("config", "--unset-all", "remote.origin.pushurl")
        self.publish(fixed, "team/pub")
        assert_rejected(remote="team/pub")  # a remote name with a slash

    def test_missing_gitleaks_fails_closed(self) -> None:
        dirs = os.environ.get("PATH", "").split(os.pathsep)
        kept = [d for d in dirs if d and not any(
            os.path.exists(os.path.join(d, n)) for n in ("gitleaks", "gitleaks.exe"))]
        env = dict(self.env, PATH=os.pathsep.join(kept))
        found = [shutil.which(n, path=env["PATH"]) for n in ("git", "sh", "gitleaks")]
        if found[0] is None or found[1] is None or found[2] is not None:
            self.skipTest("cannot build a PATH without gitleaks that keeps git and sh")
        self.stage("src/a.py", b"ok\n")
        rc, out = self.commit_with_hook("0", env=env)
        if "no Python interpreter found" in out:
            self.skipTest("Python is only reachable next to gitleaks")
        self.assertNotEqual(rc, 0)
        self.assertIn("gitleaks is not on PATH; rejecting (fail closed)", out)

    def test_pre_push_passes_stdin_to_global_and_checks(self) -> None:
        base = self.commit({"src/a.py": b"ok\n"})
        bad = self.commit({"src/a.py": b"ok\n", "notes.txt": b"x\n"}, base)
        hook = os.path.join(self.hooks, "pre-push")

        def push(line: str, rc: str = "0") -> tuple[int, str]:
            env = dict(self.env, FAKE_GLOBAL_RC=rc)
            proc = subprocess.run(
                [SH or "sh", hook, "origin", "https://example.invalid/r.git"],
                cwd=self.repo,
                input=line.encode(),
                capture_output=True,
                env=env,
                check=False,
            )
            return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")

        good_line = f"refs/heads/main {base} refs/heads/main {ZERO}\n"
        self.assertEqual(push(good_line)[0], 0)
        self.assertIn(good_line.strip(), self.read_log())

        rc, out = push(f"refs/heads/main {bad} refs/heads/main {base}\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("notes.txt: not in allowlist", out)

        self.assertEqual(push(f"(delete) {ZERO} refs/heads/old {bad}\n")[0], 0)
        self.assertNotEqual(push(good_line, rc="3")[0], 0)


if __name__ == "__main__":
    unittest.main()
