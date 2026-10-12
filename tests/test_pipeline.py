"""Offline contract tests for the public build/publish control plane."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pipeline_under_test", ROOT / "scripts/pipeline.py")
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)
CACHE_SPEC = importlib.util.spec_from_file_location("cache_under_test", ROOT / "scripts/build_cache.py")
build_cache = importlib.util.module_from_spec(CACHE_SPEC)
CACHE_SPEC.loader.exec_module(build_cache)

SOURCE = "a1234567" + "89abcdef" * 4
HEAD = "b" * 40
CHECKOUT = "c" * 40
VERSION = "20261010-123456-" + SOURCE[:8]
BUILD_REPO = "dc0d32/wezterm-builds"
REQUEST_REPO = "dc0d32/nixos"
BRANCH = "automation/update-flake-lock"
WORKFLOW = ".github/workflows/windows-build.yml"
RUN = 12345
ATTEMPT = 2
REQUIRED_FILES = {
    "wezterm.exe", "wezterm-gui.exe", "wezterm-mux-server.exe",
    "strip-ansi-escapes.exe", "wezterm.pdb", "conpty.dll", "OpenConsole.exe",
    "libEGL.dll", "libGLESv2.dll", "mesa/opengl32.dll",
}


def request(nonce="67890", source=SOURCE):
    material = f"{REQUEST_REPO}\n{BRANCH}\n{source}\n{nonce}".encode("utf-8")
    return {
        "schema": 1, "repository": REQUEST_REPO, "branch": BRANCH,
        "source_repository": "wezterm/wezterm", "source_sha": source,
        "request_id": hashlib.sha256(material).hexdigest(),
        "requested_at": "2026-10-11T15:00:00Z", "nonce": nonce,
    }


def snapshot(nonce="67890"):
    return {
        "request": request(nonce), "pr_number": 42, "pr_head": HEAD,
        "default_branch": "main", "version": VERSION,
    }


def pr():
    return {
        "number": 42, "state": "open", "merged": False, "merged_at": None,
        "head": {"repo": {"full_name": REQUEST_REPO}, "ref": BRANCH, "sha": HEAD},
        "base": {"repo": {"full_name": REQUEST_REPO}, "ref": "main"},
    }


def run():
    return {
        "id": RUN, "run_attempt": ATTEMPT, "path": WORKFLOW,
        "event": "schedule", "head_repository": {"full_name": BUILD_REPO},
        "head_branch": "main", "head_sha": CHECKOUT,
        "status": "completed", "conclusion": "success",
    }


def build_job():
    return {
        "name": "build", "run_id": RUN, "run_attempt": ATTEMPT,
        "status": "completed", "conclusion": "success",
    }


def environment(snap=None):
    return {
        "GITHUB_REPOSITORY": BUILD_REPO, "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": CHECKOUT,
        "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": str(ATTEMPT),
        "SNAPSHOT": json.dumps(snap or snapshot()), "ARTIFACT_ID": "789",
    }


def manifest(snap=None, archive=b"fixture", run_id=RUN, attempt=ATTEMPT):
    snap = snap or snapshot()
    req = snap["request"]
    build_id = f"{req['source_sha']}-{run_id}-{attempt}"
    return {
        "schema": 1, "source_repository": "wezterm/wezterm",
        "source_sha": req["source_sha"], "build_repository": BUILD_REPO,
        "run_id": run_id, "run_attempt": attempt, "build_id": build_id,
        "version": snap["version"], "archive_root": "WezTerm-windows-" + snap["version"],
        "asset_name": "WezTerm-windows-" + build_id + ".zip",
        "sha256": hashlib.sha256(archive).hexdigest(), "size": len(archive),
        "success": True, "request_id": req["request_id"],
        "requested_at": req["requested_at"], "nonce": req["nonce"],
    }


def checksum(obj):
    return f"{obj['sha256']}  {obj['asset_name']}\n".encode("ascii")


def release(obj):
    return {
        "id": 456, "draft": False, "prerelease": False, "immutable": True,
        "tag_name": "wezterm-" + obj["build_id"],
        "assets": [
            {"name": obj["asset_name"], "state": "uploaded", "size": obj["size"],
             "digest": "sha256:" + obj["sha256"]},
            {"name": "provenance.json", "state": "uploaded"},
            {"name": "SHA256SUMS", "state": "uploaded"},
        ],
    }


class FakePublic:
    """Explicit routes fail on unexpected reads rather than falling back to HTTP."""

    def __init__(self, snap=None):
        self.snap = snap or snapshot()
        self.pr = pr()
        self.pr_reads = 0
        self.race_at = None
        self.race = None
        self.run = run()
        self.jobs = [build_job()]
        self.releases = []
        self.blobs = {}
        self.calls = []
        self.commit_sha = SOURCE
        self.branch_sha = HEAD
        self.tag_sha = CHECKOUT

    def get(self, path):
        self.calls.append(("get", path))
        if path in (f"/repos/{BUILD_REPO}", f"/repos/{REQUEST_REPO}"):
            return {"default_branch": "main"}
        if path == f"/repos/{REQUEST_REPO}/pulls/42":
            self.pr_reads += 1
            if self.race_at is not None and self.pr_reads >= self.race_at:
                self.race(self)
            return copy.deepcopy(self.pr)
        if path == f"/repos/{REQUEST_REPO}/git/ref/heads/{BRANCH}":
            return {"ref": "refs/heads/" + BRANCH,
                    "object": {"type": "commit", "sha": self.branch_sha}}
        if path.startswith(f"/repos/{BUILD_REPO}/git/ref/tags/wezterm-"):
            tag = path.rsplit("/", 1)[1]
            return {"ref": "refs/tags/" + tag,
                    "object": {"type": "commit", "sha": self.tag_sha}}
        if path == f"/repos/{REQUEST_REPO}/contents/.github/wezterm-request.json?ref={self.pr['head']['sha']}":
            data = json.dumps(self.snap["request"]).encode("utf-8")
            return {
                "type": "file", "path": ".github/wezterm-request.json", "encoding": "base64",
                "size": len(data), "content": base64.b64encode(data).decode("ascii"),
            }
        if path == f"/repos/wezterm/wezterm/commits/{SOURCE}":
            return {
                "sha": self.commit_sha,
                "commit": {"committer": {"date": "2026-10-10T12:34:56Z"}},
            }
        if path == f"/repos/{BUILD_REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}":
            return copy.deepcopy(self.run)
        if path == f"/repos/{BUILD_REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}/jobs?per_page=100&page=1":
            return {"jobs": copy.deepcopy(self.jobs)}
        raise AssertionError("unexpected anonymous route: " + path)

    def pages(self, path):
        self.calls.append(("pages", path))
        if path.startswith(f"/repos/{REQUEST_REPO}/pulls?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            assert query == {"state": ["open"], "head": ["dc0d32:" + BRANCH], "base": ["main"]}
            return iter([copy.deepcopy(self.pr)])
        if path == f"/repos/{BUILD_REPO}/releases":
            return iter(copy.deepcopy(self.releases))
        raise AssertionError("unexpected anonymous pagination: " + path)

    def raw(self, url, limit):
        self.calls.append(("raw", url))
        data = self.blobs[url]
        assert len(data) <= limit
        return data

    def install_release(self, obj, value=None):
        value = value or release(obj)
        self.releases.append(value)
        prefix = f"https://github.com/{BUILD_REPO}/releases/download/{value['tag_name']}/"
        self.blobs[prefix + "provenance.json"] = json.dumps(obj).encode("utf-8")
        self.blobs[prefix + "SHA256SUMS"] = checksum(obj)
        return value


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.work_root = Path(__file__).resolve().parent / ".test-work"
        self.work = self.work_root / uuid.uuid4().hex
        self.work.mkdir(parents=True)
        self.old_cwd = Path.cwd()
        os.chdir(self.work)
        self.addCleanup(self.cleanup_work)
        self.env_patch = mock.patch.dict(os.environ, environment(), clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def cleanup_work(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.work)
        try:
            self.work_root.rmdir()
        except OSError:
            pass

    def make_zip(self, path, members=None):
        members = members if members is not None else [
            ("WezTerm-windows-" + VERSION + "/" + name, b"dummy binary")
            for name in sorted(REQUIRED_FILES)
        ]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, data in members:
                    archive.writestr(name, data)
        return path

    def make_package(self, snap=None):
        snap = snap or snapshot()
        directory = self.work / "fixture-package"
        directory.mkdir()
        obj = manifest(snap)
        archive = self.make_zip(directory / obj["asset_name"])
        obj["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        obj["size"] = archive.stat().st_size
        (directory / "provenance.json").write_text(json.dumps(obj), encoding="utf-8")
        (directory / "SHA256SUMS").write_bytes(checksum(obj))
        return directory, obj

    def publication(self, snap=None):
        directory, obj = self.make_package(snap)
        artifact = self.work / "fixture-artifact.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            for item in directory.iterdir():
                archive.write(item, item.name)
        public = FakePublic(snap)
        own = mock.Mock()
        uploaded = []

        def call(method, suffix, data=None, content_type="application/json", upload=False):
            if (method, suffix) == ("POST", "/git/refs"):
                self.assertEqual(data, {"ref": "refs/tags/wezterm-" + obj["build_id"],
                                        "sha": CHECKOUT})
                return {"ref": data["ref"], "object": {"type": "commit", "sha": CHECKOUT}}
            if (method, suffix) == ("GET", "/actions/artifacts/789"):
                return {
                    "id": 789, "name": "package-" + obj["build_id"], "expired": False,
                    "workflow_run": {"id": RUN, "head_sha": CHECKOUT, "head_branch": "main"},
                }
            if (method, suffix) == ("POST", "/releases"):
                self.assertTrue(data["draft"])
                self.assertFalse(data["prerelease"])
                self.assertEqual(data["target_commitish"], CHECKOUT)
                self.assertEqual(data["tag_name"], "wezterm-" + obj["build_id"])
                return {"id": 456, "draft": True}
            if method == "POST" and suffix.startswith("/releases/456/assets?name="):
                self.assertTrue(upload)
                self.assertEqual(content_type, "application/octet-stream")
                name = suffix.split("name=", 1)[1]
                uploaded.append(name)
                self.assertEqual(data, (directory / name).read_bytes())
                return {
                    "name": name, "state": "uploaded", "size": len(data),
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                }
            if (method, suffix) == ("PATCH", "/releases/456"):
                self.assertEqual(data, {"draft": False, "prerelease": False, "make_latest": "false"})
                return public.install_release(obj)
            raise AssertionError("unexpected authenticated route: " + suffix)

        def download(artifact_id, destination):
            self.assertEqual(artifact_id, 789)
            self.assertFalse(destination.exists())
            destination.write_bytes(artifact.read_bytes())

        own.call.side_effect = call
        own.optional.return_value = None
        own.download_artifact.side_effect = download
        return public, own, obj, uploaded


class RequestTests(unittest.TestCase):
    def test_exact_request_hash_and_numeric_string_nonce(self):
        value = request()
        self.assertEqual(pipeline.validate_request(value), value)
        self.assertEqual(set(value), {
            "schema", "repository", "branch", "source_repository", "source_sha",
            "request_id", "requested_at", "nonce",
        })
        expected = hashlib.sha256(
            ("dc0d32/nixos\nautomation/update-flake-lock\n" + SOURCE + "\n67890").encode("utf-8")
        ).hexdigest()
        self.assertEqual(value["request_id"], expected)
        self.assertNotEqual(request("67891")["request_id"], expected)

    def test_request_rejects_extra_and_missing_keys(self):
        for key in request():
            with self.subTest(missing=key):
                value = request()
                del value[key]
                with self.assertRaises(ValueError):
                    pipeline.validate_request(value)
        with self.assertRaises(ValueError):
            pipeline.validate_request(dict(request(), extra=True))

    def test_request_rejects_wrong_types_identity_timestamp_and_hash(self):
        invalid = {
            "schema": [True, "1", 0, 2],
            "repository": ["attacker/nixos", BUILD_REPO],
            "branch": ["main", BRANCH + "/other"],
            "source_repository": ["attacker/wezterm"],
            "source_sha": [SOURCE.upper(), SOURCE[:-1], "g" * 40, None],
            "request_id": ["0" * 64, request()["request_id"].upper(), "a" * 63],
            "nonce": [67890, True, "", "0", "01", "-1", "1.0", " 1", "١"],
            "requested_at": [
                "2026-10-11", "2026-10-11T15:00:00+00:00", "2026-02-30T15:00:00Z",
                "2026-10-11T25:00:00Z", "2026-10-11T15:00:00.1234567Z", None,
            ],
        }
        for key, values in invalid.items():
            for bad in values:
                with self.subTest(key=key, value=bad):
                    value = request()
                    value[key] = bad
                    with self.assertRaises(ValueError):
                        pipeline.validate_request(value)

    def test_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for data in ('{"schema":1,"schema":1}', '{"x":{"a":1,"a":2}}',
                     '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                pipeline.parse_json(data)

    def test_identity_exact_source_run_attempt(self):
        self.assertEqual(pipeline.identity(SOURCE, RUN, ATTEMPT), (
            f"{SOURCE}-{RUN}-{ATTEMPT}", f"wezterm-{SOURCE}-{RUN}-{ATTEMPT}",
            f"WezTerm-windows-{SOURCE}-{RUN}-{ATTEMPT}.zip",
        ))
        for sha, run_id, attempt in [(SOURCE.upper(), RUN, ATTEMPT),
                                     (SOURCE, True, ATTEMPT), (SOURCE, RUN, "2"),
                                     (SOURCE, 0, ATTEMPT), (SOURCE, RUN, 0)]:
            with self.subTest(identity=(sha, run_id, attempt)), self.assertRaises(ValueError):
                pipeline.identity(sha, run_id, attempt)


class DiscoveryTests(unittest.TestCase):
    def test_discovery_reads_exact_public_commit_and_pinned_request(self):
        api = FakePublic()
        self.assertEqual(pipeline.discover(api), snapshot())
        self.assertIn(("get", f"/repos/wezterm/wezterm/commits/{SOURCE}"), api.calls)
        self.assertIn(("get", f"/repos/{REQUEST_REPO}/contents/.github/wezterm-request.json?ref={HEAD}"),
                      api.calls)
        self.assertEqual(api.pr_reads, 2)

    def test_source_commit_must_be_exact_and_timestamp_timezone_aware(self):
        api = FakePublic()
        api.commit_sha = "d" * 40
        with self.assertRaises(ValueError):
            pipeline.source_version(api, SOURCE)
        api = mock.Mock()
        api.get.return_value = {
            "sha": SOURCE, "commit": {"committer": {"date": "2026-10-10T12:34:56"}},
        }
        with self.assertRaises(ValueError):
            pipeline.source_version(api, SOURCE)
        api.get.return_value["commit"]["committer"]["date"] = "2026-10-10T14:34:56+02:00"
        self.assertEqual(pipeline.source_version(api, SOURCE), VERSION)

    def test_no_eligible_pr_and_ambiguous_prs(self):
        api = FakePublic()
        api.pr["state"] = "closed"
        self.assertIsNone(pipeline.discover(api))
        api = FakePublic()
        api.pages = mock.Mock(return_value=iter([pr(), dict(pr(), number=43)]))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            pipeline.discover(api)

    def test_pr_must_be_open_same_repository_fixed_branch_default_base(self):
        mutations = [
            lambda p: p.update(state="closed"),
            lambda p: p.update(merged=True),
            lambda p: p.update(merged_at="2026-10-11T15:00:00Z"),
            lambda p: p["head"].update(repo=None),
            lambda p: p["head"].update(repo={"full_name": "attacker/nixos"}),
            lambda p: p["head"].update(repo={"full_name": REQUEST_REPO, "fork": True}),
            lambda p: p["head"].update(ref="main"),
            lambda p: p["head"].update(sha=HEAD.upper()),
            lambda p: p["base"].update(repo={"full_name": "attacker/nixos"}),
            lambda p: p["base"].update(ref="other"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                value = pr()
                mutate(value)
                self.assertFalse(pipeline.valid_pr(value, "main"))

    def test_polling_rejects_closed_merged_fork_and_superseded_races(self):
        races = [
            lambda api: api.pr.update(state="closed"),
            lambda api: api.pr.update(merged=True),
            lambda api: api.pr["head"].update(repo={"full_name": "attacker/nixos"}),
            lambda api: api.pr["head"].update(sha="d" * 40),
        ]
        for at in (1, 2):
            for index, race in enumerate(races):
                if at == 1 and index == 3:
                    continue
                with self.subTest(at=at, race=index):
                    api = FakePublic()
                    api.race_at, api.race = at, race
                    with self.assertRaises(ValueError):
                        pipeline.discover(api)

    def test_recheck_rejects_request_identity_change(self):
        api = FakePublic(snapshot("67891"))
        with self.assertRaises(ValueError):
            pipeline.recheck(api, snapshot())

    def test_discovery_rejects_branch_ref_ahead_of_pr_metadata(self):
        api = FakePublic()
        api.branch_sha = "d" * 40
        with self.assertRaisesRegex(ValueError, "branch superseded"):
            pipeline.discover(api)

    def test_request_file_metadata_and_bytes_are_checked(self):
        original = FakePublic()
        route = f"/repos/{REQUEST_REPO}/contents/.github/wezterm-request.json?ref={HEAD}"
        good = original.get(route)
        mutations = [
            {"type": "dir"}, {"path": "other.json"}, {"encoding": "utf-8"},
            {"size": True}, {"size": 0}, {"size": 16385}, {"size": good["size"] + 1},
            {"content": "%%%"},
        ]
        for change in mutations:
            with self.subTest(change=change):
                api = FakePublic()
                real_get = api.get
                api.get = mock.Mock(side_effect=lambda path: dict(good, **change)
                                    if path == route else real_get(path))
                with self.assertRaises(ValueError):
                    pipeline.discover(api)


class ProvenanceTests(unittest.TestCase):
    def test_context_accepts_only_own_repository_default_branch_allowed_events(self):
        for event in ("schedule", "workflow_dispatch"):
            self.assertEqual(pipeline.context(FakePublic(), dict(environment(), GITHUB_EVENT_NAME=event)),
                             ("main", RUN, ATTEMPT))
        changes = {
            "GITHUB_REPOSITORY": [REQUEST_REPO, "attacker/wezterm-builds"],
            "GITHUB_EVENT_NAME": ["pull_request", "push", "repository_dispatch"],
            "GITHUB_REF": ["refs/heads/feature", "refs/tags/main", "refs/pull/42/merge"],
            "GITHUB_SHA": [CHECKOUT.upper(), "x" * 40, ""],
            "GITHUB_RUN_ID": ["0", "01", str(RUN) + ".0"],
            "GITHUB_RUN_ATTEMPT": ["0", "-1", ""],
        }
        for key, values in changes.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    pipeline.context(FakePublic(), dict(environment(), **{key: value}))

    def test_run_proof_happy_path_same_checkout_and_attempt(self):
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                api = FakePublic()
                api.run["event"] = event
                self.assertEqual(pipeline.prove_run(api, RUN, ATTEMPT, "main",
                                                   completed=True, head_sha=CHECKOUT), api.run)
                self.assertTrue(any(f"/attempts/{ATTEMPT}/jobs?" in path for _, path in api.calls))

    def test_run_proof_rejects_wrong_workflow_event_repo_branch_sha_or_attempt(self):
        changes = [
            {"id": RUN + 1}, {"run_attempt": ATTEMPT + 1},
            {"path": "windows-build.yml"}, {"path": WORKFLOW + "@refs/heads/main"},
            {"event": "pull_request"}, {"head_repository": {"full_name": "attacker/builds"}},
            {"head_repository": None}, {"head_branch": "feature"},
            {"head_sha": CHECKOUT.upper()}, {"head_sha": "d" * 40},
            {"status": "in_progress"}, {"conclusion": "failure"},
        ]
        for change in changes:
            with self.subTest(change=change):
                api = FakePublic()
                api.run.update(change)
                with self.assertRaises(ValueError):
                    pipeline.prove_run(api, RUN, ATTEMPT, "main", completed=True, head_sha=CHECKOUT)

    def test_run_proof_requires_one_successful_build_job_same_attempt(self):
        jobs = [
            [], [dict(build_job(), name="publish")], [build_job(), build_job()],
            [dict(build_job(), run_id=RUN + 1)], [dict(build_job(), run_attempt=ATTEMPT + 1)],
            [dict(build_job(), status="in_progress")], [dict(build_job(), conclusion="failure")],
            [dict(build_job(), conclusion="skipped")],
        ]
        for rows in jobs:
            with self.subTest(jobs=rows):
                api = FakePublic()
                api.jobs = rows
                with self.assertRaises(ValueError):
                    pipeline.prove_run(api, RUN, ATTEMPT, "main")

    def test_manifest_exact_keys_identity_and_request_provenance(self):
        good = manifest()
        self.assertEqual(pipeline.validate_manifest(good, snapshot(), RUN, ATTEMPT), good)
        for key in good:
            with self.subTest(missing=key):
                value = dict(good)
                del value[key]
                with self.assertRaises(ValueError):
                    pipeline.validate_manifest(value)
        changes = [
            {"extra": True}, {"schema": True}, {"success": 1},
            {"source_repository": "attacker/wezterm"}, {"build_repository": REQUEST_REPO},
            {"source_sha": SOURCE.upper()}, {"run_id": True}, {"run_attempt": 0},
            {"build_id": "wrong"}, {"asset_name": "WezTerm-windows.zip"},
            {"sha256": good["sha256"].upper()}, {"size": True}, {"size": 0},
            {"size": pipeline.MAX_ZIP + 1}, {"version": "20261010-123456-deadbeef"},
            {"archive_root": "wrong"}, {"request_id": "0" * 64}, {"nonce": 67890},
            {"requested_at": "2026-10-11T15:00:00+00:00"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                pipeline.validate_manifest(dict(good, **change), snapshot(), RUN, ATTEMPT)
        with self.assertRaises(ValueError):
            pipeline.validate_manifest(manifest(snapshot("67891")), snapshot(), RUN, ATTEMPT)
        with self.assertRaises(ValueError):
            pipeline.validate_manifest(good, snapshot(), RUN, ATTEMPT + 1)


class ArchiveTests(WorkspaceCase):
    def test_valid_tiny_nonempty_windows_zip_and_package(self):
        directory, obj = self.make_package()
        self.assertEqual(pipeline.validate_package(directory, snapshot(), RUN, ATTEMPT), obj)
        self.assertEqual(pipeline.digest_file(directory / obj["asset_name"]), obj["sha256"])

    def test_zip_rejects_traversal_windows_names_and_casefold_duplicates(self):
        bad_names = [
            "../escape", "/absolute", "root/../escape", "root/./file", "root//file",
            r"root\file", "C:/file", "root/name.", "root/name ", "root/a:b",
            "root/a?b", "root/a*b", "root/a|b", "root/a<b", 'root/a"b',
            "root/\x01file", "root/CON", "root/con.exe", "root/NUL.txt",
            "root/aux", "root/PRN", "root/COM1.dll", "root/LPT9.txt",
        ]
        for name in bad_names:
            with self.subTest(name=name):
                path = self.make_zip(self.work / "bad.zip", [(name, b"x")])
                with zipfile.ZipFile(path) as archive, self.assertRaises(ValueError):
                    pipeline.zip_members(archive)
        for names in [("root/file", "root/file"), ("root/File", "root/file"),
                      ("root/dir/", "root/dir")]:
            with self.subTest(duplicates=names):
                path = self.make_zip(self.work / "bad.zip", [(name, b"x") for name in names])
                with zipfile.ZipFile(path) as archive, self.assertRaises(ValueError):
                    pipeline.zip_members(archive)

    def test_zip_rejects_symlinks_and_other_special_entries(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
            with self.subTest(mode=mode):
                info = zipfile.ZipInfo("root/link")
                info.create_system = 3
                info.external_attr = (mode | 0o777) << 16
                path = self.make_zip(self.work / "special.zip", [(info, b"target")])
                with zipfile.ZipFile(path) as archive, self.assertRaises(ValueError):
                    pipeline.zip_members(archive)

    def test_zip_rejects_windows_reserved_superscript_device_names(self):
        for name in ("root/COM¹.exe", "root/COM².dll", "root/com³",
                     "root/LPT¹.txt", "root/lpt²", "root/LPT³.dll"):
            with self.subTest(name=name):
                path = self.make_zip(self.work / "reserved.zip", [(name, b"x")])
                with zipfile.ZipFile(path) as archive, self.assertRaises(ValueError):
                    pipeline.zip_members(archive)

    def test_zip_rejects_file_directory_and_implicit_case_collisions(self):
        cases = [
            ["root/mesa", "root/mesa/opengl32.dll"],
            ["root/mesa/opengl32.dll", "root/mesa"],
            ["root/mesa/one.dll", "root/MeSa/two.dll"],
            ["root/mesa/", "root/MeSa/two.dll"],
        ]
        for names in cases:
            with self.subTest(names=names):
                path = self.make_zip(self.work / "collision.zip", [(name, b"x") for name in names])
                with zipfile.ZipFile(path) as archive, self.assertRaises(ValueError):
                    pipeline.zip_members(archive)

    def test_zip_metadata_rejects_nul_encryption_unsupported_encoding_and_limits(self):
        good = zipfile.ZipInfo("root/file")
        good.file_size = 1
        for key, value in [
            ("orig_filename", "root/file\x00hidden"), ("flag_bits", 1),
            ("compress_type", zipfile.ZIP_BZIP2), ("file_size", pipeline.MAX_FILE + 1),
        ]:
            with self.subTest(key=key):
                info = copy.copy(good)
                setattr(info, key, value)
                archive = mock.Mock()
                archive.infolist.return_value = [info]
                with self.assertRaises(ValueError):
                    pipeline.zip_members(archive)
        archive = mock.Mock()
        archive.infolist.return_value = []
        with self.assertRaises(ValueError):
            pipeline.zip_members(archive)
        archive.infolist.return_value = [good] * 10001
        with self.assertRaises(ValueError):
            pipeline.zip_members(archive)
        archive.infolist.return_value = [good]
        with mock.patch.object(pipeline, "MAX_EXPANDED", 0), self.assertRaises(ValueError):
            pipeline.zip_members(archive)

    def test_zip_requires_exact_root_all_runtime_files_and_nonempty_files(self):
        root = "WezTerm-windows-" + VERSION
        members = [(root + "/" + name, b"x") for name in sorted(REQUIRED_FILES)]
        cases = [
            members[:-1], [(name, b"") if index == 0 else (name, data)
                           for index, (name, data) in enumerate(members)],
            members + [("other/file", b"x")],
        ]
        for index, rows in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                pipeline.check_zip(self.make_zip(self.work / "bad.zip", rows), root)

    def test_zip_reads_and_rejects_corrupt_crc_even_with_matching_manifest_sha(self):
        directory, obj = self.make_package()
        path = directory / obj["asset_name"]
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            for name in sorted(REQUIRED_FILES):
                archive.writestr(obj["archive_root"] + "/" + name, b"dummy binary")
        data = path.read_bytes().replace(b"dummy binary", b"wrong binary", 1)
        path.write_bytes(data)
        obj["sha256"] = hashlib.sha256(data).hexdigest()
        obj["size"] = len(data)
        (directory / "provenance.json").write_text(json.dumps(obj), encoding="utf-8")
        (directory / "SHA256SUMS").write_bytes(checksum(obj))
        with self.assertRaises(zipfile.BadZipFile):
            pipeline.validate_package(directory, snapshot(), RUN, ATTEMPT)

    def test_package_rejects_tampering_extra_files_and_symlinks(self):
        for target in ("archive", "checksum", "manifest", "extra", "symlink"):
            with self.subTest(target=target):
                directory, obj = self.make_package()
                if target == "archive":
                    (directory / obj["asset_name"]).write_bytes(b"tampered")
                elif target == "checksum":
                    (directory / "SHA256SUMS").write_bytes(b"wrong\n")
                elif target == "manifest":
                    obj["request_id"] = "0" * 64
                    (directory / "provenance.json").write_text(json.dumps(obj), encoding="utf-8")
                elif target == "extra":
                    (directory / "unexpected.exe").write_bytes(b"x")
                else:
                    archive = directory / obj["asset_name"]
                    original = self.work / "archive-original"
                    archive.rename(original)
                    archive.symlink_to(original)
                with self.assertRaises(ValueError):
                    pipeline.validate_package(directory, snapshot(), RUN, ATTEMPT)
                shutil.rmtree(directory)
        directory, _ = self.make_package()
        link = self.work / "directory-link"
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            pipeline.validate_package(link, snapshot(), RUN, ATTEMPT)

    def test_artifact_unpack_only_exact_three_regular_files_into_fresh_directory(self):
        directory, obj = self.make_package()
        members = [(item.name, item.read_bytes()) for item in directory.iterdir()]
        path = self.make_zip(self.work / "artifact-fixture.zip", members)
        destination = self.work / "unpacked"
        pipeline.unpack_artifact(path, destination, obj["asset_name"])
        self.assertEqual(pipeline.validate_package(destination, snapshot(), RUN, ATTEMPT), obj)
        with self.assertRaises(ValueError):
            pipeline.unpack_artifact(path, destination, obj["asset_name"])
        for index, rows in enumerate([
            members + [("extra", b"x")], members[:-1],
            members + [("../escape", b"x")],
        ]):
            with self.subTest(case=index), self.assertRaises(ValueError):
                pipeline.unpack_artifact(
                    self.make_zip(self.work / "invalid-artifact.zip", rows),
                    self.work / ("unpacked-" + str(index)), obj["asset_name"],
                )
        self.assertFalse((self.work / "escape").exists())


class ReleaseTests(unittest.TestCase):
    def test_durable_release_deduplicates_across_request_identities(self):
        api = FakePublic(snapshot("67891"))
        obj = manifest(snapshot("67890"))
        value = api.install_release(obj)
        self.assertNotEqual(obj["request_id"], api.snap["request"]["request_id"])
        self.assertEqual(pipeline.successful_source(api, SOURCE, "main"), value)

    def test_release_requires_exact_tag_assets_integrity_and_immutability(self):
        changes = [
            {"draft": True}, {"prerelease": True}, {"immutable": False},
            {"tag_name": "wezterm-" + SOURCE},
            {"tag_name": f"wezterm-{SOURCE}-{RUN}-3"},
        ]
        for change in changes:
            with self.subTest(change=change):
                api = FakePublic()
                value = release(manifest())
                value.update(change)
                api.install_release(manifest(), value)
                self.assertIsNone(pipeline.successful_source(api, SOURCE, "main"))
        for target in ("missing", "extra", "upload", "digest", "size", "checksum", "provenance"):
            with self.subTest(target=target):
                api = FakePublic()
                obj = manifest()
                value = api.install_release(obj)
                prefix = f"https://github.com/{BUILD_REPO}/releases/download/{value['tag_name']}/"
                if target == "missing":
                    value["assets"].pop()
                elif target == "extra":
                    value["assets"].append({"name": "extra", "state": "uploaded"})
                elif target == "upload":
                    value["assets"][0]["state"] = "new"
                elif target == "digest":
                    value["assets"][0]["digest"] = "sha256:" + "0" * 64
                elif target == "size":
                    value["assets"][0]["size"] += 1
                elif target == "checksum":
                    api.blobs[prefix + "SHA256SUMS"] = b"wrong"
                else:
                    obj["source_sha"] = "d" * 40
                    api.blobs[prefix + "provenance.json"] = json.dumps(obj).encode("utf-8")
                self.assertIsNone(pipeline.successful_source(api, SOURCE, "main"))

    def test_dedup_requires_completed_successful_run_and_same_attempt_build(self):
        for change in ({"status": "in_progress"}, {"conclusion": "failure"},
                       {"run_attempt": ATTEMPT + 1}, {"path": "other.yml"}):
            with self.subTest(run=change):
                api = FakePublic()
                api.install_release(manifest())
                api.run.update(change)
                self.assertIsNone(pipeline.successful_source(api, SOURCE, "main"))
        api = FakePublic()
        api.install_release(manifest())
        api.jobs[0]["run_attempt"] += 1
        self.assertIsNone(pipeline.successful_source(api, SOURCE, "main"))

    def test_invalid_release_does_not_hide_later_valid_success(self):
        api = FakePublic()
        bad = api.install_release(manifest())
        bad["immutable"] = False
        good = api.install_release(manifest())
        self.assertEqual(pipeline.successful_source(api, SOURCE, "main"), good)

    def test_existing_release_manifest_must_be_identical_never_overwritten(self):
        api = FakePublic()
        obj = manifest()
        value = api.install_release(obj)
        with self.assertRaisesRegex(ValueError, "never overwrite"):
            pipeline.valid_release(api, value, SOURCE, "main",
                                   expected=manifest(snapshot("67891")))

    def test_release_tag_must_point_at_its_proven_run_head(self):
        api = FakePublic()
        value = api.install_release(manifest())
        api.tag_sha = "d" * 40
        with self.assertRaisesRegex(ValueError, "tag run provenance"):
            pipeline.valid_release(api, value, SOURCE, "main")


class ControlPlaneTests(WorkspaceCase):
    def test_poll_happy_path_outputs_snapshot_and_exact_build_identity(self):
        output = self.work / "github-output"
        os.environ["GITHUB_OUTPUT"] = str(output)
        pipeline.poll(FakePublic())
        rows = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(json.loads(rows["snapshot"]), snapshot())
        self.assertEqual(rows["build_id"], f"{SOURCE}-{RUN}-{ATTEMPT}")

    def test_poll_dedup_or_no_request_produces_no_build_output(self):
        output = self.work / "github-output"
        os.environ["GITHUB_OUTPUT"] = str(output)
        api = FakePublic(snapshot("67891"))
        api.install_release(manifest(snapshot("67890")))
        pipeline.poll(api)
        self.assertFalse(output.exists())
        api = FakePublic()
        api.pr["state"] = "closed"
        pipeline.poll(api)
        self.assertFalse(output.exists())

    def test_poll_rechecks_before_emitting_build_output(self):
        output = self.work / "github-output"
        os.environ["GITHUB_OUTPUT"] = str(output)
        api = FakePublic()
        api.race_at = 3
        api.race = lambda value: value.pr.update(state="closed")
        with self.assertRaises(ValueError):
            pipeline.poll(api)
        self.assertFalse(output.exists())

    def test_package_happy_path_creates_provenance_without_publication_client(self):
        candidate = self.work / "candidate"
        candidate.mkdir()
        self.make_zip(candidate / ("WezTerm-windows-" + VERSION + ".zip"))
        with mock.patch.object(pipeline, "OwnAPI", side_effect=AssertionError("write token boundary")):
            pipeline.package(FakePublic())
        obj = pipeline.validate_package(self.work / "package", snapshot(), RUN, ATTEMPT)
        self.assertEqual(obj["request_id"], request()["request_id"])
        self.assertEqual(obj["asset_name"], f"WezTerm-windows-{SOURCE}-{RUN}-{ATTEMPT}.zip")

    def test_publish_happy_path_verifies_artifact_and_creates_immutable_release(self):
        api, own, obj, uploaded = self.publication()
        pipeline.publish(api, own)
        self.assertEqual(set(uploaded), {obj["asset_name"], "provenance.json", "SHA256SUMS"})
        self.assertEqual(len(uploaded), 3)
        own.download_artifact.assert_called_once()
        self.assertEqual(api.pr_reads, 6)
        self.assertEqual(pipeline.successful_source(api, SOURCE, "main"), api.releases[0])
        mutations = [call.args[0] for call in own.call.call_args_list if call.args[0] != "GET"]
        self.assertEqual(mutations, ["POST", "POST", "POST", "POST", "POST", "PATCH"])

    def test_publish_dedup_across_request_identities_never_downloads_or_writes(self):
        api = FakePublic(snapshot("67891"))
        api.install_release(manifest(snapshot("67890")))
        os.environ["SNAPSHOT"] = json.dumps(api.snap)
        own = mock.Mock()
        pipeline.publish(api, own)
        self.assertEqual(own.mock_calls, [])

    def test_publish_rejects_races_before_download_draft_and_visibility(self):
        for at in (1, 3, 5):
            for race_name in ("closed", "merged", "fork", "superseded"):
                with self.subTest(at=at, race=race_name):
                    api, own, _, _ = self.publication()
                    api.race_at = at
                    def race(value, name=race_name):
                        if name == "closed":
                            value.pr["state"] = "closed"
                        elif name == "merged":
                            value.pr["merged"] = True
                        elif name == "fork":
                            value.pr["head"]["repo"]["full_name"] = "attacker/nixos"
                        else:
                            value.snap = snapshot("67891")
                    api.race = race
                    with self.assertRaises(ValueError):
                        pipeline.publish(api, own)
                    calls = [call.args[:2] for call in own.call.call_args_list]
                    self.assertNotIn(("PATCH", "/releases/456"), calls)
                    if at < 5:
                        self.assertNotIn(("POST", "/releases"), calls)
                    if at == 1:
                        own.download_artifact.assert_not_called()
                    for path in self.work.iterdir():
                        if path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink()

    def test_publish_existing_identical_release_is_read_only(self):
        api, own, obj, _ = self.publication()
        value = api.install_release(obj)
        api.releases.clear()
        own.optional.return_value = value
        pipeline.publish(api, own)
        self.assertEqual([call.args[0] for call in own.call.call_args_list], ["GET"])
        own.optional.assert_called_once_with("/releases/tags/wezterm-" + obj["build_id"])

    def test_publish_refuses_preexisting_tag_without_release(self):
        api, own, _, _ = self.publication()
        own.optional.side_effect = [None, {"ref": "existing"}]
        with self.assertRaisesRegex(ValueError, "never reuse"):
            pipeline.publish(api, own)
        self.assertEqual([call.args[0] for call in own.call.call_args_list], ["GET"])

    def test_publish_tag_creation_race_fails_without_creating_release_or_reusing_tag(self):
        api, own, _, _ = self.publication()
        original = own.call.side_effect
        def collision(method, suffix, *args, **kwargs):
            if (method, suffix) == ("POST", "/git/refs"):
                raise urllib.error.HTTPError("https://api.github.com", 422, "Reference exists", {}, None)
            return original(method, suffix, *args, **kwargs)
        own.call.side_effect = collision
        with self.assertRaises(urllib.error.HTTPError):
            pipeline.publish(api, own)
        self.assertNotIn(("POST", "/releases"), [call.args[:2] for call in own.call.call_args_list])
        self.assertFalse(any(call.args[0] in ("PATCH", "DELETE") for call in own.call.call_args_list))

    def test_publish_rejects_artifact_metadata_before_download(self):
        changes = [
            {"id": 790}, {"name": "package-wrong"}, {"expired": True},
            {"workflow_run": {"id": RUN + 1, "head_sha": CHECKOUT, "head_branch": "main"}},
            {"workflow_run": {"id": RUN, "head_sha": "d" * 40, "head_branch": "main"}},
            {"workflow_run": {"id": RUN, "head_sha": CHECKOUT, "head_branch": "feature"}},
        ]
        for change in changes:
            with self.subTest(change=change):
                api = FakePublic()
                own = mock.Mock()
                own.call.return_value = dict(
                    id=789, name=f"package-{SOURCE}-{RUN}-{ATTEMPT}", expired=False,
                    workflow_run={"id": RUN, "head_sha": CHECKOUT, "head_branch": "main"},
                )
                own.call.return_value.update(change)
                with self.assertRaises(ValueError):
                    pipeline.publish(api, own)
                own.download_artifact.assert_not_called()
                own.optional.assert_not_called()

    def test_publish_upload_integrity_failure_never_makes_draft_visible(self):
        api, own, _, _ = self.publication()
        real_call = own.call.side_effect
        def corrupt_upload(method, suffix, *args, **kwargs):
            result = real_call(method, suffix, *args, **kwargs)
            if method == "POST" and kwargs.get("upload"):
                result["digest"] = "sha256:" + "0" * 64
            return result
        own.call.side_effect = corrupt_upload
        with self.assertRaisesRegex(ValueError, "uploaded asset integrity"):
            pipeline.publish(api, own)
        self.assertFalse(any(call.args[0] in ("PATCH", "DELETE")
                             for call in own.call.call_args_list))
        self.assertEqual(api.releases, [])

    def test_publish_corrupted_package_never_creates_release(self):
        api, own, obj, _ = self.publication()
        artifact = self.work / "fixture-artifact.zip"
        directory = self.work / "fixture-package"
        (directory / obj["asset_name"]).write_bytes(b"tampered")
        with zipfile.ZipFile(artifact, "w") as archive:
            for item in directory.iterdir():
                archive.write(item, item.name)
        with self.assertRaisesRegex(ValueError, "archive checksum/size"):
            pipeline.publish(api, own)
        own.optional.assert_not_called()
        self.assertEqual([call.args[0] for call in own.call.call_args_list], ["GET"])

    def test_main_poll_and_package_never_construct_authenticated_client(self):
        for command in ("poll", "package"):
            with self.subTest(command=command), \
                 mock.patch.object(pipeline.sys, "argv", ["pipeline.py", command]), \
                 mock.patch.object(pipeline, "PublicAPI") as public, \
                 mock.patch.object(pipeline, "OwnAPI", side_effect=AssertionError("token access")), \
                 mock.patch.object(pipeline, command) as action:
                os.environ["GITHUB_TOKEN"] = "publication-secret"
                pipeline.main()
                action.assert_called_once_with(public.return_value)

    def test_artifact_download_token_only_goes_to_build_repository(self):
        opener = mock.MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.read.side_effect = [b"archive fixture", b""]
        with mock.patch.object(pipeline.urllib.request, "build_opener", return_value=opener):
            own = pipeline.OwnAPI("publication-token")
            destination = self.work / "download.zip"
            own.download_artifact(789, destination)
            self.assertEqual(destination.read_bytes(), b"archive fixture")
            req = opener.open.call_args.args[0]
            self.assertEqual(req.full_url,
                             f"https://api.github.com/repos/{BUILD_REPO}/actions/artifacts/789/zip")
            self.assertEqual(req.get_header("Authorization"), "Bearer publication-token")
            opener.open.reset_mock()
            for invalid in (True, "789", 0, -1):
                with self.subTest(artifact_id=invalid), self.assertRaises(ValueError):
                    own.download_artifact(invalid, self.work / "forbidden.zip")
            opener.open.assert_not_called()
            self.assertFalse((self.work / "forbidden.zip").exists())


class TokenBoundaryTests(unittest.TestCase):
    def opener(self):
        opener = mock.MagicMock()
        response = mock.Mock()
        response.read.return_value = b'{"ok":true}'
        opener.open.return_value.__enter__.return_value = response
        return opener, response

    def test_public_reads_ignore_all_token_environment_variables(self):
        opener, _ = self.opener()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "secret", "GH_TOKEN": "secret2"}), \
             mock.patch.object(pipeline.urllib.request, "build_opener", return_value=opener):
            api = pipeline.PublicAPI()
            self.assertEqual(api.get(f"/repos/wezterm/wezterm/commits/{SOURCE}"), {"ok": True})
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, f"https://api.github.com/repos/wezterm/wezterm/commits/{SOURCE}")
        self.assertNotIn("authorization", {name.lower() for name, _ in req.header_items()})
        self.assertNotIn("secret", repr(req.header_items()))

    def test_public_api_requires_https_and_enforces_size_limit(self):
        opener, response = self.opener()
        with mock.patch.object(pipeline.urllib.request, "build_opener", return_value=opener):
            api = pipeline.PublicAPI()
            with self.assertRaises(ValueError):
                api.raw("http://api.github.com/repos/wezterm/wezterm")
            opener.open.assert_not_called()
            response.read.return_value = b"12345"
            with self.assertRaises(ValueError):
                api.raw("https://api.github.com/repos/wezterm/wezterm", 4)

    def test_authenticated_requests_only_address_build_repository(self):
        opener, _ = self.opener()
        with mock.patch.object(pipeline.urllib.request, "build_opener", return_value=opener):
            api = pipeline.OwnAPI("publication-token")
            api.call("POST", "/releases", {"draft": True})
            req = opener.open.call_args.args[0]
            self.assertEqual(req.full_url, f"https://api.github.com/repos/{BUILD_REPO}/releases")
            self.assertEqual(req.get_header("Authorization"), "Bearer publication-token")
            asset = f"WezTerm-windows-{SOURCE}-{RUN}-{ATTEMPT}.zip"
            api.call("POST", "/releases/456/assets?name=" + asset, b"zip",
                     content_type="application/octet-stream", upload=True)
            req = opener.open.call_args.args[0]
            self.assertEqual(req.full_url,
                             f"https://uploads.github.com/repos/{BUILD_REPO}/releases/456/assets?name=" + asset)
            for suffix in ("https://attacker.invalid/", "//attacker.invalid/", "releases",
                           "/releases/456/assets?name=test.zip", "/immutable-releases",
                           "/releases/456?name=../../nixos"):
                with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                    api.call("GET", suffix)

    def test_authenticated_api_rejects_repository_escape_dot_segments(self):
        opener, _ = self.opener()
        with mock.patch.object(pipeline.urllib.request, "build_opener", return_value=opener):
            api = pipeline.OwnAPI("publication-token")
            for suffix in ("/../nixos/issues", "/%2e%2e/nixos/issues"):
                with self.subTest(suffix=suffix):
                    with self.assertRaises(ValueError):
                        api.call("POST", suffix, {"title": "must never leave build repo"})
                    opener.open.assert_not_called()

    def test_redirect_strips_token_and_rejects_http(self):
        handler = pipeline.NoAuthRedirect()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{BUILD_REPO}/actions/artifacts/789/zip",
            headers={"Authorization": "Bearer secret", "User-Agent": "test"},
        )
        redirected = handler.redirect_request(
            req, None, 302, "Found", {}, "https://artifact.example.invalid/blob",
        )
        self.assertNotIn("authorization", {name.lower() for name, _ in redirected.header_items()})
        with self.assertRaises(ValueError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://artifact.example.invalid/blob")

    def test_optional_suppresses_only_404(self):
        api = object.__new__(pipeline.OwnAPI)
        api.call = mock.Mock()
        for status in (404, 403, 500):
            api.call.side_effect = urllib.error.HTTPError("https://api.github.com", status, "error", {}, None)
            if status == 404:
                self.assertIsNone(api.optional("/releases/tags/missing"))
            else:
                with self.assertRaises(urllib.error.HTTPError):
                    api.optional("/releases/tags/missing")


class VisibilityTests(unittest.TestCase):
    def error(self, status):
        return urllib.error.HTTPError("https://github.com/release", status, "delayed", {}, None)

    def test_release_asset_visibility_retries_transient_reads(self):
        for failure in (self.error(404), self.error(429), self.error(503),
                        urllib.error.URLError("network"), TimeoutError("network")):
            with self.subTest(failure=str(failure)):
                api = mock.Mock()
                api.raw.side_effect = [failure, b"asset"]
                with mock.patch.object(pipeline.time, "sleep") as sleep:
                    result = pipeline.release_asset_bytes(api, "tag", "provenance.json", 16384)
                self.assertEqual(result, b"asset")
                self.assertEqual(api.raw.call_count, 2)
                sleep.assert_called_once_with(1)

    def test_release_asset_read_backoff_is_bounded_and_integrity_errors_not_retried(self):
        api = mock.Mock()
        api.raw.side_effect = self.error(404)
        with mock.patch.object(pipeline.time, "sleep") as sleep, \
             self.assertRaises(urllib.error.HTTPError):
            pipeline.release_asset_bytes(api, "tag", "provenance.json", 16384)
        self.assertEqual(api.raw.call_count, 6)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 4, 8, 16])
        for failure in (self.error(403), ValueError("response too large")):
            api.raw.reset_mock()
            api.raw.side_effect = failure
            with mock.patch.object(pipeline.time, "sleep") as sleep, \
                 self.assertRaises(type(failure)):
                pipeline.release_asset_bytes(api, "tag", "provenance.json", 16384)
            self.assertEqual(api.raw.call_count, 1)
            sleep.assert_not_called()

    def test_publication_survives_delayed_manifest_visibility(self):
        case = ControlPlaneTests("test_publish_happy_path_verifies_artifact_and_creates_immutable_release")
        case.setUp()
        try:
            api, own, _, _ = case.publication()
            original = api.raw
            attempts = []
            def delayed(url, limit):
                attempts.append(url)
                if len(attempts) == 1:
                    raise self.error(404)
                return original(url, limit)
            api.raw = delayed
            with mock.patch.object(pipeline.time, "sleep") as sleep:
                pipeline.publish(api, own)
            sleep.assert_called_once_with(1)
            self.assertEqual(len(attempts), 3)
        finally:
            case.doCleanups()


class BuildCacheTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.identity = {
            "os": "Windows", "arch": "X64", "target": "x86_64-pc-windows-msvc",
            "rustc": "rustc 1.90.0\nhost: x86_64-pc-windows-msvc",
            "cargo": "cargo 1.90.0\nhost: x86_64-pc-windows-msvc",
            "image_os": "win25", "image_version": "20261005.1.0",
            "native": "cl/link:sha256", "environment": {"LIB": "sdk", "RUSTFLAGS": None},
        }
        self.scripts = {"scripts/build.ps1": "a" * 64, "scripts/build_cache.py": "b" * 64}
        self.lock = b"version = 4\n"

    def plan(self, **kwargs):
        args = dict(identity=self.identity, lock=self.lock, source=SOURCE, scripts=self.scripts)
        args.update(kwargs)
        return build_cache.cache_plan(**args)

    def write_cache(self, relative, content=b"fixture"):
        path = self.work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_keys_are_deterministic_and_bounded(self):
        plan = self.plan()
        reordered = dict(reversed(list(self.identity.items())))
        self.assertEqual(plan, self.plan(identity=reordered))
        self.assertEqual(set(plan), {
            "registry_key", "registry_restore", "target_key", "target_restore", "nextest_key",
        })
        for key, value in plan.items():
            self.assertLess(len(value), 512)
            self.assertRegex(value, r"^wt-win-v1-Windows-X64-[0-9a-f]{64}-")
            self.assertNotIn("\n", value)
        self.assertTrue(plan["target_key"].endswith(
            hashlib.sha256(self.lock).hexdigest() + "-" + SOURCE))

    def test_weekly_source_reuse_never_drops_environment_or_lock(self):
        old, new = self.plan(), self.plan(source="d" * 40)
        for kind in ("registry", "target"):
            self.assertNotEqual(old[kind + "_key"], new[kind + "_key"])
            self.assertTrue(old[kind + "_key"].startswith(new[kind + "_restore"]))
        self.assertEqual(old["nextest_key"], new["nextest_key"])
        changed = self.plan(lock=self.lock + b"# changed")
        self.assertFalse(old["target_key"].startswith(changed["target_restore"]))
        self.assertTrue(old["registry_key"].startswith(changed["registry_restore"]))
        self.assertEqual(old["nextest_key"], changed["nextest_key"])

    def test_all_environment_changes_invalidate_all_cache_families(self):
        old = self.plan()
        for field in ("rustc", "cargo", "native", "image_os", "image_version", "environment"):
            value = copy.deepcopy(self.identity)
            if field == "environment":
                value[field]["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS"] = "-C target-cpu=native"
            else:
                value[field] += "\nchanged"
            with self.subTest(field=field):
                new = self.plan(identity=value)
                for kind in ("registry", "target"):
                    self.assertFalse(old[kind + "_key"].startswith(new[kind + "_restore"]))
                self.assertNotEqual(old["nextest_key"], new["nextest_key"])

    def test_build_script_and_nextest_version_invalidation(self):
        old = self.plan()
        changed = self.plan(scripts=dict(self.scripts, additional="c" * 64))
        for kind in ("registry", "target", "nextest"):
            self.assertNotEqual(old[kind + "_key"], changed[kind + "_key"])
        versioned = self.plan(nextest_version="0.9.115")
        self.assertNotEqual(old["nextest_key"], versioned["nextest_key"])
        self.assertEqual(old["target_key"], versioned["target_key"])

    def test_bad_identity_source_and_missing_material_fail_closed(self):
        for field in self.identity:
            value = copy.deepcopy(self.identity)
            del value[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.plan(identity=value)
        for field, bad in (("os", "Linux"), ("arch", "ARM64"), ("target", "other"),
                           ("rustc", "rustc\nhost: other"), ("cargo", ""), ("environment", {})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan(identity=dict(self.identity, **{field: bad}))
        for invalid in (SOURCE[:8], SOURCE.upper(), "g" * 40, SOURCE + "\n"):
            with self.assertRaises(ValueError):
                self.plan(source=invalid)
        for kwargs in ({"lock": b""}, {"scripts": {}}, {"nextest_version": "latest"}):
            with self.assertRaises(ValueError):
                self.plan(**kwargs)

    def test_missing_caches_and_allowed_files_are_normal(self):
        build_cache.validate_cache(self.work)
        self.write_cache(".cargo-build/registry/cache/index.crates.io-1949cf8c6b5b557f/serde-1.0.0.crate")
        self.write_cache("candidate/target/release/deps/libserde.rlib")
        self.write_cache("candidate/target/debug/deps/serde.exe")
        self.write_cache(".nextest/bin/cargo-nextest.exe")
        build_cache.validate_cache(self.work)

    def test_registry_configuration_extracted_sources_and_other_registries_rejected(self):
        root = self.work / build_cache.PATHS["registry"]
        for entry in ("config.toml", "credentials.toml", "index.crates.io-abc/config.json",
                      "other-registry-abc/foo-1.crate", "index.crates.io-abc/src/lib.rs",
                      "index.crates.io-abc/.cargo-checksum.json"):
            path = self.write_cache(str(Path(build_cache.PATHS["registry"]) / entry))
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                build_cache.validate_cache(self.work)
            path.unlink()
        shutil.rmtree(root)

    def test_nextest_receipts_config_wrong_tool_empty_and_directories_rejected(self):
        root = self.work / build_cache.PATHS["nextest"]
        for entry in (".crates.toml", ".crates2.json", "config.toml", "cargo-other.exe"):
            self.write_cache(str(Path(build_cache.PATHS["nextest"]) / entry))
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                build_cache.validate_cache(self.work)
            shutil.rmtree(root)
        self.write_cache(".nextest/bin/cargo-nextest.exe", b"")
        with self.assertRaises(ValueError):
            build_cache.validate_cache(self.work)
        shutil.rmtree(root)
        (root / "extra").mkdir(parents=True)
        with self.assertRaises(ValueError):
            build_cache.validate_cache(self.work)

    def test_empty_nextest_hit_fails_but_empty_miss_installs_normally(self):
        build_cache.validate_cache(self.work, nextest_hit=False)
        with self.assertRaisesRegex(ValueError, "missing its executable"):
            build_cache.validate_cache(self.work, nextest_hit=True)
        self.write_cache(".nextest/bin/cargo-nextest.exe")
        build_cache.validate_cache(self.work, nextest_hit=True)

    def test_windows_reparse_points_are_rejected_on_ancestor_and_file(self):
        file = self.write_cache("candidate/target/release/deps/libserde.rlib")
        original = Path.lstat
        for poisoned in (self.work / "candidate", file):
            def fake_lstat(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == poisoned:
                    return mock.Mock(st_mode=info.st_mode, st_file_attributes=0x400)
                return info
            with mock.patch.object(Path, "lstat", fake_lstat):
                with self.subTest(path=poisoned), self.assertRaises(ValueError):
                    build_cache.validate_cache(self.work)

    def test_cache_links_and_ancestor_links_rejected_before_traversal(self):
        destination = self.work / "not-cached"
        destination.mkdir()
        for relative in build_cache.PATHS.values():
            path = self.work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(destination, target_is_directory=True)
            with self.subTest(path=relative), self.assertRaises(ValueError):
                build_cache.validate_cache(self.work)
            path.unlink()
        parent = self.work / ".nextest"
        parent.rmdir()
        parent.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            build_cache.validate_cache(self.work)
        parent.unlink()
        self.write_cache("candidate/target/file")
        (self.work / "candidate/target/link").symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            build_cache.validate_cache(self.work)

    def test_nextest_version_check_rejects_wrong_or_corrupt_output(self):
        for output in ("cargo-nextest 0.9.114", "cargo-nextest 0.9.114 (abcdef123 2026-10-01)"):
            build_cache.validate_nextest_version(output)
        for output in ("", "nextest 0.9.114", "cargo-nextest 0.9.113",
                       "cargo-nextest 0.9.114-extra", "cargo-nextest 0.9.114\nerror"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                build_cache.validate_nextest_version(output)

    def test_prepare_verify_and_changed_lock_fixture(self):
        self.write_cache(".build-identity.json", json.dumps(self.identity).encode())
        self.write_cache("candidate/Cargo.lock", self.lock)
        for name in ("scripts/build.ps1", "scripts/build_cache.py", "scripts/cache_restore.py",
                     ".github/actions/cache-restore/action.yml",
                     ".github/actions/cache-restore/index.js", ".github/workflows/windows-build.yml"):
            self.write_cache("control/" + name)
        output = self.work / "step-output"
        os.environ["GITHUB_OUTPUT"] = str(output)
        os.environ["SNAPSHOT"] = json.dumps(snapshot())
        with mock.patch.object(build_cache.sys, "argv", ["build_cache.py", "prepare"]):
            build_cache.main()
        plan = json.loads((self.work / ".build-cache-plan.json").read_text())
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(outputs.pop("nextest_version"), build_cache.NEXTEST_VERSION)
        self.assertEqual(outputs, plan)
        with mock.patch.object(build_cache.sys, "argv", ["build_cache.py", "verify"]):
            build_cache.main()
            (self.work / "candidate/Cargo.lock").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "identity changed"):
                build_cache.main()


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / WORKFLOW).read_text(encoding="utf-8")
        self.build = self.workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        self.publish = self.workflow.split("\n  publish:\n", 1)[1]

    def test_only_schedule_and_dispatch_on_default_build_repository(self):
        triggers = self.workflow.split("\npermissions:", 1)[0]
        self.assertIn("schedule:", triggers)
        self.assertIn("cron: '23 * * * *'", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        for trigger in ("pull_request:", "pull_request_target:", "push:", "workflow_run:",
                        "repository_dispatch:"):
            self.assertNotIn(trigger, triggers)
        self.assertIn("github.repository == 'dc0d32/wezterm-builds'", self.workflow)
        self.assertIn("github.ref_name == github.event.repository.default_branch", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_remote_actions_are_reviewed_pins_and_restore_is_local(self):
        actions = re.findall(r"uses: ([^\s#]+)", self.workflow)
        self.assertEqual(len(actions), 10)
        allowed = {
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "./control/.github/actions/cache-restore",
            "actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830",
        }
        self.assertEqual(set(actions), allowed)
        self.assertEqual(actions.count("./control/.github/actions/cache-restore"), 3)
        self.assertEqual(actions.count("actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830"), 3)
        self.assertNotIn("actions/cache/restore@", self.workflow)
        self.assertEqual(self.workflow.count("persist-credentials: false"), 3)
        self.assertEqual(self.workflow.count("ref: ${{ github.sha }}"), 3)

    def test_build_has_no_write_token_and_current_attempt_artifact_identity(self):
        self.assertIn("contents: read", self.build)
        self.assertNotIn("contents: write", self.build)
        self.assertNotIn("secrets.", self.build)
        self.assertNotIn("GITHUB_TOKEN:", self.build)
        self.assertNotIn("actions: write", self.build)
        self.assertIn("overwrite: false", self.build)
        self.assertIn("package-${{ fromJSON(needs.poll.outputs.snapshot).request.source_sha }}"
                      "-${{ github.run_id }}-${{ github.run_attempt }}", self.build)
        script = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
        self.assertIn("https://github.com/wezterm/wezterm.git", script)
        self.assertIn("'checkout', '--detach', 'FETCH_HEAD'", script)
        self.assertIn("'submodule', 'update', '--init', '--recursive'", script)
        self.assertIn("protocol.allow=never", script)
        self.assertIn("protocol.https.allow=always", script)
        self.assertIn("Invoke-Checked cargo @('build', '--locked', '--release'", script)
        self.assertIn("Invoke-Checked $nextest @('nextest', 'run', '--locked', '--all', '--no-fail-fast')", script)
        self.assertNotIn("--all-targets", script)
        self.assertIn(".tag", script)
        self.assertIn("ci/deploy.sh", script)

    def test_build_uses_upstream_nextest_without_skipping_ssh(self):
        script = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
        self.assertIn("'install', 'cargo-nextest', '--locked', '--version', \"=$nextestVersion\"", script)
        self.assertLess(script.index("'install', 'cargo-nextest'"),
                        script.index("Push-Location candidate"))
        self.assertIn("'nextest', 'run', '--locked', '--all', '--no-fail-fast'", script)
        for forbidden in ("cargo test ", "--exclude", "--skip", "--run-ignored",
                          "rm -rf", "wezterm-ssh/tests"):
            self.assertNotIn(forbidden, script)

    def test_build_keeps_upstream_crt_config_and_packaging_dependencies(self):
        script = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
        self.assertIn("Invoke-Checked cargo @('vendor', '--locked', '--versioned-dirs') |", script)
        self.assertIn("Out-File -Append -Encoding utf8 .cargo/config.toml", script)
        self.assertIn(r"C:\Strawberry\perl\bin", script)
        self.assertIn(r"C:\Program Files\Inno Setup 6", script)
        self.assertIn(r"C:\Program Files\Git\bin\bash.exe", script)
        self.assertIn("$env:TAG_NAME = $version", script)
        self.assertIn("$env:BUILD_REASON = ''", script)

    def test_publisher_executes_only_trusted_default_scripts(self):
        self.assertIn("needs: [poll, build]", self.publish)
        self.assertIn("needs.build.result == 'success'", self.publish)
        self.assertIn("contents: write", self.publish)
        self.assertIn("actions: read", self.publish)
        self.assertIn("path: control", self.publish)
        self.assertIn("python3 -B control/scripts/pipeline.py publish", self.publish)
        self.assertIn("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", self.publish)
        for forbidden in ("cargo ", "deploy.sh", "upstream", "candidate/", "download-artifact@",
                          "actions/cache", ".cargo-build", ".nextest", "build_cache.py"):
            self.assertNotIn(forbidden, self.publish)

    def test_restore_and_save_have_only_the_three_narrow_paths(self):
        paths = {"registry": ".cargo-build/registry/cache", "target": "candidate/target",
                 "nextest": ".nextest/bin"}
        self.assertEqual(paths, build_cache.PATHS)
        restore, save = [], []
        for block in self.build.split("      - name: ")[1:]:
            if ("uses: actions/cache/save@" not in block
                    and "uses: ./control/.github/actions/cache-restore" not in block):
                continue
            path = re.search(r"^          path: (.+)$", block, re.M).group(1)
            kind = next(kind for kind, value in paths.items() if value == path)
            self.assertIn("${{ steps.prepare.outputs." + kind + "_key }}", block)
            if "uses: ./control/.github/actions/cache-restore" in block:
                restore.append(path)
                self.assertIn(f"id: {kind}", block)
                if kind == "nextest":
                    self.assertNotIn("restore-keys:", block)
                else:
                    self.assertIn("restore-keys: ${{ steps.prepare.outputs." + kind + "_restore }}", block)
            else:
                save.append(path)
                for gate in ("success()", "steps.compile.outcome == 'success'",
                             "github.repository == 'dc0d32/wezterm-builds'",
                             "github.ref_name == github.event.repository.default_branch",
                             "github.event_name == 'schedule'", "github.event_name == 'workflow_dispatch'",
                             f"steps.{kind}.outputs.cache-hit != 'true'"):
                    self.assertIn(gate, block)
        self.assertCountEqual(restore, paths.values())
        self.assertCountEqual(save, paths.values())
        self.assertNotIn("continue-on-error", self.build)

    def test_fresh_prepare_precedes_restore_and_compile_precedes_save(self):
        prepare = self.build.index("-Phase Prepare")
        compile_step = self.build.index("-Phase Compile")
        restores = list(re.finditer(r"uses: \./control/\.github/actions/cache-restore", self.build))
        self.assertEqual(len(restores), 3)
        for match in restores:
            self.assertLess(prepare, match.start())
            self.assertLess(match.start(), compile_step)
        for match in re.finditer("uses: actions/cache/save@", self.build):
            self.assertLess(compile_step, match.start())
        for gate in ("github.repository == 'dc0d32/wezterm-builds'",
                     "github.ref_name == github.event.repository.default_branch",
                     "github.event_name == 'schedule'", "github.event_name == 'workflow_dispatch'"):
            self.assertIn(gate, self.build.split("    runs-on:", 1)[0])

    def test_script_rechecks_identity_tool_and_forces_local_source_recompile(self):
        script = (ROOT / "scripts/build.ps1").read_text()
        self.assertIn('$env:GITHUB_REF -cne "refs/heads/$env:BUILD_DEFAULT_BRANCH"', script)
        self.assertIn("$PSNativeCommandUseErrorActionPreference = $true", script)
        self.assertIn("$env:RUSTUP_TOOLCHAIN = 'stable'", script)
        self.assertIn("if ($LASTEXITCODE -ne 0)", script)
        verify = script.index("'control/scripts/build_cache.py', 'verify'")
        install = script.index("'install', 'cargo-nextest'")
        check = script.index("'check-nextest-version', $toolVersion")
        clean = script.index("'clean', '--package', $package.id")
        build = script.index("'build', '--locked', '--release'")
        self.assertLess(verify, install)
        self.assertLess(check, clean)
        self.assertLess(clean, build)
        self.assertIn("if ($null -eq $package.source)", script)
        self.assertIn("Stale workspace executable", script)
        self.assertIn("Nextest cache hit is missing its executable", script)
        self.assertIn("'--root', (Join-Path $root '.nextest-install')", script)
        self.assertIn("'--target-dir', (Join-Path $root '.nextest-install/target')", script)
        self.assertIn("Copy-Item '.nextest-install/bin/cargo-nextest.exe' $nextest", script)
        self.assertNotIn("catch", script)
        self.assertLess(script.index("'control/scripts/pipeline.py', 'package'"),
                        script.rindex("'control/scripts/build_cache.py', 'validate'"))


if __name__ == "__main__":
    unittest.main()
