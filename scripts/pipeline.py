#!/usr/bin/env python3
"""Trusted control plane. All external reads are anonymous; never run artifact code."""

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

BUILD_REPO = "dc0d32/wezterm-builds"
REQUEST_REPO = "dc0d32/nixos"
BRANCH = "automation/update-flake-lock"
REQUEST_PATH = ".github/wezterm-request.json"
SOURCE_REPO = "wezterm/wezterm"
WORKFLOW = ".github/workflows/windows-build.yml"
API = "https://api.github.com"
REQUEST_KEYS = {
    "schema", "repository", "branch", "source_repository", "source_sha",
    "request_id", "requested_at", "nonce",
}
MANIFEST_KEYS = {
    "schema", "source_repository", "source_sha", "build_repository", "run_id",
    "run_attempt", "build_id", "version", "archive_root", "asset_name",
    "sha256", "size", "success", "request_id", "requested_at", "nonce",
}
MAX_ZIP = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * MAX_ZIP
MAX_FILE = 512 * 1024 * 1024
REQUIRED_FILES = {
    "wezterm.exe", "wezterm-gui.exe", "wezterm-mux-server.exe",
    "strip-ansi-escapes.exe", "wezterm.pdb", "conpty.dll", "OpenConsole.exe",
    "libEGL.dll", "libGLESv2.dll", "mesa/opengl32.dll",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive_int(value):
    return type(value) is int and value > 0


def hex_string(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value)


def numeric_string(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def parse_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, "non-finite JSON"))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_request(obj):
    require(type(obj) is dict and set(obj) == REQUEST_KEYS, "request keys")
    require(type(obj["schema"]) is int and obj["schema"] == 1, "request schema")
    for key, value in (("repository", REQUEST_REPO), ("branch", BRANCH),
                       ("source_repository", SOURCE_REPO)):
        require(obj[key] == value, "fixed request " + key)
    require(hex_string(obj["source_sha"], 40), "source SHA")
    require(hex_string(obj["request_id"], 64), "request ID")
    require(numeric_string(obj["nonce"]), "nonce must be numeric GitHub run ID")
    stamp = obj["requested_at"]
    require(isinstance(stamp, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", stamp),
        "requested_at must be ISO UTC with Z")
    dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    material = f"{REQUEST_REPO}\n{BRANCH}\n{obj['source_sha']}\n{obj['nonce']}"
    require(obj["request_id"] == hashlib.sha256(material.encode("utf-8")).hexdigest(),
            "request ID hash")
    return obj


class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == "https", "non-HTTPS redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


class PublicAPI:
    """No token, including environment GH_TOKEN/GITHUB_TOKEN, is ever consulted."""

    def __init__(self):
        self.opener = urllib.request.build_opener(NoAuthRedirect())

    def raw(self, url, limit=1024 * 1024):
        require(url.startswith("https://"), "HTTPS required")
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dc0d32-wezterm-builds",
            "Cache-Control": "no-cache",
        })
        with self.opener.open(request, timeout=60) as response:
            data = response.read(limit + 1)
        require(len(data) <= limit, "response too large")
        return data

    def get(self, path):
        require(path.startswith("/repos/"), "public API path")
        return parse_json(self.raw(API + path, 4 * 1024 * 1024))

    def pages(self, path):
        separator = "&" if "?" in path else "?"
        for page in range(1, 1001):
            rows = self.get(f"{path}{separator}per_page=100&page={page}")
            require(type(rows) is list, "paginated API response")
            yield from rows
            if len(rows) < 100:
                return
        raise ValueError("pagination exceeded safe bound")


class OwnAPI:
    """Authenticated requests can address only this build repository."""

    def __init__(self, token):
        require(bool(token), "publication token required")
        self.token = token
        self.opener = urllib.request.build_opener(NoAuthRedirect())

    def call(self, method, suffix, data=None, content_type="application/json", upload=False):
        tag = r"wezterm-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*"
        asset = r"(?:WezTerm-windows-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*\.zip|provenance\.json|SHA256SUMS)"
        route = rf"/(?:actions/artifacts/[1-9][0-9]*|git/refs|git/ref/tags/{tag}|releases(?:/tags/{tag}|/[1-9][0-9]*(?:/assets\?name={asset})?)?)"
        require(isinstance(suffix, str) and re.fullmatch(route, suffix), "own API suffix")
        require(method in ("GET", "POST", "PATCH"), "own API method")
        require(not upload or (method == "POST" and "/assets?name=" in suffix),
                "upload endpoint")
        host = "https://uploads.github.com" if upload else API
        url = f"{host}/repos/{BUILD_REPO}{suffix}"
        if data is not None and content_type == "application/json":
            data = canonical(data).encode()
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dc0d32-wezterm-builds",
            "Content-Type": content_type,
        })
        with self.opener.open(request, timeout=120) as response:
            return parse_json(response.read(8 * 1024 * 1024))

    def optional(self, suffix):
        try:
            return self.call("GET", suffix)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def download_artifact(self, artifact_id, destination):
        require(positive_int(artifact_id), "artifact ID")
        request = urllib.request.Request(
            f"{API}/repos/{BUILD_REPO}/actions/artifacts/{artifact_id}/zip",
            headers={"Authorization": "Bearer " + self.token,
                     "User-Agent": "dc0d32-wezterm-builds"})
        with self.opener.open(request, timeout=120) as response:
            with destination.open("xb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    require(total <= MAX_ZIP + 1024 * 1024, "artifact too large")
                    output.write(chunk)


def source_version(api, sha):
    require(hex_string(sha, 40), "upstream SHA")
    commit = api.get(f"/repos/{SOURCE_REPO}/commits/{sha}")
    require(commit["sha"] == sha, "upstream did not return exact commit")
    stamp = dt.datetime.fromisoformat(commit["commit"]["committer"]["date"].replace("Z", "+00:00"))
    require(stamp.tzinfo is not None, "upstream commit timestamp")
    return stamp.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + sha[:8]


def valid_pr(pr, default):
    return (
        pr.get("state") == "open" and pr.get("merged_at") is None
        and pr.get("merged", False) is False
        and pr.get("head", {}).get("repo", {}) is not None
        and (pr["head"].get("repo") or {}).get("full_name") == REQUEST_REPO
        and (pr["head"].get("repo") or {}).get("fork", False) is False
        and pr["head"].get("ref") == BRANCH
        and (pr.get("base", {}).get("repo") or {}).get("full_name") == REQUEST_REPO
        and pr["base"].get("ref") == default
        and hex_string(pr["head"].get("sha"), 40)
    )


def discover(api):
    default = api.get(f"/repos/{REQUEST_REPO}")["default_branch"]
    query = urllib.parse.urlencode({"state": "open", "head": "dc0d32:" + BRANCH,
                                  "base": default})
    prs = [pr for pr in api.pages(f"/repos/{REQUEST_REPO}/pulls?{query}")
           if valid_pr(pr, default)]
    if not prs:
        return None
    require(len(prs) == 1, "ambiguous request PR")
    pr = api.get(f"/repos/{REQUEST_REPO}/pulls/{prs[0]['number']}")
    require(valid_pr(pr, default), "PR no longer eligible")
    sha = pr["head"]["sha"]
    file = api.get(f"/repos/{REQUEST_REPO}/contents/{REQUEST_PATH}?ref={sha}")
    require(file.get("type") == "file" and file.get("path") == REQUEST_PATH
            and file.get("encoding") == "base64" and type(file.get("size")) is int
            and 0 < file["size"] <= 16384, "request file metadata")
    content = base64.b64decode(file["content"].replace("\n", ""), validate=True)
    require(len(content) == file["size"], "request content size")
    request = validate_request(parse_json(content))
    version = source_version(api, request["source_sha"])
    again = api.get(f"/repos/{REQUEST_REPO}/pulls/{pr['number']}")
    require(valid_pr(again, default) and again["head"]["sha"] == sha,
            "request superseded while polling")
    ref = api.get(f"/repos/{REQUEST_REPO}/git/ref/heads/{BRANCH}")
    require(ref.get("ref") == "refs/heads/" + BRANCH
            and ref.get("object", {}).get("type") == "commit"
            and ref["object"].get("sha") == sha, "request branch superseded")
    return {"request": request, "pr_number": pr["number"], "pr_head": sha,
            "default_branch": default, "version": version}


def validate_snapshot(snapshot):
    require(type(snapshot) is dict and set(snapshot) == {
        "request", "pr_number", "pr_head", "default_branch", "version"}, "snapshot keys")
    validate_request(snapshot["request"])
    require(positive_int(snapshot["pr_number"]), "PR number")
    require(hex_string(snapshot["pr_head"], 40), "PR head")
    require(isinstance(snapshot["default_branch"], str)
            and bool(snapshot["default_branch"]), "PR base branch")
    require(isinstance(snapshot["version"], str) and re.fullmatch(
        r"\d{8}-\d{6}-[0-9a-f]{8}", snapshot["version"]), "version")
    require(snapshot["version"].endswith(snapshot["request"]["source_sha"][:8]),
            "version SHA")
    return snapshot


def recheck(api, snapshot):
    validate_snapshot(snapshot)
    require(discover(api) == snapshot, "closed, merged or superseded request")


def identity(source_sha, run_id, run_attempt):
    require(hex_string(source_sha, 40) and positive_int(run_id)
            and positive_int(run_attempt), "build identity")
    build_id = f"{source_sha}-{run_id}-{run_attempt}"
    return build_id, "wezterm-" + build_id, "WezTerm-windows-" + build_id + ".zip"


def context(api, env=os.environ):
    require(env.get("GITHUB_REPOSITORY") == BUILD_REPO, "build repository")
    require(env.get("GITHUB_EVENT_NAME") in ("schedule", "workflow_dispatch"), "event")
    default = api.get(f"/repos/{BUILD_REPO}")["default_branch"]
    require(env.get("GITHUB_REF") == "refs/heads/" + default, "default branch only")
    require(hex_string(env.get("GITHUB_SHA"), 40), "workflow head SHA")
    require(numeric_string(env.get("GITHUB_RUN_ID"))
            and numeric_string(env.get("GITHUB_RUN_ATTEMPT")), "run identity")
    return default, int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])


def prove_run(api, run_id, attempt, default, completed=False, head_sha=None):
    run = api.get(f"/repos/{BUILD_REPO}/actions/runs/{run_id}/attempts/{attempt}")
    require(run.get("id") == run_id and run.get("run_attempt") == attempt, "run/attempt")
    require(run.get("path") == WORKFLOW and run.get("event") in ("schedule", "workflow_dispatch")
            and (run.get("head_repository") or {}).get("full_name") == BUILD_REPO
            and run.get("head_branch") == default, "workflow provenance")
    require(hex_string(run.get("head_sha"), 40), "run head SHA")
    if head_sha is not None:
        require(run["head_sha"] == head_sha, "workflow checkout SHA")
    if completed:
        require(run.get("status") == "completed" and run.get("conclusion") == "success",
                "release run not completed successfully")
    path = f"/repos/{BUILD_REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    rows = []
    for page in range(1, 101):
        result = api.get(f"{path}?per_page=100&page={page}")
        jobs = result["jobs"]
        rows.extend(jobs)
        if len(jobs) < 100:
            break
    else:
        raise ValueError("jobs pagination exceeded safe bound")
    builds = [job for job in rows if job.get("name") == "build"]
    require(len(builds) == 1 and builds[0].get("run_id") == run_id
            and builds[0].get("run_attempt") == attempt
            and builds[0].get("status") == "completed"
            and builds[0].get("conclusion") == "success", "successful build job required")
    return run


def validate_manifest(obj, snapshot=None, run_id=None, attempt=None):
    require(type(obj) is dict and set(obj) == MANIFEST_KEYS, "manifest keys")
    require(type(obj["schema"]) is int and obj["schema"] == 1, "manifest schema")
    require(obj["success"] is True and obj["source_repository"] == SOURCE_REPO
            and obj["build_repository"] == BUILD_REPO, "manifest repositories/success")
    build_id, _, asset = identity(obj["source_sha"], obj["run_id"], obj["run_attempt"])
    require(obj["build_id"] == build_id and obj["asset_name"] == asset, "manifest identity")
    require(hex_string(obj["sha256"], 64) and positive_int(obj["size"])
            and obj["size"] <= MAX_ZIP, "manifest checksum/size")
    request = {key: obj[key] for key in
               ("schema", "source_repository", "source_sha", "request_id", "requested_at", "nonce")}
    request.update(repository=REQUEST_REPO, branch=BRANCH)
    validate_request(request)
    require(isinstance(obj["version"], str) and re.fullmatch(
        r"\d{8}-\d{6}-[0-9a-f]{8}", obj["version"])
        and obj["version"].endswith(obj["source_sha"][:8]), "manifest version")
    require(obj["archive_root"] == "WezTerm-windows-" + obj["version"], "archive root")
    if snapshot is not None:
        validate_snapshot(snapshot)
        require(all(obj[key] == snapshot["request"][key] for key in
                    ("source_sha", "request_id", "requested_at", "nonce")),
                "manifest request mismatch")
        require(obj["version"] == snapshot["version"], "manifest intended version")
    if run_id is not None:
        require(obj["run_id"] == run_id and obj["run_attempt"] == attempt, "manifest run mismatch")
    return obj


def zip_members(archive):
    members = archive.infolist()
    require(0 < len(members) <= 10000, "ZIP member count")
    seen = set()
    files = set()
    directories = {}
    total = 0
    for entry in members:
        name = entry.filename
        require("\x00" not in name and "\\" not in name and not name.startswith("/")
                and name == entry.orig_filename, "unsafe ZIP path")
        parts = name.rstrip("/").split("/")
        require(all(part and part not in (".", "..") and not part.endswith((" ", "."))
                    and not re.search(r'[<>:"|?*\x00-\x1f]', part)
                    and not re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?", part)
                    for part in parts), "unsafe Windows ZIP path")
        folded = name.rstrip("/").casefold()
        require(folded not in seen, "duplicate ZIP path")
        seen.add(folded)
        for index in range(1, len(parts) + (1 if entry.is_dir() else 0)):
            directory = "/".join(parts[:index])
            key = directory.casefold()
            require(key not in files, "ZIP file/directory collision")
            require(key not in directories or directories[key] == directory,
                    "case-colliding ZIP directories")
            directories[key] = directory
        if not entry.is_dir():
            require(folded not in directories, "ZIP file/directory collision")
            files.add(folded)
        mode = entry.external_attr >> 16
        require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "special ZIP entry")
        require(not entry.flag_bits & 1 and entry.compress_type in
                (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsupported ZIP encoding")
        require(entry.file_size <= MAX_FILE, "ZIP member too large")
        total += entry.file_size
        require(total <= MAX_EXPANDED, "ZIP expansion too large")
    return members


def check_zip(path, root):
    with zipfile.ZipFile(path) as archive:
        members = zip_members(archive)
        files = set()
        for entry in members:
            require(entry.filename == root + "/" or entry.filename.startswith(root + "/"),
                    "unexpected archive root")
            if not entry.is_dir():
                name = entry.filename[len(root) + 1:]
                files.add(name)
                require(entry.file_size > 0, "empty package file")
                with archive.open(entry) as stream:
                    while stream.read(1024 * 1024):
                        pass
        require(REQUIRED_FILES <= files, "missing Windows runtime/package files")


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_bytes(manifest):
    return f"{manifest['sha256']}  {manifest['asset_name']}\n".encode("ascii")


def validate_package(directory, snapshot, run_id, attempt):
    require(directory.is_dir() and not directory.is_symlink(), "package directory")
    entries = list(directory.iterdir())
    _, _, asset = identity(snapshot["request"]["source_sha"], run_id, attempt)
    require({item.name for item in entries} == {asset, "provenance.json", "SHA256SUMS"},
            "package file allowlist")
    require(all(item.is_file() and not item.is_symlink() for item in entries), "package regular files")
    manifest_path = directory / "provenance.json"
    require(manifest_path.stat().st_size <= 16384, "manifest too large")
    manifest = validate_manifest(parse_json(manifest_path.read_bytes()), snapshot, run_id, attempt)
    zip_path = directory / asset
    require(zip_path.stat().st_size == manifest["size"]
            and digest_file(zip_path) == manifest["sha256"], "archive checksum/size")
    require((directory / "SHA256SUMS").stat().st_size <= 1024
            and (directory / "SHA256SUMS").read_bytes() == checksum_bytes(manifest), "SHA256SUMS")
    check_zip(zip_path, manifest["archive_root"])
    return manifest


def unpack_artifact(path, destination, asset):
    require(not destination.exists(), "fresh incoming directory required")
    with zipfile.ZipFile(path) as archive:
        members = zip_members(archive)
        require({entry.filename for entry in members} == {asset, "provenance.json", "SHA256SUMS"}
                and len(members) == 3 and all(not entry.is_dir() for entry in members),
                "artifact file allowlist")
        for entry in members:
            limit = MAX_ZIP if entry.filename == asset else 16384
            require(entry.file_size <= limit, "artifact member size")
        destination.mkdir()
        for entry in members:
            with archive.open(entry) as source, (destination / entry.filename).open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)


def release_asset_bytes(api, tag, name, limit):
    url = f"https://github.com/{BUILD_REPO}/releases/download/{tag}/{name}"
    # Public release CDN visibility may lag the successful publication API call.
    delays = (1, 2, 4, 8, 16)
    for attempt in range(len(delays) + 1):
        try:
            return api.raw(url, limit)
        except urllib.error.HTTPError as exc:
            if exc.code not in (404, 429, 500, 502, 503, 504):
                raise
            failure = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            failure = exc
        if attempt == len(delays):
            raise failure
        time.sleep(delays[attempt])


def valid_release(api, release, source_sha, default, expected=None, completed=True):
    if release.get("draft") is not False or release.get("prerelease") is not False:
        return None
    tag = release.get("tag_name", "")
    if not re.fullmatch(r"wezterm-" + source_sha + r"-[1-9][0-9]*-[1-9][0-9]*", tag):
        return None
    require(release.get("immutable") is True, "release immutability must be enabled")
    manifest = validate_manifest(parse_json(
        release_asset_bytes(api, tag, "provenance.json", 16384)))
    _, wanted_tag, asset_name = identity(source_sha, manifest["run_id"], manifest["run_attempt"])
    require(tag == wanted_tag and manifest["source_sha"] == source_sha, "release identity")
    require(manifest["version"] == source_version(api, source_sha), "release source version")
    if expected is not None:
        require(manifest == expected, "existing release differs; never overwrite")
    assets = release.get("assets", [])
    require(len(assets) == 3 and {a["name"] for a in assets} ==
            {asset_name, "provenance.json", "SHA256SUMS"}, "release assets")
    require(all(a.get("state") == "uploaded" for a in assets), "incomplete release assets")
    archive = next(a for a in assets if a["name"] == asset_name)
    require(archive.get("size") == manifest["size"]
            and archive.get("digest") == "sha256:" + manifest["sha256"],
            "release archive digest/size")
    require(release_asset_bytes(api, tag, "SHA256SUMS", 1024) == checksum_bytes(manifest),
            "release checksum")
    run = prove_run(api, manifest["run_id"], manifest["run_attempt"], default, completed=completed)
    ref = api.get(f"/repos/{BUILD_REPO}/git/ref/tags/{tag}")
    require(ref.get("ref") == "refs/tags/" + tag
            and ref.get("object", {}).get("type") == "commit"
            and ref["object"].get("sha") == run["head_sha"], "release tag run provenance")
    return manifest


def successful_source(api, source_sha, default):
    for release in api.pages(f"/repos/{BUILD_REPO}/releases"):
        tag = release.get("tag_name", "")
        if not tag.startswith("wezterm-" + source_sha + "-"):
            continue
        try:
            if valid_release(api, release, source_sha, default) is not None:
                return release
        except ValueError as exc:
            print("Ignoring unsuccessful/invalid release:", tag, str(exc), file=sys.stderr)
    return None


def poll(api):
    default, run_id, attempt = context(api)
    snapshot = discover(api)
    if snapshot is None:
        print("No eligible open same-repository request PR.")
        return
    source_sha = snapshot["request"]["source_sha"]
    if successful_source(api, source_sha, default):
        print("Source already has a durable successful release.")
        return
    recheck(api, snapshot)
    build_id, _, _ = identity(source_sha, run_id, attempt)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write("snapshot=" + canonical(snapshot) + "\n")
        output.write("build_id=" + build_id + "\n")


def package(api):
    _, run_id, attempt = context(api)
    snapshot = validate_snapshot(parse_json(os.environ["SNAPSHOT"]))
    require(source_version(api, snapshot["request"]["source_sha"]) == snapshot["version"],
            "package upstream version")
    directory = Path("package")
    directory.mkdir()
    build_id, _, asset = identity(snapshot["request"]["source_sha"], run_id, attempt)
    original = Path("candidate") / ("WezTerm-windows-" + snapshot["version"] + ".zip")
    require(original.is_file() and not original.is_symlink() and 0 < original.stat().st_size <= MAX_ZIP,
            "upstream package ZIP")
    check_zip(original, "WezTerm-windows-" + snapshot["version"])
    target = directory / asset
    with original.open("rb") as source, target.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            output.write(chunk)
    manifest = {
        "schema": 1, "source_repository": SOURCE_REPO,
        "source_sha": snapshot["request"]["source_sha"], "build_repository": BUILD_REPO,
        "run_id": run_id, "run_attempt": attempt, "build_id": build_id,
        "version": snapshot["version"], "archive_root": "WezTerm-windows-" + snapshot["version"],
        "asset_name": asset, "sha256": digest_file(target), "size": target.stat().st_size,
        "success": True,
    }
    manifest.update({key: snapshot["request"][key] for key in ("request_id", "requested_at", "nonce")})
    (directory / "provenance.json").write_text(canonical(manifest) + "\n", encoding="utf-8")
    (directory / "SHA256SUMS").write_bytes(checksum_bytes(manifest))
    validate_package(directory, snapshot, run_id, attempt)


def publish(api, own):
    default, run_id, attempt = context(api)
    snapshot = validate_snapshot(parse_json(os.environ["SNAPSHOT"]))
    run = prove_run(api, run_id, attempt, default, head_sha=os.environ["GITHUB_SHA"])
    recheck(api, snapshot)
    source_sha = snapshot["request"]["source_sha"]
    if successful_source(api, source_sha, default):
        print("Source already published successfully; no duplicate release.")
        return
    require(numeric_string(os.environ.get("ARTIFACT_ID")), "artifact ID output")
    artifact_id = int(os.environ["ARTIFACT_ID"])
    build_id, tag, asset = identity(source_sha, run_id, attempt)
    artifact = own.call("GET", f"/actions/artifacts/{artifact_id}")
    require(artifact.get("id") == artifact_id and artifact.get("name") == "package-" + build_id
            and artifact.get("expired") is False, "artifact identity")
    metadata = artifact.get("workflow_run") or {}
    require(metadata.get("id") == run_id and metadata.get("head_sha") == run["head_sha"]
            and metadata.get("head_branch") == default, "artifact run provenance")
    own.download_artifact(artifact_id, Path("artifact.zip"))
    unpack_artifact(Path("artifact.zip"), Path("incoming"), asset)
    manifest = validate_package(Path("incoming"), snapshot, run_id, attempt)
    recheck(api, snapshot)
    existing = own.optional("/releases/tags/" + tag)
    if existing is not None:
        require(valid_release(api, existing, source_sha, default, expected=manifest, completed=False)
                is not None, "existing tag is not a successful identical release")
        print("Identical successful release already exists; no changes.")
        return
    require(own.optional("/git/ref/tags/" + tag) is None, "tag already exists; never reuse")
    # Atomic creation rejects a tag that appeared after the preceding GET.
    reserved = own.call("POST", "/git/refs", {"ref": "refs/tags/" + tag, "sha": run["head_sha"]})
    require(reserved.get("ref") == "refs/tags/" + tag
            and reserved.get("object", {}).get("type") == "commit"
            and reserved["object"].get("sha") == run["head_sha"], "new tag reservation")
    release = own.call("POST", "/releases", {
        "tag_name": tag, "target_commitish": run["head_sha"], "name": tag,
        "body": f"Exact {SOURCE_REPO}@{source_sha}\nRequest {snapshot['request']['request_id']}\n"
                f"Run https://github.com/{BUILD_REPO}/actions/runs/{run_id}/attempts/{attempt}\n"
                "Permanent assets: never overwrite or delete successful releases.",
        "draft": True, "prerelease": False, "make_latest": "false",
    })
    require(positive_int(release.get("id")) and release.get("draft") is True, "new draft")
    release_id = release["id"]
    for name in (asset, "provenance.json", "SHA256SUMS"):
        payload = (Path("incoming") / name).read_bytes()
        uploaded = own.call("POST", f"/releases/{release_id}/assets?name={name}",
                            payload, content_type="application/octet-stream", upload=True)
        require(uploaded.get("name") == name and uploaded.get("state") == "uploaded"
                and uploaded.get("size") == len(payload)
                and uploaded.get("digest") == "sha256:" + hashlib.sha256(payload).hexdigest(),
                "uploaded asset integrity")
    # The final check is immediately before the visibility/immutability transition.
    recheck(api, snapshot)
    final = own.call("PATCH", f"/releases/{release_id}", {
        "draft": False, "prerelease": False, "make_latest": "false",
    })
    require(final.get("immutable") is True, "enable repository release immutability in Settings")
    require(valid_release(api, final, source_sha, default, expected=manifest, completed=False)
            is not None, "published release validation")
    print("Published permanent immutable release:", tag)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ("poll", "package", "publish"), "command")
    api = PublicAPI()
    if sys.argv[1] == "publish":
        publish(api, OwnAPI(os.environ.get("GITHUB_TOKEN")))
    else:
        {"poll": poll, "package": package}[sys.argv[1]](api)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, zipfile.BadZipFile) as exc:
        print("Failing closed:", str(exc), file=sys.stderr)
        sys.exit(1)
