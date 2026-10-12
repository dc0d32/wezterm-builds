"""Download cache v2 data without ever extracting its outer tar into the workspace."""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import tarfile
import urllib.parse
import urllib.request
import uuid

import build_cache


MAX_COMPRESSED = 10 * 1024 ** 3
MAX_EXPANDED = 30 * 1024 ** 3
MAX_MEMBERS = 300000
TIMEOUT = 1800
ROUTE = "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL"
KEY = re.compile(r"wt-win-v1-Windows-X64-[0-9a-f]{64}-(?:registry-[0-9a-f]{64}-[0-9a-f]{40}|target-[0-9a-f]{64}-[0-9a-f]{40}|nextest-\d+\.\d+\.\d+)")


def cache_version(path):
    return hashlib.sha256(
        f"{path}|zstd-without-long|windows-only|1.0".encode()).hexdigest()


def validate_keys(kind, primary, fallback, plan):
    if (kind not in build_cache.PATHS or not isinstance(primary, str)
            or not KEY.fullmatch(primary)
            or f"-{kind}-" not in primary
            or primary != plan.get(kind + "_key")
            or fallback != plan.get(kind + "_restore", "")):
        raise ValueError("Invalid cache identity")
    base = primary.split(f"-{kind}-")[0] + f"-{kind}-"
    expected = (base if kind == "registry" else
                base + primary[len(base):].split("-")[0] + "-" if kind == "target" else "")
    if fallback != expected:
        raise ValueError("Unsafe fallback scope")


def validate_url(url, blob=False):
    if (not isinstance(url, str) or not url or "#" in url
            or "\\" in url or re.search(r"[\x00-\x20\x7f]", url)):
        raise ValueError("Invalid service URL")
    parsed = urllib.parse.urlsplit(url)
    suffixes = (("blob.core.windows.net",) if blob else
                ("results-receiver.actions.githubusercontent.com",
                 "pipeline.actions.githubusercontent.com"))
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or parsed.netloc != host
            or not re.fullmatch(r"[a-z0-9.-]+", host)
            or any(not label or label.startswith("-") or label.endswith("-")
                   for label in host.split("."))
            or not any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)):
        raise ValueError("Unapproved service origin")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Cache redirects are forbidden")


def open_request(request):
    # Ignore ambient proxies; only the approved HTTPS origin receives credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    return opener.open(request, timeout=60)


def response_blocks(response, limit, timeout=TIMEOUT):
    start, total = time.monotonic(), 0
    # read1 returns after one socket read; read(n) can wait forever on trickled data.
    read = getattr(response, "read1", response.read)
    while True:
        if time.monotonic() - start > timeout:
            raise ValueError("Cache transfer timed out")
        block = read(min(1024 * 1024, limit - total + 1))
        if not block:
            return
        total += len(block)
        if total > limit:
            raise ValueError("Oversized cache transfer")
        yield block


def lookup(env, path, primary, fallback):
    if env.get("ACTIONS_CACHE_SERVICE_V2", "").lower() != "true":
        raise ValueError("Cache v2 is required")
    origin = validate_url(env.get("ACTIONS_RESULTS_URL"))
    token = env.get("ACTIONS_RUNTIME_TOKEN")
    if not token or re.search(r"[\x00-\x20\x7f]", token):
        raise ValueError("Missing runtime credential")
    body = {"key": primary, "version": cache_version(path)}
    if fallback:
        body["restore_keys"] = [fallback]
    request = urllib.request.Request(
        urllib.parse.urljoin(origin, ROUTE), data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST")
    with open_request(request) as response:
        if response.status != 200:
            raise ValueError("Cache API failed")
        data = b"".join(response_blocks(response, 1024 * 1024, timeout=60))
    reply = json.loads(data)
    if not isinstance(reply, dict):
        raise ValueError("Invalid API response")
    # Protobuf JSON omits false/default fields on an absent entry.
    if reply.get("ok", False) is False:
        return "", ""
    if reply.get("ok") is not True:
        raise ValueError("Invalid API status")
    matched = reply.get("matched_key")
    if (not isinstance(matched, str) or not KEY.fullmatch(matched)
            or not (matched == primary or fallback and matched.startswith(fallback))):
        raise ValueError("Unexpected matched cache key")
    return matched, validate_url(reply.get("signed_download_url"), blob=True)


def download(url, destination):
    request = urllib.request.Request(validate_url(url, blob=True), method="GET")
    with open_request(request) as response, open(destination, "xb") as output:
        if response.status != 200:
            raise ValueError("Cache download failed")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_COMPRESSED):
            raise ValueError("Oversized compressed cache")
        total = 0
        for block in response_blocks(response, MAX_COMPRESSED):
            total += len(block)
            output.write(block)
        if not total or length is not None and total != int(length):
            raise ValueError("Incomplete cache download")


def clean_environment(env):
    return {key: value for key, value in env.items()
            if not key.upper().startswith(("ACTIONS_", "INPUT_"))
            and key.upper() not in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ENV", "GITHUB_OUTPUT")}


def zstd_path():
    executable = shutil.which("zstd")
    if not executable:
        raise ValueError("Hosted zstd is required")
    version = subprocess.run(
        [executable, "--quiet", "--version"], env=clean_environment(os.environ),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
    if not re.search(rb"\bv?1\.\d+\.\d+\b", version.stdout):
        raise ValueError("Unsupported zstd")
    return executable


def decompress(source, destination):
    executable = zstd_path()
    process = subprocess.Popen(
        [executable, "--quiet", "-d", "-c", "--long=27", "--memory=128MB", str(source)],
        env=clean_environment(os.environ), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    # A watchdog kills this exact child even if a pipe read blocks.
    watchdog = threading.Timer(TIMEOUT, process.kill)
    watchdog.start()
    try:
        total = 0
        with open(destination, "xb") as output:
            while True:
                block = process.stdout.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_EXPANDED:
                    raise ValueError("Oversized expanded cache")
                output.write(block)
        if process.wait(timeout=30) != 0 or not total:
            raise ValueError("Cache decompression failed")
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def member_path(name, directory=False):
    if (not isinstance(name, str) or not name or name.startswith("/") or "//" in name
            or len(name) > 32767 or "\\" in name
            or re.search(r"[\x00-\x1f\x7f:\ud800-\udfff]", name)):
        raise ValueError("Unsafe archive path")
    if name.startswith("./"):
        name = name[2:]
    if directory:
        if name.endswith("/"):
            name = name[:-1]
        if name in ("", "."):
            return ""
    parts = name.split("/")
    if len(parts) > 128:
        raise ValueError("Excessively nested archive path")
    for part in parts:
        if (part in ("", ".", "..") or part.endswith((".", " "))
                or re.search(r'[<>\"|?*]', part)
                or re.fullmatch(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])",
                                part.split(".")[0].rstrip(" "), re.IGNORECASE)):
            raise ValueError("Unsafe archive path")
    return "/".join(parts)


def validate_tar_framing(path):
    """Bound extension allocation and reject tarfile's permissive early EOF."""
    size = Path(path).stat().st_size
    if size > MAX_EXPANDED or size % 512:
        raise ValueError("Invalid tar framing")
    extensions = {tarfile.XHDTYPE,
                  tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
    offset, count, metadata, chain = 0, 0, 0, 0
    with open(path, "rb") as stream:
        while offset < size:
            header = stream.read(512)
            if header == bytes(512):
                if size - offset < 1024:
                    raise ValueError("Missing tar terminator")
                while True:
                    padding = stream.read(1024 * 1024)
                    if not padding:
                        return
                    if any(padding):
                        raise ValueError("Non-padding tar tail")
            try:
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (tarfile.TarError, UnicodeError) as error:
                raise ValueError("Invalid tar header") from error
            # tarfile copies global fields into every member, amplifying memory use.
            if member.type == tarfile.XGLTYPE:
                raise ValueError("Unsupported global PAX metadata")
            count += 1
            if count > MAX_MEMBERS * 2 or member.size < 0:
                raise ValueError("Excessive tar headers")
            end = offset + 512 + ((member.size + 511) // 512) * 512
            if end > size:
                raise ValueError("Truncated tar payload")
            if member.type in extensions:
                chain += 1
                metadata += member.size
                if chain > 16 or member.size > 1024 * 1024 or metadata > 64 * 1024 * 1024:
                    raise ValueError("Excessive tar metadata")
                payload = stream.read(member.size)
                if member.type == tarfile.XHDTYPE:
                    cursor = 0
                    while cursor < len(payload):
                        space = payload.find(b" ", cursor)
                        length_text = payload[cursor:space]
                        if space < 0 or not length_text.isdigit() or len(length_text) > 10:
                            raise ValueError("Invalid PAX record")
                        length = int(length_text)
                        record = payload[space + 1:cursor + length]
                        if (length <= space - cursor + 1 or cursor + length > len(payload)
                                or not record.endswith(b"\n") or b"=" not in record):
                            raise ValueError("Invalid PAX record")
                        key, value = record[:-1].split(b"=", 1)
                        if (key == b"size" or b"sparse" in key.lower()
                                or key == b"SCHILY.realsize"
                                or key == b"SCHILY.filetype" and value == b"sparse"):
                            raise ValueError("Unsupported PAX size/sparse metadata")
                        if key in (b"path", b"linkpath"):
                            member_path(value.decode("utf-8", "strict"),
                                        directory=value.endswith(b"/"))
                        cursor += length
                else:
                    value = payload.rstrip(b"\0")
                    member_path(value.decode("utf-8", "strict"),
                                directory=value.endswith(b"/"))
            else:
                chain = 0
                if not (member.isdir() or member.isreg() or member.islnk()):
                    raise ValueError("Unsupported tar member")
                # TarInfo strips *all* trailing directory slashes while decoding.
                # Check the raw spelling before that normalization hides an attack.
                if member.isdir():
                    raw_name = header[:100].split(b"\0", 1)[0]
                    prefix = header[345:500].split(b"\0", 1)[0]
                    if header[257:265] == tarfile.POSIX_MAGIC and prefix:
                        raw_name = prefix + b"/" + raw_name
                    if raw_name.startswith(b"/") or b"//" in raw_name:
                        raise ValueError("Unsafe raw directory path")
            stream.seek(end)
            offset = end
    raise ValueError("Missing tar terminator")


def extract_archive(tar_path, stage_root, relative):
    if relative not in build_cache.PATHS.values():
        raise ValueError("Unapproved cache path")
    stage_root = Path(stage_root)
    if any(stage_root.iterdir()):
        raise ValueError("Stage must be empty")
    validate_tar_framing(tar_path)
    ancestors = {"/".join(relative.split("/")[:i])
                 for i in range(1, len(relative.split("/")))}
    entries, canonical, directory_names = {}, {}, set()
    expanded = 0
    with tarfile.open(tar_path, "r:") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_MEMBERS:
                raise ValueError("Too many cache members")
            if (member.sparse is not None
                    or any("sparse" in key.lower() or key == "SCHILY.realsize"
                           or key == "SCHILY.filetype" and value == "sparse"
                           for key, value in member.pax_headers.items())
                    or not (member.isdir() or member.isreg() or member.islnk())
                    or member.size < 0 or member.isdir() and member.size != 0
                    or member.islnk() and member.size != 0):
                raise ValueError("Unsupported archive member")
            name = member_path(member.name, member.isdir())
            inside = name == relative or name.startswith(relative + "/")
            if not inside and not (member.isdir() and name in ancestors | {""}):
                raise ValueError("Archive escapes requested cache root")
            if not member.isdir() and name == relative:
                raise ValueError("Cache root must be a directory")
            if name in entries:
                raise ValueError("Duplicate archive member")
            parts = name.split("/") if name else []
            for i in range(1, len(parts) + 1):
                path = "/".join(parts[:i])
                folded = path.casefold()
                if folded in canonical and canonical[folded] != path:
                    raise ValueError("Case-colliding archive paths")
                canonical[folded] = path
                if i < len(parts):
                    directory_names.add(path)
            if member.isdir():
                directory_names.add(name)
            entries[name] = member
            if member.isreg():
                expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ValueError("Oversized cache content")
            if member.isreg() and member.offset_data + member.size > Path(tar_path).stat().st_size:
                raise ValueError("Truncated archive content")
        if not entries or any(name in directory_names and not member.isdir()
                              for name, member in entries.items()):
            raise ValueError("Conflicting cache paths")
        resolved = {}
        for name, member in entries.items():
            if member.isdir():
                continue
            trail, visited, current = [], set(), name
            while current not in resolved:
                if current in visited or current not in entries:
                    raise ValueError("Missing or cyclic hardlink")
                target = entries[current]
                if target.isreg():
                    resolved[current] = target
                    break
                if not target.islnk():
                    raise ValueError("Hardlink must resolve to a regular file")
                trail.append(current)
                visited.add(current)
                current = member_path(target.linkname)
                if not current.startswith(relative + "/"):
                    raise ValueError("Hardlink escapes cache root")
            for item in trail:
                resolved[item] = resolved[current]
            if member.islnk():
                expanded += resolved[name].size
            if expanded > MAX_EXPANDED:
                raise ValueError("Oversized materialized cache")
        # No filesystem writes occur before the complete member/link validation.
        (stage_root / relative).mkdir(parents=True)
        for name, member in entries.items():
            if name != relative and not name.startswith(relative + "/"):
                continue
            destination = stage_root / name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = resolved[name]
            with archive.extractfile(source) as stream, destination.open("xb") as output:
                remaining = source.size
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("Truncated cache member")
                    output.write(block)
                    remaining -= len(block)
            # Preserve Cargo fingerprints, but never permissions/ownership/xattrs.
            mtime = member.mtime
            if isinstance(mtime, (int, float)) and math.isfinite(mtime) and 0 <= mtime <= time.time() + 86400:
                os.utime(destination, (mtime, mtime))


def safe_restore(root, relative, url):
    root = Path(root)
    if relative not in build_cache.PATHS.values():
        raise ValueError("Unapproved cache path")
    build_cache.plain_tree(root, relative)
    destination = root / relative
    if destination.exists():
        raise ValueError("Restore requires a fresh cache root")
    scratch = root / (".cache-restore-" + uuid.uuid4().hex)
    scratch.mkdir(mode=0o700)
    try:
        compressed, archive, stage = scratch / "cache.zst", scratch / "cache.tar", scratch / "stage"
        download(url, compressed)
        decompress(compressed, archive)
        stage.mkdir(mode=0o700)
        extract_archive(archive, stage, relative)
        build_cache.validate_cache(stage, nextest_hit=relative == build_cache.PATHS["nextest"])
        build_cache.plain_tree(root, relative)
        if destination.exists():
            raise ValueError("Cache destination changed")
        destination.parent.mkdir(parents=True, exist_ok=True)
        (stage / relative).rename(destination)
    finally:
        shutil.rmtree(scratch)


def run(env, root):
    if (env.get("GITHUB_REPOSITORY") != "dc0d32/wezterm-builds"
            or env.get("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch")
            or not env.get("BUILD_DEFAULT_BRANCH")
            or env.get("GITHUB_REF") != "refs/heads/" + env["BUILD_DEFAULT_BRANCH"]
            or env.get("RUNNER_OS") != "Windows" or env.get("RUNNER_ARCH") != "X64"
            or env.get("ACTIONS_CACHE_SERVICE_V2", "").lower() != "true"
            or env.get("GITHUB_TOKEN") or env.get("GH_TOKEN")):
        raise ValueError("Restore is not allowed in this context")
    path, primary, fallback = (env.get("CACHE_PATH"), env.get("CACHE_KEY"),
                               env.get("CACHE_RESTORE_KEYS", ""))
    kind = next((kind for kind, value in build_cache.PATHS.items() if value == path), None)
    plan = json.loads((Path(root) / ".build-cache-plan.json").read_text(encoding="utf-8"))
    validate_keys(kind, primary, fallback, plan)
    zstd_path()
    matched, url = lookup(env, path, primary, fallback)
    if matched:
        # Defense in depth for the transport boundary (also useful for injected tests).
        if not KEY.fullmatch(matched) or not (matched == primary or fallback and matched.startswith(fallback)):
            raise ValueError("Unexpected matched cache key")
        safe_restore(root, path, url)
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as output:
        output.write(f"cache-hit={'true' if matched == primary else 'false'}\n")
        output.write(f"cache-matched-key={matched}\n")


if __name__ == "__main__":
    try:
        run(os.environ, Path.cwd())
    except Exception:
        # Never render HTTP exceptions: they can contain signed URLs or credentials.
        raise SystemExit("Secure cache restore failed")
