"""Cache identity and fail-closed filesystem checks; no cached code runs here."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


NEXTEST_VERSION = "0.9.114"
CACHE_SCHEMA = "wt-win-v1"
PATHS = {
    "registry": ".cargo-build/registry/cache",
    "target": "candidate/target",
    "nextest": ".nextest/bin",
}
IDENTITY_FIELDS = {
    "os", "arch", "target", "rustc", "cargo", "image_os", "image_version",
    "native", "environment",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cache_plan(identity, lock, source, scripts, nextest_version=NEXTEST_VERSION):
    """Every fallback retains the complete toolchain/native/environment scope."""
    if set(identity) != IDENTITY_FIELDS:
        raise ValueError("Incomplete build environment identity")
    if identity["os"] != "Windows" or identity["arch"] != "X64":
        raise ValueError("Unsupported runner")
    targets = {
        "x86_64-pc-windows-msvc": "X64",
        "aarch64-pc-windows-msvc": "ARM64",
    }
    if identity["target"] not in targets:
        raise ValueError("Unsupported target")
    for field in IDENTITY_FIELDS - {"environment"}:
        if not isinstance(identity[field], str) or not identity[field].strip():
            raise ValueError(f"Missing identity: {field}")
    for tool in ("rustc", "cargo"):
        if "host: x86_64-pc-windows-msvc" not in identity[tool].splitlines():
            raise ValueError(f"Wrong {tool} host")
    if not isinstance(identity["environment"], dict) or not identity["environment"]:
        raise ValueError("Missing compiler environment")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("Invalid full source SHA")
    if not re.fullmatch(r"\d+\.\d+\.\d+", nextest_version):
        raise ValueError("Invalid nextest version")
    if not lock or not scripts:
        raise ValueError("Missing lockfile or build scripts")
    scope = digest(json.dumps(
        {"identity": identity, "scripts": scripts}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True,
    ).encode())
    base = f"{CACHE_SCHEMA}-Windows-{targets[identity['target']]}-{scope}"
    revision = f"{digest(lock)}-{source}"
    return {
        "registry_key": f"{base}-registry-{revision}",
        "registry_restore": f"{base}-registry-",
        "target_key": f"{base}-target-{revision}",
        # No environment-only target fallback: reuse only the same lockfile.
        "target_restore": f"{base}-target-{digest(lock)}-",
        "nextest_key": f"{base}-nextest-{nextest_version}",
    }


def plain_tree(root, relative):
    """Reject links/junctions on ancestors too, before traversing cache data."""
    path = root
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Cache link: {path}")
        if path.exists():
            mode = path.lstat()
            if getattr(mode, "st_file_attributes", 0) & 0x400:
                raise ValueError(f"Cache reparse point: {path}")
            if not stat.S_ISDIR(mode.st_mode):
                raise ValueError(f"Cache root must be a directory: {path}")
    if not path.exists():
        return []
    files = []
    for directory, dirs, names in os.walk(path, followlinks=False):
        for name in dirs + names:
            entry = Path(directory) / name
            mode = entry.lstat()
            if (stat.S_ISLNK(mode.st_mode)
                    or getattr(mode, "st_file_attributes", 0) & 0x400
                    or not (stat.S_ISDIR(mode.st_mode) or stat.S_ISREG(mode.st_mode))):
                raise ValueError(f"Unsafe cache entry: {entry}")
            if stat.S_ISREG(mode.st_mode):
                files.append(entry.relative_to(path))
    return files


def validate_cache(root, nextest_hit=False):
    registry = plain_tree(root, PATHS["registry"])
    for file in registry:
        if (len(file.parts) != 2
                or not re.fullmatch(r"index\.crates\.io-[0-9a-f]+", file.parts[0])
                or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.crate", file.name)):
            raise ValueError(f"Not a crates.io download: {file}")
    plain_tree(root, PATHS["target"])
    tools = plain_tree(root, PATHS["nextest"])
    if tools and tools != [Path("cargo-nextest.exe")]:
        raise ValueError("Nextest cache must contain only cargo-nextest.exe")
    tool_root = root / PATHS["nextest"]
    if tool_root.exists() and any(entry.is_dir() for entry in tool_root.iterdir()):
        raise ValueError("Nextest cache must not contain directories")
    executable = root / PATHS["nextest"] / "cargo-nextest.exe"
    if nextest_hit and not executable.exists():
        raise ValueError("Nextest cache hit is missing its executable")
    if executable.exists() and executable.stat().st_size == 0:
        raise ValueError("Empty Nextest executable")


def validate_nextest_version(reported):
    # Upstream short() optionally includes a source commit/date; it is not
    # evidence of integrity. This check detects accidental corrupt/wrong hits.
    expected = rf"cargo-nextest {re.escape(NEXTEST_VERSION)}(?: \([0-9a-f]{{7,40}} \d{{4}}-\d{{2}}-\d{{2}}\))?"
    if not re.fullmatch(expected, reported):
        raise ValueError(f"Unexpected Nextest version: {reported!r}")


def current_plan(root):
    identity = json.loads((root / ".build-identity.json").read_text(encoding="utf-8-sig"))
    snapshot = json.loads(os.environ["SNAPSHOT"])
    scripts = {
        name: digest((root / "control" / name).read_bytes())
        for name in ("scripts/build.ps1", "scripts/build_cache.py", "scripts/cache_restore.py",
                     ".github/actions/cache-restore/action.yml",
                     ".github/actions/cache-restore/index.js", ".github/workflows/windows-build.yml")
    }
    return cache_plan(identity, (root / "candidate/Cargo.lock").read_bytes(),
                      snapshot["request"]["source_sha"], scripts)


def main():
    phase = sys.argv[1]
    root = Path.cwd()
    if phase == "prepare":
        plan = current_plan(root)
        (root / ".build-cache-plan.json").write_text(
            json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as output:
            for name, value in plan.items():
                output.write(f"{name}={value}\n")
            output.write(f"nextest_version={NEXTEST_VERSION}\n")
    elif phase == "verify":
        saved = json.loads((root / ".build-cache-plan.json").read_text(encoding="utf-8"))
        if saved != current_plan(root):
            raise ValueError("Build identity changed after preparation")
        validate_cache(root, nextest_hit=bool(os.environ.get("NEXTEST_CACHE_MATCHED")))
    elif phase == "validate":
        validate_cache(root)
    elif phase == "nextest-version":
        print(NEXTEST_VERSION)
    elif phase == "check-nextest-version":
        validate_nextest_version(sys.argv[2])
    else:
        raise ValueError("Unknown cache phase")


if __name__ == "__main__":
    main()
