"""Offline adversarial tests for the cache restore trust boundary."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
with mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
    SPEC = importlib.util.spec_from_file_location(
        "cache_restore_under_test", ROOT / "scripts/cache_restore.py")
    restore = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(restore)

PATHS = {
    "registry": ".cargo-build/registry/cache",
    "target": "candidate/target",
    "nextest": ".nextest/bin",
}
RUNTIME_URL = "https://cache.results-receiver.actions.githubusercontent.com/"
BLOB_URL = "https://cache.blob.core.windows.net/archive?sig=fixture"
SCOPE = "a" * 64
LOCK = "b" * 64
SOURCE = "c" * 40
BASE = f"wt-win-v1-Windows-X64-{SCOPE}"
PLAN = {
    "registry_key": f"{BASE}-registry-{LOCK}-{SOURCE}",
    "registry_restore": f"{BASE}-registry-",
    "target_key": f"{BASE}-target-{LOCK}-{SOURCE}",
    "target_restore": f"{BASE}-target-{LOCK}-",
    "nextest_key": f"{BASE}-nextest-0.9.114",
}


def regular(name, data=b"fixture"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def directory(name):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    return info, None


def link(name, target, kind=tarfile.LNKTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.scratch_root = ROOT / "tests/.cache-restore-work"
        self.work = self.scratch_root / uuid.uuid4().hex
        self.work.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.workspace = self.work / "workspace"
        self.workspace.mkdir()
        self.archive_counter = 0

    def cleanup(self):
        shutil.rmtree(self.work)
        try:
            self.scratch_root.rmdir()
        except OSError:
            pass

    def archive(self, members, format=tarfile.PAX_FORMAT):
        self.archive_counter += 1
        path = self.work / f"archive-{self.archive_counter}.tar"
        with tarfile.open(path, "w", format=format) as archive:
            for info, content in members:
                archive.addfile(info, io.BytesIO(content) if content is not None else None)
        return path

    def stage(self):
        path = self.work / uuid.uuid4().hex
        path.mkdir()
        return path

    def tree(self, root):
        return {
            str(path.relative_to(root)): (
                "directory" if path.is_dir() else path.read_bytes())
            for path in root.rglob("*")
        }

    def assert_archive_rejected(self, members, relative="candidate/target"):
        stage = self.stage()
        with self.assertRaises(ValueError):
            restore.extract_archive(self.archive(members), stage, relative)
        self.assertEqual(self.tree(stage), {}, "validation must precede all extraction writes")

    def protect_workspace(self):
        for relative in ("candidate/src/main.rs", "candidate/Cargo.lock",
                         "candidate/.cargo/config.toml", "candidate/.tag",
                         "control/scripts/build.ps1", ".build-cache-plan.json",
                         ".cargo-build/config.toml"):
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"trusted: " + relative.encode())
        return self.tree(self.workspace)


class IdentityTests(unittest.TestCase):
    def test_version_matches_existing_windows_zstd_cache_format(self):
        known = {
            ".cargo-build/registry/cache":
                "f99ec46b664de94fc40e2180980b4ef199d52a8f7eec45ddb27fbdfd04612a9e",
            "candidate/target":
                "1fc899ef0c27aeb2f7d840e07adad6bfcc764eb6d8faf8b8d3d048e1fa6fd447",
            ".nextest/bin":
                "091750be3f666f816cf07ba8fd8a6cbdcea1f68f9de714c4cc7faf83d98cb462",
        }
        for path, expected in known.items():
            with self.subTest(path=path):
                self.assertEqual(restore.cache_version(path), expected)
                self.assertEqual(expected, hashlib.sha256(
                    f"{path}|zstd-without-long|windows-only|1.0".encode()).hexdigest())

    def test_keys_must_be_exact_prepared_values(self):
        for kind in PATHS:
            primary = PLAN[kind + "_key"]
            fallback = PLAN.get(kind + "_restore", "")
            restore.validate_keys(kind, primary, fallback, PLAN)
            for wrong_primary, wrong_fallback in (
                (primary + "-extra", fallback),
                (primary.upper(), fallback),
                (primary.replace(SCOPE, "d" * 64), fallback),
                (primary.replace(LOCK, "e" * 64) if kind != "nextest"
                 else primary.replace("0.9.114", "0.9.115"), fallback),
                (primary + "\nforged=value", fallback),
                ("", fallback),
                (primary, fallback + "extra"),
                (primary, fallback + "\nother-prefix-"),
                (primary, "*"),
            ):
                with self.subTest(kind=kind, primary=wrong_primary, fallback=wrong_fallback):
                    with self.assertRaises(ValueError):
                        restore.validate_keys(kind, wrong_primary, wrong_fallback, PLAN)

    def test_fallback_cannot_broaden_target_or_nextest_scope(self):
        for kind, fallback in (
            ("target", f"{BASE}-target-"),
            ("target", f"{BASE}-"),
            ("registry", "wt-win-v1-Windows-X64-"),
            ("nextest", PLAN["nextest_key"]),
            ("nextest", f"{BASE}-nextest-"),
        ):
            with self.subTest(kind=kind, fallback=fallback), self.assertRaises(ValueError):
                restore.validate_keys(kind, PLAN[kind + "_key"], fallback, PLAN)


class UrlTests(unittest.TestCase):
    def test_https_runtime_and_blob_hosts_allow_only_exact_suffix_boundaries(self):
        for host in ("results-receiver.actions.githubusercontent.com",
                     "x.results-receiver.actions.githubusercontent.com",
                     "pipeline.actions.githubusercontent.com",
                     "x.y.pipeline.actions.githubusercontent.com"):
            url = f"https://{host}/cache/?opaque=query"
            with self.subTest(url=url):
                self.assertEqual(restore.validate_url(url), url)
        for host in ("blob.core.windows.net", "cache.blob.core.windows.net",
                     "x.y.blob.core.windows.net"):
            url = f"https://{host}/cache?sig=fixture"
            with self.subTest(url=url):
                self.assertEqual(restore.validate_url(url, blob=True), url)

    def test_rejects_host_confusion_credentials_fragments_ports_and_non_https(self):
        for blob, good in ((False, "pipeline.actions.githubusercontent.com"),
                           (True, "cache.blob.core.windows.net")):
            for url in (
                f"http://{good}/",
                f"ftp://{good}/",
                f"https://{good}:443/",
                f"https://{good}:80/",
                f"https://user@{good}/",
                f"https://user:password@{good}/",
                f"https://{good}/#fragment",
                f"https://{good}/#",
                f"https://{good}.evil.example/",
                "https://evil-blob.core.windows.net/" if blob else f"https://evil-{good}/",
                f"https://{good}@evil.example/",
                f"https://{good}\\@evil.example/",
                f"https://{good}./",
                f"//{good}/",
                "https://127.0.0.1/",
                "https://[::1]/",
                "file:///etc/passwd",
                "",
                f"https://{good}/\nforged",
            ):
                with self.subTest(blob=blob, url=url), self.assertRaises(ValueError):
                    restore.validate_url(url, blob=blob)

    def test_runtime_and_blob_allowlists_are_not_interchangeable(self):
        with self.assertRaises(ValueError):
            restore.validate_url(BLOB_URL)
        with self.assertRaises(ValueError):
            restore.validate_url(RUNTIME_URL, blob=True)


class Response(io.BytesIO):
    def __init__(self, body, url=RUNTIME_URL, headers=None):
        super().__init__(body)
        self.status = 200
        self.headers = headers or {}
        self.url = url

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def info(self):
        return self.headers


class TransportTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.env = {
            "ACTIONS_CACHE_SERVICE_V2": "true",
            "ACTIONS_RESULTS_URL": RUNTIME_URL,
            "ACTIONS_RUNTIME_TOKEN": "runtime-token",
        }

    def lookup(self):
        return restore.lookup(self.env, PATHS["target"], PLAN["target_key"],
                              PLAN["target_restore"])

    def test_cache_v2_flag_accepts_only_case_insensitive_true(self):
        for flag in ("True", "true", "TRUE", "false", "False", "", "1", " true ", None):
            env = dict(self.env)
            if flag is None:
                env.pop("ACTIONS_CACHE_SERVICE_V2")
            else:
                env["ACTIONS_CACHE_SERVICE_V2"] = flag
            with self.subTest(flag=flag), \
                    mock.patch.object(restore, "open_request",
                                      return_value=Response(b'{"ok":false}')) as transport:
                if flag in ("True", "true", "TRUE"):
                    self.assertEqual(restore.lookup(
                        env, PATHS["target"], PLAN["target_key"], PLAN["target_restore"]),
                        ("", ""))
                    transport.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, "Cache v2 is required"):
                        restore.lookup(
                            env, PATHS["target"], PLAN["target_key"], PLAN["target_restore"])
                    transport.assert_not_called()

    def test_lookup_uses_v2_runtime_token_and_compatible_version(self):
        response = {
            "ok": True, "matched_key": PLAN["target_key"],
            "signed_download_url": BLOB_URL,
        }
        with mock.patch.object(urllib.request.OpenerDirector, "open", return_value=Response(
                json.dumps(response).encode())) as transport:
            self.assertEqual(self.lookup(), (PLAN["target_key"], BLOB_URL))
        request = transport.call_args.args[0]
        self.assertEqual(
            request.full_url,
            RUNTIME_URL + "twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer runtime-token")
        body = json.loads(request.data)
        self.assertEqual(body["key"], PLAN["target_key"])
        self.assertEqual(body["restore_keys"], [PLAN["target_restore"]])
        self.assertEqual(body["version"], restore.cache_version(PATHS["target"]))
        self.assertNotIn("runtime-token", request.full_url)
        self.assertNotIn("runtime-token", request.data.decode())

    def test_explicit_api_miss_does_not_require_download_fields(self):
        with mock.patch.object(urllib.request.OpenerDirector, "open",
                               return_value=Response(b'{"ok":false}')):
            self.assertEqual(self.lookup(), ("", ""))

    def test_omitted_protobuf_defaults_are_a_cache_miss(self):
        with mock.patch.object(urllib.request.OpenerDirector, "open",
                               return_value=Response(b"{}")):
            self.assertEqual(self.lookup(), ("", ""))

    def test_nonboolean_api_status_and_nondictionary_responses_fail_closed(self):
        for reply in ([True], None, "ok", {"ok": 0}, {"ok": 1},
                      {"ok": None}, {"ok": "false"}, {"ok": []}, {"ok": {}}):
            with self.subTest(reply=reply), \
                    mock.patch.object(urllib.request.OpenerDirector, "open",
                                      return_value=Response(json.dumps(reply).encode())):
                with self.assertRaises(ValueError):
                    self.lookup()

    def test_oversized_api_response_is_bounded_before_json_parsing(self):
        with mock.patch.object(urllib.request.OpenerDirector, "open",
                               return_value=Response(b" " * (1024 * 1024 + 1))), \
                mock.patch.object(restore.json, "loads") as parser:
            with self.assertRaisesRegex(ValueError, "Oversized"):
                self.lookup()
            parser.assert_not_called()

    def test_nextest_request_has_no_restore_keys_and_rejects_primary_suffix(self):
        for matched in (PLAN["nextest_key"], PLAN["nextest_key"] + "-suffix",
                        PLAN["nextest_key"].replace("0.9.114", "0.9.115")):
            response = {"ok": True, "matched_key": matched, "signed_download_url": BLOB_URL}
            with self.subTest(matched=matched), \
                    mock.patch.object(urllib.request.OpenerDirector, "open",
                                      return_value=Response(json.dumps(response).encode())) as transport:
                if matched == PLAN["nextest_key"]:
                    self.assertEqual(restore.lookup(
                        self.env, PATHS["nextest"], PLAN["nextest_key"], ""), (matched, BLOB_URL))
                else:
                    with self.assertRaises(ValueError):
                        restore.lookup(self.env, PATHS["nextest"], PLAN["nextest_key"], "")
                self.assertNotIn("restore_keys", json.loads(transport.call_args.args[0].data))

    def test_exact_primary_suffix_fails_without_any_fallback(self):
        for kind in PATHS:
            response = {"ok": True, "matched_key": PLAN[kind + "_key"] + "-suffix",
                        "signed_download_url": BLOB_URL}
            with self.subTest(kind=kind), \
                    mock.patch.object(urllib.request.OpenerDirector, "open",
                                      return_value=Response(json.dumps(response).encode())):
                with self.assertRaises(ValueError):
                    restore.lookup(self.env, PATHS[kind], PLAN[kind + "_key"], "")

    def test_redirects_never_issue_a_second_request_or_forward_credentials(self):
        # Exercise urllib's real redirect dispatch, replacing only network I/O.
        class RedirectTransport(urllib.request.HTTPSHandler):
            def __init__(self, status, target):
                super().__init__()
                self.status, self.target = status, target
                self.requests = []

            def https_open(self, request):
                self.requests.append(request)
                response = Response(b"", url=request.full_url,
                                    headers={"location": self.target})
                response.status = response.code = self.status
                response.msg = "fixture redirect"
                return response

        build_opener = urllib.request.build_opener
        for status in (301, 302, 303, 307, 308):
            for target in ("https://evil.example/stolen", BLOB_URL, RUNTIME_URL + "other"):
                for operation in ("lookup", "download"):
                    handler = RedirectTransport(status, target)
                    with self.subTest(status=status, target=target, operation=operation), \
                            mock.patch.object(urllib.request, "build_opener",
                                              side_effect=lambda *handlers: build_opener(
                                                  *handlers, handler)) as factory:
                        with self.assertRaisesRegex(ValueError, "redirects"):
                            if operation == "lookup":
                                self.lookup()
                            else:
                                restore.download(BLOB_URL, self.work / uuid.uuid4().hex)
                    factory.assert_called_once()
                    handlers = factory.call_args.args
                    self.assertTrue(any(isinstance(item, restore.NoRedirect) for item in handlers))
                    self.assertEqual(next(item for item in handlers if isinstance(
                        item, urllib.request.ProxyHandler)).proxies, {})
                    self.assertEqual(len(handler.requests), 1)
                    request = handler.requests[0]
                    self.assertEqual(request.get_header("Authorization"),
                                     "Bearer runtime-token" if operation == "lookup" else None)

    def test_lookup_http_auth_throttle_server_and_not_found_errors_fail_closed(self):
        for status in (401, 403, 404, 429, 500, 503):
            error = urllib.error.HTTPError(RUNTIME_URL, status, "fixture", {}, None)
            with self.subTest(status=status), \
                    mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=error):
                with self.assertRaises((ValueError, urllib.error.HTTPError)):
                    self.lookup()

    def test_malformed_success_and_non_allowlisted_blob_urls_are_not_misses(self):
        for response in (
            {"ok": True}, {"ok": True, "matched_key": PLAN["target_key"]},
            {"ok": True, "signed_download_url": BLOB_URL},
            {"ok": True, "matched_key": PLAN["target_key"],
             "signed_download_url": "https://evil.example/cache"},
            {"ok": True, "matched_key": PLAN["target_key"],
             "signed_download_url": RUNTIME_URL},
        ):
            with self.subTest(response=response), \
                    mock.patch.object(urllib.request.OpenerDirector, "open", return_value=Response(
                        json.dumps(response).encode())):
                with self.assertRaises(ValueError):
                    self.lookup()

    def test_runtime_url_is_validated_before_sending_bearer_token(self):
        for url in ("https://evil.example/", BLOB_URL,
                    RUNTIME_URL.replace("https:", "http:"),
                    RUNTIME_URL + "#fragment"):
            with self.subTest(url=url), \
                    mock.patch.object(urllib.request.OpenerDirector, "open") as transport:
                with self.assertRaises(ValueError):
                    restore.lookup({**self.env, "ACTIONS_RESULTS_URL": url},
                                   PATHS["target"], PLAN["target_key"], PLAN["target_restore"])
                transport.assert_not_called()

    def test_compressed_limit_applies_to_stream_even_without_content_length(self):
        for headers in ({}, {"Content-Length": "5"}):
            destination = self.work / uuid.uuid4().hex
            with self.subTest(headers=headers), \
                    mock.patch.object(restore, "MAX_COMPRESSED", 4), \
                    mock.patch.object(urllib.request.OpenerDirector, "open",
                                      return_value=Response(b"12345", url=BLOB_URL, headers=headers)):
                with self.assertRaises(ValueError):
                    restore.download(BLOB_URL, destination)

    def test_download_does_not_forward_runtime_bearer_to_blob(self):
        destination = self.work / "compressed"
        with mock.patch.dict(os.environ, self.env), \
                mock.patch.object(urllib.request.OpenerDirector, "open",
                                  return_value=Response(b"archive", url=BLOB_URL)) as transport:
            restore.download(BLOB_URL, destination)
        request = transport.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(destination.read_bytes(), b"archive")


class ArchiveTests(WorkspaceCase):
    def test_dot_root_directories_are_accepted(self):
        for name in (".", "./"):
            with self.subTest(name=name):
                stage = self.stage()
                restore.extract_archive(self.archive([
                    directory(name), regular("candidate/target/file")]),
                    stage, PATHS["target"])
                self.assertEqual((stage / "candidate/target/file").read_bytes(), b"fixture")

    def test_absolute_and_repeated_separator_directories_are_rejected(self):
        for name in ("/", "//", "///", "/candidate/target/",
                     "//candidate/target/", ".//", "candidate//target/",
                     "candidate/target//", "candidate/target/d//"):
            with self.subTest(name=name):
                self.assert_archive_rejected([
                    regular("candidate/target/valid"), directory(name)])

    def test_windows_console_and_superscript_devices_are_rejected(self):
        for name in ("CONIN$", "conout$", "CON .txt", "con   .txt",
                     "COM¹", "COM².txt", "com³.exe", "LPT¹", "lpt².txt", "LPT³.exe"):
            with self.subTest(name=name):
                self.assert_archive_rejected([
                    regular("candidate/target/valid"), regular("candidate/target/" + name)])

    def test_unicode_case_collisions_include_implicit_directories(self):
        for first, second in (("Straße", "STRASSE"), ("Σ", "ς"), ("K", "k")):
            for suffix in ("", "/file"):
                with self.subTest(first=first, second=second, suffix=suffix):
                    self.assert_archive_rejected([
                        regular("candidate/target/" + first + suffix),
                        regular("candidate/target/" + second + suffix)])

    def test_path_depth_accepts_128_components_and_rejects_129_before_writes(self):
        accepted = "candidate/target/" + "/".join(["d"] * 125 + ["file"])
        self.assertEqual(len(accepted.split("/")), 128)
        self.assertEqual(restore.member_path(accepted), accepted)
        stage = self.stage()
        restore.extract_archive(self.archive([regular(accepted)]), stage, PATHS["target"])
        self.assertEqual((stage / accepted).read_bytes(), b"fixture")
        for member in (regular(accepted + "/too-deep"), directory(accepted + "/too-deep/"),
                       link("candidate/target/link", accepted + "/too-deep")):
            with self.subTest(kind=member[0].type):
                self.assert_archive_rejected([regular("candidate/target/valid"), member])

    def test_gnu_longname_and_longlink_are_compatible(self):
        original = "candidate/target/" + "long-original-" * 12
        alias = "candidate/target/" + "long-alias-" * 12
        archive = self.archive([regular(original, b"gnu"), link(alias, original)],
                               format=tarfile.GNU_FORMAT)
        raw = archive.read_bytes()
        self.assertIn(tarfile.GNUTYPE_LONGNAME, [raw[i + 156:i + 157]
                                             for i in range(0, len(raw), 512)])
        self.assertIn(tarfile.GNUTYPE_LONGLINK, [raw[i + 156:i + 157]
                                             for i in range(0, len(raw), 512)])
        stage = self.stage()
        restore.extract_archive(archive, stage, PATHS["target"])
        for name in (original, alias):
            self.assertEqual((stage / name).read_bytes(), b"gnu")
            self.assertFalse((stage / name).is_symlink())

    def test_normal_pax_mtime_is_preserved_without_archive_permissions(self):
        info, content = regular("candidate/target/file")
        info.mtime = 1600000000.125
        info.mode = 0o7777
        info.uid, info.gid = 12345, 23456
        archive = self.archive([(info, content)])
        self.assertIn(b"mtime=1600000000.125\n", archive.read_bytes())
        stage = self.stage()
        restore.extract_archive(archive, stage, PATHS["target"])
        extracted = stage / info.name
        self.assertEqual(extracted.read_bytes(), content)
        self.assertAlmostEqual(extracted.stat().st_mtime, info.mtime, places=3)
        self.assertEqual(stat.S_IMODE(extracted.stat().st_mode) & 0o7111, 0)

    def test_ordinary_archives_support_inert_ancestors_and_explicit_directories(self):
        for kind, relative in PATHS.items():
            parts = relative.split("/")
            ancestors = [directory("/".join(parts[:i])) for i in range(1, len(parts) + 1)]
            suffix = {
                "registry": "index.crates.io-1949cf8c6b5b557f/serde-1.0.0.crate",
                "target": "release/deps/libserde.rlib",
                "nextest": "cargo-nextest.exe",
            }[kind]
            nested = suffix.split("/")
            dirs = [directory(relative + "/" + "/".join(nested[:i]))
                    for i in range(1, len(nested))]
            for prefix in ("", "./"):
                with self.subTest(kind=kind, prefix=prefix):
                    members = ancestors + dirs + [regular(relative + "/" + suffix, b"payload")]
                    for info, _ in members:
                        info.name = prefix + info.name
                    stage = self.stage()
                    restore.extract_archive(self.archive(members), stage, relative)
                    self.assertEqual((stage / relative / suffix).read_bytes(), b"payload")
                    restore.build_cache.validate_cache(stage, nextest_hit=kind == "nextest")

    def test_sibling_source_config_lock_tag_and_other_cache_roots_are_rejected(self):
        for name in (
            "candidate/src/main.rs", "candidate/Cargo.lock",
            "candidate/.cargo/config.toml", "candidate/.tag",
            "control/scripts/cache_restore.py", "control/.github/actions/cache-restore/index.js",
            ".build-cache-plan.json", ".cargo/config.toml", ".cargo-build/config.toml",
            ".cargo-build/registry/src/injected.rs", ".cargo-build/registry/index/config.json",
            ".cargo-build/registry/cache/index.crates.io-a/evil.crate",
            ".nextest/bin/cargo-nextest.exe", "package/wezterm.exe",
        ):
            with self.subTest(name=name):
                self.assert_archive_rejected([
                    regular("candidate/target/valid.rlib"), regular(name, b"attack")])

    def test_outside_directories_are_not_inert_ancestors(self):
        for name in ("candidate/src", "control", ".cargo-build", "candidate/other"):
            with self.subTest(name=name):
                self.assert_archive_rejected([directory(name), regular("candidate/target/file")])

    def test_each_cache_is_confined_to_its_own_requested_root(self):
        for kind, relative in PATHS.items():
            for other, wrong_root in PATHS.items():
                if other != kind:
                    with self.subTest(kind=kind, other=other):
                        self.assert_archive_rejected(
                            [regular(relative + "/valid"), regular(wrong_root + "/attack")],
                            relative)
            for name in (relative + "/../../injected", "candidate/.tag",
                         ".cargo-build/config.toml", "control/scripts/build.ps1"):
                with self.subTest(kind=kind, name=name):
                    self.assert_archive_rejected(
                        [regular(relative + "/valid"), regular(name)], relative)

    def test_path_attacks_fail_before_any_valid_member_is_written(self):
        for name in (
            "../candidate/target/file", "candidate/target/../../src/main.rs",
            "candidate/target/../file", "candidate/target/./file",
            "/candidate/target/file", "C:/candidate/target/file",
            "C:candidate/target/file", "//server/share/candidate/target/file",
            r"candidate\target\file", "candidate//target/file",
            "candidate/target/file:stream", "candidate/target/file.",
            "candidate/target/file ", "candidate/target/CON",
            "candidate/target/nul.exe", "candidate/target/LPT1.txt",
            "candidate/target/aux", "candidate/target/COM9",
            "candidate/target/a\nb", "candidate/target/a\rb",
        ):
            with self.subTest(name=name):
                self.assert_archive_rejected([regular("candidate/target/valid"), regular(name)])

    def test_unknown_requested_root_is_rejected(self):
        for relative in ("candidate", "candidate/src", "../target", "/target",
                         "candidate/target/", "C:/candidate/target"):
            with self.subTest(relative=relative):
                self.assert_archive_rejected([regular("candidate/target/file")], relative)

    def test_duplicates_and_case_collisions_include_implicit_ancestors(self):
        for members in (
            [regular("candidate/target/a"), regular("candidate/target/a")],
            [regular("candidate/target/a"), regular("candidate/target/A")],
            [directory("candidate/target/d"), directory("candidate/target/d")],
            [regular("candidate/target/Dir/a"), regular("candidate/target/dir/b")],
            [regular("candidate/target/Dir/a"), directory("candidate/target/dir")],
            [directory("Candidate"), regular("candidate/target/file")],
            [regular("candidate/target/d"), regular("candidate/target/d/file")],
            [regular("candidate/target/d/file"), regular("candidate/target/d")],
            [directory("candidate/target/a"), regular("candidate/target/a")],
        ):
            with self.subTest(names=[info.name for info, _ in members]):
                self.assert_archive_rejected(members)

    def test_links_special_members_and_sparse_files_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE, b"V"):
            info = tarfile.TarInfo("candidate/target/unsafe")
            info.type = kind
            info.linkname = "candidate/src"
            with self.subTest(kind=kind):
                self.assert_archive_rejected([regular("candidate/target/valid"), (info, None)])
        for attributes in (
            {"GNU.sparse.size": "1024"},
            {"GNU.sparse.map": "0,1", "GNU.sparse.size": "1024"},
            {"SCHILY.realsize": "1024", "SCHILY.filetype": "sparse"},
        ):
            info, content = regular("candidate/target/sparse", b"x")
            info.pax_headers = attributes
            with self.subTest(attributes=attributes):
                self.assert_archive_rejected([regular("candidate/target/valid"), (info, content)])

    def test_forward_backward_and_chain_hardlinks_are_materialized_as_regular_files(self):
        target = "candidate/target/"
        entries = [
            regular(target + "original", b"payload"),
            link(target + "first", target + "original"),
            link(target + "second", target + "first"),
        ]
        for members in (entries, list(reversed(entries))):
            stage = self.stage()
            restore.extract_archive(self.archive(members), stage, "candidate/target")
            for name in ("original", "first", "second"):
                file = stage / target / name
                self.assertFalse(file.is_symlink())
                self.assertTrue(file.is_file())
                self.assertEqual(file.read_bytes(), b"payload")

    def test_missing_cyclic_directory_and_outside_hardlinks_are_rejected(self):
        prefix = "candidate/target/"
        for members in (
            [link(prefix + "a", prefix + "missing")],
            [link(prefix + "a", prefix + "a")],
            [link(prefix + "a", prefix + "b"), link(prefix + "b", prefix + "a")],
            [directory(prefix + "dir"), link(prefix + "a", prefix + "dir")],
            [link(prefix + "a", "candidate/src/main.rs")],
            [link(prefix + "a", "../candidate/target/regular")],
            [link(prefix + "a", "/candidate/target/regular")],
            [regular(prefix + "regular"), link(prefix + "a", prefix + "Regular")],
            [link(prefix + "a", prefix + "b"), link(prefix + "b", ".nextest/bin/tool")],
            [link(prefix + "a", r"candidate\target\regular")],
        ):
            with self.subTest(names=[info.name for info, _ in members]):
                self.assert_archive_rejected([regular(prefix + "valid"), *members])

    def test_limits_match_documented_caps(self):
        self.assertEqual(restore.MAX_COMPRESSED, 10 * 1024 ** 3)
        self.assertEqual(restore.MAX_EXPANDED, 30 * 1024 ** 3)
        self.assertEqual(restore.MAX_MEMBERS, 300000)

    def test_member_and_expanded_limits_validate_before_writing(self):
        members = [regular("candidate/target/a", b"123"), regular("candidate/target/b", b"456")]
        with mock.patch.object(restore, "MAX_MEMBERS", 1):
            self.assert_archive_rejected(members)
        with mock.patch.object(restore, "MAX_EXPANDED", 5):
            self.assert_archive_rejected(members)

    def test_hardlink_expansion_cannot_bypass_expanded_limit(self):
        with mock.patch.object(restore, "MAX_EXPANDED", 5):
            self.assert_archive_rejected([
                regular("candidate/target/a", b"123"),
                link("candidate/target/b", "candidate/target/a"),
                link("candidate/target/c", "candidate/target/b"),
            ])

    def test_truncated_archive_never_promotes_or_leaves_extracted_data(self):
        path = self.archive([regular("candidate/target/a", b"a" * 4096)])
        path.write_bytes(path.read_bytes()[:1024])
        stage = self.stage()
        with self.assertRaises((ValueError, tarfile.TarError, OSError)):
            restore.extract_archive(path, stage, "candidate/target")


class TarFramingTests(WorkspaceCase):
    EXTENSIONS = (tarfile.XHDTYPE,
                  tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
    MIB = 1024 * 1024

    @staticmethod
    def pax_record(key, value):
        body = key + b"=" + value + b"\n"
        length = len(body) + 2
        while True:
            record = str(length).encode() + b" " + body
            if len(record) == length:
                return record
            length = len(record)

    def extension(self, kind, size):
        info = tarfile.TarInfo("metadata")
        info.type, info.size = kind, size
        if kind in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            digits = len(str(size))
            payload = self.pax_record(b"comment", b"x" * (size - digits - 10))
            self.assertEqual(len(payload), size)
        else:
            payload = b"filename" + bytes(size - len(b"filename"))
        return info, payload

    def framed_archive(self, members, tail=bytes(1024)):
        self.archive_counter += 1
        path = self.work / f"framing-{self.archive_counter}.tar"
        with path.open("wb") as output:
            for info, content in members:
                output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                if content is None:
                    # Sparse fixture payloads exercise the real caps without large buffers.
                    output.seek(((info.size + 511) // 512) * 512, io.SEEK_CUR)
                else:
                    self.assertEqual(len(content), info.size)
                    output.write(content)
                    output.write(bytes((-info.size) % 512))
            output.write(tail)
        return path

    def assert_framing_rejected_before_parser(self, path, message=None):
        stage = self.stage()
        with mock.patch.object(restore.tarfile, "open") as parser:
            with self.assertRaisesRegex(ValueError, message or "."):
                restore.extract_archive(path, stage, PATHS["target"])
            parser.assert_not_called()
        self.assertEqual(self.tree(stage), {}, "framing must precede every stage write")

    def test_global_pax_is_unsupported_even_when_empty_or_benign(self):
        for payload in (b"", self.pax_record(b"mtime", b"1600000000"),
                        self.extension(tarfile.XGLTYPE, self.MIB)[1]):
            info = tarfile.TarInfo("metadata")
            info.type, info.size = tarfile.XGLTYPE, len(payload)
            with self.subTest(size=len(payload)):
                archive = self.framed_archive([
                    regular("candidate/target/valid"), (info, payload),
                    regular("candidate/target/file")])
                self.assert_framing_rejected_before_parser(archive, "global PAX")

    def test_global_pax_field_amplification_is_rejected_before_payload_read(self):
        payload = b"".join(self.pax_record(f"field-{index}".encode(), b"x")
                           for index in range(10000))
        self.assertLess(len(payload), self.MIB)
        info = tarfile.TarInfo("metadata")
        info.type, info.size = tarfile.XGLTYPE, len(payload)
        archive = self.framed_archive([
            regular("candidate/target/valid", b""), (info, payload),
            *(regular(f"candidate/target/file-{index}", b"") for index in range(500))])
        with archive.open("rb") as stream:
            observed = mock.MagicMock(wraps=stream)
            observed.__enter__.return_value = observed
            with mock.patch.object(restore, "open", return_value=observed, create=True):
                self.assert_framing_rejected_before_parser(archive, "global PAX")
            self.assertEqual(observed.read.call_args_list, [mock.call(512), mock.call(512)],
                             "global metadata must be rejected before reading its payload")

    def test_each_extension_accepts_exactly_one_mib(self):
        for kind in self.EXTENSIONS:
            with self.subTest(kind=kind):
                archive = self.framed_archive([
                    self.extension(kind, self.MIB), regular("candidate/target/file")])
                restore.validate_tar_framing(archive)

    def test_each_extension_rejects_over_one_mib_before_payload_allocation(self):
        for kind in self.EXTENSIONS:
            info = tarfile.TarInfo("metadata")
            info.type, info.size = kind, self.MIB + 1
            archive = self.framed_archive([
                regular("candidate/target/valid"), (info, None)])
            with self.subTest(kind=kind), archive.open("rb") as stream:
                observed = mock.MagicMock(wraps=stream)
                observed.__enter__.return_value = observed
                with mock.patch.object(restore, "open", return_value=observed, create=True):
                    self.assert_framing_rejected_before_parser(archive, "metadata")
                self.assertTrue(observed.read.called)
                self.assertTrue(all(call.args == (512,) for call in observed.read.call_args_list),
                                "oversized metadata must be rejected before reading its payload")

    def test_aggregate_metadata_accepts_64_mib_and_rejects_more_with_chain_resets(self):
        metadata, payload = self.extension(tarfile.XHDTYPE, self.MIB)
        members = [regular("candidate/target/first")]
        for index in range(64):
            members.extend([(metadata, payload), regular(f"candidate/target/file-{index}", b"")])
        restore.validate_tar_framing(self.framed_archive(members))
        members.extend([(metadata, payload), regular("candidate/target/overflow", b"")])
        archive = self.framed_archive(members)
        with archive.open("rb") as stream:
            observed = mock.MagicMock(wraps=stream)
            observed.__enter__.return_value = observed
            with mock.patch.object(restore, "open", return_value=observed, create=True):
                self.assert_framing_rejected_before_parser(archive, "metadata")
            self.assertEqual(observed.read.call_args_list.count(mock.call(self.MIB)), 64,
                             "aggregate overflow must precede the 65th metadata allocation")

    def test_extension_chain_accepts_16_resets_on_members_and_rejects_17(self):
        chain = []
        for index in range(16):
            kind = self.EXTENSIONS[index % len(self.EXTENSIONS)]
            payload = (self.pax_record(b"mtime", b"1600000000")
                       if kind == tarfile.XHDTYPE else b"filename\0")
            info = tarfile.TarInfo("metadata")
            info.type, info.size = kind, len(payload)
            chain.append((info, payload))
        restore.validate_tar_framing(self.framed_archive([
            *chain, regular("candidate/target/first"),
            *chain, regular("candidate/target/second")]))
        archive = self.framed_archive([
            regular("candidate/target/valid"), *chain, chain[0],
            regular("candidate/target/file")])
        self.assert_framing_rejected_before_parser(archive, "metadata")

    def test_invalid_and_truncated_headers_and_tails_after_valid_member(self):
        valid = self.framed_archive([regular("candidate/target/valid")]).read_bytes()[:1024]
        invalid = bytearray(regular("candidate/target/other")[0].tobuf())
        invalid[0] ^= 1
        truncated = tarfile.TarInfo("candidate/target/truncated")
        truncated.size = 2048
        cases = {
            "bad checksum": valid + invalid + bytes(1024),
            "partial header": valid + b"broken header",
            "aligned garbage header": valid + b"!" * 512 + bytes(1024),
            "missing terminator": valid,
            "one zero terminator": valid + bytes(512),
            "truncated payload": valid + truncated.tobuf() + bytes(512),
            "nonzero second terminator": valid + bytes(512) + b"!" * 512,
            "junk after terminator": valid + bytes(1024) + b"!" * 512,
            "unaligned zero tail": valid + bytes(1025),
        }
        for label, content in cases.items():
            with self.subTest(label=label):
                archive = self.work / f"{label.replace(' ', '-')}.tar"
                archive.write_bytes(content)
                self.assert_framing_rejected_before_parser(archive)

    def test_appended_sibling_archive_cannot_hide_behind_valid_terminator(self):
        valid = self.archive([regular("candidate/target/valid")])
        sibling = self.archive([regular("candidate/src/injected.rs")])
        valid.write_bytes(valid.read_bytes() + sibling.read_bytes())
        self.assert_framing_rejected_before_parser(valid, "tail")

    def test_normal_tar_padding_is_accepted(self):
        archive = self.archive([regular("candidate/target/file")])
        with archive.open("ab") as output:
            output.write(bytes(4096))
        stage = self.stage()
        restore.extract_archive(archive, stage, PATHS["target"])
        self.assertEqual((stage / "candidate/target/file").read_bytes(), b"fixture")

    def test_invalid_pax_records_and_size_overrides_fail_before_parser(self):
        payloads = [b"not a record\n", b"999 mtime=0\n", b"0 x=y\n",
                    b"12 mtime=0!", b"12 noequals\n", b"0000000000012 x=y\n"]
        payloads.extend(self.pax_record(key, value) for key, value in (
            (b"size", b"1000000000"), (b"GNU.sparse.size", b"1"),
            (b"SCHILY.realsize", b"1"), (b"SCHILY.filetype", b"sparse")))
        for payload in payloads:
            for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                info = tarfile.TarInfo("metadata")
                info.type, info.size = kind, len(payload)
                with self.subTest(payload=payload, kind=kind):
                    archive = self.framed_archive([
                        regular("candidate/target/valid"), (info, payload),
                        regular("candidate/target/file")])
                    self.assert_framing_rejected_before_parser(archive, "PAX")


class ZstdTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.env = {
            "PATH": "/fixture/bin", "SystemRoot": "C:\\Windows",
            "ACTIONS_RUNTIME_TOKEN": "runtime-secret", "actions_results_url": RUNTIME_URL,
            "INPUT_KEY": "input-secret", "input_path": PATHS["target"],
            "GITHUB_TOKEN": "write-secret", "gh_token": "other-secret",
            "GITHUB_ENV": "environment-channel", "github_output": "output-channel",
        }
        self.clean_env = {"PATH": "/fixture/bin", "SystemRoot": "C:\\Windows"}

    def test_version_probe_strips_credentials_and_keeps_arguments_separate(self):
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(restore.shutil, "which", return_value="/fixture/zstd"), \
                mock.patch.object(restore.subprocess, "run", return_value=mock.Mock(
                    stdout=b"*** Zstandard CLI (64-bit) v1.5.7 ***")) as run:
            self.assertEqual(restore.zstd_path(), "/fixture/zstd")
        run.assert_called_once_with(
            ["/fixture/zstd", "--quiet", "--version"], env=self.clean_env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)

    def test_missing_or_unsupported_zstd_version_fails_closed(self):
        with mock.patch.object(restore.shutil, "which", return_value=None), \
                mock.patch.object(restore.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                restore.zstd_path()
            run.assert_not_called()
        for version in (b"", b"zstd v0.9.0", b"zstd v2.0.0", b"not a version"):
            with self.subTest(version=version), \
                    mock.patch.object(restore.shutil, "which", return_value="/fixture/zstd"), \
                    mock.patch.object(restore.subprocess, "run",
                                      return_value=mock.Mock(stdout=version)):
                with self.assertRaises(ValueError):
                    restore.zstd_path()

    def test_version_subprocess_failure_and_timeout_are_not_suppressed(self):
        for error in (subprocess.CalledProcessError(1, ["zstd", "--version"]),
                      subprocess.TimeoutExpired(["zstd", "--version"], 30),
                      OSError("cannot execute")):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(restore.shutil, "which", return_value="/fixture/zstd"), \
                    mock.patch.object(restore.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)):
                    restore.zstd_path()

    def child(self, payload=b"expanded", code=0):
        process = mock.Mock()
        process.stdout = io.BytesIO(payload)
        process.wait.return_value = code
        process.poll.return_value = code
        return process

    def test_decompression_uses_bounded_args_clean_environment_and_exact_child_watchdog(self):
        source, destination = self.work / "opaque ; signed.zst", self.work / "expanded.tar"
        process = self.child()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(restore, "zstd_path", return_value="/fixture/zstd"), \
                mock.patch.object(restore.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(restore.threading, "Timer") as timer:
            restore.decompress(source, destination)
        popen.assert_called_once_with(
            ["/fixture/zstd", "--quiet", "-d", "-c", "--long=27", "--memory=128MB",
             str(source)], env=self.clean_env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        timer.assert_called_once_with(restore.TIMEOUT, process.kill)
        timer.return_value.start.assert_called_once_with()
        timer.return_value.cancel.assert_called_once_with()
        process.kill.assert_not_called()
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=30), mock.call()])
        self.assertTrue(process.stdout.closed)
        self.assertEqual(destination.read_bytes(), b"expanded")

    def test_expanded_limit_kills_and_reaps_only_the_exact_child_before_writing_block(self):
        process = self.child(b"12345")
        process.poll.return_value = None
        destination = self.work / "expanded.tar"
        with mock.patch.object(restore, "MAX_EXPANDED", 4), \
                mock.patch.object(restore, "zstd_path", return_value="zstd"), \
                mock.patch.object(restore.subprocess, "Popen", return_value=process), \
                mock.patch.object(restore.threading, "Timer") as timer:
            with self.assertRaisesRegex(ValueError, "Oversized expanded"):
                restore.decompress(self.work / "compressed.zst", destination)
        timer.assert_called_once_with(restore.TIMEOUT, process.kill)
        timer.return_value.cancel.assert_called_once_with()
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()
        self.assertTrue(process.stdout.closed)
        self.assertEqual(destination.read_bytes(), b"")

    def test_watchdog_callback_kills_exact_child_and_decompression_fails(self):
        process = self.child(b"", code=-9)
        watchdog = mock.Mock()
        watchdog.start.side_effect = process.kill
        with mock.patch.object(restore, "zstd_path", return_value="zstd"), \
                mock.patch.object(restore.subprocess, "Popen", return_value=process), \
                mock.patch.object(restore.threading, "Timer", return_value=watchdog) as timer:
            with self.assertRaisesRegex(ValueError, "decompression failed"):
                restore.decompress(self.work / "source", self.work / "destination")
        timer.assert_called_once_with(restore.TIMEOUT, process.kill)
        process.kill.assert_called_once_with()
        watchdog.cancel.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)
        self.assertTrue(process.stdout.closed)

    def test_empty_or_nonzero_decompression_is_not_a_success(self):
        for payload, code in ((b"", 0), (b"partial", 1)):
            process = self.child(payload, code)
            with self.subTest(payload=payload, code=code), \
                    mock.patch.object(restore, "zstd_path", return_value="zstd"), \
                    mock.patch.object(restore.subprocess, "Popen", return_value=process), \
                    mock.patch.object(restore.threading, "Timer") as timer:
                with self.assertRaises(ValueError):
                    restore.decompress(self.work / "source", self.work / uuid.uuid4().hex)
                timer.return_value.cancel.assert_called_once_with()
                self.assertTrue(process.stdout.closed)

    def test_pipe_read_error_still_cancels_watchdog_kills_and_reaps_child(self):
        process = self.child()
        process.stdout = mock.Mock()
        process.stdout.read.side_effect = OSError("fixture pipe failure")
        process.poll.return_value = None
        with mock.patch.object(restore, "zstd_path", return_value="zstd"), \
                mock.patch.object(restore.subprocess, "Popen", return_value=process), \
                mock.patch.object(restore.threading, "Timer") as timer:
            with self.assertRaisesRegex(OSError, "fixture pipe failure"):
                restore.decompress(self.work / "source", self.work / "destination")
        timer.return_value.cancel.assert_called_once_with()
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()
        process.stdout.close.assert_called_once_with()

    @unittest.skipUnless(shutil.which("zstd"), "Optional real integration needs installed zstd")
    def test_real_zstd_compress_decompress_extract_preserves_data_and_mtimes_not_modes(self):
        original, content = regular("candidate/target/deps/file.rlib", b"real zstd fixture")
        original.mtime, original.mode = 1600000000.125, 0o7777
        alias = link("candidate/target/deps/alias.rlib", original.name)
        alias[0].mtime, alias[0].mode = 1600000001.25, 0o7777
        archive = self.archive([directory("."), directory("candidate"),
                                directory("candidate/target"), (original, content), alias])
        compressed, expanded = self.work / "cache.zst", self.work / "actual.tar"
        with compressed.open("wb") as output:
            subprocess.run([shutil.which("zstd"), "--quiet", "-c", str(archive)],
                           env=restore.clean_environment(os.environ), stdout=output,
                           stderr=subprocess.PIPE, timeout=30, check=True)
        restore.decompress(compressed, expanded)
        self.assertEqual(expanded.read_bytes(), archive.read_bytes())
        stage = self.stage()
        restore.extract_archive(expanded, stage, PATHS["target"])
        for info in (original, alias[0]):
            path = stage / info.name
            self.assertEqual(path.read_bytes(), content)
            self.assertFalse(path.is_symlink())
            self.assertAlmostEqual(path.stat().st_mtime, info.mtime, places=3)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o7111, 0)


class SafeRestoreTests(WorkspaceCase):
    def restore_fixture(self, members, relative="candidate/target", validator=None, fail_at=None):
        archive = self.archive(members)
        def download(url, destination):
            if fail_at == "download":
                raise ValueError("download failed")
            self.assertEqual(url, BLOB_URL)
            self.assertTrue(Path(destination).is_relative_to(self.workspace))
            shutil.copyfile(archive, destination)

        def decompress(source, destination):
            if fail_at == "decompress":
                raise ValueError("decompression failed")
            self.assertTrue(Path(source).is_relative_to(self.workspace))
            self.assertTrue(Path(destination).is_relative_to(self.workspace))
            shutil.copyfile(source, destination)

        with mock.patch.object(restore, "download", side_effect=download), \
                mock.patch.object(restore, "decompress", side_effect=decompress):
            if validator is None:
                return restore.safe_restore(self.workspace, relative, BLOB_URL)
            with mock.patch.object(restore.build_cache, "validate_cache", side_effect=validator):
                return restore.safe_restore(self.workspace, relative, BLOB_URL)

    def test_promotion_happens_only_after_private_stage_validation(self):
        before = self.protect_workspace()
        validations = []
        def validate(stage, nextest_hit=False):
            stage = Path(stage)
            self.assertTrue(stage.is_relative_to(self.workspace))
            self.assertNotEqual(stage, self.workspace)
            self.assertEqual((stage / "candidate/target/deps/file").read_bytes(), b"payload")
            self.assertFalse((self.workspace / "candidate/target").exists())
            for path, value in before.items():
                if value != "directory":
                    self.assertEqual((self.workspace / path).read_bytes(), value)
            self.assertFalse(nextest_hit)
            validations.append(stage)

        self.restore_fixture([regular("candidate/target/deps/file", b"payload")],
                             validator=validate)
        self.assertEqual(len(validations), 1)
        self.assertFalse(validations[0].exists(), "private staging tree must be cleaned")
        self.assertEqual((self.workspace / "candidate/target/deps/file").read_bytes(), b"payload")
        expected = {**before, "candidate/target": "directory",
                    "candidate/target/deps": "directory",
                    "candidate/target/deps/file": b"payload"}
        self.assertEqual(self.tree(self.workspace), expected)

    def test_bad_archive_or_cache_validation_preserves_workspace_and_cleans_scratch(self):
        before = self.protect_workspace()
        for relative, members in (
            ("candidate/target", [regular("candidate/target/ok"), regular("candidate/src/main.rs")]),
            (PATHS["registry"], [regular(PATHS["registry"] + "/config.toml")]),
            (PATHS["nextest"], [regular(PATHS["nextest"] + "/unexpected.exe")]),
            (PATHS["nextest"], [regular(PATHS["nextest"] + "/cargo-nextest.exe", b"")]),
            (PATHS["nextest"], [directory(PATHS["nextest"])]),
        ):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.restore_fixture(members, relative)
            self.assertEqual(self.tree(self.workspace), before)

    def test_nextest_hit_validation_and_normal_registry_restore(self):
        for relative, suffix, nextest in (
            (PATHS["registry"], "index.crates.io-a/serde-1.0.0.crate", False),
            (PATHS["nextest"], "cargo-nextest.exe", True),
        ):
            with self.subTest(relative=relative):
                original = restore.build_cache.validate_cache
                with mock.patch.object(restore.build_cache, "validate_cache", wraps=original) as validator:
                    self.restore_fixture([regular(relative + "/" + suffix)], relative)
                    self.assertEqual(validator.call_args.kwargs, {"nextest_hit": nextest})
                self.assertEqual((self.workspace / relative / suffix).read_bytes(), b"fixture")

    def test_download_decompress_and_validator_failures_clean_scratch(self):
        before = self.protect_workspace()
        for operation in ("download", "decompress"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.restore_fixture([regular("candidate/target/a")], fail_at=operation)
            self.assertEqual(self.tree(self.workspace), before)

        with self.assertRaises(ValueError):
            self.restore_fixture([regular("candidate/target/a")],
                                 validator=mock.Mock(side_effect=ValueError("invalid cache")))
        self.assertEqual(self.tree(self.workspace), before)

    def test_symlinked_workspace_ancestors_cannot_redirect_promotion(self):
        outside = self.work / "not-workspace"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"unchanged")
        for parent, relative in (("candidate", PATHS["target"]),
                                 (".cargo-build", PATHS["registry"]),
                                 (".nextest", PATHS["nextest"])):
            symlink = self.workspace / parent
            symlink.symlink_to(outside, target_is_directory=True)
            before = self.tree(outside)
            try:
                with self.subTest(parent=parent), self.assertRaises(ValueError):
                    self.restore_fixture([regular(relative + "/file")], relative)
                self.assertEqual(self.tree(outside), before)
            finally:
                symlink.unlink()
            self.assertEqual(self.tree(self.workspace), {})


class RunTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        (self.workspace / ".build-cache-plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
        self.output = self.work / "github-output"
        self.env = {
            "GITHUB_REPOSITORY": "dc0d32/wezterm-builds",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "BUILD_DEFAULT_BRANCH": "main",
            "RUNNER_OS": "Windows",
            "RUNNER_ARCH": "X64",
            "ACTIONS_CACHE_SERVICE_V2": "true",
            "ACTIONS_RESULTS_URL": RUNTIME_URL,
            "ACTIONS_RUNTIME_TOKEN": "runtime-token",
            "GITHUB_OUTPUT": str(self.output),
            "CACHE_PATH": PATHS["target"],
            "CACHE_KEY": PLAN["target_key"],
            "CACHE_RESTORE_KEYS": PLAN["target_restore"],
        }
        zstd = mock.patch.object(restore, "zstd_path", return_value="hosted-zstd")
        zstd.start()
        self.addCleanup(zstd.stop)

    def outputs(self):
        return self.output.read_text(encoding="utf-8").splitlines()

    def test_cache_v2_flag_accepts_only_case_insensitive_true(self):
        for flag in ("True", "true", "TRUE", "false", "False", "", "1", " true ", None):
            env = dict(self.env)
            if flag is None:
                env.pop("ACTIONS_CACHE_SERVICE_V2")
            else:
                env["ACTIONS_CACHE_SERVICE_V2"] = flag
            if self.output.exists():
                self.output.unlink()
            with self.subTest(flag=flag), \
                    mock.patch.object(restore, "lookup", return_value=("", "")) as lookup, \
                    mock.patch.object(restore, "safe_restore") as safe:
                if flag in ("True", "true", "TRUE"):
                    restore.run(env, self.workspace)
                    lookup.assert_called_once_with(
                        env, PATHS["target"], PLAN["target_key"], PLAN["target_restore"])
                    self.assertEqual(self.outputs(), ["cache-hit=false", "cache-matched-key="])
                else:
                    with self.assertRaisesRegex(ValueError, "Restore is not allowed"):
                        restore.run(env, self.workspace)
                    lookup.assert_not_called()
                    self.assertFalse(self.output.exists())
                safe.assert_not_called()

    def test_exact_prefix_and_miss_outputs_have_only_two_declared_names(self):
        for kind in PATHS:
            primary = PLAN[kind + "_key"]
            fallback = PLAN.get(kind + "_restore", "")
            self.env.update(CACHE_PATH=PATHS[kind], CACHE_KEY=primary, CACHE_RESTORE_KEYS=fallback)
            matches = [(primary, "true"), ("", "false")]
            if fallback:
                matches.append((f"{BASE}-registry-{LOCK}-{'d' * 40}" if kind == "registry"
                                else fallback + "d" * 40, "false"))
            for matched, hit in matches:
                with self.subTest(kind=kind, matched=matched):
                    if self.output.exists():
                        self.output.unlink()
                    with mock.patch.object(restore, "lookup", return_value=(
                            matched, BLOB_URL if matched else "")) as lookup, \
                            mock.patch.object(restore, "safe_restore") as safe:
                        restore.run(self.env, self.workspace)
                        lookup.assert_called_once()
                        if matched:
                            safe.assert_called_once_with(self.workspace, PATHS[kind], BLOB_URL)
                        else:
                            safe.assert_not_called()
                    self.assertCountEqual(self.outputs(), [
                        "cache-hit=" + hit, "cache-matched-key=" + matched])

    def test_policy_is_rechecked_before_lookup_or_filesystem_restore(self):
        for field, value in (
            ("GITHUB_REPOSITORY", "attacker/wezterm-builds"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF", "refs/tags/main"),
            ("BUILD_DEFAULT_BRANCH", "other"),
            ("BUILD_DEFAULT_BRANCH", ""),
            ("RUNNER_OS", "Linux"),
            ("RUNNER_ARCH", "ARM64"),
            ("ACTIONS_CACHE_SERVICE_V2", "false"),
            ("ACTIONS_CACHE_SERVICE_V2", ""),
        ):
            with self.subTest(field=field, value=value), \
                    mock.patch.object(restore, "lookup") as lookup, \
                    mock.patch.object(restore, "safe_restore") as safe:
                with self.assertRaises(ValueError):
                    restore.run({**self.env, field: value}, self.workspace)
                lookup.assert_not_called()
                safe.assert_not_called()
                self.assertFalse(self.output.exists())
        with mock.patch.object(restore, "lookup", return_value=("", "")):
            restore.run({**self.env, "GITHUB_EVENT_NAME": "workflow_dispatch"}, self.workspace)

    def test_inputs_cannot_override_prepared_plan(self):
        for field, value in (
            ("CACHE_PATH", "candidate/src"),
            ("CACHE_PATH", "../candidate/target"),
            ("CACHE_PATH", PATHS["registry"]),
            ("CACHE_KEY", PLAN["registry_key"]),
            ("CACHE_KEY", PLAN["target_key"] + "-suffix"),
            ("CACHE_RESTORE_KEYS", f"{BASE}-target-"),
            ("CACHE_RESTORE_KEYS", PLAN["target_restore"] + "\n" + f"{BASE}-"),
        ):
            with self.subTest(field=field, value=value), \
                    mock.patch.object(restore, "lookup") as lookup:
                with self.assertRaises(ValueError):
                    restore.run({**self.env, field: value}, self.workspace)
                lookup.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_matched_key_must_be_exact_or_within_only_the_prepared_fallback(self):
        for matched in (
            PLAN["registry_key"], PLAN["nextest_key"],
            PLAN["target_key"].upper(), f"{BASE}-target-{'e' * 64}-{'f' * 40}",
            "unrelated-key", PLAN["target_key"] + "\nforged=secret",
        ):
            with self.subTest(matched=matched), \
                    mock.patch.object(restore, "lookup", return_value=(matched, BLOB_URL)), \
                    mock.patch.object(restore, "safe_restore") as safe:
                with self.assertRaises(ValueError):
                    restore.run(self.env, self.workspace)
                safe.assert_not_called()
                self.assertFalse(self.output.exists())
        self.env.update(CACHE_PATH=PATHS["nextest"], CACHE_KEY=PLAN["nextest_key"],
                        CACHE_RESTORE_KEYS="")
        with mock.patch.object(restore, "lookup", return_value=(PLAN["nextest_key"] + "-suffix", BLOB_URL)), \
                mock.patch.object(restore, "safe_restore") as safe:
            with self.assertRaises(ValueError):
                restore.run(self.env, self.workspace)
            safe.assert_not_called()

    def test_http_errors_are_failures_not_cache_misses(self):
        for status in (401, 403, 404, 429, 500, 503):
            error = urllib.error.HTTPError(RUNTIME_URL, status, "fixture", {}, None)
            with self.subTest(status=status), \
                    mock.patch.object(restore, "lookup", side_effect=error), \
                    mock.patch.object(restore, "safe_restore") as safe:
                with self.assertRaises((ValueError, urllib.error.HTTPError)):
                    restore.run(self.env, self.workspace)
                safe.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_failed_extraction_cannot_claim_a_hit(self):
        with mock.patch.object(restore, "lookup", return_value=(PLAN["target_key"], BLOB_URL)), \
                mock.patch.object(restore, "safe_restore", side_effect=ValueError("bad archive")):
            with self.assertRaises(ValueError):
                restore.run(self.env, self.workspace)
        self.assertFalse(self.output.exists())


class CompileBoundaryTests(unittest.TestCase):
    def test_workflow_compile_uses_the_token_stripping_build_phase(self):
        workflow = (ROOT / ".github/workflows/windows-build.yml").read_text(encoding="utf-8")
        compile_step = workflow.split("        id: compile\n", 1)[1].split(
            "      - name:", 1)[0]
        self.assertIn("run: ./control/scripts/build.ps1 -Phase Compile", compile_step)
        self.assertNotIn("ACTIONS_", compile_step)
        self.assertNotIn("GITHUB_TOKEN", compile_step)

        build = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
        self.assertIn("$PSNativeCommandUseErrorActionPreference = $true", build)
        stripping = """if ($Phase -eq 'Compile') {
    Get-ChildItem Env: | Where-Object { $_.Name -match '^ACTIONS_' } |
        ForEach-Object { Remove-Item "Env:$($_.Name)" }
}"""
        self.assertIn(stripping, build)
        self.assertLess(build.index(stripping), build.index("function Invoke-Checked"))
        self.assertLess(build.index(stripping), build.index("Invoke-Checked git"))
        self.assertLess(build.index(stripping), build.index("Invoke-Checked cargo"))


@unittest.skipUnless(shutil.which("node"), "Node is needed to exercise the action wrapper")
class ActionWrapperTests(unittest.TestCase):
    def invoke(self, status=0, throws=False):
        harness = r"""
const childProcess = require('node:child_process');
childProcess.spawnSync = (command, args, options) => {
  process.stdout.write('CAPTURE:' + JSON.stringify({command, args, options}) + '\n');
  if (process.env.TEST_SPAWN_THROWS === 'true') {
    throw new Error('CHILD_SECRET_OUTPUT');
  }
  return {
    status: Number(process.env.TEST_SPAWN_STATUS),
    stdout: Buffer.from('CHILD_SECRET_OUTPUT\n::set-output name=forged::value\n'),
    stderr: Buffer.from('CHILD_SECRET_OUTPUT\n'),
  };
};
require(process.argv[1]);
"""
        env = {
            **os.environ,
            "GITHUB_WORKSPACE": str(ROOT),
            "GITHUB_REPOSITORY": "dc0d32/wezterm-builds",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "BUILD_DEFAULT_BRANCH": "main",
            "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
            "ACTIONS_CACHE_SERVICE_V2": "true",
            "ACTIONS_RUNTIME_TOKEN": "runtime-only-fixture",
            "ACTIONS_RESULTS_URL": RUNTIME_URL,
            "GITHUB_TOKEN": "write-token-must-not-reach-child",
            "PYTHONPATH": "parent-only-python-search-path",
            "PYTHONSTARTUP": "parent-only-python-startup",
            "UNTRUSTED_EXTRA": "parent-only-fixture",
            "INPUT_PATH": PATHS["target"],
            "INPUT_KEY": PLAN["target_key"],
            "INPUT_RESTORE-KEYS": PLAN["target_restore"],
            "TEST_SPAWN_STATUS": str(status),
            "TEST_SPAWN_THROWS": "true" if throws else "false",
        }
        result = subprocess.run([
            shutil.which("node"), "-e", harness,
            str(ROOT / ".github/actions/cache-restore/index.js"),
        ], cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
        captures = [json.loads(line[len("CAPTURE:"):])
                    for line in result.stdout.splitlines() if line.startswith("CAPTURE:")]
        self.assertEqual(len(captures), 1, result.stderr)
        return result, captures[0]

    def test_real_wrapper_separates_runtime_credentials_inputs_and_arguments(self):
        result, captured = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(captured["command"], "python")
        self.assertEqual(captured["args"], ["-B", "control/scripts/cache_restore.py"])
        options = captured["options"]
        self.assertEqual(options["cwd"], str(ROOT))
        self.assertFalse(options.get("shell", False))
        child_env = options["env"]
        self.assertEqual(child_env["CACHE_PATH"], PATHS["target"])
        self.assertEqual(child_env["CACHE_KEY"], PLAN["target_key"])
        self.assertEqual(child_env["CACHE_RESTORE_KEYS"], PLAN["target_restore"])
        self.assertEqual(child_env["ACTIONS_RUNTIME_TOKEN"], "runtime-only-fixture")
        self.assertEqual(child_env["ACTIONS_RESULTS_URL"], RUNTIME_URL)
        for name in ("GITHUB_TOKEN", "UNTRUSTED_EXTRA", "INPUT_PATH", "INPUT_KEY",
                     "INPUT_RESTORE-KEYS", "TEST_SPAWN_STATUS", "TEST_SPAWN_THROWS",
                     "PYTHONPATH", "PYTHONSTARTUP"):
            self.assertNotIn(name, child_env)
        self.assertNotIn("runtime-only-fixture", " ".join(captured["args"]))
        self.assertNotIn("CHILD_SECRET_OUTPUT", result.stdout + result.stderr)
        self.assertNotIn("::set-output", result.stdout + result.stderr)

    def test_child_failures_and_spawn_exceptions_do_not_replay_untrusted_output(self):
        for status, throws in ((1, False), (9, False), (0, True)):
            with self.subTest(status=status, throws=throws):
                result, _ = self.invoke(status=status, throws=throws)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("CHILD_SECRET_OUTPUT", result.stdout + result.stderr)
                self.assertNotIn("::set-output", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
