# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Exercise source-cache refusals without downloading or running native code."""

import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import seed_kafka_source as seed


class Response(io.BytesIO):
    url = seed.ARCHIVE_URL


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as output:
        for name, kind in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.mode = 0o700
            entry.linkname = "../foreign"
            if kind == tarfile.REGTYPE:
                entry.size = 4
                output.addfile(entry, io.BytesIO(b"safe"))
            else:
                output.addfile(entry)
    return data.getvalue()


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="arkenivajs-kafka-seed-test-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.workspace = base / "workspace"
        self.reports = base / "reports"
        self.workspace.mkdir(mode=0o700)
        self.reports.mkdir(mode=0o700)
        self.sdk = self.workspace / (
            "node_modules/.pnpm/owned-sdk/node_modules/@confluentinc/kafka-javascript"
        )
        self.sdk.mkdir(mode=0o700, parents=True)
        (self.sdk / "package.json").write_text(json.dumps({
            "name": "@confluentinc/kafka-javascript", "version": "1.11.0",
        }))
        installed = (Path(__file__).resolve().parents[2] / (
            "packages/messaging-kafka/node_modules/@confluentinc/kafka-javascript"
        )).resolve(strict=True)
        for relative in seed.VENDOR_GUARDS:
            target = self.sdk / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes((installed / relative).read_bytes())
        self.alias = self.workspace / (
            "packages/messaging-kafka/node_modules/@confluentinc/kafka-javascript"
        )
        self.alias.parent.mkdir(mode=0o700, parents=True)
        self.alias.symlink_to(os.path.relpath(self.sdk, self.alias.parent))
        self.target = self.sdk / "deps/librdkafka/mklove/deps/src/zlib"
        for path in self.workspace.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)

    def assert_no_native_effects(self):
        with patch.object(seed, "download_archive") as download, \
                patch.object(seed.subprocess, "run") as execute:
            with self.assertRaises((ValueError, FileNotFoundError)):
                seed.seed(self.workspace, self.reports)
            download.assert_not_called()
            execute.assert_not_called()

    def test_owned_pinned_workspace_is_resolved_without_building(self):
        self.assertEqual(seed.cache_target(self.workspace), (self.sdk, self.target))
        seed.guard_vendor(self.sdk)
        self.assertFalse(self.target.exists())

    def test_checksum_failure_precedes_extraction_and_execution(self):
        with patch.object(seed.urllib.request.OpenerDirector, "open", return_value=Response(
                b"x" * seed.ARCHIVE_BYTES)), \
                patch.object(seed.subprocess, "run") as execute:
            with self.assertRaisesRegex(ValueError, "pinned checksum"):
                seed.seed(self.workspace, self.reports)
            execute.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.reports.iterdir()), [])

    def test_each_redirect_rejects_foreign_insecure_or_credential_origins_before_following(self):
        handler = seed.ApprovedRedirects()
        request = seed.urllib.request.Request(seed.ARCHIVE_URL)
        for url in [
            "http://github.com/source", "https://foreign.invalid/source",
            "https://user:secret@github.com/source", "https://github.com:444/source",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        url = "https://release-assets.githubusercontent.com/owned-source"
        self.assertEqual(
            handler.redirect_request(request, None, 302, "Found", {}, url).full_url,
            url,
        )

    def test_empty_nonempty_and_symlink_caches_are_never_replaced(self):
        self.target.mkdir(mode=0o700, parents=True)
        self.assert_no_native_effects()
        marker = self.target / "keep"
        marker.write_text("owned prior cache")
        self.assert_no_native_effects()
        self.assertEqual(marker.read_text(), "owned prior cache")
        marker.unlink()
        self.target.rmdir()
        self.target.symlink_to(self.reports, target_is_directory=True)
        self.assert_no_native_effects()
        self.assertTrue(self.target.is_symlink())

    def test_shared_cache_and_linked_parent_are_refused_before_network(self):
        original = self.sdk.parent.parent.parent
        external = self.reports / "external-cache"
        original.rename(external)
        original.symlink_to(external, target_is_directory=True)
        self.assert_no_native_effects()

    def test_other_owner_writable_directory_and_wrong_sdk_are_refused(self):
        with patch.object(seed.os, "getuid", return_value=os.getuid() + 1):
            self.assert_no_native_effects()
        self.sdk.chmod(0o777)
        self.assert_no_native_effects()
        self.sdk.chmod(0o700)
        (self.sdk / "package.json").write_text(json.dumps({
            "name": "foreign-sdk", "version": "1.11.0",
        }))
        self.assert_no_native_effects()

    def test_changed_or_linked_installer_is_refused(self):
        path = self.sdk / "util/configure.js"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        self.assert_no_native_effects()
        path.unlink()
        copy = self.reports / "foreign-configure.js"
        copy.write_bytes(original)
        path.symlink_to(copy)
        self.assert_no_native_effects()

    def test_archive_escape_links_special_entries_and_duplicates_write_nothing(self):
        cases = [
            [("zlib-1.3.2/../../escape", tarfile.REGTYPE)],
            [("/zlib-1.3.2/escape", tarfile.REGTYPE)],
            [("foreign/file", tarfile.REGTYPE)],
            [("zlib-1.3.2/link", tarfile.SYMTYPE)],
            [("zlib-1.3.2/link", tarfile.LNKTYPE)],
            [("zlib-1.3.2/pipe", tarfile.FIFOTYPE)],
            [("zlib-1.3.2/a", tarfile.REGTYPE)] * 2,
            [("zlib-1.3.2/file" + str(i), tarfile.REGTYPE) for i in range(513)],
        ]
        for entries in cases:
            with self.subTest(entries=entries[:1]):
                with self.assertRaises(ValueError):
                    seed.extract_archive(archive(entries), self.reports)
                self.assertEqual(list(self.reports.iterdir()), [])

    def test_regular_source_extracts_and_exclusive_publication_preserves_old_cache(self):
        source = seed.extract_archive(archive([
            ("zlib-1.3.2/fixture", tarfile.REGTYPE),
        ]), self.reports)
        seed.publish_cache(source, self.target)
        self.assertEqual((self.target / "fixture").read_bytes(), b"safe")
        other = self.reports / "another-source"
        other.mkdir(mode=0o700)
        (other / "fixture").write_text("replacement")
        with self.assertRaises(FileExistsError):
            seed.publish_cache(other, self.target)
        self.assertEqual((self.target / "fixture").read_bytes(), b"safe")
        self.assertEqual((other / "fixture").read_text(), "replacement")

    def test_publication_works_across_real_filesystems_without_replacing_a_cache(self):
        with tempfile.TemporaryDirectory(prefix="arkenivajs-kafka-source-", dir="/dev/shm") as name:
            source = Path(name)
            self.assertNotEqual(source.stat().st_dev, self.workspace.stat().st_dev)
            (source / "Makefile").write_text("configured source")
            (source / "test").mkdir(mode=0o700)
            (source / "test/example.c").write_text("owned fixture")
            seed.publish_cache(source, self.target)
            self.assertEqual((self.target / "Makefile").read_text(), "configured source")
            self.assertEqual((self.target / "test/example.c").read_text(), "owned fixture")
            self.assertEqual((source / "Makefile").read_text(), "configured source")

    def test_configuration_uses_only_fixed_arguments_and_a_clean_environment(self):
        def configure(arguments, **options):
            source = options["cwd"]
            self.assertTrue(source.is_relative_to(self.reports))
            self.assertEqual(arguments, [str(source / "configure"), "--static", "--prefix=/usr"])
            self.assertEqual(options["env"], {
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "CFLAGS": "-fPIC", "libdir": "/usr/lib",
            })
            self.assertTrue(options["check"])
            self.assertEqual(options["timeout"], 60)
            self.assertEqual(options["stdin"], seed.subprocess.DEVNULL)
            (source / "Makefile").write_text("owned configured fixture")

        data = archive([("zlib-1.3.2/configure", tarfile.REGTYPE)])
        with patch.object(seed, "download_archive", return_value=data), \
                patch.object(seed.subprocess, "run", side_effect=configure) as execute, \
                patch.dict(os.environ, {"CC": "untrusted", "BASH_ENV": "untrusted"}):
            result = seed.seed(self.workspace, self.reports)
        self.assertEqual(execute.call_count, 1)
        self.assertTrue(result["staticLinkageUnchanged"])
        self.assertFalse(result["nativeRebuildPerformed"])
        self.assertEqual((self.target / "Makefile").read_text(), "owned configured fixture")
        self.assertTrue((self.reports / "zlib-source-seed.json").is_file())


if __name__ == "__main__":
    unittest.main()
