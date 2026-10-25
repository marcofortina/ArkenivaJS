# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Exercise real tar archives, including hostile headers and misleading metadata."""

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from package_contents import ROOT, create_evidence, inspect_archive


class PackageContentsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="arkenivajs-package-check-")
        self.addCleanup(self.temporary.cleanup)
        self.location = Path(self.temporary.name)
        (self.location / "dist").mkdir()
        (self.location / "src").mkdir()
        (self.location / "src/index.ts").write_text("export const answer = 42;\n")
        self.license = (ROOT / "LICENSE").read_bytes()
        self.manifest = {"name": "@arkenivajs/test-fixture", "version": "0.1.0",
                         "type": "module", "license": "AGPL-3.0-or-later", "private": True,
                         "exports": {".": {"types": "./dist/index.d.ts", "import": "./dist/index.js"}},
                         "engines": {"node": "^24.22.1"},
                         "dependencies": {"@arkenivajs/core": "workspace:*"},
                         "files": ["dist", "README.md", "CHANGELOG.md"]}
        self.metadata = {**self.manifest, "dependencies": {"@arkenivajs/core": "0.1.0"}}
        self.entries = {"package/package.json": json.dumps(self.metadata).encode(),
                        "package/LICENSE": self.license, "package/README.md": b"Fixture documentation.\n",
                        "package/CHANGELOG.md": b"Initial synthetic fixture.\n",
                        "package/dist/index.js": b"export const answer = 42;\n",
                        "package/dist/index.d.ts": b"export declare const answer = 42;\n"}
        for path, payload in self.entries.items():
            if path not in {"package/package.json", "package/LICENSE"}:
                (self.location / path.removeprefix("package/")).write_bytes(payload)

    def inspect(self, extra=()):
        archive = self.location / "fixture.tgz"
        with tarfile.open(archive, "w:gz") as target:
            for path, payload in self.entries.items():
                member = tarfile.TarInfo(path)
                member.size = len(payload)
                target.addfile(member, io.BytesIO(payload))
            for member, payload in extra:
                target.addfile(member, io.BytesIO(payload))
        return inspect_archive(archive, self.location, self.manifest,
                               {"@arkenivajs/core": "0.1.0"}, self.license)

    def update_metadata(self):
        self.entries["package/package.json"] = json.dumps(self.metadata).encode()

    def test_real_archive_reports_exact_files_hashes_and_private_state(self):
        result = self.inspect()
        self.assertEqual(result["name"], self.manifest["name"])
        self.assertTrue(result["private"])
        self.assertEqual(set(result["files"]), set(self.entries))
        self.assertEqual(len(result["sha256"]), 64)

    def test_traversal_duplicates_links_and_private_paths_are_rejected_without_extraction(self):
        for name in ["package/../escaped", "/absolute", "package/.env", "package/test/key.pem",
                     "package/dist/index.js", "package/dist/../../escaped", "package\\dist\\key"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.inspect([(tarfile.TarInfo(name), b"")])
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE]:
            member = tarfile.TarInfo("package/dist/link.js")
            member.type, member.linkname = kind, "/outside"
            with self.assertRaises(ValueError):
                self.inspect([(member, b"")])
        self.assertFalse((self.location / "escaped").exists())

    def test_missing_exports_docs_legal_notices_and_modified_build_bytes_fail(self):
        for name in ["package/dist/index.js", "package/CHANGELOG.md", "package/LICENSE"]:
            with self.subTest(name=name):
                value = self.entries.pop(name)
                with self.assertRaises(ValueError):
                    self.inspect()
                self.entries[name] = value
        for name in ["package/dist/index.js", "package/LICENSE", "package/README.md"]:
            with self.subTest(name=name):
                value = self.entries[name]
                self.entries[name] += b"Altered content.\n"
                with self.assertRaises(ValueError):
                    self.inspect()
                self.entries[name] = value
        self.entries["package/dist/removed.js"] = b"export {};\n"
        (self.location / "dist/removed.js").write_bytes(self.entries["package/dist/removed.js"])
        with self.assertRaisesRegex(ValueError, "stale"):
            self.inspect()

    def test_packed_metadata_cannot_enable_publication_or_hide_dependency_drift(self):
        for field, value in [("private", False), ("license", "UNLICENSED"), ("version", "0.2.0")]:
            original = self.metadata[field]
            self.metadata[field] = value
            self.update_metadata()
            with self.assertRaises(ValueError):
                self.inspect()
            self.metadata[field] = original
        for reference in ["workspace:*", "file:/outside", "0.2.0"]:
            self.metadata["dependencies"] = {"@arkenivajs/core": reference}
            self.update_metadata()
            with self.assertRaises(ValueError):
                self.inspect()
        self.metadata["dependencies"] = {}
        self.update_metadata()
        with self.assertRaises(ValueError):
            self.inspect()

    def test_existing_legal_notices_must_not_disappear_from_the_package(self):
        (self.location / "THIRD_PARTY_NOTICES.md").write_text("Synthetic third-party attribution.\n")
        with self.assertRaisesRegex(ValueError, "legal notices"):
            self.inspect()

    def test_evidence_cannot_be_retained_in_git_or_at_a_relative_path(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            create_evidence(Path("relative"))
        with self.assertRaisesRegex(ValueError, "outside Git"):
            create_evidence(ROOT / "private-package-results")


if __name__ == "__main__":
    unittest.main()
