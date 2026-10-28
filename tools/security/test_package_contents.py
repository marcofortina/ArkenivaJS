# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Exercise real tar archives, including hostile headers and misleading metadata."""

import io
import hashlib
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

    def add_ide(self):
        self.manifest["name"] = self.metadata["name"] = "@arkenivajs/graphql"
        self.update_metadata()
        for path in ["browser/ide.ts", "scripts/build-ide.mjs"]:
            target = self.location / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("// Synthetic owned build fixture.\n")
        assets = {"app.js": b"export {};\n", "app.css": b"body { margin: 0; }\n"}
        data = {"format": 1, "files": [{"name": name, "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()} for name, payload in assets.items()]}
        files = {"dist/ide/assets/" + name: payload for name, payload in assets.items()}
        files.update({"dist/ide/manifest.json": json.dumps(data).encode(),
                      "dist/ide/THIRD_PARTY_NOTICES.txt": b"Synthetic dependency notices.\n",
                      "dist/ide/licenses/fixture@1.0.0/LICENSE": b"Synthetic license fixture.\n"})
        for path, payload in files.items():
            target = self.location / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            self.entries["package/" + path] = payload
        return data

    def test_graphql_ide_accepts_only_manifest_assets_and_complete_notices(self):
        self.add_ide()
        result = self.inspect()
        self.assertIn("package/dist/ide/assets/app.css", result["files"])
        for name in ["package/dist/ide/assets/app.js", "package/dist/ide/licenses/fixture@1.0.0/LICENSE"]:
            value = self.entries.pop(name)
            with self.assertRaises(ValueError):
                self.inspect()
            self.entries[name] = value

    def test_ide_exception_cannot_apply_to_other_packages_or_unowned_builds(self):
        self.add_ide()
        self.manifest["name"] = self.metadata["name"] = "@arkenivajs/other"
        self.update_metadata()
        with self.assertRaises(ValueError):
            self.inspect()
        self.manifest["name"] = self.metadata["name"] = "@arkenivajs/graphql"
        self.update_metadata()
        (self.location / "browser/ide.ts").unlink()
        with self.assertRaisesRegex(ValueError, "owned build sources"):
            self.inspect()

    def test_graphql_ide_rejects_manifest_drift_traversal_and_extra_chunks(self):
        data = self.add_ide()
        path = self.location / "dist/ide/manifest.json"
        original = path.read_bytes()
        for field, value in [("name", "../outside.js"), ("sha256", "0" * 64), ("bytes", True)]:
            before = data["files"][0][field]
            data["files"][0][field] = value
            path.write_text(json.dumps(data))
            self.entries["package/dist/ide/manifest.json"] = path.read_bytes()
            with self.assertRaises(ValueError):
                self.inspect()
            data["files"][0][field] = before
        path.write_bytes(original)
        self.entries["package/dist/ide/manifest.json"] = original
        extra = self.location / "dist/ide/assets/stale.js"
        extra.write_bytes(b"export {};\n")
        self.entries["package/dist/ide/assets/stale.js"] = extra.read_bytes()
        with self.assertRaisesRegex(ValueError, "stale"):
            self.inspect()

    def test_graphql_ide_retains_private_key_rejection_inside_manifest_assets(self):
        data = self.add_ide()
        payload = b"-----BEGIN " + b"PRIVATE KEY-----\n"
        target = self.location / "dist/ide/assets/app.js"
        target.write_bytes(payload)
        self.entries["package/dist/ide/assets/app.js"] = payload
        data["files"][0].update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        manifest = json.dumps(data).encode()
        (self.location / "dist/ide/manifest.json").write_bytes(manifest)
        self.entries["package/dist/ide/manifest.json"] = manifest
        with self.assertRaisesRegex(ValueError, "private key"):
            self.inspect()


if __name__ == "__main__":
    unittest.main()
