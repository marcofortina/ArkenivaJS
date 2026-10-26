# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Verify actual secret-history detection and refusal of incomplete source evidence."""

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

# Keep disposable execution checkouts clean while importing the scanner fixture.
sys.dont_write_bytecode = True
from run import (scan, reviewed_public_vectors, reviewed_version_metadata, reviewed_ignore,
                 REVIEWED_VECTOR, REVIEWED_VERSIONS, REVIEWED_VERSION_COMMIT)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.environ.get("ARKENIVA_SECURITY_DISPOSABLE"), "1")
        self.temporary = tempfile.TemporaryDirectory(prefix="arkenivajs-security-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir(mode=0o700)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Disposable security fixture")
        self.git("config", "user.email", "security@example.test")
        (self.repository / "README.md").write_text("Synthetic scanner fixture.\n")
        self.commit("Create disposable scanner fixture")

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.repository,
                                       stderr=subprocess.STDOUT, text=True)

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--message", message)

    def test_actual_clean_and_deleted_secret_history(self):
        self.assertEqual(scan(self.repository, self.directory / "clean-results"), 0)
        # This synthetic pattern has no provider account, permission or external validity.
        token = "ghp_" + hashlib.sha256(b"ArkenivaJS synthetic scanner fixture").hexdigest()[:36]
        path = self.repository / "synthetic-credential.txt"
        path.write_text("token=" + token + "\n")
        self.commit("Add synthetic detection fixture")
        path.unlink()
        self.commit("Remove synthetic detection fixture from the current tree")
        output = self.directory / "history-results"
        self.assertEqual(scan(self.repository, output), 1)
        findings = json.loads((output / "findings.json").read_text())
        self.assertTrue(any(item["RuleID"] == "github-pat" for item in findings))
        for path in output.iterdir():
            self.assertNotIn(token, path.read_text())

    def test_dirty_and_shallow_source_are_rejected(self):
        (self.repository / "uncommitted.txt").write_text("No partial evidence.\n")
        with self.assertRaises(ValueError):
            scan(self.repository, self.directory / "dirty-results")
        (self.repository / "uncommitted.txt").unlink()
        shallow = self.directory / "shallow"
        subprocess.run(["git", "clone", "--depth", "1", self.repository.as_uri(), str(shallow)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaises(ValueError):
            scan(shallow, self.directory / "shallow-results")

    def test_owner_review_does_not_hide_another_secret(self):
        source = Path(__file__).resolve().parents[2]
        reviewed = self.directory / "reviewed-repository"
        subprocess.run(["git", "clone", "--no-hardlinks", "--branch", "main",
                        str(source), str(reviewed)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original = self.repository
        self.repository = reviewed
        try:
            self.git("config", "user.name", "Disposable security fixture")
            self.git("config", "user.email", "security@example.test")
            good = self.directory / "reviewed-results"
            self.assertEqual(scan(reviewed, good), 0)
            summary = json.loads((good / "summary.json").read_text())
            self.assertEqual(len(summary["reviewedPublicVectorFingerprints"]), 1)
            self.assertEqual(len(summary["reviewedVersionMetadataFingerprints"]), 5)
            self.assertEqual(summary["scans"]["dir"]["status"], "PASS")
            token = "ghp_" + hashlib.sha256(b"Separate synthetic detection fixture").hexdigest()[:36]
            (reviewed / "synthetic-credential.txt").write_text("token=" + token + "\n")
            self.commit("Add independent synthetic detection fixture")
            output = self.directory / "separate-results"
            self.assertEqual(scan(reviewed, output), 1)
            findings = json.loads((output / "findings.json").read_text())
            self.assertTrue(any(item["RuleID"] == "github-pat" for item in findings))
            for path in output.iterdir():
                self.assertNotIn(token, path.read_text())
            policy = reviewed / "tools/security/reviewed-public-vectors.json"
            document = json.loads(policy.read_text())
            document["fingerprint"] = document["fingerprint"].replace("generic-api-key", "github-pat")
            policy.write_text(json.dumps(document) + "\n")
            self.commit("Try an unapproved fingerprint change")
            with self.assertRaises(ValueError):
                scan(reviewed, self.directory / "unapproved-results")
        finally:
            self.repository = original

    def test_current_tree_scans_git_ignored_files_without_exceptions(self):
        (self.repository / ".gitignore").write_text("synthetic-credential.txt\n")
        self.commit("Ignore a disposable local fixture")
        token = "ghp_" + hashlib.sha256(b"Ignored synthetic detection fixture").hexdigest()[:36]
        (self.repository / "synthetic-credential.txt").write_text("token=" + token + "\n")
        output = self.directory / "ignored-results"
        self.assertEqual(scan(self.repository, output), 1)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["scans"]["git"]["status"], "PASS")
        self.assertEqual(summary["scans"]["dir"]["status"], "FAIL")
        self.assertEqual((output / "no-fingerprints.ignore").read_text(), "")
        for path in output.iterdir():
            self.assertNotIn(token, path.read_text())

    def test_unapproved_global_ignore_and_custom_rules_are_rejected(self):
        ignore = self.repository / ".gitleaksignore"
        ignore.write_text("synthetic-credential.txt:github-pat:1\n")
        self.commit("Try an unapproved global fingerprint")
        with self.assertRaises(ValueError):
            scan(self.repository, self.directory / "global-ignore-results")
        ignore.write_text("# No reviewed findings in this fixture.\n")
        (self.repository / ".gitleaks.toml").write_text("[allowlist]\npaths = ['.*']\n")
        self.commit("Try custom detection rules")
        with self.assertRaises(ValueError):
            scan(self.repository, self.directory / "custom-rules-results")

    def test_historical_exception_cannot_hide_same_path_and_line_in_another_commit(self):
        source = Path(__file__).resolve().parents[2]
        reviewed = self.directory / "same-line-repository"
        subprocess.run(["git", "clone", "--no-hardlinks", "--branch", "main",
                        str(source), str(reviewed)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original = self.repository
        self.repository = reviewed
        try:
            self.git("config", "user.name", "Disposable security fixture")
            self.git("config", "user.email", "security@example.test")
            approved = reviewed_public_vectors(reviewed)
            self.assertEqual(approved, [REVIEWED_VECTOR])
            self.assertTrue(reviewed_ignore(reviewed, approved + reviewed_version_metadata(reviewed)))
            commit, filename, rule, number = REVIEWED_VECTOR.split(":")
            historical = self.git("show", commit + ":" + filename).splitlines()[int(number) - 1]
            path = reviewed / filename
            lines = path.read_text().splitlines()
            lines[int(number) - 1] = historical
            path.write_text("\n".join(lines) + "\n")
            self.commit("Reintroduce the public fixture at its historical line in a new commit")
            current = self.git("rev-parse", "HEAD").strip()
            output = self.directory / "same-line-results"
            self.assertEqual(scan(reviewed, output), 1)
            findings = json.loads((output / "findings.json").read_text())
            self.assertTrue(any(item["Commit"] == current and item["File"] == filename
                                and item["RuleID"] == rule and item["StartLine"] == int(number)
                                and item["Fingerprint"] != REVIEWED_VECTOR for item in findings))
            self.assertGreater(json.loads((output / "summary.json").read_text())["scans"]["dir"]["findings"], 0)
            ignore = reviewed / ".gitleaksignore"
            original_ignore = ignore.read_text()
            ignore.unlink()
            self.commit("Remove the required historical policy file")
            with self.assertRaises(ValueError):
                scan(reviewed, self.directory / "missing-ignore-results")
            ignore.write_text(original_ignore + filename + ":" + rule + ":" + number + "\n")
            self.commit("Try broadening the historical exception to a global finding")
            with self.assertRaises(ValueError):
                scan(reviewed, self.directory / "broadened-ignore-results")
        finally:
            self.repository = original


    def test_metadata_exception_cannot_hide_recurrence_or_synthetic_credentials(self):
        source = Path(__file__).resolve().parents[2]
        reviewed = self.directory / "metadata-repository"
        subprocess.run(["git", "clone", "--no-hardlinks", "--branch", "main",
                        str(source), str(reviewed)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original = self.repository
        self.repository = reviewed
        try:
            self.git("config", "user.name", "Disposable security fixture")
            self.git("config", "user.email", "security@example.test")
            versions = reviewed_version_metadata(reviewed)
            self.assertEqual(len(versions), 5)
            filename, number, _ = REVIEWED_VERSIONS[2]
            historical = self.git("show", REVIEWED_VERSION_COMMIT + ":" + filename)
            line = historical.splitlines()[number - 1]
            path = reviewed / filename
            lines = path.read_text().splitlines()
            lines[number - 1] = line
            path.write_text("\n".join(lines) + "\n")
            self.commit("Reintroduce inert metadata at the same fixture line in a new commit")
            recurrence = self.git("rev-parse", "HEAD").strip()
            output = self.directory / "metadata-recurrence-results"
            self.assertEqual(scan(reviewed, output), 1)
            findings = json.loads((output / "findings.json").read_text())
            self.assertTrue(any(item["Commit"] == recurrence and item["File"] == filename
                                and item["StartLine"] == number and item["RuleID"] == "generic-api-key"
                                and item["Fingerprint"] not in versions for item in findings))
            token = "ghp_" + hashlib.sha256(b"Synthetic metadata exception negative control").hexdigest()[:36]
            with path.open("a") as stream:
                stream.write("\nsyntheticCredential='" + token + "'\n")
            other = "packages/security-crypto/test/unit/synthetic-negative.txt"
            (reviewed / other).write_text("token=" + token + "\n")
            self.commit("Add synthetic credentials in the reviewed and an unrelated fixture path")
            output = self.directory / "metadata-secret-results"
            self.assertEqual(scan(reviewed, output), 1)
            for report in ["findings.json", "tree-findings.json"]:
                findings = json.loads((output / report).read_text())
                for candidate in [filename, other]:
                    self.assertTrue(any(item["File"].endswith(candidate)
                                        and item["RuleID"] == "github-pat" for item in findings))
            for report in output.iterdir():
                self.assertNotIn(token, report.read_text())
        finally:
            self.repository = original

    def test_metadata_review_rejects_forged_fingerprints_hashes_and_extra_findings(self):
        source = Path(__file__).resolve().parents[2]
        reviewed = self.directory / "metadata-tamper-repository"
        subprocess.run(["git", "clone", "--no-hardlinks", "--branch", "main",
                        str(source), str(reviewed)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original = self.repository
        self.repository = reviewed
        try:
            self.git("config", "user.name", "Disposable security fixture")
            self.git("config", "user.email", "security@example.test")
            policy = reviewed / "tools/security/reviewed-version-metadata.json"
            content = policy.read_text()
            for key in ["fingerprint", "sourceLineSha256", "sourceFileSha256"]:
                document = json.loads(content)
                document["findings"][0][key] = "unapproved"
                policy.write_text(json.dumps(document) + "\n")
                self.commit("Verify rejection of altered metadata review " + key)
                with self.assertRaises(ValueError):
                    reviewed_version_metadata(reviewed)
            document = json.loads(content)
            document["findings"].append(document["findings"][0])
            policy.write_text(json.dumps(document) + "\n")
            self.commit("Verify rejection of an extra metadata finding")
            with self.assertRaises(ValueError):
                reviewed_version_metadata(reviewed)
        finally:
            self.repository = original


if __name__ == "__main__":
    unittest.main()
