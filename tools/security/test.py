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
from run import scan


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


if __name__ == "__main__":
    unittest.main()
