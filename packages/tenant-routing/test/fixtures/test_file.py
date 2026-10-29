# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Verify privileged fixture admission before any owned deployment is created."""

import os
from pathlib import Path
import unittest
from unittest.mock import patch

import file as fixture


class FileFixtureGuards(unittest.TestCase):
    def test_identity_rejects_external_paths_and_privileged_targets(self):
        valid = Path("/run/arkenivajs-tenant-file-" + "a" * 24)
        for root, uid, gid, nonce in [
            (Path("/tmp/other"), 1000, 1000, "a" * 32),
            (Path(str(valid) + "/../other"), 1000, 1000, "a" * 32),
            (valid, 0, 1000, "a" * 32), (valid, 1000, 0, "a" * 32),
            (valid, 1000, 1000, "invalid"),
        ]:
            with self.subTest(root=root, uid=uid, gid=gid):
                with self.assertRaises(ValueError):
                    fixture.identity(root, uid, gid, nonce)

    def test_no_disposable_opt_in_never_executes_a_command(self):
        with patch.dict(os.environ, {}, clear=True), patch("file.subprocess.run") as run:
            with self.assertRaises(ValueError):
                fixture.main()
            run.assert_not_called()

    def test_root_cannot_substitute_for_the_unprivileged_application(self):
        with patch.dict(os.environ, {"ARKENIVA_TENANT_FILE_DISPOSABLE": "1"}), \
                patch("file.sys.argv", ["file.py", "--", "node"]), \
                patch("file.os.getuid", return_value=0), patch("file.subprocess.run") as run:
            with self.assertRaises(ValueError):
                fixture.main()
            run.assert_not_called()

    def test_prepare_and_cleanup_refuse_unowned_targets(self):
        valid = Path("/run/arkenivajs-tenant-file-" + "b" * 24)
        with patch("file.os.getuid", return_value=1000):
            with self.assertRaises(ValueError):
                fixture.prepare(valid, 1000, 1000, "b" * 32)
        with patch("file.Path.is_dir", return_value=False):
            with self.assertRaises(ValueError):
                fixture.cleanup(valid, 1000, 1000, "b" * 32)


if __name__ == "__main__":
    unittest.main()
