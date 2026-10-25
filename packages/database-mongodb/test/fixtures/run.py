# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run a command with private disposable MongoDB fixture variables without printing them."""

import json
import os
from pathlib import Path
import subprocess
import sys


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("Usage: run.py PRIVATE_ENVIRONMENT_JSON COMMAND [ARGUMENT ...]")
    path = Path(sys.argv[1])
    if path.stat().st_mode & 0o077:
        raise SystemExit("The fixture environment must not be accessible to other users")
    variables = json.loads(path.read_text())
    if not isinstance(variables, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in variables.items()):
        raise SystemExit("Invalid fixture environment mapping")
    environment = os.environ.copy()
    environment.update(variables)
    raise SystemExit(subprocess.run(sys.argv[2:], env=environment, check=False).returncode)
