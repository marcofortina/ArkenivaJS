# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run a command with private disposable NATS variables without printing them."""

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
        raise SystemExit("The fixture environment must not be accessible by other users")
    variables = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(variables, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in variables.items()
    ):
        raise SystemExit("Invalid fixture environment mapping")
    environment = os.environ.copy()
    environment.update(variables)
    result = subprocess.run(sys.argv[2:], env=environment, check=False)
    raise SystemExit(result.returncode)
