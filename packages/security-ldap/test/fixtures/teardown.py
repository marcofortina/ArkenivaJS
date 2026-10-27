# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Remove only container names bound to the supplied disposable fixture directory."""
import json
from pathlib import Path
import re
import subprocess
import sys

path = Path(sys.argv[1]).resolve(strict=True)
metadata = json.loads(path.read_text())
directory = Path(metadata["directory"]).resolve(strict=True)
if path.parent != directory or path.name != "runtime.json" or not re.fullmatch(r"arkenivajs-ldap-[a-z0-9_]{8}", directory.name):
    raise ValueError("The owned LDAP fixture path is invalid")
expected = [directory.name + "-server", directory.name + "-wrong"]
if metadata["containers"] != expected:
    raise ValueError("The LDAP fixture container ownership is invalid")
for name in expected:
    result = subprocess.run(["docker", "inspect", "--format", '{{range .Mounts}}{{if eq .Destination "/fixture"}}{{.Source}}{{end}}{{end}}', name], check=True, capture_output=True, text=True)
    suffix = "server" if name.endswith("-server") else "wrong"
    if result.stdout.strip() != str(directory / suffix):
        raise ValueError("The LDAP fixture container mount does not match its owner")
    subprocess.run(["docker", "rm", "--force", name], check=True, stdout=subprocess.DEVNULL)
