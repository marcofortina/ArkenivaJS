# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Stop only a positively identified, owned disposable OpenSSH fixture."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

path = Path(sys.argv[1]).resolve()
value = json.loads(path.read_text())
directory = Path(value['directory']).resolve()
if path != directory / 'runtime.json' or not directory.name.startswith('arkenivajs-sftp-') or value['container'] != directory.name:
    raise SystemExit('The fixture ownership check failed')
result = subprocess.run(['docker', 'inspect', '--format', '{{index .Config.Labels "arkenivajs.fixture"}}', value['container']], check=True, capture_output=True, text=True)
if result.stdout.strip() != 'sftp':
    raise SystemExit('The fixture label does not prove ownership')
subprocess.run(['docker', 'rm', '--force', value['container']], check=True, stdout=subprocess.DEVNULL)
shutil.rmtree(directory)
print('The owned OpenSSH fixture was stopped and its private files removed')
