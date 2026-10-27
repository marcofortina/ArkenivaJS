# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Create one disposable OpenSSH fixture inside the integration VM or a disposable CI runner."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

os.umask(0o077)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--github-env', type=Path)
parser.add_argument('--port', type=int, default=0)
args = parser.parse_args()
if not 0 <= args.port <= 65535:
    raise SystemExit('The fixture port is invalid')
root = Path(tempfile.mkdtemp(prefix='arkenivajs-sftp-'))
container = root.name

def run(*command):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

for name in ['host', 'user']:
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name))
host = (root / 'host.pub').read_text().split()[1]
pin = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(host)).digest()).decode().rstrip('=')
metadata = {'directory': str(root), 'container': container, 'host': '127.0.0.1', 'port': args.port,
            'username': 'transfer', 'privateKeyFile': str(root / 'user'), 'pins': [pin], 'root': '/home/transfer/data'}
(root / 'runtime.json').write_text(json.dumps(metadata))
try:
    run('docker', 'run', '--detach', '--name', container, '--label', 'arkenivajs.fixture=sftp',
        '--read-only', '--network', 'bridge', '--memory', '192m', '--cpus', '1', '--pids-limit', '64',
        '--tmpfs', '/run:rw,nosuid,size=8m', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
        '--tmpfs', '/home/transfer:rw,noexec,nosuid,size=64m',
        '--mount', 'type=bind,source=' + str(root) + ',target=/fixture,readonly',
        '--publish', '127.0.0.1:' + str(args.port) + ':2222', 'arkenivajs-owned-sftp:r1')
    mapping = json.loads(run('docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', container))
    metadata['port'] = int(mapping['2222/tcp'][0]['HostPort'])
    (root / 'runtime.json').write_text(json.dumps(metadata))
    for attempt in range(50):
        try:
            run('ssh', '-p', str(metadata['port']), '-i', str(root / 'user'), '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(root / 'known_hosts'),
                '-o', 'ConnectTimeout=2', 'transfer@127.0.0.1', '/usr/bin/true')
            break
        except subprocess.CalledProcessError:
            # Pin the exact locally created public host key; never learn it from the connection.
            (root / 'known_hosts').write_text('[127.0.0.1]:' + str(metadata['port']) + ' ' + (root / 'host.pub').read_text())
            if attempt == 49:
                raise RuntimeError('The owned OpenSSH fixture did not become ready') from None
            time.sleep(0.1)
except BaseException:
    subprocess.run(['docker', 'rm', '--force', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raise
if args.github_env:
    with args.github_env.open('a') as output:
        output.write('ARKENIVA_SFTP_FIXTURE=' + str(root / 'runtime.json') + '\n')
print(root / 'runtime.json')
