# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run a command against an owned verified-HTTPS OAuth fixture, then close its process."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--test-only', action='store_true', required=True)
parser.add_argument('command', nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ['--'] else args.command
if not command:
    parser.error('A command is required')
os.umask(0o077)
directory = Path(tempfile.mkdtemp(prefix='arkenivajs-oauth-'))
child = None

def openssl(*arguments):
    subprocess.run(['openssl', *arguments], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2', '-subj', '/CN=Owned OAuth Fixture CA', '-keyout', str(directory / 'ca.key'), '-out', str(directory / 'ca.crt'))
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Owned OAuth Fixture', '-keyout', str(directory / 'server.key'), '-out', str(directory / 'server.csr'))
    (directory / 'server.ext').write_text('subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', str(directory / 'server.csr'), '-CA', str(directory / 'ca.crt'), '-CAkey', str(directory / 'ca.key'), '-CAcreateserial', '-days', '2', '-sha256', '-extfile', str(directory / 'server.ext'), '-out', str(directory / 'server.crt'))
    environment = os.environ.copy()
    environment['ARKENIVA_OAUTH_FIXTURE'] = str(directory / 'runtime.json')
    environment['NODE_EXTRA_CA_CERTS'] = str(directory / 'ca.crt')
    # Preserve the caller's PostgreSQL and other fixture variables; print no credential metadata.
    with (directory / 'server.log').open('x') as log:
        child = subprocess.Popen(['node', str(Path(__file__).with_name('server.mjs')), '--test-only', str(directory)], env=environment, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while not (directory / 'runtime.json').is_file():
            if child.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('The owned OAuth fixture did not become ready')
            time.sleep(0.05)
        result = subprocess.run(command, env=environment)
        raise SystemExit(result.returncode)
finally:
    if child is not None:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    shutil.rmtree(directory)
