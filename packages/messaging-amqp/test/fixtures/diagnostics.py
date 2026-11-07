# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Collect bounded, redacted startup evidence from this fixture's container."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

LIMIT = 65536
TIMEOUT = 5


def capture(command, limit=LIMIT, timeout=TIMEOUT):
    """Bound both output allocation and lifetime, including inherited pipes."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    reason = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'timeout'
                    break
                if not selector.select(remaining):
                    reason = 'timeout'
                    break
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    try:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        reason = 'timeout'
                    break
                output.extend(chunk)
                if len(output) > limit:
                    reason = 'output-limit'
                    break
    finally:
        # The child and any inherited pipe owners belong only to this command.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=1)
        process.stdout.close()
    return {'text': bytes(output[:limit]).decode('utf-8', errors='replace'),
            'exitCode': process.returncode, 'limit': reason}


def secret_values(directory):
    values = []
    for name in ('cookie', 'ca.key', 'server.key'):
        path = directory / name
        if path.exists():
            if path.is_symlink() or path.stat().st_size > LIMIT:
                raise ValueError('Private diagnostic inputs must be bounded regular files')
            value = path.read_text()
            values.append(value)
            values.extend(line for line in value.splitlines() if len(line) >= 8)
    definitions = json.loads((directory / 'definitions.json').read_text())
    for user in definitions['users']:
        values.extend(str(user[key]) for key in ('name', 'password_hash'))
    metadata = directory / 'runtime.json'
    if metadata.exists():
        for user in json.loads(metadata.read_text())['users'].values():
            values.extend(user.values())
    return sorted(set(values), key=len, reverse=True)


def redact(text, secrets):
    for value in secrets:
        if value:
            text = text.replace(value, '[redacted]')
    text = re.sub(r'-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|$)',
                  '[redacted private key]', text, flags=re.S)
    return re.sub(r'amqps?://[^\s/@]+:[^\s/@]+@', 'amqps://[redacted]@', text)


def startup_failure(directory, name, stream=None):
    """Never replace the startup exception or inspect an unowned container."""
    stream = sys.stderr if stream is None else stream
    try:
        directory = Path(directory)
        if directory.is_symlink() or directory.name != name or not re.fullmatch(r'arkenivajs-amqp-[a-z0-9_-]+', name):
            raise ValueError('Invalid fixture ownership')
        label = capture(('docker', 'container', 'inspect', '--format',
                         '{{index .Config.Labels "arkenivajs.fixture"}}', name), limit=128)
        if label['exitCode'] != 0 or label['limit'] is not None or label['text'].strip() != 'amqp':
            raise ValueError('Unverified fixture ownership')
        secrets = secret_values(directory)
        state = capture(('docker', 'container', 'inspect', '--format',
                         '{"status":{{json .State.Status}},"exitCode":{{.State.ExitCode}},'
                         '"oomKilled":{{.State.OOMKilled}},"error":{{json .State.Error}}}', name), limit=4096)
        logs = capture(('docker', 'logs', '--tail', '80', name))
        for result in (state, logs):
            # A byte bound can split a credential; retain only complete rows.
            if result['limit'] is not None:
                result['text'] = result['text'].rpartition('\n')[0]
            result['text'] = redact(result['text'], secrets)
        print(json.dumps({'amqpStartupDiagnostics': {'state': state, 'tail': logs}}, ensure_ascii=True), file=stream)
    except Exception:
        print('Owned AMQP startup diagnostics are unavailable', file=stream)
