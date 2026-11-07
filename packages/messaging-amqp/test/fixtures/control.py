# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Control only the positively identified disposable RabbitMQ fixture."""
import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def owned(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('The fixture metadata must not be a symbolic link')
    path = path.resolve(strict=True)
    value = json.loads(path.read_text())
    directory = Path(value['directory']).resolve(strict=True)
    name = value['container']
    if (path != directory / 'runtime.json' or name != directory.name
            or not re.fullmatch(r'arkenivajs-amqp-[a-z0-9_-]+', name)
            or value['network'] != name + '-net' or value['volume'] != name + '-data'
            or value['caFile'] != str(directory / 'ca.crt')):
        raise ValueError('The fixture ownership metadata is invalid')
    for kind, resource in [('container', name), ('network', value['network']), ('volume', value['volume'])]:
        field = '.Config.Labels' if kind == 'container' else '.Labels'
        label = run('docker', kind, 'inspect', '--format', '{{index ' + field + ' "arkenivajs.fixture"}}', resource)
        if label != 'amqp':
            raise ValueError('The fixture resource label does not prove ownership')
    return value


def ready(value, timeout=45):
    context = ssl.create_default_context(cafile=value['caFile'])
    deadline = time.monotonic() + timeout
    last_verification = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', value['port']), timeout=1) as stream:
                with context.wrap_socket(stream, server_hostname='localhost'):
                    return
        except ssl.SSLCertVerificationError as error:
            # OpenSSL supplies a verification reason, never certificate/key data.
            last_verification = {'verifyCode': error.verify_code,
                                 'verifyMessage': error.verify_message[:256]}
            time.sleep(0.1)
        except (OSError, ssl.SSLError):
            time.sleep(0.1)
    evidence = {'python': platform.python_version(), 'openssl': ssl.OPENSSL_VERSION,
                'verifyFlags': int(context.verify_flags),
                'lastCertificateVerification': last_verification}
    raise RuntimeError('The owned verified AMQPS listener did not become ready: '
                       + json.dumps(evidence, ensure_ascii=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['restart', 'teardown'])
    parser.add_argument('metadata', type=Path)
    args = parser.parse_args()
    value = owned(args.metadata)
    if args.action == 'restart':
        run('docker', 'restart', '--time', '3', value['container'])
        ready(value)
        print('The owned RabbitMQ broker restarted with verified AMQPS')
    else:
        run('docker', 'rm', '--force', value['container'])
        run('docker', 'volume', 'rm', value['volume'])
        run('docker', 'network', 'rm', value['network'])
        shutil.rmtree(value['directory'])
        print('The owned RabbitMQ fixture and its private files were removed')


if __name__ == '__main__':
    main()
