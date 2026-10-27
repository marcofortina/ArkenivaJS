# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Create an isolated AMQPS broker inside the integration VM or disposable CI runner."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
from urllib.parse import quote

from control import ready, run

IMAGE = 'rabbitmq:4.2.9-management@sha256:b8674f6c6dcd8fb5f96c87d66586875960da032ae2674ee93168db7a4df58745'


def password_hash(value):
    salt = secrets.token_bytes(4)
    return base64.b64encode(salt + hashlib.sha256(salt + value.encode()).digest()).decode()


def available_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-env', type=Path)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--management-port', type=int, default=0)
    args = parser.parse_args()
    if any(port < 0 or port > 65535 for port in [args.port, args.management_port]):
        raise ValueError('The fixture port is invalid')
    # Docker reallocates a published port zero on restart; pin each selected loopback port.
    port = args.port or available_port()
    management_port = args.management_port or available_port()
    while management_port == port and not args.management_port:
        management_port = available_port()
    if management_port == port:
        raise ValueError('The fixture listeners require distinct ports')
    root = Path(tempfile.mkdtemp(prefix='arkenivajs-amqp-'))
    name, network, volume = root.name, root.name + '-net', root.name + '-data'
    created = []
    try:
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
            '-subj', '/CN=Owned AMQP Fixture CA', '-keyout', str(root / 'ca.key'), '-out', str(root / 'ca.crt'))
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Owned AMQP Server',
            '-keyout', str(root / 'server.key'), '-out', str(root / 'server.csr'))
        (root / 'server.ext').write_text('subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-in', str(root / 'server.csr'), '-CA', str(root / 'ca.crt'),
            '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '2', '-sha256',
            '-extfile', str(root / 'server.ext'), '-out', str(root / 'server.crt'))
        users = {role: {'username': role + '-' + secrets.token_hex(4), 'password': secrets.token_urlsafe(32)}
                 for role in ['admin', 'service', 'denied']}
        vhost = 'fixture'
        definitions = {
            'users': [{'name': value['username'], 'password_hash': password_hash(value['password']),
                       'hashing_algorithm': 'rabbit_password_hashing_sha256',
                       'tags': ['administrator'] if role == 'admin' else []} for role, value in users.items()],
            'vhosts': [{'name': vhost}],
            'permissions': [{'user': value['username'], 'vhost': vhost,
                             'configure': '.*' if role == 'admin' else '^$',
                             'write': '.*' if role == 'admin' else r'^fixture\.' if role == 'service' else '^$',
                             'read': '.*' if role == 'admin' else r'^fixture\.' if role == 'service' else '^$'}
                            for role, value in users.items()],
            'exchanges': [], 'queues': [], 'bindings': [],
        }
        (root / 'definitions.json').write_text(json.dumps(definitions))
        (root / 'cookie').write_text(secrets.token_hex(32))
        (root / 'rabbit.conf').write_text('''listeners.tcp = none
listeners.ssl.default = 5671
ssl_options.cacertfile = /tmp/ca.crt
ssl_options.certfile = /tmp/server.crt
ssl_options.keyfile = /tmp/server.key
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = false
management.tcp.port = 15672
definitions.import_backend = local_filesystem
definitions.local.path = /tmp/definitions.json
max_message_size = 16777216
log.console = true
log.file = false
''')
        (root / 'runtime.env').write_text('RABBITMQ_CONFIG_FILE=/tmp/rabbit.conf\n'
            'RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2 +SDcpu 1 +SDio 1\n'
            'RABBITMQ_CTL_ERL_ARGS=+S 1:1 +SDcpu 1 +SDio 1\nRABBITMQ_LOGS=-\n')
        entry = ('set -eu; cp /fixture/server.key /fixture/server.crt /fixture/ca.crt /fixture/rabbit.conf '
                 '/fixture/definitions.json /tmp/; cp /fixture/cookie /var/lib/rabbitmq/.erlang.cookie; '
                 'chown 999:999 /tmp/server.key /tmp/server.crt /tmp/ca.crt /tmp/rabbit.conf '
                 '/tmp/definitions.json /var/lib/rabbitmq/.erlang.cookie; '
                 'chmod 600 /tmp/server.key /var/lib/rabbitmq/.erlang.cookie; exec docker-entrypoint.sh rabbitmq-server')
        for kind, resource in [('network', network), ('volume', volume)]:
            run('docker', kind, 'create', '--label', 'arkenivajs.fixture=amqp', resource)
            created.append((kind, resource))
        run('docker', 'run', '--detach', '--name', name, '--label', 'arkenivajs.fixture=amqp',
            '--hostname', 'amqp-fixture', '--user', '0:0', '--read-only', '--network', network,
            '--memory', '768m', '--cpus', '2', '--pids-limit', '256', '--env-file', str(root / 'runtime.env'),
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
            '--mount', 'type=bind,source=' + str(root) + ',target=/fixture,readonly',
            '--mount', 'type=volume,source=' + volume + ',target=/var/lib/rabbitmq',
            '--publish', '127.0.0.1:' + str(port) + ':5671',
            '--publish', '127.0.0.1:' + str(management_port) + ':15672',
            '--entrypoint', '/bin/sh', IMAGE, '-ec', entry)
        created.append(('container', name))
        ports = json.loads(run('docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', name))
        port = int(ports['5671/tcp'][0]['HostPort'])
        metadata = {'directory': str(root), 'container': name, 'network': network, 'volume': volume,
                    'port': port, 'managementPort': int(ports['15672/tcp'][0]['HostPort']),
                    'caFile': str(root / 'ca.crt'), 'users': users, 'vhost': vhost,
                    'uris': {role: 'amqps://' + quote(value['username'], safe='') + ':'
                             + quote(value['password'], safe='') + '@127.0.0.1:' + str(port) + '/' + vhost
                             for role, value in users.items()},
                    'restartCommand': ['python3', str(Path(__file__).with_name('control.py').resolve()),
                                       'restart', str(root / 'runtime.json')]}
        (root / 'runtime.json').write_text(json.dumps(metadata))
        ready(metadata)
    except BaseException:
        for kind, resource in reversed(created):
            field = '.Config.Labels' if kind == 'container' else '.Labels'
            try:
                label = run('docker', kind, 'inspect', '--format', '{{index ' + field + ' "arkenivajs.fixture"}}', resource)
                if label == 'amqp':
                    command = ['docker', kind, 'rm'] + (['--force'] if kind == 'container' else []) + [resource]
                    subprocess.run(command, check=True, capture_output=True, timeout=30)
            except (subprocess.SubprocessError, OSError):
                pass
        raise
    if args.github_env:
        with args.github_env.open('a') as output:
            output.write('ARKENIVA_AMQP_FIXTURE=' + str(root / 'runtime.json') + '\n')
    print(root / 'runtime.json')


if __name__ == '__main__':
    main()
