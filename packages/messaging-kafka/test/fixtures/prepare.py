# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

from pathlib import Path
import json, os, secrets, subprocess, sys
os.umask(63)
if len(sys.argv) != 2:
    raise SystemExit('Supply an empty private fixture directory')
root = Path(sys.argv[1]).resolve()
root.mkdir(mode=448)

def run(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise RuntimeError('Fixture command failed: ' + args[0] + ' ' + result.stderr[-1800:])
password = secrets.token_urlsafe(24)
(root / 'keystore-password').write_text(password)
for ca in ['ca', 'other-ca']:
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3', '-sha256', '-subj', '/CN=Owned Kafka ' + ca, '-keyout', str(root / (ca + '.key')), '-out', str(root / (ca + '.pem')))
for name, san in [('server', 'DNS:localhost,IP:127.0.0.1'), ('wrong', 'DNS:wrong.fixture.invalid')]:
    run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + name, '-keyout', str(root / (name + '.key')), '-out', str(root / (name + '.csr')))
    (root / (name + '.ext')).write_text('subjectAltName=' + san + '\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    run('openssl', 'x509', '-req', '-in', str(root / (name + '.csr')), '-CA', str(root / 'ca.pem'), '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '3', '-sha256', '-extfile', str(root / (name + '.ext')), '-out', str(root / (name + '.pem')))
    run('openssl', 'pkcs12', '-export', '-name', name, '-in', str(root / (name + '.pem')), '-inkey', str(root / (name + '.key')), '-certfile', str(root / 'ca.pem'), '-out', str(root / (name + '.p12')), '-passout', 'file:' + str(root / 'keystore-password'))
credentials = {name: secrets.token_urlsafe(24) for name in ['fixture-admin', 'fixture-allowed', 'fixture-denied']}
jaas = 'KafkaServer { org.apache.kafka.common.security.plain.PlainLoginModule required ' + ' '.join(('user_' + name + '="' + value + '"' for name, value in credentials.items())) + '; };\n'
(root / 'jaas.conf').write_text(jaas)
for name, value in credentials.items():
    (root / (name + '.json')).write_text(json.dumps({'mechanism': 'plain', 'username': name, 'password': value}) + '\n')
config = {'KAFKA_NODE_ID': '2', 'KAFKA_PROCESS_ROLES': 'broker,controller', 'KAFKA_LISTENERS': 'PLAINTEXT://:19096,SASL_SSL://:19094,CONTROLLER://:19095,WRONG://:19097', 'KAFKA_ADVERTISED_LISTENERS': 'PLAINTEXT://127.0.0.1:19096,SASL_SSL://127.0.0.1:19094,WRONG://127.0.0.1:19097', 'KAFKA_LISTENER_SECURITY_PROTOCOL_MAP': 'PLAINTEXT:PLAINTEXT,SASL_SSL:SASL_SSL,CONTROLLER:PLAINTEXT,WRONG:SASL_SSL', 'KAFKA_CONTROLLER_LISTENER_NAMES': 'CONTROLLER', 'KAFKA_CONTROLLER_QUORUM_VOTERS': '2@localhost:19095', 'KAFKA_INTER_BROKER_LISTENER_NAME': 'PLAINTEXT', 'KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR': '1', 'KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR': '1', 'KAFKA_TRANSACTION_STATE_LOG_MIN_ISR': '1', 'KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS': '0', 'KAFKA_AUTO_CREATE_TOPICS_ENABLE': 'false', 'KAFKA_SSL_KEYSTORE_FILENAME': 'server.p12', 'KAFKA_SSL_KEYSTORE_TYPE': 'PKCS12', 'KAFKA_SSL_KEY_CREDENTIALS': 'keystore-password', 'KAFKA_SSL_KEYSTORE_CREDENTIALS': 'keystore-password', 'KAFKA_SSL_ENABLED_PROTOCOLS': 'TLSv1.2,TLSv1.3', 'KAFKA_SSL_CLIENT_AUTH': 'none', 'KAFKA_LISTENER_NAME_WRONG_SSL_KEYSTORE_LOCATION': '/etc/kafka/secrets/wrong.p12', 'KAFKA_SASL_ENABLED_MECHANISMS': 'PLAIN', 'KAFKA_OPTS': '-Djava.security.auth.login.config=/etc/kafka/secrets/jaas.conf', 'KAFKA_AUTHORIZER_CLASS_NAME': 'org.apache.kafka.metadata.authorizer.StandardAuthorizer', 'KAFKA_SUPER_USERS': 'User:ANONYMOUS;User:fixture-admin', 'KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND': 'false', 'KAFKA_HEAP_OPTS': '-Xms256m -Xmx512m'}
(root / 'secure.env').write_text(''.join((name + '=' + value + '\n' for name, value in config.items())))
print('Prepared owned short-lived TLS/SASL fixture; no credential values emitted.')
