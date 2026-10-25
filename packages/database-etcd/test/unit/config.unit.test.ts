import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { noop } from 'cockatiel';
import { etcdConfiguration } from '../../dist/config.js';

const variable = 'ARKENIVA_ETCD_CONFIG_TEST';
const definition = { driver: 'etcd' as const, connectionStringEnv: variable };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-SEC-001 etcd captures bounded mTLS material, endpoint order and disabled native write retries', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-etcd-config-'));
  try {
    for (const name of ['ca', 'cert', 'key'])
      writeFileSync(join(directory, name), name, { mode: 0o600 });
    const query = new URLSearchParams({
      sslca: join(directory, 'ca'),
      sslcert: join(directory, 'cert'),
      sslkey: join(directory, 'key'),
      prefix: '/tenant-a/',
    });
    process.env[variable] = 'https://db.example:2379?' + query;
    const config = etcdConfiguration(
      { ...definition, endpoints: ['https://db.example:2379', 'https://replica.example:2379'] },
      'production',
    );
    assert.deepEqual(config.native.hosts, [
      'https://db.example:2379',
      'https://replica.example:2379',
    ]);
    assert.equal(config.prefix, '/tenant-a/');
    assert.equal(config.native.faultHandling?.global, noop);
    assert.equal(config.native.faultHandling?.host?.('db.example'), noop);
    assert.equal(config.native.grpcOptions?.['grpc.enable_retries'], 0);
    assert.equal(config.native.grpcOptions?.['grpc.max_receive_message_length'], 2_097_152);
    assert.deepEqual(config.native.credentials?.rootCertificate, Buffer.from('ca'));
    assert.deepEqual(config.native.credentials?.certChain, Buffer.from('cert'));
    assert.deepEqual(config.native.credentials?.privateKey, Buffer.from('key'));
    writeFileSync(join(directory, 'key'), 'changed');
    assert.deepEqual(config.native.credentials?.privateKey, Buffer.from('key'));
    query.delete('sslca');
    process.env[variable] = 'https://db.example:2379?' + query;
    assert.ok(
      etcdConfiguration(definition, 'production').native.credentials!.rootCertificate.length > 0,
    );
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});

test('EK-CONF-001 etcd accepts only explicitly trusted development loopback without credentials', () => {
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    const definition = { driver: 'etcd' as const, endpoints: [`http://${host}:2379`] };
    assert.deepEqual(etcdConfiguration(definition, 'test').native.hosts, definition.endpoints);
    assert.equal(etcdConfiguration(definition, 'development').native.credentials, undefined);
    assert.throws(() => etcdConfiguration(definition, 'production'), code('EK_CONFIG_INVALID'));
  }
  assert.throws(() => etcdConfiguration({ driver: 'etcd' }, 'test'), code('EK_CONFIG_MISSING'));
  for (const name of ['', 'bad-name', 'NAME\n'])
    assert.throws(
      () => etcdConfiguration({ driver: 'etcd', connectionStringEnv: name }, 'test'),
      code('EK_CONFIG_MISSING'),
    );
  delete process.env[variable];
  assert.throws(() => etcdConfiguration(definition, 'test'), code('EK_CONFIG_MISSING'));
});

test('EK-SEC-001 etcd rejects ambiguous origins, insecure remote transports and incomplete identities before allocation', () => {
  try {
    for (const value of [
      'https://user:password@localhost:2379',
      'http://db.example:2379',
      'https://db.example:2379',
      'https://localhost:2379?sslcert=/tmp/cert',
      'https://localhost:2379?sslkey=/tmp/key',
      'http://localhost:2379?sslca=/tmp/ca',
      'https://localhost:2379/path',
      'https://localhost:0',
      'https://localhost:99999',
      'ftp://localhost:2379',
      'https://-bad.example:2379',
      'http://localhost:2379\n',
      'http://localhost:2379#fragment',
      'http://localhost:2379?prefix=/a/&prefix=/b/',
      'http://localhost:2379?unknown=true',
      'http://localhost:2379?prefix=relative',
      'http://localhost:2379?prefix=/missing-slash',
      `http://localhost:2379?prefix=/${'a'.repeat(256)}/`,
      'https://localhost:2379?sslca=relative',
      'https://localhost:2379?sslca=/does/not/exist',
    ]) {
      process.env[variable] = value;
      assert.throws(() => etcdConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    process.env[variable] = 'http://localhost:2379?prefix=/';
    assert.equal(etcdConfiguration(definition, 'test').prefix, '/');
    for (const input of [
      { ...definition, driver: 'redis' as const },
      { ...definition, poolMin: 0 },
      { ...definition, poolMax: 1 },
      { ...definition, endpoints: null as never },
      { ...definition, endpoints: [] },
      { ...definition, endpoints: Array(9).fill('http://localhost:2379') },
      { ...definition, endpoints: ['http://other.example:2379'] },
      { ...definition, endpoints: ['http://localhost:2379?prefix=/other/'] },
      { ...definition, endpoints: ['http://localhost:2379', 'https://localhost:2379'] },
    ])
      assert.throws(() => etcdConfiguration(input, 'test'), code('EK_CONFIG_INVALID'));
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 etcd rejects empty, oversized and non-regular TLS material without opening native resources', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-etcd-material-'));
  const file = join(directory, 'ca');
  try {
    process.env[variable] = 'https://localhost:2379?sslca=' + encodeURIComponent(directory);
    assert.throws(() => etcdConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    process.env[variable] = 'https://localhost:2379?sslca=' + encodeURIComponent(file);
    for (const value of ['', 'x'.repeat(1_048_577)]) {
      writeFileSync(file, value, { mode: 0o600 });
      assert.throws(() => etcdConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});
