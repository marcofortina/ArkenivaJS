import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import redis from 'redis';
import type { PeerCertificate } from 'node:tls';
import { KitError } from '@arkenivajs/core';
import { redisConfiguration, redisReconnect } from '../../dist/config.js';

const variable = 'ARKENIVA_REDIS_CONFIGURATION_TEST';
const definition = { driver: 'redis' as const, connectionStringEnv: variable };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-SEC-001 Redis captures explicit authentication, bounded queues and verified TLS without connection side effects', () => {
  try {
    process.env[variable] = 'rediss://alice:p%40ss@db.example:6380/2?prefix=tenant-a:';
    const { native, prefix } = redisConfiguration(definition, 'production');
    assert.equal(prefix, 'tenant-a:');
    assert.equal(native.username, 'alice');
    assert.equal(native.password, 'p@ss');
    assert.equal(native.database, 2);
    assert.equal(native.disableOfflineQueue, true);
    assert.equal(native.commandsQueueMaxLength, 128);
    assert.equal(native.maintNotifications, 'disabled');
    assert.equal(native.disableClientInfo, true);
    assert.ok(native.socket && 'tls' in native.socket && native.socket.tls);
    assert.equal(native.socket.host, 'db.example');
    assert.equal(native.socket.port, 6380);
    assert.equal(native.socket.connectTimeout, 5000);
    assert.equal(native.socket.rejectUnauthorized, true);
    assert.equal(native.socket.minVersion, 'TLSv1.2');
    assert.equal(native.socket.servername, 'db.example');
    assert.ok(Array.isArray(native.socket.ca) && native.socket.ca.length > 0);
    assert.equal(
      native.socket.checkServerIdentity!('ignored.invalid', {
        subjectaltname: 'DNS:db.example',
      } as PeerCertificate),
      undefined,
    );
    assert.ok(
      native.socket.checkServerIdentity!('db.example', {
        subjectaltname: 'DNS:wrong.invalid',
      } as PeerCertificate),
    );
    for (const host of ['localhost', '127.0.0.1', '[::1]']) {
      process.env[variable] = `redis://user:password@${host}`;
      const local = redisConfiguration(definition, 'test');
      assert.equal(local.native.database, 0);
      assert.equal(local.prefix, '');
      assert.equal(local.native.socket?.tls, false);
      assert.throws(() => redisConfiguration(definition, 'production'), code('EK_CONFIG_INVALID'));
    }
    process.env[variable] = 'rediss://user:password@127.0.0.1';
    const ip = redisConfiguration(definition, 'production').native.socket;
    assert.ok(ip && 'tls' in ip && ip.tls);
    assert.equal(ip.servername, undefined);
    assert.equal(
      ip.checkServerIdentity!('ignored.invalid', {
        subjectaltname: 'IP Address:127.0.0.1',
      } as PeerCertificate),
      undefined,
    );
  } finally {
    delete process.env[variable];
  }
});

test('EK-CONF-001 Redis rejects missing definitions, ambiguous URLs and unsupported options before native allocation', () => {
  delete process.env[variable];
  assert.throws(() => redisConfiguration(definition, 'test'), code('EK_CONFIG_MISSING'));
  for (const connectionStringEnv of [undefined, '', 'bad-name', 'NAME\n'])
    assert.throws(
      () =>
        redisConfiguration(
          {
            driver: 'redis',
            ...(connectionStringEnv === undefined ? {} : { connectionStringEnv }),
          },
          'test',
        ),
      code('EK_CONFIG_MISSING'),
    );
  try {
    process.env[variable] = 'redis://user:password@localhost';
    for (const input of [
      { ...definition, driver: 'mysql' as const },
      { ...definition, endpoints: [] },
      { ...definition, poolMin: 0 },
      { ...definition, poolMax: 1 },
    ])
      assert.throws(() => redisConfiguration(input, 'test'), code('EK_CONFIG_INVALID'));
    for (const url of [
      'http://user:password@localhost',
      'redis://localhost',
      'redis://user@localhost',
      'redis://user:password@db.example',
      'redis://user:password@-bad.example',
      'redis://user:password@localhost:0',
      'redis://user:password@localhost:99999',
      'redis://user:password@localhost/-1',
      'redis://user:password@localhost/1.5',
      'redis://user:password@localhost/2147483648',
      'redis://user:password@localhost/1/2',
      'redis://user%00:password@localhost',
      'redis://user:pass%0Aword@localhost',
      'redis://user:pass%ZZ@localhost',
      'redis://user:password@localhost#fragment',
      'redis://user:password@localhost\n',
      `redis://user:${'x'.repeat(65_536)}@localhost`,
      'redis://user:password@localhost?prefix=a:&prefix=b:',
      'redis://user:password@localhost?unknown=true',
      'redis://user:password@localhost?prefix=no-colon',
      'redis://user:password@localhost?prefix=%0A:',
      `redis://user:password@localhost?prefix=${'x'.repeat(128)}:`,
      'redis://user:password@localhost?sslca=/tmp/ca',
      'rediss://user:password@localhost?sslca=relative',
      'rediss://user:password@localhost?sslca=%00',
      'rediss://user:password@localhost?sslca=/does/not/exist.crt',
    ]) {
      process.env[variable] = url;
      assert.throws(() => redisConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 Redis captures a bounded regular CA file and rejects directories, empty and oversized inputs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-redis-ca-'));
  const file = join(directory, 'ca.crt');
  try {
    process.env[variable] =
      `rediss://user:password@localhost?sslca=${encodeURIComponent(directory)}`;
    assert.throws(() => redisConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    process.env[variable] = `rediss://user:password@localhost?sslca=${encodeURIComponent(file)}`;
    for (const content of ['', 'x'.repeat(1_048_577)]) {
      writeFileSync(file, content, { mode: 0o600 });
      assert.throws(() => redisConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    writeFileSync(file, 'captured-ca');
    const socket = redisConfiguration(definition, 'test').native.socket;
    writeFileSync(file, 'changed-ca');
    assert.ok(socket && 'tls' in socket && socket.tls);
    assert.deepEqual(socket.ca, Buffer.from('captured-ca'));
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});

test('EK-CORE-001 Redis reconnects only the transport with bounded jitter and stops on authentication and trust failures', () => {
  for (let attempt = 0; attempt < 5; attempt++) {
    const delay = redisReconnect(
      attempt,
      Object.assign(new Error('Transport failed'), { code: 'ECONNRESET' }),
    );
    assert.ok(typeof delay === 'number');
    assert.ok(
      delay >= Math.min(100 * 2 ** attempt, 1000) &&
        delay < Math.min(100 * 2 ** attempt, 1000) + 100,
    );
  }
  for (const attempt of [-1, 1.5, NaN, Infinity, 5, 100])
    assert.equal(redisReconnect(attempt, new Error('Failed')), false);
  for (const error of [
    new redis.SimpleError('WRONGPASS Invalid credentials'),
    new redis.SimpleError('NOAUTH Authentication required'),
    Object.assign(new Error('Trust failed'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
  ])
    assert.equal(redisReconnect(0, error), false);
});
