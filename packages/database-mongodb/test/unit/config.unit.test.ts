// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rootCertificates } from 'node:tls';
import { MongoClient } from 'mongodb';
import { mongoConfiguration } from '../../dist/config.js';

const variable = 'ARKENIVA_MONGODB_CONFIG_TEST';
const definition = { driver: 'mongodb' as const, connectionStringEnv: variable };

test('MongoDB captures verified TLS trust, scoped URI options and bounded native policies before construction', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-mongodb-config-'));
  try {
    const ca = join(directory, 'ca.crt');
    writeFileSync(ca, rootCertificates[0]!, { mode: 0o600 });
    const query = new URLSearchParams({
      tls: 'true',
      tlsCAFile: ca,
      authSource: 'accounts',
      replicaSet: 'rs0',
      prefix: 'tenant_',
    });
    process.env[variable] =
      'mongodb://application:password@db.example:27017,replica.example:27017/records?' + query;
    const config = mongoConfiguration(definition, 'production');
    assert.equal(config.database, 'records');
    assert.equal(config.prefix, 'tenant_');
    assert.equal(config.native.minPoolSize, 0);
    assert.equal(config.native.maxPoolSize, 8);
    assert.equal(config.native.maxConnecting, 2);
    assert.equal(config.native.retryReads, false);
    assert.equal(config.native.retryWrites, false);
    assert.equal(config.native.maxAdaptiveRetries, 0);
    assert.equal(config.native.enableOverloadRetargeting, false);
    assert.equal(config.native.rejectUnauthorized, true);
    assert.equal(config.native.authMechanism, 'SCRAM-SHA-256');
    assert.ok(config.native.secureContext);
    assert.equal(config.url.includes('tlsCAFile'), false);
    assert.equal(config.url.includes('prefix='), false);
    assert.deepEqual(config.native.mongodbLogComponentSeverities, {
      default: 'off',
      command: 'off',
      topology: 'off',
      serverSelection: 'off',
      connection: 'off',
      client: 'off',
    });
    assert.equal(Object.isFrozen(config), true);
    assert.equal(Object.isFrozen(config.native), true);
    writeFileSync(ca, 'changed after capture');
    // Construction is offline and uses the captured SecureContext, rather than reopening the CA path.
    const client = new MongoClient(config.url, config.native);
    assert.ok(client instanceof MongoClient);
    await client.close();
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});

test('MongoDB permits explicitly trusted development loopback without silently permitting remote plaintext', () => {
  try {
    for (const host of ['localhost', '127.0.0.1', '[::1]']) {
      process.env[variable] = `mongodb://${host}:27017/records`;
      const config = mongoConfiguration(definition, 'test');
      assert.equal(config.native.tls, false);
      assert.equal(config.native.maxPoolSize, 8);
      assert.throws(() => mongoConfiguration(definition, 'production'), {
        code: 'EK_CONFIG_INVALID',
      });
    }
    process.env[variable] = 'mongodb://localhost:27017,db.example:27017/records';
    assert.throws(() => mongoConfiguration(definition, 'test'), { code: 'EK_CONFIG_INVALID' });
  } finally {
    delete process.env[variable];
  }
});

test('MongoDB validates SRV origins without resolving DNS or exposing unverified auth profiles', () => {
  try {
    process.env[variable] = 'mongodb+srv://application:password@db.example/records';
    const config = mongoConfiguration(definition, 'production');
    assert.equal(config.native.tls, true);
    assert.ok(config.native.secureContext);
    process.env[variable] += '?directConnection=true';
    assert.throws(() => mongoConfiguration(definition, 'production'), {
      code: 'EK_CONFIG_INVALID',
    });
  } finally {
    delete process.env[variable];
  }
});

test('MongoDB rejects unsupported, ambiguous or insecure URI fields before any native resource', () => {
  try {
    for (const value of [
      'mongodb://localhost:27017',
      'mongodb://localhost:27017/bad.name',
      'mongodb://localhost:27017/bad%2Fname',
      'mongodb://localhost:27017/records#fragment',
      'mongodb://localhost:27017/records\n',
      'mongodb://localhost:0/records',
      'mongodb://localhost:99999/records',
      'mongodb://db.example:27017/records',
      'mongodb://db.example:27017/records?tls=true',
      'mongodb://user@localhost:27017/records',
      'mongodb://localhost:27017/records?tls=TRUE',
      'mongodb://localhost:27017/records?tls=true&TLS=true',
      'mongodb://localhost:27017/records?unknown=true',
      'mongodb://localhost:27017/records?tlsAllowInvalidCertificates=true',
      'mongodb://localhost:27017/records?tlsInsecure=true',
      'mongodb://localhost:27017/records?retryWrites=true',
      'mongodb://localhost:27017/records?authMechanism=PLAIN',
      'mongodb://localhost:27017/records?prefix=bad.name',
      'mongodb://localhost:27017/records?prefix=' + 'a'.repeat(65),
      'mongodb://localhost:27017/records?replicaSet=bad.name',
      'mongodb://localhost:27017/records?authSource=bad%2Fname',
      'mongodb://localhost:27017/records?tlsCAFile=/tmp/ca.crt',
      'mongodb://localhost:27017/records?tls=true&tlsCAFile=relative',
      'mongodb://localhost:27017/records?tls=true&tlsCAFile=/does/not/exist',
      'mongodb://localhost:27017,127.0.0.1:27017/records?directConnection=true',
      'mongodb://' + Array(9).fill('localhost:27017').join(',') + '/records',
      'mongodb://localhost:27017/' + 'a'.repeat(64),
      'mongodb://localhost:27017/records?prefix=' + 'a'.repeat(65_536),
    ]) {
      process.env[variable] = value;
      assert.throws(() => mongoConfiguration(definition, 'test'), { code: 'EK_CONFIG_INVALID' });
    }
  } finally {
    delete process.env[variable];
  }
});

test('MongoDB requires an explicit declared environment and rejects SQL pool settings and invalid driver fields', () => {
  try {
    delete process.env[variable];
    assert.throws(() => mongoConfiguration(definition, 'test'), { code: 'EK_CONFIG_MISSING' });
    for (const name of ['', 'bad-name', 'NAME\n'])
      assert.throws(
        () => mongoConfiguration({ ...definition, connectionStringEnv: name }, 'test'),
        { code: 'EK_CONFIG_MISSING' },
      );
    process.env[variable] = 'mongodb://localhost:27017/records';
    for (const input of [
      { ...definition, driver: 'redis' as const },
      { ...definition, endpoints: ['http://localhost:27017'] },
      { ...definition, poolMin: -1 },
      { ...definition, poolMax: 0 },
      { ...definition, poolMax: 65 },
      { ...definition, poolMin: 5, poolMax: 4 },
      { ...definition, poolMin: 1.5 },
      { ...definition, poolMax: NaN },
    ])
      assert.throws(() => mongoConfiguration(input, 'test'), { code: 'EK_CONFIG_INVALID' });
  } finally {
    delete process.env[variable];
  }
});

test('MongoDB refuses empty, oversized and non-regular trust material', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-mongodb-material-')),
    file = join(directory, 'ca.crt');
  try {
    for (const path of [directory, file]) {
      if (path === file) writeFileSync(file, '', { mode: 0o600 });
      process.env[variable] =
        'mongodb://localhost:27017/records?tls=true&tlsCAFile=' + encodeURIComponent(path);
      assert.throws(() => mongoConfiguration(definition, 'test'), { code: 'EK_CONFIG_INVALID' });
    }
    writeFileSync(file, 'x'.repeat(1_048_577));
    assert.throws(() => mongoConfiguration(definition, 'test'), { code: 'EK_CONFIG_INVALID' });
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});
