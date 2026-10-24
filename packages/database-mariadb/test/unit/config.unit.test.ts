import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { mariadbConfiguration } from '../../dist/config.js';

const variable = 'ARKENIVA_MARIADB_CONFIGURATION_TEST';
const definition = { driver: 'mariadb' as const, connectionStringEnv: variable };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-SEC-001 MariaDB captures credentials and pins UTC, precision, prepared statements and TLS policy', () => {
  process.env[variable] = 'mariadb://user:secret@localhost:13307/orders';
  try {
    const { pool, minimum } = mariadbConfiguration(definition, 'test');
    assert.equal(minimum, 0);
    assert.equal(pool.host, 'localhost');
    assert.equal(pool.user, 'user');
    assert.equal(pool.password, 'secret');
    assert.equal(pool.database, 'orders');
    assert.equal(pool.port, 13307);
    assert.equal(pool.ssl, undefined);
    assert.equal(pool.connectionLimit, 10);
    assert.equal(pool.minimumIdle, 0);
    assert.equal(pool.connectTimeout, 5000);
    assert.equal(pool.timezone, '+00:00');
    assert.equal(pool.charset, 'utf8mb4');
    assert.equal(pool.bigIntAsNumber, false);
    assert.equal(pool.insertIdAsNumber, false);
    assert.equal(pool.decimalAsNumber, false);
    assert.equal(pool.dateStrings, true);
    assert.equal(pool.autoJsonMap, false);
    assert.equal(pool.multipleStatements, false);
    assert.equal(pool.namedPlaceholders, false);
    assert.equal(pool.permitLocalInfile, false);
    assert.equal(pool.resetAfterUse, false);
    process.env[variable] = 'mariadb://user@db.example/orders';
    const secure = mariadbConfiguration({ ...definition, poolMin: 2, poolMax: 3 }, 'production');
    assert.equal(secure.minimum, 2);
    assert.equal(secure.pool.connectionLimit, 3);
    assert.equal(secure.pool.port, 3306);
    assert.equal(secure.pool.password, '');
    assert.ok(secure.pool.ssl && typeof secure.pool.ssl === 'object');
    assert.equal(secure.pool.ssl.rejectUnauthorized, true);
    assert.ok(Array.isArray(secure.pool.ssl.ca));
    assert.ok(secure.pool.ssl.ca.length > 0);
  } finally {
    delete process.env[variable];
  }
});

test('EK-CONF-001 MariaDB rejects missing definitions and malformed pool bounds before creating resources', () => {
  delete process.env[variable];
  assert.throws(() => mariadbConfiguration(definition, 'test'), code('EK_CONFIG_MISSING'));
  for (const connectionStringEnv of [undefined, '', 'bad-name', 'NAME\n'])
    assert.throws(
      () =>
        mariadbConfiguration(
          {
            driver: 'mariadb',
            ...(connectionStringEnv === undefined ? {} : { connectionStringEnv }),
          },
          'test',
        ),
      code('EK_CONFIG_MISSING'),
    );
  process.env[variable] = 'mariadb://user@localhost/orders';
  try {
    for (const input of [
      { ...definition, driver: 'mysql' as const },
      { ...definition, endpoints: [] },
      ...[-1, 0, 1.1, NaN].map((poolMax) => ({ ...definition, poolMax })),
      { ...definition, poolMin: -1 },
      { ...definition, poolMin: 11 },
    ])
      assert.throws(() => mariadbConfiguration(input, 'test'), code('EK_CONFIG_INVALID'));
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 MariaDB refuses ambiguous URLs, insecure TLS and invalid trust configuration', () => {
  const invalid = [
    'http://user@localhost/orders',
    'mariadb://localhost/orders',
    'mariadb://user@localhost/',
    'mariadb://user@localhost/a%2Fb',
    'mariadb://user@localhost/orders#fragment',
    'mariadb://user@localhost:99999/orders',
    'mariadb://user%00@localhost/orders',
    'mariadb://user:secret%0A@localhost/orders',
    'mariadb://user@localhost/orders\n',
    'mariadb://user@localhost/orders?ssl=disable&ssl=verify-full',
    'mariadb://user@localhost/orders?multipleStatements=true',
    'mariadb://user@localhost/orders?ssl=unsafe',
    'mariadb://user@db.example/orders?ssl=disable',
    'mariadb://user@localhost/orders?sslca=/tmp/ca.crt',
    'mariadb://user@localhost/orders?ssl=verify-full&sslca=relative.crt',
    'mariadb://user@localhost/orders?ssl=verify-full&sslca=%00',
    'mariadb://user@localhost/orders?ssl=verify-full&sslca=/does/not/exist.crt',
  ];
  try {
    for (const url of invalid) {
      process.env[variable] = url;
      assert.throws(() => mariadbConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    process.env[variable] = 'mariadb://user@localhost/orders?ssl=disable';
    assert.throws(() => mariadbConfiguration(definition, 'production'), code('EK_CONFIG_INVALID'));
    for (const host of ['127.0.0.1', '[::1]']) {
      process.env[variable] = `mariadb://user@${host}/orders?ssl=disable`;
      assert.equal(mariadbConfiguration(definition, 'test').pool.ssl, undefined);
    }
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 explicit MariaDB CA bundles are captured and bounded without accepting empty files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-mariadb-ca-'));
  const file = join(directory, 'ca.crt');
  process.env[variable] =
    `mariadb://user@localhost/orders?ssl=verify-full&sslca=${encodeURIComponent(file)}`;
  try {
    for (const content of ['', 'x'.repeat(1_048_577)]) {
      writeFileSync(file, content, { mode: 0o600 });
      assert.throws(() => mariadbConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    writeFileSync(file, 'explicit-ca');
    const ssl = mariadbConfiguration(definition, 'test').pool.ssl;
    assert.ok(ssl && typeof ssl === 'object');
    assert.deepEqual(ssl.ca, Buffer.from('explicit-ca'));
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});
