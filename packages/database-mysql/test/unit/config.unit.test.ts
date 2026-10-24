import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { mysqlConfiguration } from '../../dist/config.js';

const variable = 'ARKENIVA_MYSQL_CONFIGURATION_TEST';
const definition = { driver: 'mysql' as const, connectionStringEnv: variable };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-SEC-001 MySQL captures credentials and pins UTC, precision, prepared statements and TLS policy', () => {
  process.env[variable] = 'mysql://user:secret@localhost:13306/orders';
  try {
    const { pool, minimum } = mysqlConfiguration(definition, 'test');
    assert.equal(minimum, 0);
    assert.equal(pool.host, 'localhost');
    assert.equal(pool.user, 'user');
    assert.equal(pool.password, 'secret');
    assert.equal(pool.database, 'orders');
    assert.equal(pool.port, 13306);
    assert.equal(pool.ssl, undefined);
    assert.equal(pool.connectionLimit, 10);
    assert.equal(pool.maxIdle, 10);
    assert.equal(pool.connectTimeout, 5000);
    assert.equal(pool.timezone, 'Z');
    assert.equal(pool.charset, 'UTF8MB4_UNICODE_CI');
    assert.equal(pool.supportBigNumbers, true);
    assert.equal(pool.bigNumberStrings, true);
    assert.equal(pool.decimalNumbers, false);
    assert.equal(pool.dateStrings, true);
    assert.equal(pool.jsonStrings, true);
    assert.equal(pool.multipleStatements, false);
    assert.equal(pool.namedPlaceholders, false);
    assert.deepEqual(pool.flags, ['-LOCAL_FILES']);
    assert.equal(pool.disableEval, true);
    process.env[variable] = 'mysql://user@db.example/orders';
    const secure = mysqlConfiguration({ ...definition, poolMin: 2, poolMax: 3 }, 'production');
    assert.equal(secure.minimum, 2);
    assert.equal(secure.pool.connectionLimit, 3);
    assert.equal(secure.pool.port, 3306);
    assert.equal(secure.pool.password, '');
    assert.deepEqual(secure.pool.ssl, {
      rejectUnauthorized: true,
      verifyIdentity: true,
      minVersion: 'TLSv1.2',
    });
  } finally {
    delete process.env[variable];
  }
});

test('EK-CONF-001 MySQL rejects missing definitions and malformed pool bounds before creating resources', () => {
  delete process.env[variable];
  assert.throws(() => mysqlConfiguration(definition, 'test'), code('EK_CONFIG_MISSING'));
  for (const connectionStringEnv of [undefined, '', 'bad-name', 'NAME\n'])
    assert.throws(
      () =>
        mysqlConfiguration(
          {
            driver: 'mysql',
            ...(connectionStringEnv === undefined ? {} : { connectionStringEnv }),
          },
          'test',
        ),
      code('EK_CONFIG_MISSING'),
    );
  process.env[variable] = 'mysql://user@localhost/orders';
  try {
    for (const input of [
      { ...definition, driver: 'mariadb' as const },
      { ...definition, endpoints: [] },
      ...[-1, 0, 1.1, NaN].map((poolMax) => ({ ...definition, poolMax })),
      { ...definition, poolMin: -1 },
      { ...definition, poolMin: 11 },
    ])
      assert.throws(() => mysqlConfiguration(input, 'test'), code('EK_CONFIG_INVALID'));
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 MySQL refuses ambiguous URLs, insecure TLS and unsupported IP identity verification', () => {
  const invalid = [
    'http://user@localhost/orders',
    'mysql://localhost/orders',
    'mysql://user@localhost/',
    'mysql://user@localhost/a%2Fb',
    'mysql://user@localhost/orders#fragment',
    'mysql://user@localhost:99999/orders',
    'mysql://user%00@localhost/orders',
    'mysql://user:secret%0A@localhost/orders',
    'mysql://user@localhost/orders\n',
    'mysql://user@localhost/orders?ssl=disable&ssl=verify-full',
    'mysql://user@localhost/orders?multipleStatements=true',
    'mysql://user@localhost/orders?ssl=unsafe',
    'mysql://user@db.example/orders?ssl=disable',
    'mysql://user@127.0.0.1/orders?ssl=verify-full',
    'mysql://user@[::1]/orders?ssl=verify-full',
    'mysql://user@localhost/orders?sslca=/tmp/ca.crt',
    'mysql://user@localhost/orders?ssl=verify-full&sslca=relative.crt',
    'mysql://user@localhost/orders?ssl=verify-full&sslca=%00',
    'mysql://user@localhost/orders?ssl=verify-full&sslca=/does/not/exist.crt',
  ];
  try {
    for (const url of invalid) {
      process.env[variable] = url;
      assert.throws(() => mysqlConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    process.env[variable] = 'mysql://user@localhost/orders?ssl=disable';
    assert.throws(() => mysqlConfiguration(definition, 'production'), code('EK_CONFIG_INVALID'));
    for (const host of ['127.0.0.1', '[::1]']) {
      process.env[variable] = `mysql://user@${host}/orders?ssl=disable`;
      assert.equal(mysqlConfiguration(definition, 'test').pool.ssl, undefined);
    }
  } finally {
    delete process.env[variable];
  }
});

test('EK-SEC-001 explicit MySQL CA bundles are captured and bounded without accepting empty files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-mysql-ca-'));
  const file = join(directory, 'ca.crt');
  process.env[variable] =
    `mysql://user@localhost/orders?ssl=verify-full&sslca=${encodeURIComponent(file)}`;
  try {
    for (const content of ['', 'x'.repeat(1_048_577)]) {
      writeFileSync(file, content, { mode: 0o600 });
      assert.throws(() => mysqlConfiguration(definition, 'test'), code('EK_CONFIG_INVALID'));
    }
    writeFileSync(file, 'explicit-ca');
    const ssl = mysqlConfiguration(definition, 'test').pool.ssl;
    assert.ok(ssl && typeof ssl === 'object');
    assert.deepEqual(ssl.ca, Buffer.from('explicit-ca'));
  } finally {
    delete process.env[variable];
    rmSync(directory, { recursive: true, force: true });
  }
});
