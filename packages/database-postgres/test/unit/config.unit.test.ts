import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import { postgresConfiguration } from '../../dist/config.js';

function configured(
  url: string,
  environment: Environment = 'test',
  overrides: Partial<DatabaseDefinition> = {},
) {
  const variable = 'ARKENIVA_PG_TEST_' + randomUUID().replaceAll('-', '_').toUpperCase();
  process.env[variable] = url;
  try {
    return postgresConfiguration(
      'primary',
      { driver: 'postgresql', connectionStringEnv: variable, ...overrides },
      environment,
      'sql-test',
    );
  } finally {
    delete process.env[variable];
  }
}
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;

test('EK-SEC-001 PostgreSQL policy derives explicit environment credentials without ambient secret defaults', async () => {
  const config = configured('postgres://app:disposable@127.0.0.1/example');
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.user, 'app');
  assert.equal(config.database, 'example');
  assert.equal(typeof config.password, 'function');
  assert.equal(await (config.password as () => string)(), 'disposable');
  assert.equal(config.ssl, false);
  assert.equal(config.max, 10);
  assert.equal(config.min, 0);
  assert.equal(config.connectionTimeoutMillis, 5000);
  assert.equal(config.query_timeout, 0);
  assert.equal(config.pipeline, false);
  assert.equal(config.application_name, 'sql-test:primary');
  const peer = configured('postgres://app@localhost/example');
  assert.equal(await (peer.password as () => string)(), '');
  const bounded = configured(
    'postgres://app:x@localhost:15432/example?application_name=explicit',
    'test',
    { poolMin: 2, poolMax: 4 },
  );
  assert.equal(bounded.port, 15432);
  assert.equal(bounded.min, 2);
  assert.equal(bounded.max, 4);
  assert.equal(bounded.application_name, 'explicit');
});

test('EK-SEC-001 PostgreSQL network TLS defaults verify certificates and the configured IP or DNS identity', () => {
  for (const [url, environment] of [
    ['postgres://app:x@127.0.0.1/example', 'production'],
    ['postgres://app:x@db.invalid/example', 'development'],
    ['postgres://app:x@localhost/example?sslmode=verify-full', 'test'],
  ] as const) {
    const ssl = configured(url, environment).ssl;
    assert.equal(typeof ssl, 'object');
    assert.ok(ssl && typeof ssl === 'object');
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(typeof ssl.checkServerIdentity, 'function');
    const certificate = { subjectaltname: 'DNS:wrong.invalid' };
    const error = ssl.checkServerIdentity!('wrong.invalid', certificate as never);
    assert.ok(error);
    assert.equal((error as NodeJS.ErrnoException).code, 'ERR_TLS_CERT_ALTNAME_INVALID');
  }
  const ssl = configured('postgres://app:x@127.0.0.1/example?sslmode=verify-full').ssl;
  assert.ok(ssl && typeof ssl === 'object');
  assert.equal(
    ssl.checkServerIdentity!('ignored.invalid', {
      subjectaltname: 'IP Address:127.0.0.1',
    } as never),
    undefined,
  );
  assert.equal(configured('postgres://app:x@localhost/example?sslmode=disable').ssl, false);
  assert.equal(
    configured('postgres://app@/example?host=%2Fvar%2Frun%2Fpostgresql', 'production').ssl,
    false,
  );
});

test('EK-CONF-001 PostgreSQL rejects missing definitions, unsafe pool bounds and invalid secret sources', () => {
  for (const definition of [
    { driver: 'postgresql' },
    { driver: 'postgresql', connectionStringEnv: 'lowercase' },
    { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_MISSING_POSTGRES_URL' },
  ] as const)
    assert.throws(
      () => postgresConfiguration('primary', definition, 'test', 'sql-test'),
      code('EK_CONFIG_MISSING'),
    );
  for (const overrides of [
    { driver: 'mysql' },
    { endpoints: [] },
    { poolMin: -1 },
    { poolMax: 0 },
    { poolMin: 3, poolMax: 2 },
    { poolMax: Number.MAX_SAFE_INTEGER + 1 },
    { poolMin: 1.5 },
  ])
    assert.throws(
      () =>
        configured(
          'postgres://app:x@localhost/example',
          'test',
          overrides as Partial<DatabaseDefinition>,
        ),
      code('EK_CONFIG_INVALID'),
    );
});

test('EK-SEC-001 PostgreSQL rejects insecure TLS, malformed DSNs and incompatible encodings before creating a pool', () => {
  for (const [url, environment] of [
    ['invalid private credential', 'test'],
    ['http://app:private@localhost/example', 'test'],
    ['postgres://app:private@localhost/example#fragment', 'test'],
    ['postgres://app:private@db.invalid/example?sslmode=disable', 'development'],
    ['postgres://app:private@localhost/example?sslmode=disable', 'production'],
    ['postgres://app:private@localhost/example?sslmode=no-verify', 'test'],
    ['postgres://app:private@localhost/example?uselibpqcompat=true&sslmode=require', 'test'],
    ['postgres://app:private@localhost/example?ssl=false', 'test'],
    ['postgres://app:private@localhost/example?client_encoding=LATIN1', 'test'],
    ['postgres://:private@localhost/example', 'test'],
    ['postgres://app:private@localhost/', 'test'],
    ['postgres://app:private@localhost:0/example', 'test'],
    ['postgres://app:private@localhost:65536/example', 'test'],
    ['postgres://app:private@localhost/example?port=5432junk', 'test'],
    ['postgres://app:private@localhost/example?port=5432%0A', 'test'],
    ['postgres://app@/example?host=%2Ftmp&sslmode=verify-full', 'test'],
  ] as const) {
    assert.throws(
      () => configured(url, environment),
      (error: unknown) => {
        assert.ok(code('EK_CONFIG_INVALID')(error));
        assert.ok(!JSON.stringify(error).includes('private'));
        return true;
      },
    );
  }
});
