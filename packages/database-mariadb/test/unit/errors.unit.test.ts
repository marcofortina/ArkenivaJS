import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { mariadbError, mariadbErrno, mariadbCommitError } from '../../dist/errors.js';

test('EK-ERR-001 MariaDB classifies tested numeric identifiers and retains sanitized native causes', () => {
  const cases = [
    [1062, 'EK_DATABASE_CONSTRAINT'],
    [1048, 'EK_DATABASE_CONSTRAINT'],
    [1451, 'EK_DATABASE_CONSTRAINT'],
    [1452, 'EK_DATABASE_CONSTRAINT'],
    [4025, 'EK_DATABASE_CONSTRAINT'],
    [1213, 'EK_DATABASE_CONFLICT'],
    [1205, 'EK_DATABASE_CONFLICT'],
    [1317, 'EK_TIMEOUT'],
    [1969, 'EK_TIMEOUT'],
    [2006, 'EK_DATABASE_UNAVAILABLE'],
    [2013, 'EK_DATABASE_UNAVAILABLE'],
    [1064, 'EK_DATABASE_QUERY'],
  ] as const;
  for (const [errno, expected] of cases) {
    const native = Object.assign(new Error('private SQL and values'), { errno });
    const error = mariadbError(native, 'query');
    assert.equal(error.code, expected);
    assert.equal(error.cause, native);
    assert.deepEqual(error.details, { errno });
    assert.ok(!JSON.stringify(error).includes('private SQL'));
    assert.equal(
      error.retryable,
      ['EK_DATABASE_CONFLICT', 'EK_DATABASE_UNAVAILABLE'].includes(expected),
    );
  }
  for (const input of [
    undefined,
    null,
    false,
    {},
    { errno: '1062' },
    { errno: 0 },
    { errno: 65536 },
    { errno: 1.1 },
  ])
    assert.equal(mariadbErrno(input), undefined);
  for (const native of [
    'ECONNREFUSED',
    'ECONNRESET',
    'EPIPE',
    'ETIMEDOUT',
    'ENETUNREACH',
    'EHOSTUNREACH',
  ])
    assert.equal(mariadbError({ code: native }, 'connect').code, 'EK_DATABASE_CONNECT');
  assert.equal(
    mariadbError({ code: 'ER_GET_CONNECTION_TIMEOUT', errno: 45028 }, 'connect').code,
    'EK_DATABASE_POOL_TIMEOUT',
  );
  assert.equal(mariadbError(new Error('Authentication failed'), 'connect').retryable, false);
  assert.equal(mariadbError('primitive failure', 'query').code, 'EK_DATABASE_QUERY');
  const own = new KitError({ code: 'EK_ABORTED', message: 'Owned cancellation' });
  assert.equal(mariadbError(own, 'query'), own);
});

test('EK-DB-001 a failed MariaDB commit acknowledgment always requires domain reconciliation', () => {
  for (const cause of [new Error('socket lost'), { errno: 1213 }, null]) {
    const error = mariadbCommitError(cause);
    assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
    assert.equal(error.retryable, false);
    assert.deepEqual(error.details, { outcome: 'unknown' });
    assert.equal(error.cause, cause);
  }
});

test('EK-SEC-001 MariaDB pool errors retain their actual authentication or TLS cause and cannot become healthy-retry claims', () => {
  const auth = Object.assign(new Error('Private authentication details'), {
    errno: 1045,
    code: 'ER_ACCESS_DENIED_ERROR',
  });
  const pooled = Object.assign(new Error('Native acquisition failed', { cause: auth }), {
    errno: 45028,
    code: 'ER_GET_CONNECTION_TIMEOUT',
  });
  const result = mariadbError(pooled, 'connect');
  assert.equal(result.code, 'EK_DATABASE_CONNECT');
  assert.equal(result.retryable, false);
  assert.equal(result.cause, pooled);
  assert.deepEqual(result.details, { errno: 1045 });
  const cyclic: { cause?: unknown } = {};
  cyclic.cause = cyclic;
  assert.equal(mariadbError(cyclic, 'connect').code, 'EK_DATABASE_CONNECT');
  for (const errno of [1927, 45001, 45004, 45009, 45012, 45013, 45019, 45026]) {
    assert.equal(mariadbError({ errno }, 'query').code, 'EK_DATABASE_UNAVAILABLE');
    assert.equal(mariadbError({ errno }, 'connect').code, 'EK_DATABASE_CONNECT');
  }
});
