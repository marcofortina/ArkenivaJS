import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { postgresError, postgresCommitError, postgresSqlState } from '../../dist/errors.js';

test('EK-ERR-001 PostgreSQL error classification preserves bounded vendor codes and safe causes', () => {
  for (const [native, phase, code, retryable] of [
    ['23505', 'query', 'EK_DATABASE_CONSTRAINT', false],
    ['23503', 'query', 'EK_DATABASE_CONSTRAINT', false],
    ['40001', 'query', 'EK_DATABASE_CONFLICT', true],
    ['40P01', 'query', 'EK_DATABASE_CONFLICT', true],
    ['57014', 'query', 'EK_TIMEOUT', false],
    ['08006', 'query', 'EK_DATABASE_UNAVAILABLE', true],
    ['57P01', 'query', 'EK_DATABASE_UNAVAILABLE', true],
    ['ECONNREFUSED', 'connect', 'EK_DATABASE_CONNECT', true],
    ['ECONNRESET', 'query', 'EK_DATABASE_UNAVAILABLE', true],
    ['28P01', 'connect', 'EK_DATABASE_CONNECT', false],
    ['42601', 'query', 'EK_DATABASE_QUERY', false],
  ] as const) {
    const cause = Object.assign(new Error('disposable password and raw SQL'), {
      code: native,
      detail: 'private row contents',
    });
    const error = postgresError(cause, phase);
    assert.equal(error.code, code);
    assert.equal(error.retryable, retryable);
    assert.equal(error.cause, cause);
    assert.ok(!JSON.stringify(error).includes('password'));
    assert.ok(!JSON.stringify(error).includes('private'));
    if (native.length === 5) assert.equal(error.details?.sqlState, native);
    else assert.equal(error.details?.sqlState, undefined);
  }
  const typed = new KitError({ code: 'EK_ABORTED', message: 'SQL operation aborted' });
  assert.equal(postgresError(typed, 'query'), typed);
  assert.equal(
    postgresError(new Error('timeout exceeded when trying to connect'), 'connect').code,
    'EK_DATABASE_POOL_TIMEOUT',
  );
  assert.equal(
    postgresError(new Error('Connection terminated unexpectedly'), 'query').code,
    'EK_DATABASE_UNAVAILABLE',
  );
  assert.equal(postgresError(new Error('Connection terminated'), 'connect').retryable, true);
  assert.equal(
    postgresError(new Error('Connection terminated due to connection timeout'), 'connect').code,
    'EK_DATABASE_POOL_TIMEOUT',
  );
  for (const cause of [undefined, null, 0, '', new Error('unclassified'), { code: '23505\n' }]) {
    assert.equal(postgresSqlState(cause), undefined);
    assert.equal(postgresError(cause, 'query').code, 'EK_DATABASE_QUERY');
  }
});

test('EK-DB-001 uncertain commit outcomes never become safe-to-retry claims', () => {
  for (const cause of [
    new Error('socket closed'),
    { code: 'ECONNRESET' },
    { code: '57P01' },
    new KitError({ code: 'EK_TIMEOUT', message: 'Commit deadline exceeded' }),
  ]) {
    const error = postgresCommitError(cause);
    assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
    assert.equal(error.details?.outcome, 'unknown');
    assert.equal(error.retryable, false);
    assert.equal(error.cause, cause);
  }
  for (const state of ['23505', '40001', '25P02']) {
    const error = postgresCommitError({ code: state });
    assert.equal(error.details?.outcome, undefined);
    assert.equal(error.retryable, false);
  }
});
