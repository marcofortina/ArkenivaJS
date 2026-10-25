// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { mysqlError, mysqlErrno, mysqlCommitError } from '../../dist/errors.js';

test('EK-ERR-001 MySQL classifies tested numeric identifiers and retains sanitized native causes', () => {
  const cases = [
    [1062, 'EK_DATABASE_CONSTRAINT'],
    [1048, 'EK_DATABASE_CONSTRAINT'],
    [1451, 'EK_DATABASE_CONSTRAINT'],
    [1452, 'EK_DATABASE_CONSTRAINT'],
    [3819, 'EK_DATABASE_CONSTRAINT'],
    [1213, 'EK_DATABASE_CONFLICT'],
    [1205, 'EK_DATABASE_CONFLICT'],
    [1317, 'EK_TIMEOUT'],
    [3024, 'EK_TIMEOUT'],
    [2006, 'EK_DATABASE_UNAVAILABLE'],
    [2013, 'EK_DATABASE_UNAVAILABLE'],
    [1064, 'EK_DATABASE_QUERY'],
  ] as const;
  for (const [errno, expected] of cases) {
    const native = Object.assign(new Error('private SQL and values'), { errno });
    const error = mysqlError(native, 'query');
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
    assert.equal(mysqlErrno(input), undefined);
  for (const native of [
    'ECONNREFUSED',
    'ECONNRESET',
    'EPIPE',
    'ETIMEDOUT',
    'ENETUNREACH',
    'EHOSTUNREACH',
    'PROTOCOL_CONNECTION_LOST',
  ])
    assert.equal(mysqlError({ code: native }, 'connect').code, 'EK_DATABASE_CONNECT');
  for (const message of ['Queue limit reached.', 'No connections available.'])
    assert.equal(mysqlError(new Error(message), 'connect').code, 'EK_DATABASE_POOL_TIMEOUT');
  assert.equal(mysqlError(new Error('Authentication failed'), 'connect').retryable, false);
  assert.equal(mysqlError('primitive failure', 'query').code, 'EK_DATABASE_QUERY');
  const own = new KitError({ code: 'EK_ABORTED', message: 'Owned cancellation' });
  assert.equal(mysqlError(own, 'query'), own);
});

test('EK-DB-001 a failed MySQL commit acknowledgment always requires domain reconciliation', () => {
  for (const cause of [new Error('socket lost'), { errno: 1213 }, null]) {
    const error = mysqlCommitError(cause);
    assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
    assert.equal(error.retryable, false);
    assert.deepEqual(error.details, { outcome: 'unknown' });
    assert.equal(error.cause, cause);
  }
});
