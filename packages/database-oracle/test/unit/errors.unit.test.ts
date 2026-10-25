// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { oracleCode, oracleError, oracleCommitError } from '../../dist/errors.js';
test('EK-DB-001 Oracle maps only tested vendor codes and preserves unsafe native text exclusively as cause', () => {
  for (const phase of ['query', 'connect'] as const) {
    for (const code of ['ORA-00001', 'ORA-01400', 'ORA-02290', 'ORA-02291', 'ORA-02292'])
      assert.equal(oracleError({ code }, phase).code, 'EK_DATABASE_CONSTRAINT');
    for (const code of ['ORA-00060', 'ORA-08177']) {
      assert.equal(oracleError({ code }, phase).code, 'EK_DATABASE_CONFLICT');
      assert.equal(oracleError({ code }, phase).retryable, true);
    }
    for (const code of ['ORA-01013', 'DPI-1067', 'NJS-040'])
      assert.equal(
        oracleError({ code }, phase).code,
        phase === 'connect' && code === 'NJS-040' ? 'EK_DATABASE_POOL_TIMEOUT' : 'EK_TIMEOUT',
      );
    for (const code of ['ORA-03113', 'ORA-03114', 'ORA-03135', 'NJS-500', 'NJS-501', 'NJS-503'])
      assert.equal(
        oracleError({ code }, phase).code,
        phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_UNAVAILABLE',
      );
    for (const error of [
      null,
      undefined,
      0,
      'ORA-00001',
      { code: 'ORA-00001\n' },
      { code: 1 },
      { code: 'ECONNRESET' },
      { code: 'ORA-01017' },
    ]) {
      const wrapped = oracleError(error, phase);
      assert.equal(wrapped.cause, error);
      assert.equal(wrapped.retryable, false);
      assert.equal(wrapped.code, phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_QUERY');
    }
  }
  assert.equal(oracleCode({ code: 'ORA-12345' }), 'ORA-12345');
  const known = new KitError({ code: 'EK_ABORTED', message: 'Caller aborted' });
  assert.equal(oracleError(known, 'query'), known);
  const unknown = oracleCommitError(known);
  assert.equal(unknown.details?.outcome, 'unknown');
  assert.equal(unknown.retryable, false);
  assert.equal(unknown.cause, known);
});
