// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import type { SqlProvider, SqlStatement, SqlTransaction, SqlResult } from '@arkenivajs/core';
import { compileSql } from '@arkenivajs/database';

/** Compile-time checks keep the public facade independent of native client types. */
function publicContract(sql: SqlProvider, tx: SqlTransaction, statement: SqlStatement): void {
  const result: Promise<SqlResult<{ id: bigint }>> = sql.query<{ id: bigint }>(
    'primary',
    statement,
    { maxRows: 2 },
  );
  const one: Promise<{ id: bigint } | null> = sql.queryOne<{ id: bigint }>('primary', statement);
  const transactional: Promise<SqlResult> = sql.transaction('primary', (connection) =>
    connection.execute(statement),
  );
  const inTransaction: Promise<SqlResult> = tx.query(statement, { maxRows: 2 });
  void [result, one, transactional, inTransaction];
}
void publicContract;

test('EK-DB-001 published compiler uses structural core statement contracts', () => {
  const statement: SqlStatement = { text: 'SELECT :id', bindings: { id: 1n } };
  assert.deepEqual(compileSql(statement, 'postgres').parameters, [1n]);
});
