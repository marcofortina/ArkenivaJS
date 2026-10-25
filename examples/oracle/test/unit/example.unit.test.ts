// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { SqlProvider, SqlStatement } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import { readOracleExact, runOracleExample } from '../../dist/main.js';

test('The Oracle consumer preserves a NUMBER string through its JSON boundary with exact named binds', async () => {
  let captured: SqlStatement | undefined;
  const sql = {
    async queryOne(name: string, statement: SqlStatement) {
      assert.equal(name, 'legacy');
      captured = statement;
      return { exact: '9007199254740993' };
    },
  } as Pick<SqlProvider, 'queryOne'>;
  const result = await readOracleExact(sql, 9007199254740993n);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { exact: '9007199254740993' });
  assert.ok(Object.isFrozen(result));
  assert.match(captured!.text, /CAST\(:value AS NUMBER\(38,0\)\)/);
  assert.equal(captured!.bindings?.value, 9007199254740993n);
  for (const value of [Number('9007199254740993'), 10n ** 38n])
    await assert.rejects(
      readOracleExact(sql, value as bigint),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_INVALID',
    );
  for (const row of [null, { exact: 9007199254740992 }, { exact: '1.25' }]) {
    const invalid = {
      async queryOne() {
        return row;
      },
    } as Pick<SqlProvider, 'queryOne'>;
    await assert.rejects(
      readOracleExact(invalid, 1n),
      (e) => e instanceof KitError && e.code === 'EK_DATABASE_QUERY',
    );
  }
});

test('The Oracle consumer requires explicit live configuration and prints only safe CLI errors', async () => {
  const previous = {
    marker: process.env.ARKENIVA_ORACLE_LIVE,
    url: process.env.ARKENIVA_ORACLE_URL,
  };
  try {
    delete process.env.ARKENIVA_ORACLE_LIVE;
    delete process.env.ARKENIVA_ORACLE_URL;
    await assert.rejects(
      runOracleExample(),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_INVALID',
    );
    process.env.ARKENIVA_ORACLE_LIVE = '1';
    await assert.rejects(
      runOracleExample(),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_MISSING',
    );
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (error) => {
        assert.ok(error && typeof error === 'object' && 'stderr' in error);
        const safe = JSON.parse(String(error.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.stack, undefined);
        assert.equal(safe.cause, undefined);
        return true;
      },
    );
  } finally {
    for (const [key, value] of [
      ['ARKENIVA_ORACLE_LIVE', previous.marker],
      ['ARKENIVA_ORACLE_URL', previous.url],
    ] as const)
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
  }
});
