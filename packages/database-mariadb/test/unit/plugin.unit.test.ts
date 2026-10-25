// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { mariadbPlugin } from '@arkenivajs/database-mariadb';
import { MariadbConnection } from '../../dist/connection.js';

const variable = 'ARKENIVA_MARIADB_PLUGIN_BOUNDARY_TEST';
const service = { name: 'mariadb-plugin-boundary', version: '1.0.0', environment: 'test' as const };

test('EK-CORE-001 MariaDB startup verifies readiness and aggregates cleanup failures across named pools', async (context) => {
  process.env[variable] = 'mariadb://user@localhost/test';
  context.mock.method(MariadbConnection.prototype, 'warm', async () => undefined);
  context.mock.method(MariadbConnection.prototype, 'queryOne', async () => null);
  const cleanup = new Error('Pool cleanup failed');
  context.mock.method(MariadbConnection.prototype, 'close', async () => {
    throw cleanup;
  });
  try {
    const app = await createApplication({
      service,
      plugins: [mariadbPlugin()],
      databases: { main: { driver: 'mariadb', connectionStringEnv: variable } },
    });
    await assert.rejects(app.start(), (error: unknown) => {
      assert.ok(error instanceof KitError);
      assert.ok(error.cause instanceof KitError);
      assert.ok(error.cause.cause instanceof AggregateError);
      assert.equal((error.cause.cause.errors[0] as KitError).code, 'EK_DATABASE_CONNECT');
      assert.equal(error.cause.cause.errors[1], cleanup);
      return true;
    });
    assert.equal(app.state, 'CLOSED');
  } finally {
    delete process.env[variable];
  }
});

test('EK-CORE-001 MariaDB shutdown attempts all named pools even when one close fails', async (context) => {
  process.env[variable] = 'mariadb://user@localhost/test';
  context.mock.method(MariadbConnection.prototype, 'warm', async () => undefined);
  context.mock.method(MariadbConnection.prototype, 'queryOne', async () => ({ healthy: 1 }));
  let closed = 0;
  context.mock.method(MariadbConnection.prototype, 'close', async () => {
    closed++;
    if (closed === 1) throw new Error('One pool failed to close');
  });
  try {
    const app = await createApplication({
      service,
      plugins: [mariadbPlugin()],
      databases: {
        main: { driver: 'mariadb', connectionStringEnv: variable },
        secondary: { driver: 'mariadb', connectionStringEnv: variable },
      },
    });
    await app.start();
    await assert.rejects(app.stop(), (error: unknown) => error instanceof KitError);
    assert.equal(closed, 2);
    assert.equal(app.state, 'CLOSED');
  } finally {
    delete process.env[variable];
  }
});
