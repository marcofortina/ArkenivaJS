// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { mariadbPlugin } from '@arkenivajs/database-mariadb';

const service = { name: 'mariadb-contract', version: '1.0.0', environment: 'test' as const };
const factory: () => Plugin = mariadbPlugin;

test('EK-CORE-002 MariaDB factory prepares the common SQL facade without connecting at import or creation', async () => {
  const plugin = factory();
  assert.ok(plugin.capabilities.has('database.mariadb'));
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: {
      main: { driver: 'mariadb', connectionStringEnv: 'ARKENIVA_UNUSED_MARIADB_CONTRACT' },
    },
  });
  assert.equal(app.state, 'CREATED');
  await assert.rejects(
    app.sql.query('main', { text: 'SELECT 1' }),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LIFECYCLE_STATE',
  );
  await app.stop();
  assert.equal(app.state, 'CLOSED');
});

test('EK-CONF-001 MariaDB requires a matching root definition at startup and closes after failure', async () => {
  const app = await createApplication({ service, plugins: [factory()] });
  await assert.rejects(
    app.start(),
    (error: unknown) =>
      error instanceof KitError &&
      error.cause instanceof KitError &&
      error.cause.code === 'EK_CONFIG_MISSING',
  );
  await app.stop();
  assert.equal(app.state, 'CLOSED');
});
