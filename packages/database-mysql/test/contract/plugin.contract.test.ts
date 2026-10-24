import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { mysqlPlugin } from '@arkenivajs/database-mysql';

const service = { name: 'mysql-contract', version: '1.0.0', environment: 'test' as const };
const factory: () => Plugin = mysqlPlugin;

test('EK-CORE-002 MySQL factory prepares the common SQL facade without connecting at import or creation', async () => {
  const plugin = factory();
  assert.ok(plugin.capabilities.has('database.mysql'));
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: { main: { driver: 'mysql', connectionStringEnv: 'ARKENIVA_UNUSED_MYSQL_CONTRACT' } },
  });
  assert.equal(app.state, 'CREATED');
  await assert.rejects(
    app.sql.query('main', { text: 'SELECT 1' }),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LIFECYCLE_STATE',
  );
  await app.stop();
  assert.equal(app.state, 'CLOSED');
});

test('EK-CONF-001 MySQL requires a matching root definition at startup and closes after failure', async () => {
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
