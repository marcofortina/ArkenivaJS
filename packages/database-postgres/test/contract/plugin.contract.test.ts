import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';

const service = { name: 'postgres-contract', version: '1.0.0', environment: 'test' as const };
const factory: () => Plugin = postgresPlugin;

test('EK-CORE-002 PostgreSQL zero-argument factory declares its native driver and prepares SQL without network resources', async () => {
  const plugin = factory();
  assert.ok(plugin.capabilities.has('database.postgresql'));
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: {
      main: { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_UNUSED_CONTRACT_URL' },
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

test('EK-CONF-001 PostgreSQL missing root definitions fail at startup and cleanup remains idempotent', async () => {
  const app = await createApplication({ service, plugins: [factory()] });
  await assert.rejects(app.start(), (error: unknown) => {
    assert.ok(error instanceof KitError);
    assert.ok(error.cause instanceof KitError);
    assert.equal(error.cause.code, 'EK_CONFIG_MISSING');
    return true;
  });
  assert.equal(app.state, 'CLOSED');
  await app.stop();
});
