import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { oraclePlugin } from '@arkenivajs/database-oracle';
import { OracleConnection } from '../../dist/connection.js';
const variable = 'ARKENIVA_ORACLE_PLUGIN_TEST';
const service = { name: 'oracle-lifecycle', version: '1.0.0', environment: 'test' as const };

test('EK-CONF-001 Oracle validates mode at factory time and all named definitions before opening resources', async (context) => {
  for (const options of [null, [], false, { mode: 'auto' }, { mode: null }, { extra: true }])
    assert.throws(
      () => oraclePlugin(options as never),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_INVALID',
    );
  let created = 0;
  context.mock.method(OracleConnection, 'create', async () => {
    created++;
    throw new Error('No pool may be opened');
  });
  process.env[variable] = 'oracle://app:pw@localhost/FREE';
  try {
    const app = await createApplication({
      service,
      plugins: [oraclePlugin({ mode: 'thin' })],
      databases: {
        one: { driver: 'oracle', connectionStringEnv: variable },
        two: { driver: 'oracle', connectionStringEnv: 'ARKENIVA_MISSING_ORACLE_DEFINITION' },
      },
    });
    await assert.rejects(app.start());
    assert.equal(created, 0);
    assert.equal(app.state, 'CLOSED');
  } finally {
    delete process.env[variable];
  }
});

test('EK-CORE-001 Oracle startup authenticates readiness, registers named pools and releases every pool on shutdown', async (context) => {
  const created: string[] = [],
    closed: string[] = [];
  context.mock.method(OracleConnection, 'create', async (name: string) => {
    created.push(name);
    return {
      async queryOne() {
        return { healthy: '1' };
      },
      async query() {
        return { rows: [{ name }], rowCount: 1, metadata: {} };
      },
      async execute() {},
      async transaction() {},
      async ping() {
        return true;
      },
      stats() {
        return {};
      },
      native() {
        return name;
      },
      async close() {
        closed.push(name);
      },
    } as unknown as OracleConnection;
  });
  process.env[variable] = 'oracle://app:pw@localhost/FREE';
  try {
    const plugin = oraclePlugin();
    const app = await createApplication({
      service,
      plugins: [plugin],
      databases: {
        one: { driver: 'oracle', connectionStringEnv: variable },
        two: { driver: 'oracle', connectionStringEnv: variable },
      },
    });
    await app.start();
    assert.equal(app.state, 'READY');
    assert.deepEqual(created, ['one', 'two']);
    assert.equal((await app.sql.query('two', { text: 'SELECT 1 FROM DUAL' })).rows[0]?.name, 'two');
    assert.equal(app.sql.native('one'), 'one');
    const sql = app.sql;
    await app.stop();
    await app.stop();
    assert.deepEqual(closed.sort(), ['one', 'two']);
    await assert.rejects(sql.query('one', { text: 'SELECT 1 FROM DUAL' }));
  } finally {
    delete process.env[variable];
  }
});

test('EK-CORE-001 Oracle startup retains readiness and cleanup faults; failed pool creation releases earlier pools', async (context) => {
  process.env[variable] = 'oracle://app:pw@localhost/FREE';
  let unhealthy = true,
    cleanupFailed = true,
    created = 0,
    closed = 0;
  context.mock.method(OracleConnection, 'create', async () => {
    created++;
    if (created > 1) throw new Error('Second pool failed to open');
    return {
      async queryOne() {
        return unhealthy ? null : { healthy: '1' };
      },
      async close() {
        closed++;
        if (cleanupFailed) throw 'cleanup';
      },
      query() {},
      execute() {},
      transaction() {},
      ping() {},
      stats() {},
      native() {},
    } as unknown as OracleConnection;
  });
  try {
    const definition = { driver: 'oracle' as const, connectionStringEnv: variable };
    const app = await createApplication({
      service,
      plugins: [oraclePlugin()],
      databases: { one: definition },
    });
    await assert.rejects(app.start(), (error) => {
      assert.ok(error instanceof KitError);
      assert.ok(error.cause instanceof KitError);
      assert.ok(error.cause.cause instanceof AggregateError);
      assert.equal(error.cause.cause.errors[1], 'cleanup');
      return true;
    });
    assert.equal(closed, 1);
    assert.equal(app.state, 'CLOSED');
    unhealthy = false;
    cleanupFailed = false;
    created = 0;
    closed = 0;
    const next = await createApplication({
      service,
      plugins: [oraclePlugin()],
      databases: { one: definition, two: definition },
    });
    await assert.rejects(next.start());
    assert.equal(closed, 1);
  } finally {
    delete process.env[variable];
  }
});

test('EK-CORE-001 Oracle shutdown attempts all named pools when a close fails', async (context) => {
  let closed = 0;
  context.mock.method(
    OracleConnection,
    'create',
    async () =>
      ({
        async queryOne() {
          return { healthy: '1' };
        },
        async close() {
          closed++;
          if (closed === 1) throw new Error('First pool close failed');
        },
        query() {},
        execute() {},
        transaction() {},
        ping() {},
        stats() {},
        native() {},
      }) as unknown as OracleConnection,
  );
  process.env[variable] = 'oracle://app:pw@localhost/FREE';
  try {
    const definition = { driver: 'oracle' as const, connectionStringEnv: variable };
    const app = await createApplication({
      service,
      plugins: [oraclePlugin()],
      databases: { one: definition, two: definition },
    });
    await app.start();
    await assert.rejects(app.stop());
    assert.equal(closed, 2);
    assert.equal(app.state, 'CLOSED');
  } finally {
    delete process.env[variable];
  }
});
