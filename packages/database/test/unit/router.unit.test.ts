// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, COMPONENTS, KitError } from '@arkenivajs/core';
import type {
  ApplicationOptions,
  OperationOptions,
  SqlQueryOptions,
  SqlResult,
  SqlStatement,
  SqlTransaction,
} from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import {
  SQL_DRIVER_REGISTRY,
  SQL_SUPPORT_ID,
  sqlSupportPlugin,
} from '@arkenivajs/database/support';
import type {
  SqlConnectionAdapter,
  SqlDriverRegistry,
  RelationalDriver,
} from '@arkenivajs/database/support';

const service = { name: 'sql-routing-test', version: '1.0.0', environment: 'test' as const };
const statement = { text: 'SELECT :id', bindings: { id: 1 } };
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;
type Call = { name: string; method: string; options?: OperationOptions | SqlQueryOptions };

function adapter(name: string, calls: Call[]): SqlConnectionAdapter {
  const result = <T extends object>(): SqlResult<T> => ({
    rows: [{ connection: name } as unknown as T],
    rowCount: 1,
    metadata: {},
  });
  const implementation: SqlConnectionAdapter = {
    async query<T extends object>(
      _statement: SqlStatement,
      options?: SqlQueryOptions,
    ): Promise<SqlResult<T>> {
      calls.push({ name, method: 'query', ...(options ? { options } : {}) });
      return result<T>();
    },
    async queryOne<T extends object>(
      _statement: SqlStatement,
      options?: OperationOptions,
    ): Promise<T | null> {
      calls.push({ name, method: 'queryOne', ...(options ? { options } : {}) });
      return result<T>().rows[0]!;
    },
    async execute(_statement, options) {
      calls.push({ name, method: 'execute', ...(options ? { options } : {}) });
      return result();
    },
    async transaction<T>(
      handler: (tx: SqlTransaction) => Promise<T>,
      options?: OperationOptions,
    ): Promise<T> {
      calls.push({ name, method: 'begin', ...(options ? { options } : {}) });
      try {
        const value = await handler(implementation);
        calls.push({ name, method: 'commit' });
        return value;
      } catch (error) {
        calls.push({ name, method: 'rollback' });
        throw error;
      }
    },
    async ping(options) {
      calls.push({ name, method: 'ping', ...(options ? { options } : {}) });
      return true;
    },
    stats() {
      return Object.freeze({ active: 0, idle: 1, waiting: null });
    },
    native() {
      return this;
    },
  };
  return implementation;
}

function driver(
  identity: RelationalDriver,
  calls: Call[],
  onRegister?: (
    registry: SqlDriverRegistry,
    name: string,
    implementation: SqlConnectionAdapter,
  ) => void,
): ComposablePlugin {
  return {
    id: `database-${identity}`,
    version: '1.0.0',
    capabilities: new Set([`database.${identity}`]),
    dependencies: [SQL_SUPPORT_ID],
    [SUPPORT_PLUGINS]: [sqlSupportPlugin],
    init(context) {
      const registry = context.require<SqlDriverRegistry>(SQL_DRIVER_REGISTRY);
      for (const [name, definition] of Object.entries(context.options.databases ?? {})) {
        if (definition.driver !== identity) continue;
        const implementation = adapter(name, calls);
        if (onRegister) onRegister(registry, name, implementation);
        else registry.register(name, identity, implementation);
      }
    },
    close() {
      calls.push({ name: identity, method: 'close' });
    },
  };
}

test('EK-CORE-002 one isolated SQL facade routes multiple names and drivers without an extra application plugin', async () => {
  const calls: Call[] = [];
  const plugins = [driver('postgresql', calls), driver('mysql', calls)];
  const options: ApplicationOptions = {
    service,
    plugins,
    databases: {
      primary: { driver: 'postgresql' },
      archive: { driver: 'postgresql' },
      reporting: { driver: 'mysql' },
    },
  };
  const first = await createApplication(options);
  const second = await createApplication(options);
  assert.notEqual(first.sql, second.sql);
  const retained = first.sql;
  await assert.rejects(first.sql.query('primary', statement), code('EK_LIFECYCLE_STATE'));
  assert.equal(calls.length, 0);
  try {
    await first.start();
    await second.start();
    assert.ok(Object.isFrozen(first.sql));
    for (const name of ['primary', 'archive', 'reporting']) {
      assert.deepEqual((await first.sql.query(name, statement)).rows, [{ connection: name }]);
      assert.deepEqual(await first.sql.queryOne(name, statement), { connection: name });
      assert.equal((await first.sql.execute(name, statement)).rowCount, 1);
      assert.equal(await first.sql.ping(name), true);
      assert.deepEqual(first.sql.stats(name), { active: 0, idle: 1, waiting: null });
      assert.notEqual(first.sql.native(name), second.sql.native(name));
    }
    await first.stop();
    await assert.rejects(retained.execute('primary', statement), code('EK_LIFECYCLE_STATE'));
    assert.equal(await second.sql.ping('primary'), true);
  } finally {
    await first.stop();
    await second.stop();
  }
  assert.equal(calls.filter((call) => call.method === 'close').length, 4);
});

test('EK-DB-001 common routing validates names and bounded materialization before calling the selected adapter', async () => {
  const calls: Call[] = [];
  const app = await createApplication({
    service,
    plugins: [driver('postgresql', calls)],
    databases: { main: { driver: 'postgresql' } },
  });
  try {
    await app.start();
    for (const name of ['unknown', '__proto__', undefined]) {
      await assert.rejects(app.sql.query(name as string, statement), code('EK_CONFIG_INVALID'));
      assert.throws(() => app.sql.stats(name as string), code('EK_CONFIG_INVALID'));
    }
    for (const maxRows of [0, -1, 100001, 1.5, NaN, '2'])
      await assert.rejects(
        app.sql.query('main', statement, { maxRows: maxRows as number }),
        code('EK_CONFIG_INVALID'),
      );
    await assert.rejects(
      app.sql.query('main', statement, null as never),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(app.sql.transaction('main', null as never), code('EK_CONFIG_INVALID'));
    assert.equal(calls.length, 0);
    await app.sql.query('main', statement);
    assert.equal((calls.at(-1)!.options as SqlQueryOptions).maxRows, 10000);
    await app.sql.query('main', statement, { maxRows: 100000 });
    assert.equal((calls.at(-1)!.options as SqlQueryOptions).maxRows, 100000);
    const signal = new AbortController().signal;
    await app.sql.queryOne('main', statement, { signal, timeoutMs: 50 });
    assert.equal(calls.at(-1)!.method, 'queryOne');
    assert.deepEqual(calls.at(-1)!.options, { signal, timeoutMs: 50 });
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 transaction handles belong only to their active callback and pool reentry is rejected', async () => {
  const calls: Call[] = [];
  const app = await createApplication({
    service,
    plugins: [driver('postgresql', calls)],
    databases: { main: { driver: 'postgresql' } },
  });
  let captured!: SqlTransaction;
  try {
    await app.start();
    const answer = await app.sql.transaction('main', async (tx) => {
      captured = tx;
      assert.ok(Object.isFrozen(tx));
      await tx.query(statement);
      await tx.execute(statement);
      await assert.rejects(tx.query(statement, { maxRows: 0 }), code('EK_CONFIG_INVALID'));
      await assert.rejects(app.sql.query('main', statement), code('EK_DATABASE_TRANSACTION'));
      await assert.rejects(app.sql.queryOne('main', statement), code('EK_DATABASE_TRANSACTION'));
      await assert.rejects(app.sql.execute('main', statement), code('EK_DATABASE_TRANSACTION'));
      await assert.rejects(app.sql.ping('main'), code('EK_DATABASE_TRANSACTION'));
      await assert.rejects(
        app.sql.transaction('main', async () => undefined),
        code('EK_DATABASE_TRANSACTION'),
      );
      return 42;
    });
    assert.equal(answer, 42);
    assert.deepEqual(
      calls.map(({ method }) => method),
      ['begin', 'query', 'execute', 'commit'],
    );
    await assert.rejects(captured.query(statement), code('EK_DATABASE_TRANSACTION'));
    await assert.rejects(captured.execute(statement), code('EK_DATABASE_TRANSACTION'));
    const primary = new Error('callback failure');
    await assert.rejects(
      app.sql.transaction('main', async () => {
        throw primary;
      }),
      (error) => error === primary,
    );
    assert.equal(calls.at(-1)!.method, 'rollback');
  } finally {
    await app.stop();
  }
});

test('EK-CORE-002 simultaneous transactions cannot borrow handles across independent request contexts', async () => {
  const calls: Call[] = [];
  const app = await createApplication({
    service,
    plugins: [driver('postgresql', calls)],
    databases: { main: { driver: 'postgresql' } },
  });
  let publish!: () => void, release!: () => void, captured!: SqlTransaction;
  const ready = new Promise<void>((resolve) => {
    publish = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await app.start();
  const first = app.sql.transaction('main', async (tx) => {
    captured = tx;
    publish();
    await gate;
    await tx.query(statement);
    return 'first';
  });
  try {
    await ready;
    await assert.rejects(captured.query(statement), code('EK_DATABASE_TRANSACTION'));
    const second = await app.sql.transaction('main', async (tx) => {
      await assert.rejects(captured.execute(statement), code('EK_DATABASE_TRANSACTION'));
      await tx.execute(statement);
      return 'second';
    });
    assert.equal(second, 'second');
    release();
    assert.equal(await first, 'first');
  } finally {
    release();
    await first;
    await app.stop();
  }
});

test('EK-CORE-002 SQL registration matches root driver ownership and closes after activation', async () => {
  const calls: Call[] = [];
  let retained!: SqlDriverRegistry, implementation!: SqlConnectionAdapter;
  const plugin = driver('postgresql', calls, (registry, name, backend) => {
    retained = registry;
    implementation = backend;
    for (const [candidate, identity, value] of [
      ['unknown', 'postgresql', backend],
      ['main', 'mysql', backend],
      ['main', 'postgresql', {}],
    ] as const)
      assert.throws(
        () => registry.register(candidate, identity, value as SqlConnectionAdapter),
        code('EK_CONFIG_INVALID'),
      );
    registry.register(name, 'postgresql', backend);
    assert.throws(() => registry.register(name, 'postgresql', backend), code('EK_CONFIG_INVALID'));
  });
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: { main: { driver: 'postgresql' } },
  });
  try {
    await app.start();
    assert.ok(Object.isFrozen(retained));
    assert.ok(Object.isFrozen(retained.observation));
    assert.deepEqual(retained.observation, {});
    assert.throws(
      () => retained.register('main', 'postgresql', implementation),
      code('EK_LIFECYCLE_STATE'),
    );
    implementation.query = async () => {
      throw new Error('replaced method');
    };
    assert.equal((await app.sql.query('main', statement)).rowCount, 1);
    assert.equal(app.sql.native('main'), implementation);
  } finally {
    await app.stop();
  }
  assert.throws(
    () => retained.register('main', 'postgresql', implementation),
    code('EK_LIFECYCLE_STATE'),
  );
});

test('EK-CORE-001 missing SQL registration fails activation and rolls back every initialized driver', async () => {
  const calls: Call[] = [];
  const app = await createApplication({
    service,
    plugins: [driver('postgresql', calls, () => {})],
    databases: { main: { driver: 'postgresql' } },
  });
  await assert.rejects(app.start(), (error: unknown) => error instanceof KitError);
  assert.equal(app.state, 'CLOSED');
  assert.deepEqual(calls, [{ name: 'postgresql', method: 'close' }]);
});

test('EK-DB-004 SQL diagnostic ports are explicit dependencies and remain application-local', async () => {
  const calls: Call[] = [];
  const providers = [
    ['logger', COMPONENTS.logger],
    ['telemetry', COMPONENTS.telemetry],
    ['meter', COMPONENTS.meter],
  ] as const;
  const values = providers.map(() => Object.freeze({ testPort: true }));
  const plugins: ComposablePlugin[] = providers.map(([capability, key], index) => ({
    id: `port-${capability}`,
    version: '1.0.0',
    capabilities: new Set([capability]),
    init(context) {
      context.provide(key, values[index]);
    },
    close() {},
  }));
  let observed = false;
  plugins.unshift(
    driver('postgresql', calls, (registry, name, backend) => {
      observed = true;
      for (const [index, [capability]] of providers.entries())
        assert.equal(registry.observation[capability], values[index]);
      registry.register(name, 'postgresql', backend);
    }),
  );
  const app = await createApplication({
    service,
    plugins,
    databases: { main: { driver: 'postgresql' } },
  });
  try {
    await app.start();
    assert.equal(observed, true);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 a driver cannot transparently replay the transaction callback', async () => {
  const calls: Call[] = [];
  let invocations = 0;
  const plugin = driver('postgresql', calls, (registry, name, backend) => {
    backend.transaction = async (handler) => {
      await handler(backend);
      return handler(backend);
    };
    registry.register(name, 'postgresql', backend);
  });
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: { main: { driver: 'postgresql' } },
  });
  try {
    await app.start();
    await assert.rejects(
      app.sql.transaction('main', async () => {
        invocations++;
        return 1;
      }),
      code('EK_DATABASE_TRANSACTION'),
    );
    assert.equal(invocations, 1);
  } finally {
    await app.stop();
  }
});
