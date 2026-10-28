// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type {
  SqlProvider,
  SqlResult,
  SqlStatement,
  SqlTransaction,
  SqlQueryOptions,
  OperationOptions,
} from '@arkenivajs/core';
import { tenantRegistrySqlProvider, type TenantRegistrySqlOptions } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';

function row(generation: unknown = '1', revision = 'blue', changed = false) {
  const content = {
    schemaVersion: '1.1.0' as const,
    operations: [],
    bindings: [],
    implementations: changed
      ? [{ id: 'installed', kind: 'handler' as const, handlerKey: 'local' }]
      : [],
  };
  return {
    activation_generation: generation,
    revision_key: revision,
    activated_at: new Date('2026-01-01T00:00:00.000Z'),
    content_checksum: registryContentChecksum(content),
    body: JSON.stringify(content),
  };
}
const safe = { code: 'EK_TROUTE_REGISTRY', message: 'Invalid tenant routing registry' };
function fixture() {
  const state = {
    rows: [row()] as unknown,
    statements: [] as SqlStatement[],
    names: [] as string[],
    checkpointCalls: 0,
    failCommit: false,
  };
  const unused = async (): Promise<never> => {
    throw new Error('Unexpected independent pool operation');
  };
  const sql: SqlProvider = {
    query: unused,
    queryOne: unused,
    execute: unused,
    ping: unused,
    stats: () => {
      throw new Error('Unexpected stats access');
    },
    native: () => {
      throw new Error('Unexpected native access');
    },
    async transaction<T>(
      name: string,
      work: (tx: SqlTransaction) => Promise<T>,
      options?: OperationOptions,
    ): Promise<T> {
      state.names.push(name);
      assert.ok(options?.signal);
      assert.ok(options?.timeoutMs);
      const value = await work({
        execute: unused,
        async query<T extends object>(statement: SqlStatement, operation?: SqlQueryOptions) {
          assert.equal(operation?.maxRows, 2);
          assert.equal(operation?.signal, options?.signal);
          state.statements.push(statement);
          return { rows: state.rows, rowCount: null, metadata: {} } as SqlResult<T>;
        },
      });
      if (state.failCommit) throw new Error('Private commit failure');
      return value;
    },
  };
  const options: TenantRegistrySqlOptions = {
    sql,
    connectionName: 'control',
    storageKey: 'owned',
    storagePrefixes: { owned: 'control.tenant_registry' },
    activationCheckpoint: {
      accept: async () => {
        state.checkpointCalls++;
      },
    },
  };
  return { state, sql, options };
}

test('SQL provider captures an explicit identifier allowlist and uses exactly the injected named transaction', async () => {
  const { state, options } = fixture(),
    catalog = { owned: 'control.tenant_registry' };
  const provider = tenantRegistrySqlProvider({ ...options, storagePrefixes: catalog });
  catalog.owned = 'attacker.chosen';
  const snapshot = await provider.loadSnapshot();
  assert.equal(snapshot.revision, 'blue');
  assert.equal(snapshot.activationGeneration, 1);
  assert.ok(Object.isFrozen(snapshot));
  assert.deepEqual(state.names, ['control']);
  assert.equal(state.statements.length, 1);
  const statement = state.statements[0]!;
  assert.match(
    statement.text,
    /FROM control\.tenant_registry_active a JOIN control\.tenant_registry_snapshot s/,
  );
  assert.match(statement.text, /CASE WHEN OCTET_LENGTH\(s\.body\)/);
  assert.deepEqual(statement.bindings, { registry_key: 'active', max_bytes: 8388608 });
  assert.equal(state.checkpointCalls, 1);
});

test('SQL configuration rejects unknown keys, executable catalogs, SQL injection and incomplete providers', () => {
  const { options } = fixture();
  let effects = 0;
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        effects++;
        return [];
      },
    },
  );
  const getter = Object.defineProperty({}, 'owned', {
    enumerable: true,
    get() {
      effects++;
      return 'private';
    },
  });
  for (const patch of [
    { connectionName: 'missing.connection' },
    { connectionName: '' },
    { sql: {} },
    { sql: undefined },
    { storageKey: 'unknown' },
    { storageKey: 'owned; DROP TABLE data' },
    { storagePrefixes: { owned: 'x; DROP TABLE data' } },
    { storagePrefixes: { owned: 'x.y.z' } },
    { storagePrefixes: proxy },
    { storagePrefixes: getter },
    { storagePrefixes: { owned: undefined } },
    { storagePrefixes: { 'Bad-Key': 'safe' } },
    { storagePrefixes: { owned: 'UPPER' } },
    { unexpected: true },
  ])
    assert.throws(
      () => tenantRegistrySqlProvider({ ...options, ...patch } as TenantRegistrySqlOptions),
      safe,
    );
  assert.equal(effects, 0);
  assert.ok(
    tenantRegistrySqlProvider({
      sql: options.sql,
      connectionName: 'control',
      storageKey: 'tenant_registry',
    }),
  );
});

test('Absent, split and duplicate active rows fail closed without consulting another connection', async () => {
  for (const rows of [[], [row(), row()], null, {}, new Array(1)]) {
    const { state, options } = fixture();
    state.rows = rows;
    await assert.rejects(tenantRegistrySqlProvider(options).loadSnapshot(), safe);
    assert.deepEqual(state.names, ['control']);
    assert.equal(state.checkpointCalls, 0);
  }
});

test('SQL content preserves duplicate-key detection and rejects truncated, tampered or already parsed bodies', async () => {
  for (const patch of [
    {
      body: '{"schemaVersion":"1.1.0","schemaVersion":"1.1.0","operations":[],"implementations":[],"bindings":[]}',
    },
    { body: null },
    { body: {} },
    { body: '{' },
    { body: '{"private":"secret"}' },
    { content_checksum: 'sha256:' + '0'.repeat(64) },
    { content_checksum: 'unexpected' },
    { revision_key: '' },
    { activated_at: 'invalid' },
    { activated_at: new Date(NaN) },
  ]) {
    const { state, options } = fixture();
    state.rows = [{ ...row(), ...patch }];
    await assert.rejects(tenantRegistrySqlProvider(options).loadSnapshot(), safe);
    assert.equal(state.checkpointCalls, 0);
  }
});

test('BIGINT generations retain exact safe integers and reject coercion and loss of precision', async () => {
  for (const generation of [
    1,
    1n,
    '1',
    Number.MAX_SAFE_INTEGER,
    BigInt(Number.MAX_SAFE_INTEGER),
    String(Number.MAX_SAFE_INTEGER),
  ]) {
    const { state, options } = fixture();
    state.rows = [row(generation)];
    assert.equal(
      (await tenantRegistrySqlProvider(options).loadSnapshot()).activationGeneration,
      Number(generation),
    );
  }
  for (const generation of [
    0,
    -1,
    0n,
    -1n,
    1.5,
    '01',
    '1e3',
    '1.5',
    '0',
    '9007199254740992',
    9007199254740992n,
    NaN,
    Infinity,
    {},
    true,
  ]) {
    const { state, options } = fixture();
    state.rows = [row(generation)];
    await assert.rejects(tenantRegistrySqlProvider(options).loadSnapshot(), safe);
  }
});

test('Read-transaction commit errors cannot advance the external activation checkpoint', async () => {
  const { state, options } = fixture();
  state.failCommit = true;
  const provider = tenantRegistrySqlProvider(options);
  await assert.rejects(provider.loadSnapshot(), safe);
  assert.equal(state.checkpointCalls, 0);
  state.failCommit = false;
  assert.equal((await provider.loadSnapshot()).revision, 'blue');
});

test('Native UTC timestamp text retains submillisecond precision and rejects ambiguous or normalized dates', async () => {
  for (const input of [
    '2026-01-01 00:00:00.123456+00',
    '2026-01-01T00:00:00.123456Z',
    '2026-01-01 00:00:00.123456+00:00',
  ]) {
    const { state, options } = fixture();
    state.rows = [{ ...row(), activated_at: input }];
    assert.equal(
      (await tenantRegistrySqlProvider(options).loadSnapshot()).activatedAt,
      '2026-01-01T00:00:00.123456Z',
    );
  }
  for (const input of [
    '2026-02-30 00:00:00+00',
    '2026-01-01 24:00:00+00',
    '2026-01-01 00:00:00',
    '2026-01-01T00:00:00-00:00',
    '2026-01-01T01:00:00+01:00',
  ]) {
    const { state, options } = fixture();
    state.rows = [{ ...row(), activated_at: input }];
    await assert.rejects(tenantRegistrySqlProvider(options).loadSnapshot(), safe);
  }
});

test('SQL activation keeps old snapshots immutable, detects conflicting identity and permits controlled rollback', async () => {
  const { state, options } = fixture(),
    provider = tenantRegistrySqlProvider(options),
    original = await provider.loadSnapshot();
  for (const candidate of [
    row('2', 'blue', true),
    row('1', 'green', true),
    { ...row(), activated_at: new Date('2026-01-02T00:00:00.000Z') },
  ]) {
    state.rows = [candidate];
    await assert.rejects(provider.loadSnapshot(), safe);
  }
  state.rows = [row('2', 'green', true)];
  assert.equal((await provider.loadSnapshot()).revision, 'green');
  state.rows = [row()];
  await assert.rejects(provider.loadSnapshot(), safe);
  state.rows = [row('3', 'blue')];
  assert.equal((await provider.loadSnapshot()).activationGeneration, 3);
  assert.equal(original.activationGeneration, 1);
  assert.equal(original.implementations.length, 0);
});

test('Invalid deadlines and cancelled loads perform no transaction or checkpoint call', async () => {
  const { state, options } = fixture(),
    provider = tenantRegistrySqlProvider(options),
    controller = new AbortController();
  controller.abort();
  for (const operation of [
    { timeoutMs: 0 },
    { timeoutMs: -1 },
    { timeoutMs: 1.1 },
    { signal: controller.signal },
  ])
    await assert.rejects(provider.loadSnapshot(operation), safe);
  assert.equal(state.names.length, 0);
  assert.equal(state.checkpointCalls, 0);
});
