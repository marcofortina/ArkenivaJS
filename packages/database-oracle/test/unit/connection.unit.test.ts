// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import oracledb from 'oracledb';
import { KitError } from '@arkenivajs/core';
import type { SqlTransaction, Telemetry, UsageMeter, MeterSession, Logger } from '@arkenivajs/core';
import { OracleConnection, oracleFetchType } from '../../dist/connection.js';
import { nativeDouble } from '../fixtures/native-double.js';

const statement = { text: 'SELECT :id AS "id" FROM DUAL', bindings: { id: 7 } };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const vendor = (value: string) =>
  Object.assign(new Error('Sensitive native SQL and credentials'), { code: value });
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test('EK-DB-001 Oracle named binds, alternative quotes, repeated identifiers and exact scalar conversion', async (context) => {
  const mock = await nativeDouble(context);
  const date = new Date('2026-10-25T01:30:00.123Z'),
    binary = new Uint8Array([1, 2]);
  mock.plans.push({
    rows: [{ exact: '900719925474099312345.67890', raw: Buffer.from([1, 2]), missing: null }],
  });
  const pending = mock.connection.query({
    text: "SELECT :id, :id, :date, :binary, :bool, :none, q'[:not]' /* :no */ FROM DUAL",
    bindings: { id: 900719925474099312345n, date, binary, bool: false, none: null },
  });
  date.setUTCFullYear(2000);
  binary[0] = 9;
  const result = await pending;
  assert.equal(result.rows[0]?.exact, '900719925474099312345.67890');
  assert.equal(result.rowCount, 1);
  const call = mock.submissions[0]!;
  assert.match(call.text, /:id, :id/);
  assert.deepEqual(
    { ...call.binds },
    {
      id: '900719925474099312345',
      date: '2026-10-25T01:30:00.123Z',
      binary: Buffer.from([1, 2]),
      bool: false,
      none: null,
    },
  );
  assert.equal(call.options.autoCommit, false);
  assert.equal(call.options.prefetchRows, 0);
  assert.equal(call.options.resultSet, true);
  assert.equal(mock.clients[0]!.callTimeout, 5000);
  assert.equal(mock.counts.cursorCloses, 1);
  assert.deepEqual(mock.releases, [false]);
  assert.equal(mock.connection.stats().waiting, null);
  assert.equal(mock.connection.stats().active, 0);
  await mock.connection.close();
  assert.equal(mock.counts.poolCloses, 1);
});

test('EK-DB-001 Oracle uses bounded cursors and rejects overflow without partial success or automatic commit', async (context) => {
  const mock = await nativeDouble(context);
  mock.plans.push({ rows: Array.from({ length: 700 }, (_, id) => ({ id })) });
  assert.equal(
    (await mock.connection.query({ text: 'SELECT 1 FROM DUAL' }, { maxRows: 700 })).rows.length,
    700,
  );
  assert.ok(mock.fetches.every((count) => count <= 256));
  for (const kind of ['query', 'queryOne'] as const) {
    mock.plans.push({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }] });
    const before = mock.counts.commits;
    await assert.rejects(
      kind === 'query'
        ? mock.connection.query(statement, { maxRows: 1 })
        : mock.connection.queryOne(statement),
      (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_DATABASE_QUERY');
        if (kind === 'query') assert.equal(error.details?.limitExceeded, true);
        return true;
      },
    );
    assert.equal(mock.counts.commits, before);
    assert.equal(mock.fetches.at(-1), 2);
  }
  mock.plans.push({ rows: [] }, { rows: [{ id: 7 }] });
  assert.equal(await mock.connection.queryOne(statement), null);
  assert.deepEqual(await mock.connection.queryOne(statement), { id: 7 });
  mock.plans.push({ count: 3 }, {}, { count: -1 });
  assert.deepEqual((await mock.connection.execute({ text: 'UPDATE items SET id = 1' })).metadata, {
    affectedRows: 3,
  });
  assert.equal(
    (await mock.connection.execute({ text: 'CREATE TABLE items (id NUMBER)' })).rowCount,
    null,
  );
  assert.equal((await mock.connection.execute({ text: 'UPDATE items SET id = 2' })).rowCount, null);
  await mock.connection.close();
});

test('EK-DB-001 Oracle precision and LOB conversion policy is explicit and independent of ambient SDK settings', () => {
  for (const dbType of [
    oracledb.DB_TYPE_NUMBER,
    oracledb.DB_TYPE_BINARY_DOUBLE,
    oracledb.DB_TYPE_BINARY_FLOAT,
  ]) {
    const result = oracleFetchType({ name: 'exact', dbType }, []);
    assert.equal(result?.type, oracledb.DB_TYPE_VARCHAR);
    assert.equal(result?.converter?.('123.456'), '123.456');
    assert.equal(result?.converter?.(null), null);
  }
  for (const dbType of [oracledb.DB_TYPE_RAW, oracledb.DB_TYPE_VARCHAR, oracledb.DB_TYPE_BOOLEAN])
    assert.equal(oracleFetchType({ name: 'plain', dbType }, [])?.type, dbType);
  for (const dbType of [
    oracledb.DB_TYPE_CLOB,
    oracledb.DB_TYPE_NCLOB,
    oracledb.DB_TYPE_BLOB,
    oracledb.DB_TYPE_BFILE,
    oracledb.DB_TYPE_OBJECT,
    oracledb.DB_TYPE_CURSOR,
    oracledb.DB_TYPE_JSON,
    oracledb.DB_TYPE_VECTOR,
    oracledb.DB_TYPE_XMLTYPE,
    oracledb.DB_TYPE_DATE,
    oracledb.DB_TYPE_TIMESTAMP,
    oracledb.DB_TYPE_TIMESTAMP_TZ,
    oracledb.DB_TYPE_TIMESTAMP_LTZ,
  ])
    assert.throws(
      () => oracleFetchType({ name: 'advanced', dbType }, []),
      code('EK_DATABASE_QUERY'),
    );
});

test('EK-DB-001 Oracle rejects LOB metadata before fetching and never returns locators after connection release', async (context) => {
  const mock = await nativeDouble(context);
  mock.plans.push({
    rows: [{ lob: { locator: true } }],
    types: [{ name: 'lob', dbType: oracledb.DB_TYPE_CLOB }],
  });
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  assert.deepEqual(mock.fetches, []);
  assert.deepEqual(mock.releases, [true]);
  await mock.connection.close();
});

test('EK-DB-001 Oracle validates SQL, options, row limits and portable control before acquisition', async (context) => {
  const mock = await nativeDouble(context);
  for (const text of [
    'BEGIN NULL; END;',
    '-- comment\n COMMIT',
    '/* comment */ ROLLBACK',
    'DECLARE x NUMBER;',
    'SAVEPOINT example',
    'SET TRANSACTION READ WRITE',
    'CALL procedure()',
  ])
    await assert.rejects(mock.connection.query({ text }), code('EK_DATABASE_TRANSACTION'));
  await assert.rejects(
    mock.connection.query({ text: 'SELECT :missing FROM DUAL' }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    mock.connection.query({ text: 'SELECT :Id, :id FROM DUAL', bindings: { Id: 1, id: 2 } }),
    code('EK_CONFIG_INVALID'),
  );
  for (const maxRows of [0, -1, 100001, 1.1, Infinity])
    await assert.rejects(mock.connection.query(statement, { maxRows }), code('EK_CONFIG_INVALID'));
  await assert.rejects(mock.connection.query(statement, null as never), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    mock.connection.query(statement, { timeoutMs: 0 }),
    code('EK_CONFIG_INVALID'),
  );
  const aborted = AbortSignal.abort('Caller stopped');
  await assert.rejects(mock.connection.query(statement, { signal: aborted }), code('EK_ABORTED'));
  await assert.rejects(mock.connection.transaction(null as never), code('EK_CONFIG_INVALID'));
  assert.equal(mock.counts.calls, 0);
  await mock.connection.close();
});

test('EK-DB-001 Oracle keeps transaction statements pinned, serial, copied and awaited before one commit', async (context) => {
  const mock = await nativeDouble(context);
  let tx!: SqlTransaction;
  const hold = deferred();
  mock.plans.push({ rows: [{ id: 1 }], hold: hold.promise }, { count: 1 });
  const binary = new Uint8Array([7]);
  const running = mock.connection.transaction(async (owned) => {
    tx = owned;
    const first = tx.query(statement),
      second = tx.execute({ text: 'UPDATE items SET bytes = :bytes', bindings: { bytes: binary } });
    binary[0] = 9;
    hold.resolve();
    await first;
    await second;
    return 'done';
  });
  assert.equal(await running, 'done');
  assert.equal(mock.counts.calls, 1);
  assert.equal(mock.counts.commits, 1);
  assert.deepEqual((mock.submissions[1]!.binds as Record<string, unknown>).bytes, Buffer.from([7]));
  assert.deepEqual(
    mock.controls.filter((text) => text.startsWith('SET TRANSACTION')),
    ['SET TRANSACTION READ WRITE'],
  );
  await assert.rejects(tx.query(statement), code('EK_DATABASE_TRANSACTION'));
  await mock.connection.close();
});

test('EK-DB-001 Oracle preserves primitive callback failures and aggregates rollback faults', async (context) => {
  const mock = await nativeDouble(context);
  await assert.rejects(
    mock.connection.transaction(async () => {
      throw null;
    }),
    (error: unknown) => error === null,
  );
  await assert.rejects(
    mock.connection.transaction(async () => {
      mock.faults.set('rollback', 'cleanup');
      throw 'primary';
    }),
    (error) => {
      assert.ok(error instanceof KitError);
      assert.ok(error.cause instanceof AggregateError);
      assert.deepEqual(error.cause.errors, ['primary', 'cleanup']);
      return true;
    },
  );
  mock.faults.delete('rollback');
  await mock.connection.close();
});

test('EK-DB-001 Oracle never commits a swallowed native statement failure or replays queued statements', async (context) => {
  const mock = await nativeDouble(context);
  mock.plans.push({ fails: true, error: vendor('ORA-00001') });
  await assert.rejects(
    mock.connection.transaction(async (tx) => {
      const first = tx.query(statement),
        second = tx.execute({ text: 'UPDATE items SET id = 2' });
      await assert.rejects(first, code('EK_DATABASE_CONSTRAINT'));
      await assert.rejects(second, code('EK_DATABASE_CONSTRAINT'));
    }),
    code('EK_DATABASE_CONSTRAINT'),
  );
  assert.equal(mock.submissions.length, 1);
  assert.equal(mock.counts.commits, 0);
  assert.equal(mock.counts.rollbacks, 2);
  await mock.connection.close();
});

test('EK-DB-001 Oracle reports observed implicit transaction end and unknown missing status', async (context) => {
  const mock = await nativeDouble(context);
  for (const transaction of [false, undefined]) {
    mock.plans.push({ count: 0, transaction });
    await assert.rejects(
      mock.connection.transaction(async (tx) =>
        tx.execute({ text: 'CREATE TABLE items (id NUMBER)' }),
      ),
      (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(
          error.details?.outcome,
          transaction === false ? 'implicitly_committed' : 'unknown',
        );
        return true;
      },
    );
  }
  assert.equal(mock.counts.commits, 0);
  await mock.connection.close();
});

test('EK-DB-001 Oracle reports unknown COMMIT outcome in standalone and callback operations without replay', async (context) => {
  const mock = await nativeDouble(context);
  mock.faults.set('commit', vendor('ORA-03113'));
  let callbacks = 0;
  for (const operation of [
    () => mock.connection.execute({ text: 'UPDATE items SET id = 2' }),
    () =>
      mock.connection.transaction(async (tx) => {
        callbacks++;
        await tx.execute({ text: 'UPDATE items SET id = 3' });
      }),
  ]) {
    await assert.rejects(operation(), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.details?.outcome, 'unknown');
      assert.equal(error.retryable, false);
      return true;
    });
  }
  assert.equal(callbacks, 1);
  assert.equal(mock.counts.commits, 2);
  assert.equal(mock.submissions.length, 2);
  await mock.connection.close();
});

test('EK-DB-001 Oracle bounded acquisition timeout releases late arrivals exactly once', async (context) => {
  const mock = await nativeDouble(context),
    gate = deferred();
  mock.gate(gate.promise);
  await assert.rejects(
    mock.connection.query(statement, { timeoutMs: 10 }),
    code('EK_DATABASE_POOL_TIMEOUT'),
  );
  gate.resolve();
  await setImmediate();
  await setImmediate();
  assert.deepEqual(mock.releases, [true]);
  assert.equal(mock.submissions.length, 0);
  await mock.connection.close();
});

test('EK-DB-001 Oracle cancellation during COMMIT retains an unknown outcome and observes late completion', async (context) => {
  const mock = await nativeDouble(context),
    gate = deferred(),
    abort = new AbortController();
  mock.faults.set('commitGate', gate.promise);
  const running = mock.connection.transaction(
    async (tx) => {
      await tx.query(statement);
      return 'committed';
    },
    { signal: abort.signal },
  );
  for (let attempt = 0; attempt < 1000 && mock.counts.commits === 0; attempt++)
    await setImmediate();
  assert.equal(mock.counts.commits, 1);
  abort.abort('Stopped during commit');
  gate.resolve();
  await assert.rejects(running, (error) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
    assert.equal(error.details?.outcome, 'unknown');
    assert.equal(error.retryable, false);
    return true;
  });
  assert.equal(mock.counts.commits, 1);
  assert.equal(mock.submissions.length, 1);
  assert.deepEqual(mock.releases, [true]);
  await mock.connection.close();
});

test('EK-DB-001 Oracle aborts queued acquisition and observes native errors', async (context) => {
  const mock = await nativeDouble(context),
    gate = deferred(),
    abort = new AbortController();
  mock.gate(gate.promise);
  const running = mock.connection.query(statement, { signal: abort.signal });
  await setImmediate();
  abort.abort('Stopped');
  await assert.rejects(running, code('EK_ABORTED'));
  gate.resolve();
  await setImmediate();
  mock.faults.set('acquire', vendor('NJS-040'));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_POOL_TIMEOUT'));
  await mock.connection.close();
});

test('EK-DB-001 Oracle cancels native execution, closes a late cursor and drops the session', async (context) => {
  const mock = await nativeDouble(context),
    hold = deferred(),
    abort = new AbortController();
  mock.plans.push({ rows: [{ id: 7 }], hold: hold.promise });
  const running = mock.connection.query(statement, { signal: abort.signal });
  await setImmediate();
  abort.abort('Stopped');
  hold.resolve();
  await assert.rejects(running, code('EK_ABORTED'));
  assert.equal(mock.counts.breaks, 1);
  assert.equal(mock.counts.cursorCloses, 1);
  assert.deepEqual(mock.releases, [true]);
  await mock.connection.close();
});

test('EK-DB-001 Oracle cancels the transaction when a queued statement deadline expires', async (context) => {
  const mock = await nativeDouble(context),
    hold = deferred();
  mock.plans.push({ rows: [], hold: hold.promise });
  const running = mock.connection.transaction(async (tx) => {
    const first = tx.query(statement),
      second = tx.query(statement, { timeoutMs: 10 });
    void first.catch(() => undefined);
    try {
      await second;
    } finally {
      hold.resolve();
    }
  });
  await assert.rejects(running, code('EK_TIMEOUT'));
  assert.equal(mock.counts.commits, 0);
  await mock.connection.close();
});

test('EK-DB-001 Oracle closes on drain, rejects stale methods and attempts shutdown once', async (context) => {
  const mock = await nativeDouble(context),
    hold = deferred();
  mock.plans.push({ rows: [], hold: hold.promise });
  const running = mock.connection.query(statement);
  void running.catch(() => undefined);
  await setImmediate();
  const closing = mock.connection.close();
  hold.resolve();
  assert.equal(mock.connection.close(), closing);
  await assert.rejects(running, code('EK_ABORTED'));
  await closing;
  assert.equal(mock.counts.poolCloses, 1);
  assert.throws(() => mock.connection.native(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => mock.connection.stats(), code('EK_RESOURCE_CLOSED'));
  await assert.rejects(mock.connection.query(statement), code('EK_RESOURCE_CLOSED'));
});

test('EK-DB-001 Oracle surfaces native fetch, cursor, connection and pool cleanup failures', async (context) => {
  const mock = await nativeDouble(context);
  mock.plans.push({ rows: [], fetchFails: true }, { rows: [], cursorCloseFails: true });
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  mock.faults.set('release', new Error('Release failed'));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  mock.faults.delete('release');
  mock.faults.set('poolClose', new Error('Pool close failed'));
  await assert.rejects(mock.connection.close(), code('EK_DATABASE_UNAVAILABLE'));
});

test('EK-DB-001 Oracle acquisition and initialization failures retain phase and release ownership', async (context) => {
  const mock = await nativeDouble(context);
  mock.faults.set('acquire', vendor('ORA-01017'));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_CONNECT'));
  mock.faults.delete('acquire');
  mock.faults.set('rollback', new Error('Reset failed'));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  mock.faults.delete('rollback');
  mock.faults.set('SET TRANSACTION READ WRITE', new Error('Begin failed'));
  await assert.rejects(
    mock.connection.transaction(async () => 1),
    code('EK_DATABASE_QUERY'),
  );
  await mock.connection.close();
});

test('EK-DB-004 Oracle reports observed latency with correct units and isolates diagnostic faults', async (context) => {
  const histograms: { name: string; value: number }[] = [],
    usage: { name: string; value: number; unit: string }[] = [],
    missing: string[] = [],
    operations: string[] = [];
  const session = {
    recordOperation(name: string) {
      operations.push(name);
    },
    recordUsage(name: string, value: { value: number; unit: string }) {
      usage.push({ name, ...value });
    },
  } as unknown as MeterSession;
  const meter = {
    current: () => session,
    markMissing(_session: MeterSession, reason: string) {
      missing.push(reason);
    },
  } as unknown as UsageMeter;
  const telemetry = {
    withSpan: async (_name: string, callback: () => Promise<unknown>) => callback(),
    recordHistogram(name: string, value: number) {
      histograms.push({ name, value });
    },
  } as unknown as Telemetry;
  const mock = await nativeDouble(context, { meter, telemetry });
  assert.equal(await mock.connection.ping(), true);
  assert.deepEqual(operations, ['db.query']);
  assert.ok(missing.includes('driver_bytes_unavailable'));
  const elapsed = histograms.find((row) => row.name === 'db.client.operation.duration')!.value;
  assert.equal(usage[0]!.unit, 'milliseconds');
  assert.equal(elapsed, usage[0]!.value / 1000);
  mock.connection.native();
  assert.ok(missing.includes('not_instrumented'));
  await mock.connection.close();
});

test('EK-DB-004 Oracle diagnostic errors cannot replay or replace business outcomes', async (context) => {
  const session = {
    recordOperation() {
      throw new Error('Meter failed');
    },
    recordUsage() {
      throw new Error('Usage failed');
    },
  } as unknown as MeterSession;
  const telemetry = {
    withSpan() {
      throw new Error('Span failed');
    },
    recordHistogram() {
      throw new Error('Histogram failed');
    },
  } as unknown as Telemetry;
  const logger = {
    warn() {
      throw new Error('Logger failed');
    },
  } as unknown as Logger;
  const mock = await nativeDouble(context, {
    meter: { current: () => session } as unknown as UsageMeter,
    telemetry,
    logger,
  });
  await mock.connection.query(statement);
  mock.plans.push({ fails: true, error: vendor('ORA-00001') });
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_CONSTRAINT'));
  assert.equal(mock.submissions.length, 2);
  assert.ok(mock.connection.stats().observerFailures! > 0);
  await mock.connection.close();
});

test('EK-DB-001 Oracle ping distinguishes normal unavailability, unhealthy rows and structural errors', async (context) => {
  const mock = await nativeDouble(context);
  mock.plans.push({ rows: [] });
  assert.equal(await mock.connection.ping(), false);
  for (const value of ['ORA-03113', 'NJS-040']) {
    mock.faults.set('acquire', vendor(value));
    assert.equal(await mock.connection.ping(), false);
  }
  mock.faults.set('acquire', vendor('ORA-01017'));
  await assert.rejects(mock.connection.ping(), code('EK_DATABASE_CONNECT'));
  mock.faults.delete('acquire');
  mock.plans.push({ fails: true, error: vendor('ORA-03113') });
  assert.equal(await mock.connection.ping(), false);
  await mock.connection.close();
});

test('EK-DB-001 Oracle pool creation respects cancellation and closes late pools', async (context) => {
  const gate = deferred();
  let closed = 0;
  context.mock.method(oracledb, 'createPool', async () => {
    await gate.promise;
    return {
      poolMax: 1,
      async close() {
        closed++;
      },
    };
  });
  await assert.rejects(
    OracleConnection.create('test', {}, {}, 'thin', { timeoutMs: 10 }),
    code('EK_TIMEOUT'),
  );
  gate.resolve();
  await setImmediate();
  assert.equal(closed, 1);
  context.mock.method(oracledb, 'createPool', async () => {
    throw vendor('ORA-01017');
  });
  await assert.rejects(
    OracleConnection.create('test', {}, {}, 'thin'),
    code('EK_DATABASE_CONNECT'),
  );
  await assert.rejects(
    OracleConnection.create('test', {}, {}, 'thin', { signal: AbortSignal.abort() }),
    code('EK_ABORTED'),
  );
});

test('EK-DB-001 Oracle process-wide mode conflicts fail even while a Thin pool is starting', async (context) => {
  const gate = deferred();
  let initialized = 0;
  context.mock.method(oracledb, 'initOracleClient', () => {
    initialized++;
  });
  context.mock.method(oracledb, 'createPool', async () => {
    await gate.promise;
    return { poolMax: 1, async close() {} };
  });
  const starting = OracleConnection.create('pending', {}, {}, 'thin');
  await assert.rejects(
    OracleConnection.create('conflict', {}, {}, 'thick'),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(initialized, 0);
  gate.resolve();
  await (await starting).close();
  context.mock.getter(oracledb, 'thin', () => false);
  await assert.rejects(
    OracleConnection.create('external-conflict', {}, {}, 'thin'),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-DB-001 Oracle bounds waiting acquisitions and queued callback statements', async (context) => {
  const mock = await nativeDouble(context),
    gate = deferred();
  mock.gate(gate.promise);
  const waiting = Array.from({ length: 128 }, () => mock.connection.query(statement));
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_POOL_TIMEOUT'));
  assert.equal(mock.counts.calls, 128);
  gate.resolve();
  await Promise.all(waiting);
  const hold = deferred();
  mock.plans.push({ rows: [], hold: hold.promise });
  await mock.connection.transaction(async (tx) => {
    const pending = Array.from({ length: 128 }, () => tx.query(statement));
    await assert.rejects(tx.query(statement), code('EK_DATABASE_TRANSACTION'));
    hold.resolve();
    await Promise.all(pending);
  });
  await mock.connection.close();
});

test('EK-DB-001 Oracle unknown COMMIT outcome survives concurrent connection cleanup failures', async (context) => {
  const mock = await nativeDouble(context);
  mock.faults.set('commit', vendor('ORA-03113'));
  mock.faults.set('release', new Error('Close failed'));
  for (const run of [
    () => mock.connection.query(statement),
    () => mock.connection.transaction(async (tx) => tx.query(statement)),
  ])
    await assert.rejects(run(), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
      assert.equal(error.details?.outcome, 'unknown');
      assert.ok(error.cause instanceof AggregateError);
      return true;
    });
  await assert.rejects(mock.connection.close(), code('EK_DATABASE_UNAVAILABLE'));
});

test('EK-DB-001 Oracle handles timeout setter faults and broken cancellation cleanup without leaking ownership', async (context) => {
  const mock = await nativeDouble(context);
  mock.faults.set('callTimeout', 'Call timeout setter failed');
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  assert.deepEqual(mock.releases, [true]);
  mock.faults.set('release', 'Release failed');
  await assert.rejects(
    mock.connection.query(statement),
    (error) => error instanceof KitError && error.cause instanceof AggregateError,
  );
  mock.faults.delete('callTimeout');
  mock.faults.delete('release');
  mock.faults.set('break', 'Break failed');
  mock.plans.push({ fails: true, error: vendor('ORA-00001') });
  await assert.rejects(mock.connection.query(statement), code('EK_DATABASE_QUERY'));
  await assert.rejects(mock.connection.close(), code('EK_DATABASE_UNAVAILABLE'));
});

test('EK-DB-001 Oracle retains late acquisition disposal failures for shutdown', async (context) => {
  const mock = await nativeDouble(context),
    gate = deferred();
  mock.gate(gate.promise);
  mock.faults.set('release', 'Late release failed');
  await assert.rejects(
    mock.connection.query(statement, { timeoutMs: 10 }),
    code('EK_DATABASE_POOL_TIMEOUT'),
  );
  gate.resolve();
  await setImmediate();
  assert.equal(mock.connection.stats().pendingAcquires, 0);
  assert.ok(mock.connection.stats().cleanupFailures! > 0);
  await assert.rejects(mock.connection.close(), code('EK_DATABASE_UNAVAILABLE'));
});
