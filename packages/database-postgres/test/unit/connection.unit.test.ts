import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as pause } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { MeterSession, Telemetry, UsageMeter, SqlTransaction } from '@arkenivajs/core';
import { nativeDouble } from '../fixtures/native-double.js';

const sql = { text: 'SELECT :id', bindings: { id: 7 } };
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;

test('EK-DB-001 PostgreSQL cursor bounds, empty results and affected rows use actual native metadata', async () => {
  const fixture = nativeDouble();
  try {
    fixture.plans.push({ rows: [{ id: 1 }, { id: 2 }], count: 2 });
    const result = await fixture.connection.query(sql, { maxRows: 2 });
    assert.equal(result.rowCount, 2);
    assert.deepEqual(result.metadata, {});
    assert.deepEqual(fixture.reads, [3]);
    assert.equal(fixture.submissions[0]!.text, 'SELECT $1');
    assert.deepEqual(fixture.submissions[0]!.values, ['7']);
    fixture.plans.push({ rows: [], count: 0 });
    assert.equal(await fixture.connection.queryOne(sql), null);
    fixture.plans.push({ rows: [{ id: 1 }] });
    assert.deepEqual(await fixture.connection.queryOne(sql), { id: 1 });
    fixture.plans.push({ rows: [{ id: 1 }, { id: 2 }] });
    await assert.rejects(fixture.connection.queryOne(sql), code('EK_DATABASE_QUERY'));
    assert.deepEqual(fixture.reads.slice(1), [2, 2, 2]);
    fixture.plans.push({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }] });
    await assert.rejects(
      fixture.connection.query(sql, { maxRows: 2 }),
      (error: unknown) =>
        code('EK_DATABASE_QUERY')(error) && (error as KitError).details?.limitExceeded === true,
    );
    fixture.plans.push({ rows: [], command: 'UPDATE', count: 4 });
    assert.deepEqual((await fixture.connection.execute(sql)).metadata, { affectedRows: 4 });
    fixture.plans.push({ rows: [], count: null });
    assert.equal((await fixture.connection.query(sql)).rowCount, null);
    fixture.plans.push({ rows: Array.from({ length: 300 }, (_, id) => ({ id })), count: 44 });
    const multiBatch = await fixture.connection.query(sql, { maxRows: 300 });
    assert.equal(multiBatch.rows.length, 300);
    assert.equal(multiBatch.rowCount, null);
    assert.equal(fixture.releases.length, 8);
    assert.ok(fixture.releases.every((discard) => !discard));
  } finally {
    await fixture.connection.close();
  }
  await assert.rejects(fixture.connection.query(sql), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => fixture.connection.stats(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => fixture.connection.native(), code('EK_RESOURCE_CLOSED'));
});

test('EK-DB-001 invalid binds, options and manual transaction control fail before native acquisition', async () => {
  const fixture = nativeDouble();
  try {
    await assert.rejects(
      fixture.connection.query({ text: 'SELECT :missing' }),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(fixture.connection.query(sql, { maxRows: 0 }), code('EK_CONFIG_INVALID'));
    await assert.rejects(fixture.connection.execute(sql, null as never), code('EK_CONFIG_INVALID'));
    for (const text of [
      'BEGIN',
      '-- comment\n COMMIT',
      '/* outer /* inner */ body */ ROLLBACK',
      'SAVEPOINT example',
      'PREPARE item AS SELECT 1',
    ])
      await assert.rejects(fixture.connection.execute({ text }), code('EK_DATABASE_TRANSACTION'));
    await assert.rejects(fixture.connection.transaction(null as never), code('EK_CONFIG_INVALID'));
    assert.equal(fixture.clients.length, 0);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-DB-001 PostgreSQL native query and primitive cursor cleanup failures retain their causes', async () => {
  for (const cleanup of [undefined, false, 0, '']) {
    const fixture = nativeDouble();
    const primary = Object.assign(new Error('native constraint'), { code: '23505' });
    try {
      fixture.plans.push({ fail: true, error: primary, closeFails: true, closeError: cleanup });
      await assert.rejects(fixture.connection.query(sql), (error: unknown) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_DATABASE_QUERY');
        assert.ok(error.cause instanceof AggregateError);
        assert.equal((error.cause.errors[0] as KitError).cause, primary);
        assert.equal(error.cause.errors[1], cleanup);
        return true;
      });
      assert.deepEqual(fixture.releases, [true]);
    } finally {
      await fixture.connection.close();
    }
  }
});

test('EK-CORE-001 cancelled pool waiters release late leases and cancelled cursors discard exactly once', async () => {
  const fixture = nativeDouble();
  let release!: () => void;
  fixture.gate(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  const controller = new AbortController();
  try {
    const waiting = fixture.connection.query(sql, { signal: controller.signal });
    controller.abort();
    await assert.rejects(waiting, code('EK_ABORTED'));
    release();
    await pause(1);
    assert.deepEqual(fixture.releases, [true]);
    assert.equal(fixture.submissions.length, 0);
    fixture.plans.push({ hold: true });
    await assert.rejects(fixture.connection.query(sql, { timeoutMs: 5 }), code('EK_TIMEOUT'));
    assert.deepEqual(fixture.releases, [true, true]);
  } finally {
    release();
    await fixture.connection.close();
  }
});

test('EK-DB-001 transactions preserve callback outcomes, serialize statements and reject stale handles', async () => {
  const fixture = nativeDouble();
  let retained!: SqlTransaction;
  try {
    fixture.plans.push({ rows: [{ one: 1 }] }, { rows: [{ two: 2 }] });
    const answer = await fixture.connection.transaction(async (tx) => {
      retained = tx;
      const [first, second] = await Promise.all([tx.query(sql), tx.execute(sql)]);
      assert.equal(first.rows.length, 1);
      assert.equal(second.rows.length, 1);
      return 42;
    });
    assert.equal(answer, 42);
    assert.equal(fixture.clients.length, 1);
    assert.equal(fixture.controls.filter((text) => text === 'BEGIN').length, 1);
    assert.equal(fixture.controls.filter((text) => text === 'COMMIT').length, 1);
    await assert.rejects(retained.query(sql), code('EK_DATABASE_TRANSACTION'));
    for (const primary of [new Error('callback failure'), undefined, false, 0, ''])
      await assert.rejects(
        fixture.connection.transaction(async () => {
          throw primary;
        }),
        (error) => error === primary,
      );
    assert.equal(fixture.controls.filter((text) => text === 'ROLLBACK').length, 5);
    assert.equal(fixture.releases.length, 6);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-DB-001 rollback, release and unknown commit failures never replay a callback', async () => {
  for (const stage of ['rollback', 'release', 'commit', 'rolled-back'] as const) {
    const fixture = nativeDouble();
    const primary = new Error('application failure');
    let called = 0;
    if (stage === 'rollback') fixture.cleanupErrors.set('ROLLBACK', false);
    if (stage === 'release') fixture.failRelease(false);
    if (stage === 'commit')
      fixture.cleanupErrors.set(
        'COMMIT',
        Object.assign(new Error('connection lost'), { code: 'ECONNRESET' }),
      );
    if (stage === 'rolled-back') fixture.commitAs('ROLLBACK');
    try {
      await assert.rejects(
        fixture.connection.transaction(async () => {
          called++;
          if (stage === 'rollback' || stage === 'release') throw primary;
          return 42;
        }),
        (error: unknown) => {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
          if (stage === 'rollback' || stage === 'release') {
            assert.ok(error.cause instanceof AggregateError);
            assert.equal(error.cause.errors[0], primary);
            assert.equal(error.cause.errors[1], false);
          } else
            assert.equal(error.details?.outcome, stage === 'commit' ? 'unknown' : 'rolled_back');
          return true;
        },
      );
      assert.equal(called, 1);
      assert.equal(fixture.releases.length, 1);
    } finally {
      await fixture.connection.close();
    }
  }
});

test('EK-DB-004 diagnostic failures never replay native writes and observed usage remains independent of tracing', async () => {
  const quantities: unknown[] = [],
    gaps: string[] = [];
  let operations = 0;
  const session: MeterSession = {
    operationId: 'unit-scope',
    recordOperation() {
      operations++;
    },
    recordUsage(_name, value) {
      quantities.push(value);
    },
    recordError() {},
    end() {
      return { eventId: 'unit-event', accepted: true };
    },
  };
  const meter = {
    current: () => session,
    markMissing: (_session: MeterSession, reason: string) => gaps.push(reason),
  } as unknown as UsageMeter;
  const telemetry = {
    async withSpan<T>(_name: string, work: () => Promise<T>) {
      await work();
      throw new Error('closed diagnostics');
    },
    recordHistogram() {},
    setGauge() {},
  } as unknown as Telemetry;
  const fixture = nativeDouble({ meter, telemetry });
  try {
    gaps.length = 0;
    fixture.plans.push({ rows: [], command: 'INSERT', count: 1 });
    assert.equal((await fixture.connection.execute(sql)).metadata.affectedRows, 1);
    assert.equal(fixture.submissions.length, 1);
    assert.equal(operations, 1);
    assert.deepEqual(gaps, ['driver_bytes_unavailable']);
    assert.equal(quantities.length, 1);
    assert.ok(fixture.connection.stats().observerFailures! > 0);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-CORE-001 cancellation reports a failed native release without an uncaught abort-listener exception', async () => {
  const fixture = nativeDouble();
  fixture.plans.push({ hold: true });
  fixture.failRelease(false);
  try {
    await assert.rejects(fixture.connection.query(sql, { timeoutMs: 5 }), (error: unknown) => {
      assert.ok(error instanceof KitError);
      assert.ok(error.cause instanceof AggregateError);
      assert.equal((error.cause.errors[0] as KitError).code, 'EK_TIMEOUT');
      assert.equal(error.cause.errors[1], false);
      return true;
    });
    assert.deepEqual(fixture.releases, [true]);
  } finally {
    await fixture.connection.close();
  }
});
