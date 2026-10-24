import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as pause } from 'node:timers/promises';
import { setMaxListeners } from 'node:events';
import { KitError } from '@arkenivajs/core';
import type { MeterSession, Telemetry, UsageMeter, SqlTransaction } from '@arkenivajs/core';
import { nativeDouble } from '../fixtures/native-double.js';

const sql = { text: 'SELECT :id', bindings: { id: 7n } };
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;
const modeQuery =
  'SELECT @@session.sql_mode AS mode, @@session.character_set_client AS encoding, @@session.time_zone AS zone';

test('EK-DB-001 MySQL bounded native streams preserve counts, exact metadata and binary parameters', async () => {
  const fixture = nativeDouble();
  try {
    fixture.plans.push(
      { rows: [] },
      { rows: [{ id: '1' }] },
      { header: { affectedRows: 0, insertId: 0 } },
      { header: { affectedRows: 2, insertId: '9007199254740993', warningStatus: 1 } },
      { header: { affectedRows: '9007199254740993', insertId: -1 } },
    );
    assert.equal(await fixture.connection.queryOne(sql), null);
    assert.deepEqual(await fixture.connection.queryOne(sql), { id: '1' });
    assert.deepEqual(await fixture.connection.execute(sql), {
      rows: [],
      rowCount: 0,
      metadata: { affectedRows: 0, insertId: 0 },
    });
    assert.deepEqual((await fixture.connection.execute(sql)).metadata, {
      affectedRows: 2,
      insertId: '9007199254740993',
    });
    assert.deepEqual(await fixture.connection.execute(sql), {
      rows: [],
      rowCount: null,
      metadata: {},
    });
    assert.deepEqual(fixture.submissions[0], { text: 'SELECT ?', values: ['7'] });
    fixture.plans.push({ rows: [{ value: 1 }] });
    await fixture.connection.query({
      text: 'SELECT :bytes',
      bindings: { bytes: new Uint8Array([0, 255]) },
    });
    assert.deepEqual(fixture.submissions.at(-1)?.values, [Buffer.from([0, 255])]);
    assert.ok(fixture.releases.every((discard) => !discard));
  } finally {
    await fixture.connection.close();
  }
  await assert.rejects(fixture.connection.query(sql), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => fixture.connection.stats(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => fixture.connection.native(), code('EK_RESOURCE_CLOSED'));
  await fixture.connection.close();
});

test('EK-DB-001 MySQL rejects excess rows and multiple results before any partial success', async () => {
  const fixture = nativeDouble();
  try {
    fixture.plans.push({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }] });
    await assert.rejects(fixture.connection.queryOne(sql), code('EK_DATABASE_QUERY'));
    fixture.plans.push({ rows: [{ id: 1 }, { id: 2 }] });
    await assert.rejects(
      fixture.connection.query(sql, { maxRows: 1 }),
      (error: unknown) =>
        code('EK_DATABASE_QUERY')(error) && (error as KitError).details?.limitExceeded === true,
    );
    fixture.plans.push({ multiple: true, rows: [{ id: 1 }] });
    await assert.rejects(fixture.connection.execute(sql), code('EK_DATABASE_QUERY'));
    assert.deepEqual(fixture.releases, [true, true, true]);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-DB-001 invalid MySQL inputs and portable transaction control reject before native acquisition', async () => {
  const fixture = nativeDouble();
  try {
    await assert.rejects(
      fixture.connection.query({ text: 'SELECT :missing' }),
      code('EK_CONFIG_INVALID'),
    );
    for (const input of [null, [], { maxRows: 0 }, { timeoutMs: -1 }])
      await assert.rejects(
        fixture.connection.query(sql, input as never),
        code('EK_CONFIG_INVALID'),
      );
    await assert.rejects(fixture.connection.transaction(null as never), code('EK_CONFIG_INVALID'));
    for (const text of [
      ' BEGIN',
      '-- line\n COMMIT',
      '# line\n ROLLBACK',
      '/* body */ SAVEPOINT a',
      'START TRANSACTION',
      'RELEASE SAVEPOINT a',
      'XA START id',
      'PREPARE a FROM x',
      'EXECUTE a',
      'DEALLOCATE PREPARE a',
      'CALL test()',
    ])
      await assert.rejects(fixture.connection.execute({ text }), code('EK_DATABASE_TRANSACTION'));
    assert.equal(fixture.clients.length, 0);
    fixture.plans.push({ rows: [{ value: '1' }] });
    assert.equal((await fixture.connection.query({ text: '(SELECT 1)' })).rowCount, 1);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-CORE-001 MySQL owns abandoned acquisitions, active cancellation and every late release', async () => {
  const fixture = nativeDouble();
  let release!: () => void;
  fixture.gate(
    new Promise((resolve) => {
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
    await fixture.connection.close();
  }
});

test('EK-DB-001 native MySQL failure and primitive lease cleanup errors retain both causes', async () => {
  for (const cleanup of [undefined, false, 0, '']) {
    const fixture = nativeDouble();
    const primary = Object.assign(new Error('Native failure'), { errno: 1062 });
    fixture.failRelease(cleanup);
    fixture.plans.push({ error: primary });
    try {
      await assert.rejects(fixture.connection.execute(sql), (error: unknown) => {
        assert.ok(error instanceof KitError);
        assert.ok(error.cause instanceof AggregateError);
        const inner = error.cause.errors[0] as KitError;
        assert.ok(inner.cause instanceof AggregateError);
        assert.equal(inner.cause.errors[0], primary);
        assert.equal(inner.cause.errors[1], cleanup);
        assert.equal(error.cause.errors[1], cleanup);
        return true;
      });
      assert.deepEqual(fixture.releases, [true]);
    } finally {
      await fixture.connection.close();
    }
  }
});

test('EK-DB-001 a successful MySQL write with failed release is rejected without replaying it', async () => {
  const fixture = nativeDouble();
  fixture.failRelease(false);
  try {
    await assert.rejects(
      fixture.connection.execute(sql),
      (error: unknown) =>
        error instanceof KitError && error.code === 'EK_DATABASE_QUERY' && error.cause === false,
    );
    assert.equal(fixture.submissions.length, 1);
  } finally {
    await fixture.connection.close();
  }
});

test('EK-DB-001 MySQL reset failures discard the lease and ping distinguishes transport from configuration failures', async () => {
  const fixture = nativeDouble();
  try {
    fixture.failures.set('RESET', new Error('Reset failed'));
    await assert.rejects(fixture.connection.query(sql), code('EK_DATABASE_QUERY'));
    assert.deepEqual(fixture.releases, [true]);
  } finally {
    await fixture.connection.close();
  }
  for (const [error, unhealthy] of [
    [Object.assign(new Error('Unavailable'), { code: 'ECONNREFUSED' }), true],
    [new Error('No connections available.'), true],
    [new Error('Invalid credentials'), false],
  ] as const) {
    const next = nativeDouble();
    next.failAcquisition(error);
    try {
      if (unhealthy) assert.equal(await next.connection.ping(), false);
      else await assert.rejects(next.connection.ping(), code('EK_DATABASE_CONNECT'));
    } finally {
      await next.connection.close();
    }
  }
  const next = nativeDouble();
  next.plans.push({
    error: Object.assign(new Error('Socket lost'), { code: 'PROTOCOL_CONNECTION_LOST' }),
  });
  try {
    assert.equal(await next.connection.ping(), false);
  } finally {
    await next.connection.close();
  }
});

test('EK-DB-001 MySQL transactions serialize statements, capture modes and reject stale handles', async () => {
  const fixture = nativeDouble();
  let stale: SqlTransaction | undefined;
  try {
    const result = await fixture.connection.transaction(async (tx) => {
      stale = tx;
      fixture.plans.push(
        { rows: [] },
        { mode: 'NO_BACKSLASH_ESCAPES,ANSI_QUOTES', rows: [] },
        { rows: [{ value: 'a\\' }] },
      );
      const results = await Promise.all([
        tx.execute(sql),
        tx.execute({ text: "SET sql_mode='NO_BACKSLASH_ESCAPES,ANSI_QUOTES'" }),
        tx.query({ text: "SELECT 'a\\' AS value" }),
      ]);
      assert.equal(results[2]?.rows[0]?.value, 'a\\');
      return 42;
    });
    assert.equal(result, 42);
    assert.ok(fixture.controls.includes('START TRANSACTION'));
    assert.ok(fixture.controls.includes('COMMIT'));
    await assert.rejects(stale!.query(sql), code('EK_DATABASE_TRANSACTION'));
    for (const [property, value] of [
      ['encoding', 'latin1'],
      ['zone', '+05:00'],
    ] as const) {
      fixture.plans.push({ [property]: value, rows: [] });
      await assert.rejects(
        fixture.connection.transaction(async (tx) => {
          await tx.execute(sql);
          await tx.query(sql);
        }),
        code('EK_CONFIG_INVALID'),
      );
    }
  } finally {
    await fixture.connection.close();
  }
});

test('EK-DB-001 MySQL preserves primitive callback errors, failed rollback and unknown COMMIT outcomes', async () => {
  for (const failure of [undefined, false, 0, '']) {
    const fixture = nativeDouble();
    try {
      await assert.rejects(
        fixture.connection.transaction(async () => {
          throw failure;
        }),
        (error) => error === failure,
      );
      assert.ok(fixture.controls.includes('ROLLBACK'));
      const rollback = new Error('Rollback failed');
      fixture.failures.set('ROLLBACK', rollback);
      await assert.rejects(
        fixture.connection.transaction(async () => {
          throw failure;
        }),
        (error: unknown) =>
          error instanceof KitError &&
          error.cause instanceof AggregateError &&
          error.cause.errors[0] === failure &&
          error.cause.errors[1] === rollback,
      );
    } finally {
      await fixture.connection.close();
    }
  }
  for (const control of ['START TRANSACTION', 'COMMIT', modeQuery]) {
    const fixture = nativeDouble();
    fixture.failures.set(control, new Error('Native control failed'));
    let calls = 0;
    try {
      await assert.rejects(
        fixture.connection.transaction(async (tx) => {
          calls++;
          await tx.execute(sql);
        }),
        (error: unknown) => {
          assert.ok(error instanceof KitError);
          if (control === 'COMMIT') {
            assert.equal(error.code, 'EK_DATABASE_TRANSACTION');
            assert.deepEqual(error.details, { outcome: 'unknown' });
            assert.equal(error.retryable, false);
          } else assert.equal(error.code, 'EK_DATABASE_QUERY');
          return true;
        },
      );
      assert.equal(calls, control === 'START TRANSACTION' ? 0 : 1);
    } finally {
      await fixture.connection.close();
    }
  }
});

test('EK-CORE-001 cancelled MySQL transaction statements cannot commit even when their caller catches the rejection', async () => {
  for (const already of [false, true]) {
    const fixture = nativeDouble();
    const controller = new AbortController();
    if (already) controller.abort();
    try {
      await assert.rejects(
        fixture.connection.transaction(async (tx) => {
          fixture.plans.push({ hold: true });
          const running = tx.query(sql, { signal: controller.signal });
          if (!already) {
            await pause(1);
            controller.abort();
          }
          await assert.rejects(running, code('EK_ABORTED'));
        }),
        code('EK_ABORTED'),
      );
      assert.ok(!fixture.controls.includes('COMMIT'));
      assert.equal(fixture.releases.length, 1);
    } finally {
      await fixture.connection.close();
    }
  }
});

test('EK-CORE-001 MySQL bounds outstanding acquisitions and owns pending work through shutdown', async () => {
  const fixture = nativeDouble();
  let release!: () => void;
  fixture.gate(
    new Promise((resolve) => {
      release = resolve;
    }),
  );
  const waiting = Array.from({ length: 128 }, () => fixture.connection.query(sql));
  const settled = Promise.allSettled(waiting);
  await assert.rejects(fixture.connection.query(sql), code('EK_DATABASE_POOL_TIMEOUT'));
  const closing = fixture.connection.close();
  release();
  await closing;
  assert.ok((await settled).every((result) => result.status === 'rejected'));
  assert.equal(fixture.releases.length, 128);
  assert.equal(fixture.submissions.length, 0);
});

test('EK-CORE-001 MySQL bounds pending callback statements and observes native connection errors', async () => {
  const fixture = nativeDouble();
  const controller = new AbortController();
  setMaxListeners(0, controller.signal);
  try {
    await assert.rejects(
      fixture.connection.transaction(
        async (tx) => {
          fixture.plans.push({ hold: true });
          const waiting = Array.from({ length: 128 }, () => tx.query(sql));
          const settled = Promise.allSettled(waiting);
          await assert.rejects(tx.query(sql), code('EK_DATABASE_TRANSACTION'));
          controller.abort();
          await settled;
        },
        { signal: controller.signal },
      ),
      code('EK_ABORTED'),
    );
  } finally {
    await fixture.connection.close();
  }
  const next = nativeDouble();
  next.plans.push({ hold: true });
  try {
    const work = next.connection.query(sql);
    await pause(1);
    next.clients[0]!.emit(
      'error',
      Object.assign(new Error('Broken connection'), { code: 'ECONNRESET' }),
    );
    await assert.rejects(work, code('EK_DATABASE_UNAVAILABLE'));
  } finally {
    await next.connection.close();
  }
});

test('EK-DB-004 MySQL diagnostics observe once, use finite labels and cannot replay native writes', async () => {
  const recorded: unknown[] = [],
    operations: string[] = [],
    usage: unknown[] = [],
    gaps: string[] = [];
  const session = {
    recordOperation(name: string) {
      operations.push(name);
    },
    recordUsage(name: string, value: unknown) {
      usage.push({ name, value });
    },
  } as MeterSession;
  const meter = {
    current: () => session,
    markMissing: (_session: unknown, reason: string) => gaps.push(reason),
  } as unknown as UsageMeter;
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      const value = await work();
      throw new Error('Span export failed after work: ' + String(value));
    },
    recordHistogram(name: string, value: number, labels: unknown) {
      recorded.push({ name, value, labels });
    },
  } as unknown as Telemetry;
  const fixture = nativeDouble({ meter, telemetry });
  try {
    fixture.plans.push({ rows: [{ id: '7' }] });
    assert.equal((await fixture.connection.query(sql)).rows.length, 1);
    fixture.connection.native();
    assert.deepEqual(operations, ['db.query']);
    assert.equal(usage.length, 1);
    assert.ok(gaps.includes('driver_bytes_unavailable'));
    assert.ok(gaps.includes('not_instrumented'));
    assert.equal(fixture.submissions.length, 1);
    assert.equal(fixture.connection.stats().observerFailures, 1);
    assert.ok(recorded.every((record) => !JSON.stringify(record).includes('SELECT')));
  } finally {
    await fixture.connection.close();
  }
  const broken = nativeDouble({
    meter: { current: () => session } as unknown as UsageMeter,
    telemetry: {
      async withSpan() {
        throw new Error('Before callback');
      },
      recordHistogram() {
        throw new Error('Metric unavailable');
      },
    } as unknown as Telemetry,
  });
  try {
    await broken.connection.execute(sql);
    assert.equal(broken.submissions.length, 1);
    assert.ok(broken.connection.stats().observerFailures! >= 3);
  } finally {
    await broken.connection.close();
  }
});

test('EK-DB-001 MySQL transaction release and native pool shutdown failures remain visible', async () => {
  const fixture = nativeDouble();
  fixture.failRelease(0);
  try {
    await assert.rejects(
      fixture.connection.transaction(async () => 1),
      (error: unknown) =>
        error instanceof KitError && error.code === 'EK_DATABASE_TRANSACTION' && error.cause === 0,
    );
  } finally {
    await fixture.connection.close();
  }
  const next = nativeDouble();
  const primary = new Error('Native shutdown failed');
  next.failEnd(primary);
  for (let attempt = 0; attempt < 2; attempt++)
    await assert.rejects(
      next.connection.close(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_UNAVAILABLE' &&
        error.cause instanceof AggregateError &&
        error.cause.errors.includes(primary),
    );
});

test('EK-CORE-001 MySQL shutdown reports failed active cancellation instead of silently losing cleanup errors', async () => {
  const fixture = nativeDouble();
  fixture.plans.push({ hold: true });
  const work = fixture.connection.query(sql);
  const observed = assert.rejects(work, code('EK_DATABASE_QUERY'));
  await pause(1);
  fixture.failRelease(false);
  await assert.rejects(
    fixture.connection.close(),
    (error: unknown) =>
      error instanceof KitError &&
      error.code === 'EK_DATABASE_UNAVAILABLE' &&
      error.cause instanceof AggregateError &&
      error.cause.errors.includes(false),
  );
  await observed;
});

test('EK-DB-001 malformed MySQL session evidence fails closed before another queued statement', async () => {
  for (const value of [null, [], [{ mode: false, encoding: 'utf8mb4', zone: '+00:00' }]]) {
    const fixture = nativeDouble();
    fixture.sessionResult(value);
    try {
      await assert.rejects(
        fixture.connection.transaction(async (tx) => {
          await tx.execute(sql);
        }),
        code('EK_DATABASE_QUERY'),
      );
      assert.ok(!fixture.controls.includes('COMMIT'));
    } finally {
      await fixture.connection.close();
    }
  }
});
