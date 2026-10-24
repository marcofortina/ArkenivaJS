import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as pause } from 'node:timers/promises';
import { getEventListeners } from 'node:events';
import { KitError, DEFAULT_SQL_TIMEOUT_MS } from '@arkenivajs/core';
import { SqlDeadline } from '../../dist/deadline.js';

const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;

test('EK-DB-001 an omitted SQL deadline schedules the documented fifteen-second default', (context) => {
  const scheduled = context.mock.method(globalThis, 'setTimeout');
  const deadline = new SqlDeadline();
  try {
    assert.equal(scheduled.mock.calls.length, 1);
    const delay = scheduled.mock.calls[0]!.arguments[1];
    assert.ok(
      typeof delay === 'number' &&
        delay > DEFAULT_SQL_TIMEOUT_MS - 1000 &&
        delay <= DEFAULT_SQL_TIMEOUT_MS,
    );
  } finally {
    deadline.close();
  }
});

test('EK-CORE-001 SQL deadlines preserve values and errors while closing listener bookkeeping', async () => {
  const controller = new AbortController();
  const lifetime = new AbortController();
  const deadline = new SqlDeadline({ signal: controller.signal }, lifetime.signal);
  try {
    assert.equal(await deadline.run(() => 42), 42);
    const primary = new Error('primary query failure');
    await assert.rejects(
      deadline.run(() => {
        throw primary;
      }),
      (error) => error === primary,
    );
    assert.equal(getEventListeners(deadline.signal, 'abort').length, 0);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
    assert.equal(getEventListeners(lifetime.signal, 'abort').length, 1);
  } finally {
    deadline.close();
    deadline.close();
  }
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal(getEventListeners(lifetime.signal, 'abort').length, 0);
});

test('EK-CORE-001 cancelled SQL work is invoked at most once and late settlement remains observed', async () => {
  for (const failLate of [false, true]) {
    const controller = new AbortController();
    const deadline = new SqlDeadline({ signal: controller.signal });
    let invoked = 0;
    try {
      const running = deadline.run(async () => {
        invoked++;
        await pause(10);
        if (failLate) throw new Error('late native failure');
        return 1;
      });
      await pause(1);
      controller.abort();
      await assert.rejects(running, code('EK_ABORTED'));
      await pause(15);
      assert.equal(invoked, 1);
      await assert.rejects(
        deadline.run(() => {
          invoked++;
          return 2;
        }),
        code('EK_ABORTED'),
      );
      assert.equal(invoked, 1);
    } finally {
      deadline.close();
    }
  }
});

test('EK-CORE-001 SQL deadlines distinguish timeout, caller cancellation and an already closed pool', async () => {
  for (const input of [null, [], { timeoutMs: 0 }, { timeoutMs: 1.5 }, { signal: {} }])
    assert.throws(() => new SqlDeadline(input as never), code('EK_CONFIG_INVALID'));
  const expired = new SqlDeadline({ timeoutMs: 2 });
  try {
    await assert.rejects(
      expired.run(() => pause(20)),
      code('EK_TIMEOUT'),
    );
  } finally {
    expired.close();
  }
  const stopped = new AbortController();
  stopped.abort();
  for (const deadline of [
    new SqlDeadline({ signal: stopped.signal }),
    new SqlDeadline({}, stopped.signal),
  ]) {
    try {
      assert.throws(() => deadline.check(), code('EK_ABORTED'));
    } finally {
      deadline.close();
    }
  }
  const long = new SqlDeadline({ timeoutMs: 2_147_483_648 });
  try {
    assert.equal(await long.run(() => 1), 1);
  } finally {
    long.close();
  }
});
