// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as pause } from 'node:timers/promises';
import { getEventListeners } from 'node:events';
import { KitError, DEFAULT_SQL_TIMEOUT_MS } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { SqlDeadline } from '@arkenivajs/database/support';

const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;

test('SQL deadlines retain owned cancellation cleanup after request and lifetime hook replacement', async () => {
  const request = new AbortController(),
    lifetime = new AbortController();
  const deadline = new SqlDeadline({ signal: request.signal }, lifetime.signal);
  let effects = 0;
  for (const signal of [request.signal, lifetime.signal])
    Object.defineProperty(signal, 'removeEventListener', {
      value() {
        effects++;
      },
    });
  try {
    assert.equal(await deadline.run(() => 42), 42);
  } finally {
    deadline.close();
  }
  assert.equal(effects, 0);
});

test('SQL deadlines reject executable options and forged lifetime signals before attaching listeners', () => {
  let effects = 0;
  const signal = new AbortController().signal;
  const trap = () => {
    effects++;
    throw new Error('Deadline control traps must not execute');
  };
  const inputs: OperationOptions[] = [
    Object.defineProperty({}, 'signal', {
      get() {
        effects++;
        return signal;
      },
    }),
    Object.defineProperty({}, 'timeoutMs', {
      get() {
        effects++;
        return 1000;
      },
    }),
    new Proxy({}, { getPrototypeOf: trap, get: trap, ownKeys: trap }),
    { signal: new Proxy(signal, { getPrototypeOf: trap, get: trap }) },
  ];
  const deep = new AbortController().signal;
  let prototype: object = AbortSignal.prototype;
  for (let depth = 0; depth < 65; depth++) prototype = Object.create(prototype) as object;
  Object.setPrototypeOf(deep, prototype);
  inputs.push({ signal: deep });
  for (const input of inputs) {
    let deadline: SqlDeadline | undefined;
    try {
      assert.throws(() => {
        deadline = new SqlDeadline(input);
      }, code('EK_CONFIG_INVALID'));
    } finally {
      deadline?.close();
    }
  }
  for (const lifetime of [
    {
      aborted: false,
      addEventListener() {
        effects++;
      },
      removeEventListener() {
        effects++;
      },
    },
    new Proxy(signal, { getPrototypeOf: trap, get: trap }),
  ]) {
    let deadline: SqlDeadline | undefined;
    try {
      assert.throws(() => {
        deadline = new SqlDeadline({ signal }, lifetime as AbortSignal);
      }, code('EK_CONFIG_INVALID'));
    } finally {
      deadline?.close();
    }
  }
  assert.equal(effects, 0);
  assert.equal(getEventListeners(signal, 'abort').length, 0);
});

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
    // Native composition does not attach caller-visible JavaScript lifecycle hooks.
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal(getEventListeners(lifetime.signal, 'abort').length, 0);
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
