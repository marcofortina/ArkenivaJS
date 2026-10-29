// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import type { OperationOptions } from '@arkenivajs/core';
import { FederationRuntime } from '../../dist/runtime.js';

test('Federation public timeout retains late provider capacity until physical settlement', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 100 });
  let release!: () => void;
  const late = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    const first = runtime.run((call) =>
      call.step(async () => {
        await late;
        return 'late-result';
      }),
    );
    await assert.rejects(first, { code: 'EK_TIMEOUT' });
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(() => runtime.run(async () => 'not-admitted'), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    release();
    for (let index = 0; index < 100 && runtime.stats().active; index++) await setImmediate();
    assert.equal(runtime.stats().active, 0);
    assert.equal(await runtime.run(async () => 'fresh'), 'fresh');
  } finally {
    release();
    await runtime.close();
  }
});
test('Explicitly tracked native cleanup retains a finished scope and shutdown waits for it', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 1000 });
  let release!: () => void;
  const native = new Promise<void>((resolve) => {
    release = resolve;
  });
  assert.equal(
    await runtime.run(async (call) => {
      call.track(native);
      return 'observed';
    }),
    'observed',
  );
  assert.equal(runtime.stats().active, 1);
  const closed = runtime.close();
  await assert.rejects(() => runtime.run(async () => 'closed'), { code: 'EK_RESOURCE_CLOSED' });
  assert.equal(runtime.stats().active, 1);
  release();
  await closed;
  assert.equal(runtime.stats().active, 0);
  await runtime.close();
});
test('Readiness and operation options cannot be bypassed by manually constructed objects', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 1000 }, () => false);
  let effects = 0;
  await assert.rejects(
    () =>
      runtime.run(async () => {
        effects++;
      }),
    { code: 'EK_LIFECYCLE_STATE' },
  );
  await assert.rejects(
    () =>
      runtime.run(
        async () => {
          effects++;
        },
        { bootstrap: true } as OperationOptions,
      ),
    { code: 'EK_EID_PROFILE' },
  );
  await assert.rejects(
    () =>
      runtime.run(
        async () => {
          effects++;
        },
        {
          get timeoutMs(): number {
            effects++;
            throw new Error('Executable options');
          },
        },
      ),
    { code: 'EK_EID_PROFILE' },
  );
  assert.equal(effects, 0);
  assert.equal(await runtime.run(async () => 'bootstrap', undefined, true), 'bootstrap');
  await runtime.close();
});
test('Shutdown aborts public work but retains an ignoring provider until it actually returns', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 1000 });
  let release!: () => void, entered!: () => void;
  const late = new Promise<void>((resolve) => {
    release = resolve;
  });
  const began = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const work = runtime.run((call) =>
    call.step(async () => {
      entered();
      await late;
    }),
  );
  await began;
  const denied = assert.rejects(work, { code: 'EK_ABORTED' }),
    closed = runtime.close();
  await denied;
  assert.equal(runtime.stats().active, 1);
  release();
  await closed;
  assert.equal(runtime.stats().active, 0);
});
