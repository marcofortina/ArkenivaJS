import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createApi } from '@arkenivajs/api';
import type { HealthRegistry } from '@arkenivajs/core';

const service = { name: 'http-health-test', version: '1.0.0', environment: 'test' as const };

test('HTTP readiness uses dependency evidence, hides internals and recovers while liveness stays local', async () => {
  let state = 'ready',
    accepting = true,
    calls = 0;
  const api = createApi({
    service,
    port: 0,
    isReady: () => accepting,
    health: {
      live: () => {
        throw new Error('External liveness must not run');
      },
      async ready() {
        calls++;
        if (state === 'error') throw new Error('private-backend-credential');
        return state === 'ready'
          ? { status: 'ready', failing: [] }
          : { status: 'not_ready', failing: ['private-dependency'] };
      },
    },
  });
  await api.start();
  try {
    for (const stateValue of ['ready', 'offline', 'error', 'ready']) {
      state = stateValue;
      const response = await fetch(api.address() + '/readyz');
      assert.equal(response.status, state === 'ready' ? 200 : 503);
      assert.deepEqual(await response.json(), {
        status: state === 'ready' ? 'ready' : 'not_ready',
      });
      const live = await fetch(api.address() + '/livez');
      assert.equal(live.status, 200);
      assert.deepEqual(await live.json(), { status: 'live' });
    }
    accepting = false;
    const response = await fetch(api.address() + '/readyz');
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { status: 'not_ready' });
    assert.equal(calls, 4);
  } finally {
    await api.close();
  }
});

test('HTTP health bounds uncooperative work, shares concurrent probes and rechecks lifecycle after awaiting evidence', async () => {
  let calls = 0,
    accepting = true,
    release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const api = createApi({
    service,
    port: 0,
    readinessTimeoutMs: 20,
    isReady: () => accepting,
    health: {
      live: () => ({ status: 'live' }),
      async ready() {
        calls++;
        await gate;
        return { status: 'ready', failing: [] };
      },
    },
  });
  await api.start();
  try {
    const first = await Promise.all(
      Array.from({ length: 20 }, () => api.native().inject('/readyz')),
    );
    assert.ok(
      first.every(
        (response) => response.statusCode === 503 && response.json().status === 'not_ready',
      ),
    );
    assert.equal(calls, 1);
    assert.equal((await api.native().inject('/readyz')).statusCode, 503);
    assert.equal(calls, 1);
    const waiting = api.native().inject('/readyz');
    await delay(0);
    accepting = false;
    release();
    assert.equal((await waiting).statusCode, 503);
    accepting = true;
    assert.equal((await api.native().inject('/readyz')).statusCode, 200);
    assert.equal(calls, 2);
  } finally {
    release();
    await api.close();
  }
});

test('HTTP readiness rejects malformed evidence and invalid policy without weakening the public response', async () => {
  for (const policy of [
    { readinessTimeoutMs: 0 },
    { readinessTimeoutMs: 10_001 },
    { readinessTimeoutMs: NaN },
    { health: {} },
    { health: null },
  ])
    assert.throws(() => createApi({ service, ...policy } as never), { code: 'EK_CONFIG_INVALID' });
  for (const result of [
    null,
    { status: 'ready' },
    { status: 'ready', failing: ['private-dependency'] },
    { status: 'invalid', failing: [] },
  ]) {
    const api = createApi({
      service,
      port: 0,
      health: { live: () => ({ status: 'live' }), ready: async () => result } as HealthRegistry,
    });
    await api.start();
    try {
      const response = await api.native().inject('/readyz');
      assert.equal(response.statusCode, 503);
      assert.deepEqual(response.json(), { status: 'not_ready' });
    } finally {
      await api.close();
    }
  }
});
