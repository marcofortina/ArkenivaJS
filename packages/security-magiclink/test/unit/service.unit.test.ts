// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import { fixture, application } from '../fixture.js';

test('Magic links use actual keyed verification, protected URL fragments and one-use state', async () => {
  const source = fixture(),
    { app, magic } = await application(source.settings);
  try {
    const issued = await magic.issue(source.owner, 'login'),
      url = new URL(issued.redemptionUrl);
    assert.equal(url.origin, 'https://identity.fixture.invalid');
    assert.equal(url.search, '');
    assert.equal(new URLSearchParams(url.hash.slice(1)).get('token'), issued.value);
    assert.ok(!JSON.stringify([...source.rows]).includes(issued.value));
    const result = await magic.consume(issued.value, { method: 'POST', purpose: 'login' });
    assert.equal(result.subject.subject, source.owner.subject);
    assert.equal(result.intent, 'login');
    assert.equal(Object.hasOwn(result, 'assurance'), false);
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_REPLAY',
    });
  } finally {
    await app.stop();
  }
});
test('Independent service instances atomically redeem one token exactly once', async () => {
  const source = fixture(),
    first = await application(source.settings),
    second = await application(source.settings);
  try {
    const issued = await first.magic.issue(source.owner, 'login');
    const result = await Promise.allSettled([
      first.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
      second.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
    ]);
    assert.equal(result.filter((value) => value.status === 'fulfilled').length, 1);
    assert.equal(result.filter((value) => value.status === 'rejected').length, 1);
  } finally {
    await Promise.all([first.app.stop(), second.app.stop()]);
  }
});
test('GET/prefetch, wrong purposes and malformed tokens cannot consume an issued credential', async () => {
  const source = fixture(),
    { app, magic } = await application(source.settings);
  try {
    const issued = await magic.issue(source.owner, 'email-verify'),
      before = source.state.hmacChecks;
    await assert.rejects(
      magic.consume(issued.value, { method: 'GET' as 'POST', purpose: 'email-verify' }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(source.state.hmacChecks, before);
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_INVALID',
    });
    await assert.rejects(
      magic.consume(issued.value.slice(0, -1) + '!', { method: 'POST', purpose: 'email-verify' }),
    );
    assert.equal(
      (await magic.consume(issued.value, { method: 'POST', purpose: 'email-verify' })).intent,
      'email-verify',
    );
  } finally {
    await app.stop();
  }
});
test('Revocation, disabled accounts and manually constructed subjects cannot grant identity', async () => {
  const source = fixture(),
    { app, magic } = await application(source.settings);
  try {
    await assert.rejects(magic.issue({ ...source.owner, subject: 'forged' }, 'login'), {
      code: 'EK_MAGICLINK_INVALID',
    });
    source.state.authenticated = false;
    await assert.rejects(magic.issue(source.owner, 'login'), { code: 'EK_MAGICLINK_INVALID' });
    source.state.authenticated = true;
    const issued = await magic.issue(source.owner, 'account-recover');
    await magic.revoke(issued.issueId);
    await magic.revoke(issued.issueId);
    await assert.rejects(
      magic.consume(issued.value, { method: 'POST', purpose: 'account-recover' }),
      { code: 'EK_MAGICLINK_REPLAY' },
    );
    const disabled = await magic.issue(source.owner, 'login');
    source.state.enabled = false;
    await assert.rejects(magic.consume(disabled.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_INVALID',
    });
  } finally {
    await app.stop();
  }
});
test('HMAC rotation preserves outstanding tokens and stable per-owner admission quotas', async () => {
  const source = fixture(),
    { app, magic } = await application({ ...source.settings, maxClaimsPerHour: 1 });
  try {
    const issued = await magic.issue(source.owner, 'login');
    source.rotateHmac();
    await assert.rejects(magic.issue(source.owner, 'login'), { code: 'EK_MAGICLINK_INVALID' });
    await magic.consume(issued.value, { method: 'POST', purpose: 'login' });
  } finally {
    await app.stop();
  }
});
test('Storage outages and production use of test-only providers fail closed', async () => {
  const source = fixture(),
    { app, magic } = await application(source.settings);
  try {
    const issued = await magic.issue(source.owner, 'login');
    source.state.fail = true;
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    source.state.fail = false;
    await magic.consume(issued.value, { method: 'POST', purpose: 'login' });
    const checks = source.state.hmacChecks;
    await assert.rejects(
      application(source.settings, 'production'),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_CONFIG_INVALID',
    );
    assert.equal(source.state.hmacChecks, checks);
  } finally {
    await app.stop();
  }
});

test('Expiry uses the trusted clock and retains a bounded replay record', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const source = fixture(),
    { app, magic } = await application({ ...source.settings, ttlMs: 1000 });
  try {
    const issued = await magic.issue(source.owner, 'login');
    t.mock.timers.tick(1001);
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_EXPIRED',
    });
    assert.ok([...source.rows.values()].some((row) => row.id === issued.issueId));
  } finally {
    await app.stop();
  }
});

test('Lost persistence acknowledgement never returns an identity or permits later reuse', async () => {
  const source = fixture();
  let loseAcknowledgement = false;
  const store = {
    ...source.store,
    async atomicBatch(...args: Parameters<typeof source.store.atomicBatch>) {
      const result = await source.store.atomicBatch(...args);
      if (loseAcknowledgement && result.committed)
        throw new Error('Private acknowledgement diagnostic');
      return result;
    },
  };
  const { app, magic } = await application({
    ...source.settings,
    stateStore: { ...source.settings.stateStore, store },
  });
  try {
    const issued = await magic.issue(source.owner, 'login');
    loseAcknowledgement = true;
    await assert.rejects(
      magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_BACKEND_UNAVAILABLE' &&
        !JSON.stringify(error.toSafeJSON()).includes('Private acknowledgement'),
    );
    loseAcknowledgement = false;
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_REPLAY',
    });
  } finally {
    await app.stop();
  }
});

test('Invalid durations, forged clocks, pre-aborts and accessors fail before provider I/O', async () => {
  const source = fixture(),
    { app, magic } = await application(source.settings);
  try {
    const issued = await magic.issue(source.owner, 'login'),
      checks = source.state.hmacChecks;
    for (const timeoutMs of [0, -1, 0.5, NaN, Infinity])
      await assert.rejects(
        magic.consume(issued.value, { method: 'POST', purpose: 'login' }, { timeoutMs }),
        { code: 'EK_CONFIG_INVALID' },
      );
    await assert.rejects(
      magic.consume(issued.value, { method: 'POST', purpose: 'login' }, {
        clock: () => 0,
      } as OperationOptions),
      { code: 'EK_CONFIG_INVALID' },
    );
    await assert.rejects(
      magic.consume(
        issued.value,
        { method: 'POST', purpose: 'login' },
        { signal: AbortSignal.abort() },
      ),
      { code: 'EK_ABORTED' },
    );
    let accesses = 0;
    const context = Object.defineProperty({ purpose: 'login' }, 'method', {
      enumerable: true,
      get() {
        accesses++;
        return 'POST';
      },
    });
    await assert.rejects(
      magic.consume(issued.value, context as { method: 'POST'; purpose: 'login' }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(accesses, 0);
    assert.equal(source.state.hmacChecks, checks);
    await app.stop();
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_RESOURCE_CLOSED',
    });
  } finally {
    await app.stop();
  }
});

test('Uncooperative HMAC providers retain all physical admission slots after public deadlines', async () => {
  const source = fixture();
  let blocked = false,
    entered = 0,
    release!: () => void,
    arrived!: () => void;
  const barrier = new Promise<void>((resolve) => {
      release = resolve;
    }),
    allArrived = new Promise<void>((resolve) => {
      arrived = resolve;
    });
  const hmac = {
    ...source.settings.hmac,
    async verify(...args: Parameters<typeof source.settings.hmac.verify>) {
      if (blocked) {
        if (++entered === 16) arrived();
        await barrier;
      }
      return source.settings.hmac.verify(...args);
    },
  };
  const { app, magic } = await application({ ...source.settings, hmac });
  try {
    const issued = await magic.issue(source.owner, 'login');
    blocked = true;
    const attempts = Array.from({ length: 16 }, () =>
      assert.rejects(
        magic.consume(issued.value, { method: 'POST', purpose: 'login' }, { timeoutMs: 100 }),
        { code: 'EK_TIMEOUT' },
      ),
    );
    await within(() => allArrived, { timeoutMs: 1000 });
    await Promise.all(attempts);
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'login' }), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    assert.equal(entered, 16);
    blocked = false;
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    await magic.consume(issued.value, { method: 'POST', purpose: 'login' });
  } finally {
    blocked = false;
    release();
    await app.stop();
  }
});
