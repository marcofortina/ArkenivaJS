// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixtureSettings, application } from './fixture.js';
import type { SessionAuthentication } from '../../dist/index.js';

const storeFailure = { code: 'EK_SESSION_STORE' };

test('Session durable record discriminators, ownership and timestamp corruption fail before refreshed identity', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    const entry = JSON.stringify(['sessions.records.v1', issued.sessionId]),
      original = f.rows.get(entry)!;
    for (const change of [
      { kind: 'unexpected-record' },
      { id: randomUUID() },
      { ownerKey: 'g'.repeat(64) },
      { identity: { ...(original.identity as object), subject: randomUUID() } },
      { authenticatedAt: new Date(Date.parse(String(original.createdAt)) + 1000).toISOString() },
      { lastSeenAt: new Date(Date.parse(String(original.createdAt)) - 1000).toISOString() },
      {
        absoluteExpiresAt: new Date(
          Date.parse(String(original.absoluteExpiresAt)) + 1000,
        ).toISOString(),
      },
      { epoch: -1 },
    ]) {
      f.rows.set(entry, { ...original, ...change });
      await assert.rejects(sessions.validate(issued.value), storeFailure);
      f.rows.set(entry, original);
      assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
    }
  } finally {
    await app.stop();
  }
});

test('Session malformed storage acknowledgments cannot create a credential or count as rate admission', async () => {
  for (const receipt of [undefined, {}, { committed: 'true' }, { committed: true, version: '' }]) {
    const f = fixtureSettings();
    f.store.compareAndSet = async () => receipt as never;
    const { app, sessions } = await application(f.settings);
    try {
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), storeFailure);
      assert.equal([...f.rows.values()].filter((row) => row.kind === 'session-v1').length, 0);
    } finally {
      await app.stop();
    }
  }
});

test('Session durable owner guard and counter corruption cannot authorize renewal or creation', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    await sessions.validate(issued.value);
    const guard = [...f.rows.entries()].find(([, row]) => row.kind === 'session-owner-v1')!;
    for (const patch of [
      { kind: 'wrong-guard' },
      { ownerKey: '0'.repeat(64) },
      { nonce: 'invalid' },
    ]) {
      f.rows.set(guard[0], { ...guard[1], ...patch });
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), storeFailure);
      f.rows.set(guard[0], guard[1]);
    }
    const rate = [...f.rows.entries()].find(([key]) => JSON.parse(key)[1].startsWith('verify-'))!;
    for (const patch of [
      { kind: 'wrong-counter' },
      { ownerKey: '0'.repeat(64) },
      { minute: -1 },
      { count: 0 },
      { count: 10001 },
      { expiresAt: new Date(Date.now() + 600000).toISOString() },
    ]) {
      f.rows.set(rate[0], { ...rate[1], ...patch });
      await assert.rejects(sessions.validate(issued.value), storeFailure);
      f.rows.set(rate[0], rate[1]);
    }
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session nonnumeric, negative or overflowing global epochs and zero revocation increments fail closed', async () => {
  for (const value of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1']) {
    const f = fixtureSettings();
    f.store.currentOwnerEpoch = async () => value as never;
    const { app, sessions } = await application(f.settings);
    try {
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), storeFailure);
    } finally {
      await app.stop();
    }
  }
  const f = fixtureSettings();
  f.store.bumpOwnerEpoch = async () => 0;
  const { app, sessions } = await application(f.settings);
  try {
    await assert.rejects(sessions.revokeAll(f.owner()), storeFailure);
  } finally {
    await app.stop();
  }
});

test('Session identity resolver output cannot change issuer, owner or authentication time during admission', async () => {
  const f = fixtureSettings(),
    original = f.settings.authority.resolveIdentity;
  let patch: (value: SessionAuthentication) => unknown = (value: SessionAuthentication) => value;
  f.settings.authority.resolveIdentity = async (...args) =>
    patch(await Reflect.apply(original, f.settings.authority, args)) as SessionAuthentication;
  const { app, sessions } = await application(f.settings);
  try {
    for (patch of [
      (value: SessionAuthentication) => ({
        ...value,
        identity: { ...value.identity, issuer: 'https://foreign.fixture.invalid' },
      }),
      (value: SessionAuthentication) => ({
        ...value,
        subject: { ...value.subject, subject: randomUUID() },
      }),
      (value: SessionAuthentication) => ({
        ...value,
        authenticatedAt: new Date(Date.now() + 60000).toISOString(),
      }),
      (value: SessionAuthentication) => ({
        ...value,
        assuredAt: new Date(Date.now() + 60000).toISOString(),
      }),
      (value: SessionAuthentication) => ({
        ...value,
        assuredAt: new Date(Date.parse(value.authenticatedAt) - 1000).toISOString(),
      }),
    ])
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), {
        code: 'EK_SESSION_INVALID',
      });
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'session-v1').length, 0);
    patch = (value: SessionAuthentication) => value;
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session native HMAC verification rejects valid expired rows retained by storage', async (context) => {
  context.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixtureSettings(),
    read = f.store.read;
  f.store.read = async (...args) => {
    if (args[0] === 'sessions.records.v1')
      return (f.rows.get(JSON.stringify([args[0], args[1]])) ?? null) as Awaited<
        ReturnType<typeof read>
      >;
    return Reflect.apply(read, f.store, args);
  };
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), { absoluteTtlMs: 1000, idleTtlMs: 200 });
    context.mock.timers.tick(201);
    await assert.rejects(sessions.validate(issued.value), { code: 'EK_SESSION_EXPIRED' });
    await assert.rejects(sessions.renew(issued.value), { code: 'EK_SESSION_EXPIRED' });
    await sessions.revoke(randomUUID());
  } finally {
    await app.stop();
  }
});

test('Session owner indexes reject accessor rows, duplicates, foreign owners and impossible future epochs', async () => {
  const f = fixtureSettings(),
    list = f.store.listByOwner;
  let mode = '';
  f.store.listByOwner = async (...args) => {
    const rows = await Reflect.apply(list, f.store, args);
    if (!mode) return rows;
    if (mode === 'accessor')
      return Object.defineProperty(new Array(1), '0', {
        get() {
          throw new Error('An indexed accessor must not execute');
        },
      });
    if (mode === 'duplicate') return [...rows, ...rows];
    if (mode === 'foreign') return rows.map((row) => ({ ...row, ownerKey: '0'.repeat(64) }));
    return rows.map((row) => ({ ...row, fields: { ...row.fields, epoch: 1 } }));
  };
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    for (mode of ['accessor', 'duplicate', 'foreign', 'future-epoch'])
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), storeFailure);
    mode = '';
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session HMAC failures and nonboolean verifier results cannot authenticate or return credentials', async () => {
  const f = fixtureSettings(),
    digest = f.settings.hmac.digest,
    verify = f.settings.hmac.verify;
  let bad = '';
  f.settings.hmac.digest = async (...args) =>
    bad === 'digest' ? '' : Reflect.apply(digest, f.settings.hmac, args);
  f.settings.hmac.verify = async (...args) =>
    bad === 'verify' ? ('true' as never) : Reflect.apply(verify, f.settings.hmac, args);
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    bad = 'digest';
    await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), storeFailure);
    bad = 'verify';
    await assert.rejects(sessions.validate(issued.value), storeFailure);
    bad = '';
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session activity retries a definitively rejected write only within its fixed bound', async (context) => {
  context.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixtureSettings(),
    compare = f.store.compareAndSet;
  let armed = false,
    rejected = 0;
  f.store.compareAndSet = async (...args) => {
    if (armed && args[0] === 'sessions.records.v1') {
      rejected++;
      return { committed: false };
    }
    return Reflect.apply(compare, f.store, args);
  };
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    context.mock.timers.tick(10);
    armed = true;
    await assert.rejects(sessions.validate(issued.value), { code: 'EK_SESSION_INVALID' });
    assert.equal(rejected, 2);
    armed = false;
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session authority canonical owner cannot differ from the independently resolved account', async () => {
  const f = fixtureSettings(),
    require = f.settings.authority.require;
  let foreign = true;
  f.settings.authority.require = async (...args) => {
    const owner = await Reflect.apply(require, f.settings.authority, args);
    return foreign ? { ...owner, subject: randomUUID() } : owner;
  };
  const { app, sessions } = await application(f.settings);
  try {
    await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy), {
      code: 'EK_SESSION_INVALID',
    });
    foreign = false;
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session invalid dates, sparse identity arrays and signal overrides fail without executable input', async () => {
  const { instant, strings, snapshot } = await import('../../dist/validation.js');
  let effects = 0;
  const accessor = Object.defineProperty(new Array(1), '0', {
    get() {
      effects++;
      throw new Error('An array accessor must not run');
    },
  });
  for (const value of ['1969-12-31T23:59:59.000Z', '2026-02-31T00:00:00.000Z', 'invalid'])
    assert.throws(() => instant(value), { code: 'EK_CONFIG_INVALID' });
  for (const value of [new Array(1), accessor])
    assert.throws(() => strings(value, 2), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => snapshot(accessor), { code: 'EK_CONFIG_INVALID' });
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    await assert.rejects(sessions.revoke('invalid'), { code: 'EK_CONFIG_INVALID' });
    await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy, null as never), {
      code: 'EK_CONFIG_INVALID',
    });
    for (const name of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
      const signal = new AbortController().signal;
      Object.defineProperty(signal, name, {
        get() {
          effects++;
          throw new Error('Signal metadata must not run');
        },
      });
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy, { signal }), {
        code: 'EK_CONFIG_INVALID',
      });
    }
    assert.equal(effects, 0);
  } finally {
    await app.stop();
  }
});

test('Session operation ownership sanitizes unexpected failures and checks the real monotonic deadline', async () => {
  const { runtime, captureSettings } = await import('../../dist/runtime.js');
  const f = fixtureSettings(),
    owner = runtime(captureSettings(f.settings));
  try {
    await assert.rejects(
      owner.run(undefined, false, async () => {
        throw new Error('Private unexpected diagnostic');
      }),
      { code: 'EK_SESSION_INVALID' },
    );
    await assert.rejects(
      owner.run({ timeoutMs: 5 }, false, async (call) => {
        const end = performance.now() + 10;
        while (performance.now() < end) {
          /* Keep the actual event loop until the monotonic deadline passes. */
        }
        call.check();
      }),
      { code: 'EK_TIMEOUT' },
    );
  } finally {
    owner.close();
  }
});

test('Session provider classifications reject executable and unsupported usage before acquiring resources', async () => {
  const { sessionsPlugin } = await import('../../dist/index.js');
  let effects = 0;
  const accessor = fixtureSettings();
  Object.defineProperty(accessor.settings.hmac, 'usage', {
    get() {
      effects++;
      throw new Error('Provider classification metadata must not run');
    },
  });
  assert.throws(() => sessionsPlugin(accessor.settings), { code: 'EK_CONFIG_INVALID' });
  const unsupported = fixtureSettings();
  Object.defineProperty(unsupported.settings.authority, 'usage', { value: 'unsupported' });
  assert.throws(() => sessionsPlugin(unsupported.settings), { code: 'EK_CONFIG_INVALID' });
  assert.equal(effects, 0);
});

test('Session bootstrap failure never publishes a capability or persists session state', async () => {
  const { createApplication } = await import('@arkenivajs/core');
  const { loggingPlugin } = await import('@arkenivajs/logging');
  const { sessionsPlugin } = await import('../../dist/index.js');
  const f = fixtureSettings();
  f.settings.hmac.digest = async () => {
    throw new Error('Private bootstrap secret failure');
  };
  const app = await createApplication({
    service: { name: 'session-bootstrap-failure', version: '1.0.0', environment: 'test' },
    plugins: [loggingPlugin(), sessionsPlugin(f.settings)],
    logging: { level: 'silent' },
  });
  try {
    await assert.rejects(app.start(), { code: 'EK_PLUGIN_FAILED' });
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});
