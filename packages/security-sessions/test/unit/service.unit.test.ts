// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { sessionsPlugin } from '../../dist/index.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixtureSettings, application } from './fixture.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('Session authorization receives the trusted assurance for creation, validation and renewal', async () => {
  const f = fixtureSettings(),
    received: Array<readonly [string, unknown]> = [],
    original = f.settings.authority;
  f.state.assurance = 'mfa';
  const { app, sessions } = await application({
    ...f.settings,
    authority: {
      ...original,
      async require(action, subject, context, options) {
        received.push([action, context.assurance]);
        return original.require(action, subject, context, options);
      },
    },
  });
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    await sessions.validate(issued.value);
    await sessions.renew(issued.value);
    assert.deepEqual(received, [
      ['sessions.create', 'mfa'],
      ['sessions.validate', 'mfa'],
      ['sessions.renew', 'mfa'],
    ]);
  } finally {
    await app.stop();
  }
});

test('Session admission stays bounded while cancelled provider calls remain unsettled', async () => {
  const f = fixtureSettings(),
    read = f.store.read.bind(f.store);
  let armed = false,
    entered = 0,
    ready!: () => void,
    release!: () => void;
  const started = new Promise<void>((resolve) => {
      ready = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  f.store.read = async (...args) => {
    if (armed) {
      if (++entered === 32) ready();
      await held;
    }
    return read(...args);
  };
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy),
      controller = new AbortController();
    armed = true;
    const pending = Promise.allSettled(
      Array.from({ length: 32 }, () =>
        sessions.validate(issued.value, { signal: controller.signal }),
      ),
    );
    await started;
    await assert.rejects(sessions.validate(issued.value), code('EK_BACKEND_UNAVAILABLE'));
    controller.abort();
    const outcomes = await pending;
    assert.equal(outcomes.length, 32);
    for (const result of outcomes) {
      assert.equal(result.status, 'rejected');
      assert.ok(code('EK_ABORTED')(result.reason));
      assert.equal(result.reason.details.outcome, 'unknown');
    }
    await assert.rejects(sessions.validate(issued.value), code('EK_BACKEND_UNAVAILABLE'));
    assert.equal(entered, 32);
    armed = false;
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
    await app.stop();
    await assert.rejects(sessions.validate(issued.value), code('EK_RESOURCE_CLOSED'));
  } finally {
    release();
    await app.stop();
  }
});

test('Session creation never returns a late transaction acknowledgement after its deadline', async () => {
  const f = fixtureSettings(),
    commit = f.store.atomicBatch.bind(f.store);
  let release!: () => void, ready!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      ready = resolve;
    });
  f.store.atomicBatch = async (...args) => {
    ready();
    await held;
    return commit(...args);
  };
  const { app, sessions } = await application(f.settings);
  try {
    const outcome = assert.rejects(
      sessions.create(f.identity(), f.settings.defaultPolicy, { timeoutMs: 100 }),
      (error) => {
        assert.ok(error instanceof KitError);
        assert.ok(code('EK_TIMEOUT')(error));
        assert.equal(error.details.outcome, 'unknown');
        return true;
      },
    );
    await started;
    await outcome;
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'session-v1').length, 1);
  } finally {
    release();
    await app.stop();
  }
});

test('Sessions issue opaque secure-cookie credentials and resolve canonical account claims at runtime', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(
      { ...f.identity(), scopes: ['admin'], claims: { admin: true } },
      f.settings.defaultPolicy,
    );
    assert.equal(issued.cookieName, '__Host-session');
    assert.match(issued.value, /^ss1\.[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/);
    const current = await sessions.validate(issued.value);
    assert.deepEqual(current.scopes, ['orders.read']);
    assert.equal(current.claims.admin, undefined);
    assert.ok(Object.isFrozen(current));
    assert.ok(!JSON.stringify([...f.rows.values()]).includes(issued.value.split('.')[2]!));
    assert.ok(!JSON.stringify([...f.rows.values()]).includes('Original private account claims'));
  } finally {
    await app.stop();
  }
});
test('Session renewal atomically invalidates the old token without extending authentication or absolute expiry', async () => {
  const f = fixtureSettings(),
    a = await application(f.settings),
    b = await application(f.settings);
  try {
    const first = await a.sessions.create(f.identity(), f.settings.defaultPolicy),
      before = await a.sessions.validate(first.value),
      renewed = await b.sessions.renew(first.value);
    assert.notEqual(renewed.value, first.value);
    assert.notEqual(renewed.sessionId, first.sessionId);
    await assert.rejects(a.sessions.validate(first.value));
    const current = await a.sessions.validate(renewed.value);
    assert.equal(current.authenticatedAt, before.authenticatedAt);
    assert.equal(current.assuredAt, before.assuredAt);
    await a.sessions.revoke(renewed.sessionId);
    await assert.rejects(b.sessions.validate(renewed.value));
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('Global session revocation advances durable epochs and clears stale quota entries before issuing again', async () => {
  const f = fixtureSettings(),
    settings = { ...f.settings, maxSessionsPerSubject: 1 },
    a = await application(settings),
    b = await application(settings);
  try {
    const first = await a.sessions.create(f.identity(), settings.defaultPolicy);
    await assert.rejects(b.sessions.create(f.identity(), settings.defaultPolicy));
    assert.equal(await b.sessions.revokeAll(f.owner()), 1);
    await assert.rejects(a.sessions.validate(first.value), code('EK_SESSION_REVOKED'));
    const next = await a.sessions.create(f.identity(), settings.defaultPolicy);
    assert.equal((await b.sessions.validate(next.value)).sessionId, next.sessionId);
    assert.equal(await a.sessions.revokeAll(f.owner()), 2);
    await assert.rejects(b.sessions.validate(next.value));
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('Session management rejects unauthenticated caller-built identities and never creates elevated claims', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    f.state.primary = false;
    await assert.rejects(
      sessions.create({ ...f.identity() }, f.settings.defaultPolicy),
      code('EK_SESSION_INVALID'),
    );
    assert.equal(f.rows.size, 0);
    f.state.primary = true;
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    f.state.primary = false;
    await assert.rejects(sessions.revoke(issued.sessionId));
    await assert.rejects(sessions.revokeAll({ ...f.owner() }));
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
    f.state.enabled = false;
    await assert.rejects(sessions.validate(issued.value));
  } finally {
    await app.stop();
  }
});

test('Session idle expiry slides with activity while renewal preserves the original absolute deadline', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), { absoluteTtlMs: 1000, idleTtlMs: 200 });
    t.mock.timers.tick(150);
    const active = await sessions.validate(issued.value);
    assert.equal(Date.parse(active.expiresAt) - Date.now(), 200);
    t.mock.timers.tick(201);
    await assert.rejects(sessions.validate(issued.value));
    const absolute = await sessions.create(f.identity(), { absoluteTtlMs: 1000, idleTtlMs: 800 }),
      end = Date.now() + 1000;
    t.mock.timers.tick(700);
    assert.equal(Date.parse((await sessions.validate(absolute.value)).expiresAt), end);
    t.mock.timers.tick(50);
    const renewed = await sessions.renew(absolute.value);
    assert.equal(Date.parse(renewed.expiresAt), end);
    t.mock.timers.tick(251);
    await assert.rejects(sessions.validate(renewed.value));
  } finally {
    await app.stop();
  }
});
test('Session assurance and authentication timestamps cannot be promoted during validation or renewal', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixtureSettings();
  f.state.assurance = 'mfa';
  const { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(
        { ...f.identity(), assurance: 'phishing-resistant' },
        f.settings.defaultPolicy,
      ),
      before = await sessions.validate(issued.value);
    assert.equal(before.assurance, 'mfa');
    assert.ok(before.assuredAt);
    t.mock.timers.tick(50);
    const current = await sessions.validate(issued.value);
    assert.equal(current.authenticatedAt, before.authenticatedAt);
    assert.equal(current.assuredAt, before.assuredAt);
    f.state.assurance = 'phishing-resistant';
    await assert.rejects(sessions.validate(issued.value));
    await assert.rejects(sessions.renew(issued.value));
  } finally {
    await app.stop();
  }
});
test('Sessions refresh current account privileges instead of trusting persisted or caller-built claims', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(
      { ...f.identity(), scopes: ['admin'] },
      f.settings.defaultPolicy,
    );
    f.state.scopes = ['orders.read', 'orders.write'];
    const current = await sessions.validate(issued.value);
    assert.deepEqual(current.scopes, ['orders.read', 'orders.write']);
    assert.equal(current.scopes.includes('admin'), false);
  } finally {
    await app.stop();
  }
});
test('Session account ownership and global revocation cannot cross tenant boundaries', async () => {
  const f = fixtureSettings();
  f.state.tenant = 'tenant-a';
  const { app, sessions } = await application(f.settings);
  try {
    const a = f.owner(),
      issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    f.state.tenant = 'tenant-b';
    const b = await sessions.create(f.identity(), f.settings.defaultPolicy);
    await assert.rejects(sessions.validate(issued.value));
    await assert.rejects(sessions.revoke(issued.sessionId));
    await assert.rejects(sessions.revokeAll({ ...a }));
    await sessions.revokeAll(f.owner());
    await assert.rejects(sessions.validate(b.value));
    f.state.tenant = 'tenant-a';
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});
test('Concurrent session renewals contend on the same durable batch and leave one replacement', async () => {
  const f = fixtureSettings(),
    commit = f.store.atomicBatch.bind(f.store);
  let armed = false,
    entered = 0,
    release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  f.store.atomicBatch = async (mutations) => {
    if (armed) {
      if (++entered === 2) release();
      await held;
    }
    return commit(mutations);
  };
  const a = await application(f.settings),
    b = await application(f.settings);
  try {
    const issued = await a.sessions.create(f.identity(), f.settings.defaultPolicy);
    armed = true;
    const outcomes = await Promise.allSettled([
      a.sessions.renew(issued.value),
      b.sessions.renew(issued.value),
    ]);
    assert.equal(entered, 2);
    assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'session-v1').length, 1);
    await assert.rejects(a.sessions.validate(issued.value));
    const winner = outcomes.find((result) => result.status === 'fulfilled')!;
    assert.equal(winner.status, 'fulfilled');
    assert.equal((await b.sessions.validate(winner.value.value)).sessionId, winner.value.sessionId);
  } finally {
    release();
    await a.app.stop();
    await b.app.stop();
  }
});
test('Session creation cannot return an already globally revoked token when revocation races commit', async () => {
  const f = fixtureSettings(),
    commit = f.store.atomicBatch.bind(f.store);
  let armed = true,
    release!: () => void,
    ready!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      ready = resolve;
    });
  f.store.atomicBatch = async (mutations) => {
    if (armed) {
      armed = false;
      ready();
      await held;
    }
    return commit(mutations);
  };
  const { app, sessions } = await application(f.settings);
  try {
    const pending = sessions.create(f.identity(), f.settings.defaultPolicy),
      rejected = assert.rejects(pending, code('EK_SESSION_REVOKED'));
    await started;
    await sessions.revokeAll(f.owner());
    release();
    await rejected;
    const next = await sessions.create(f.identity(), f.settings.defaultPolicy);
    assert.equal((await sessions.validate(next.value)).sessionId, next.sessionId);
  } finally {
    release();
    await app.stop();
  }
});
test('Session key rotation preserves old verifiers and stable opaque ownership', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    f.rotateHmac();
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
    const renewed = await sessions.renew(issued.value);
    assert.equal((await sessions.validate(renewed.value)).sessionId, renewed.sessionId);
    await sessions.revokeAll(f.owner());
    await assert.rejects(sessions.validate(renewed.value));
  } finally {
    await app.stop();
  }
});
test('Session storage outage exposes no secret cause and never fabricates rollback or identity', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    f.state.fail = true;
    for (const operation of [
      () => sessions.validate(issued.value),
      () => sessions.renew(issued.value),
      () => sessions.revoke(issued.sessionId),
      () => sessions.revokeAll(f.owner()),
    ])
      await assert.rejects(operation(), (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_SESSION_STORE');
        assert.equal(error.cause, undefined);
        assert.equal(error.details.outcome, 'unknown');
        assert.equal(JSON.stringify(error.toSafeJSON()).includes('Private'), false);
        return true;
      });
    f.state.fail = false;
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});
test('Session policy, timeout, cancellation and clock override inputs fail before credential writes', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    for (const policy of [
      { absoluteTtlMs: 0, idleTtlMs: 1 },
      { absoluteTtlMs: 100, idleTtlMs: 101 },
      { ...f.settings.defaultPolicy, maxConcurrentSessions: null },
      { ...f.settings.defaultPolicy, cookieSameSite: null },
      { ...f.settings.defaultPolicy, cookieSameSite: 'invalid' },
      { ...f.settings.defaultPolicy, unknown: true },
    ])
      await assert.rejects(
        sessions.create(f.identity(), policy as never),
        code('EK_CONFIG_INVALID'),
      );
    for (const options of [
      { timeoutMs: 0 },
      { timeoutMs: 5001 },
      { timeoutMs: 1.5 },
      { signal: {} },
      { now: 0 },
    ])
      await assert.rejects(
        sessions.create(f.identity(), f.settings.defaultPolicy, options as never),
        code('EK_CONFIG_INVALID'),
      );
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      sessions.create(f.identity(), f.settings.defaultPolicy, { signal: controller.signal }),
      code('EK_ABORTED'),
    );
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});
test('Session untrusted identity snapshots reject executable, lossy and unbounded data before persistence', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  let invoked = 0;
  const getter = Object.defineProperty({}, 'private', {
      enumerable: true,
      get() {
        invoked++;
        return 'unsafe';
      },
    }),
    cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  let deep: unknown = null;
  for (let level = 0; level < 14; level++) deep = { child: deep };
  try {
    for (const claims of [
      undefined,
      null,
      [],
      1,
      { value: undefined },
      { value: () => true },
      { value: 1n },
      { value: NaN },
      { value: -0 },
      { value: Infinity },
      { value: new Date() },
      { value: '\ud800' },
      { value: '\u0000' },
      { value: 'x'.repeat(8193) },
      getter,
      cyclic,
      deep,
      { value: new Array(2) },
      { value: Array.from({ length: 129 }, () => null) },
      { value: Object.fromEntries(Array.from({ length: 65 }, (_, index) => ['k' + index, null])) },
      { [Symbol('invalid')]: true },
      { constructor: 'unsafe' },
      { ['x'.repeat(129)]: null },
      { ['bad\u0000key']: true },
      { a: 'x'.repeat(8192), b: 'x'.repeat(8192) },
      { value: Array.from({ length: 128 }, () => [null, null, null, null]) },
    ])
      await assert.rejects(
        sessions.create({ ...f.identity(), claims } as never, f.settings.defaultPolicy),
        code('EK_CONFIG_INVALID'),
      );
    for (const change of [
      { issuer: ' ' },
      { subject: '\ud800' },
      { scopes: ['duplicate', 'duplicate'] },
      { audience: new Array(1) },
      { assurance: 'unverified' },
      { unknown: true },
    ])
      await assert.rejects(
        sessions.create({ ...f.identity(), ...change } as never, f.settings.defaultPolicy),
        code('EK_CONFIG_INVALID'),
      );
    assert.equal(invoked, 0);
    assert.equal(f.rows.size, 0);
    const valid = await sessions.create(
      {
        ...f.identity(),
        claims: { value: [null, true, false, 0, 1.5, 'text'], nested: { ok: true } },
      },
      { absoluteTtlMs: 1000, idleTtlMs: 100, cookieSameSite: 'strict', maxConcurrentSessions: 1 },
    );
    assert.equal((await sessions.validate(valid.value)).sessionId, valid.sessionId);
  } finally {
    await app.stop();
  }
});

test('Session factories require a real identity resolver, complete shared store and safe production providers', async () => {
  const f = fixtureSettings();
  for (const input of [
    { ...f.settings, authority: { require: f.settings.authority.require } },
    { ...f.settings, maxSessionsPerSubject: 0 },
    { ...f.settings, unknown: true },
    { ...f.settings, hmac: { ...f.settings.hmac, algorithm: 'SHA1' } },
    { ...f.settings, store: { ...f.settings.store, store: { read: async () => null } } },
  ])
    assert.throws(() => sessionsPlugin(input as never), code('EK_CONFIG_INVALID'));
  const app = await createApplication({
    service: { name: 'unsafe-sessions', version: '1.0.0', environment: 'production' },
    plugins: [
      loggingPlugin(),
      sessionsPlugin({
        ...f.settings,
        store: { ...f.settings.store, securityLevel: 'production' },
      }),
    ],
  });
  await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
  await app.stop();
});
test('Session state and authentication providers cannot forge stronger factors, extended TTL or another owner', async () => {
  const f = fixtureSettings(),
    { app, sessions } = await application(f.settings);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy),
      entry = JSON.stringify(['sessions.records.v1', issued.sessionId]),
      original = f.rows.get(entry)!;
    for (const change of [
      {
        identity: { ...(original.identity as object), assurance: 'mfa' },
        assuredAt: original.authenticatedAt,
      },
      { epoch: 1 },
      { ownerKey: randomBytes(32).toString('hex') },
      { subject: { issuer: f.owner().issuer, subject: randomUUID() } },
      { expiresAt: new Date(Date.parse(String(original.expiresAt)) + 1000).toISOString() },
    ]) {
      f.rows.set(entry, { ...original, ...change });
      await assert.rejects(sessions.validate(issued.value));
    }
    f.rows.set(entry, original);
    assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
  } finally {
    await app.stop();
  }
});
