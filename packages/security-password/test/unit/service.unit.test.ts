// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import { fixtureSettings, application } from './fixture.js';
import { passwordPlugin } from '../../dist/index.js';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';

const password = () => randomBytes(24).toString('base64url');

test('Password reset subject snapshots reject executable, lossy and unbounded identity hints', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  let invoked = 0;
  const getter = Object.defineProperty({}, 'issuer', {
      enumerable: true,
      get() {
        invoked++;
        return f.owner().issuer;
      },
    }),
    cyclic: Record<string, unknown> = {};
  cyclic.subject = cyclic;
  let deep: unknown = null;
  for (let i = 0; i < 14; i++) deep = { child: deep };
  try {
    for (const bad of [
      getter,
      cyclic,
      null,
      [],
      { ...f.owner(), subject: ' ' },
      { ...f.owner(), subject: '\ud800' },
      { ...f.owner(), extra: undefined },
      { ...f.owner(), extra: NaN },
      { ...f.owner(), extra: -0 },
      { ...f.owner(), extra: 1n },
      { ...f.owner(), extra: new Date() },
      { ...f.owner(), extra: 'x'.repeat(8193) },
      { ...f.owner(), extra: '\u0000' },
      { ...f.owner(), extra: deep },
      { ...f.owner(), extra: new Array(2) },
      { ...f.owner(), extra: Array.from({ length: 129 }, () => null) },
      { ...f.owner(), extra: Array.from({ length: 128 }, () => [null, null, null, null]) },
      {
        ...f.owner(),
        extra: Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['k' + i, null])),
      },
      { ...f.owner(), extra: { constructor: 'unsafe' } },
      { ...f.owner(), extra: { [Symbol('invalid')]: true } },
      { ...f.owner(), extra: { ['x'.repeat(129)]: null } },
      { ...f.owner(), extra: { ['bad\u0000key']: true } },
      { ...f.owner(), extra: { a: 'x'.repeat(8192), b: 'x'.repeat(8192) } },
    ])
      await assert.rejects(passwords.createReset(bad as never, f.owner()));
    f.state.tenant = 'tenant-a';
    const owner = f.owner(),
      tenant = owner.tenant!;
    for (const changed of [
      { ...tenant, verifiedAt: 'not-a-date' },
      { ...tenant, source: 'untrusted' },
      { ...tenant, identity: { ...tenant.identity, issuer: 'https://other.fixture.invalid' } },
      { ...tenant, identity: { ...tenant.identity, audience: ['duplicate', 'duplicate'] } },
      { ...tenant, identity: { ...tenant.identity, scopes: new Array(1) } },
      { ...tenant, identity: { ...tenant.identity, claims: [] } },
      { ...tenant, identity: { ...tenant.identity, assurance: 'forged' } },
    ])
      await assert.rejects(passwords.createReset({ ...owner, tenant: changed } as never, owner));
    assert.equal(invoked, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password reset never returns a late transaction acknowledgement after its deadline', async () => {
  const f = fixtureSettings(),
    commit = f.settings.resetCommitter.commitReset.bind(f.settings.resetCommitter);
  let ready!: () => void, release!: () => void;
  const entered = new Promise<void>((resolve) => {
      ready = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  const { app, passwords } = await application({
    ...f.settings,
    resetCommitter: {
      async commitReset(...args: Parameters<typeof commit>) {
        ready();
        await held;
        return commit(...args);
      },
    },
  });
  try {
    const reset = await passwords.createReset(f.owner(), f.owner()),
      next = password(),
      outcome = assert.rejects(
        passwords.consumeReset(reset.value, next, { timeoutMs: 1000 }),
        (error) => {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, 'EK_TIMEOUT');
          assert.equal(error.details.outcome, 'unknown');
          return true;
        },
      );
    await entered;
    await outcome;
    assert.equal(f.credentials.size, 0);
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(f.credentials.size, 1);
    assert.equal(
      (await passwords.verify(next, f.credentials.get(f.binding(f.owner()))!)).valid,
      true,
    );
    await assert.rejects(passwords.consumeReset(reset.value, password()));
  } finally {
    release();
    await app.stop();
    f.close();
  }
});

test('Password input and request-policy validation performs no provider writes or accessor execution', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  let invoked = 0;
  try {
    const policy = Object.defineProperty({}, 'timeCost', {
      enumerable: true,
      get() {
        invoked++;
        return 1;
      },
    });
    for (const bad of [undefined, null, {}, '\ud800', 'x'.repeat(1025)])
      await assert.rejects(passwords.hash(bad as never));
    for (const bad of [
      policy,
      { timeCost: 0 },
      { memoryCostKiB: 1 },
      { parallelism: 0 },
      { minLength: 1 },
      { blockBreachedPasswords: null },
    ])
      await assert.rejects(passwords.hash(password(), bad as never));
    for (const bad of [{ timeoutMs: 0 }, { timeoutMs: 5001 }, { signal: {} }, { now: 0 }])
      await assert.rejects(passwords.hash(password(), undefined, bad as never));
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(passwords.hash(password(), undefined, { signal: controller.signal }));
    assert.equal(invoked, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password startup rejects missing atomic persistence, breach checks and test-only production providers', async () => {
  const f = fixtureSettings();
  try {
    for (const settings of [
      { ...f.settings, resetCommitter: undefined },
      { ...f.settings, policy: undefined },
      {
        ...f.settings,
        policy: { ...f.settings.policy, blockBreachedPasswords: true },
        breaches: undefined,
      },
      { ...f.settings, resetTtlMs: 0 },
      { ...f.settings, maxResetAttemptsPerHour: 0 },
      {
        ...f.settings,
        resetStore: { ...f.settings.resetStore, store: { read: async () => null } },
      },
    ])
      assert.throws(() => passwordPlugin(settings as never));
    const app = await createApplication({
      service: { name: 'production-password-guard', version: '1.0.0', environment: 'production' },
      plugins: [loggingPlugin(), passwordPlugin(f.settings)],
    });
    await assert.rejects(app.start());
    await app.stop();
  } finally {
    f.close();
  }
});

test('Password reset budgets persist across independent instances and do not silently reset after exhaustion', async () => {
  const f = fixtureSettings(),
    settings = { ...f.settings, maxResetAttemptsPerHour: 2 },
    a = await application(settings),
    b = await application(settings);
  try {
    const reset = await a.passwords.createReset(f.owner(), f.owner());
    await assert.rejects(b.passwords.consumeReset('invalid', password()));
    await assert.rejects(
      a.passwords.consumeReset(reset.value, password()),
      (error) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
    );
    await assert.rejects(b.passwords.createReset(f.owner(), f.owner()));
    assert.equal(f.credentials.size, 0);
  } finally {
    await a.app.stop();
    await b.app.stop();
    f.close();
  }
});

test('Password providers and dishonest acknowledgements cannot grant a reset or expose private failures', async () => {
  const f = fixtureSettings(),
    a = await application(f.settings),
    b = await application({
      ...f.settings,
      resetCommitter: {
        async commitReset() {
          return { committed: true };
        },
      },
    });
  try {
    const reset = await a.passwords.createReset(f.owner(), f.owner());
    await assert.rejects(b.passwords.consumeReset(reset.value, password()));
    assert.equal(f.credentials.size, 0);
    f.state.secretAvailable = false;
    await assert.rejects(a.passwords.consumeReset(reset.value, password()), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.cause, undefined);
      assert.ok(!JSON.stringify(error.toSafeJSON()).includes('Private'));
      return true;
    });
    f.state.secretAvailable = true;
    f.state.storeAvailable = false;
    await assert.rejects(a.passwords.hash(password()));
    f.state.storeAvailable = true;
    await a.passwords.consumeReset(reset.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await a.app.stop();
    await b.app.stop();
    f.close();
  }
});
test('Password public lifecycle hashes and atomically consumes a reset without issuing authentication', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  try {
    const plain = password(),
      hashed = await passwords.hash(plain);
    assert.equal(passwords.needsRehash(hashed), false);
    assert.deepEqual(await passwords.verify(plain, hashed), {
      valid: true,
      rehashRecommended: false,
    });
    const reset = await passwords.createReset(f.owner(), f.owner());
    assert.ok(!JSON.stringify([...f.rows.values()]).includes(reset.value.split('.')[2]!));
    const next = password();
    assert.equal(await passwords.consumeReset(reset.value, next), undefined);
    const stored = f.credentials.get(f.binding(f.owner()))!;
    assert.equal((await passwords.verify(next, stored)).valid, true);
    assert.equal((await passwords.verify(plain, stored)).valid, false);
    assert.equal(f.epochs.get(f.binding(f.owner())), 1);
    await assert.rejects(passwords.consumeReset(reset.value, password()));
    assert.equal(f.epochs.get(f.binding(f.owner())), 1);
  } finally {
    await app.stop();
    f.close();
  }
});
test('Password reset rejects fabricated administrators, foreign tenants and unavailable authority', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  try {
    f.state.primary = false;
    await assert.rejects(passwords.createReset({ ...f.owner() }, { ...f.owner() }));
    f.state.primary = true;
    f.state.tenant = 'tenant-a';
    const a = f.owner(),
      reset = await passwords.createReset(a, a);
    f.state.tenant = 'tenant-b';
    await assert.rejects(passwords.consumeReset(reset.value, password()));
    await assert.rejects(passwords.createReset(a, f.owner()));
    f.state.tenant = 'tenant-a';
    f.state.authorityAvailable = false;
    await assert.rejects(passwords.consumeReset(reset.value, password()));
    f.state.authorityAvailable = true;
    f.state.primary = false;
    await passwords.consumeReset(reset.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await app.stop();
    f.close();
  }
});
test('Password replacement issuance invalidates the previous reset and secret rotation fails closed', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  try {
    const first = await passwords.createReset(f.owner(), f.owner()),
      second = await passwords.createReset(f.owner(), f.owner());
    await assert.rejects(passwords.consumeReset(first.value, password()));
    f.rotateSecret();
    await assert.rejects(passwords.consumeReset(second.value, password()));
    const next = await passwords.createReset(f.owner(), f.owner());
    await passwords.consumeReset(next.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await app.stop();
    f.close();
  }
});
test('Concurrent password reset consumers reach the same commit barrier and select one complete transition', async () => {
  const f = fixtureSettings(),
    commit = f.settings.resetCommitter.commitReset.bind(f.settings.resetCommitter);
  let entered = 0,
    release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const settings = {
      ...f.settings,
      resetCommitter: {
        async commitReset(...args: Parameters<typeof commit>) {
          if (++entered === 2) release();
          await held;
          return commit(...args);
        },
      },
    },
    a = await application(settings),
    b = await application(settings);
  try {
    const reset = await a.passwords.createReset(f.owner(), f.owner()),
      x = password(),
      y = password(),
      results = await Promise.allSettled([
        a.passwords.consumeReset(reset.value, x),
        b.passwords.consumeReset(reset.value, y),
      ]);
    assert.equal(entered, 2);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(f.epochs.get(f.binding(f.owner())), 1);
    const stored = f.credentials.get(f.binding(f.owner()))!;
    assert.equal((await a.passwords.verify(x, stored)).valid, results[0]!.status === 'fulfilled');
    assert.equal((await b.passwords.verify(y, stored)).valid, results[1]!.status === 'fulfilled');
  } finally {
    release();
    await a.app.stop();
    await b.app.stop();
    f.close();
  }
});
test('Password breaches send only a k-anonymity prefix and cannot be bypassed by weakening a call policy', async () => {
  const f = fixtureSettings(),
    plain = password(),
    hash = createHash('sha1').update(plain).digest('hex').toUpperCase();
  f.breachRows.set(hash.slice(0, 5), [{ suffix: hash.slice(5), count: 1 }]);
  const { app, passwords } = await application({
    ...f.settings,
    policy: { ...f.settings.policy, blockBreachedPasswords: true },
  });
  try {
    await assert.rejects(
      passwords.hash(plain),
      (error) => error instanceof KitError && error.code === 'EK_PASSWORD_POLICY',
    );
    assert.deepEqual(f.prefixes, [hash.slice(0, 5)]);
    await assert.rejects(passwords.hash(plain, { blockBreachedPasswords: false }));
    const reset = await passwords.createReset(f.owner(), f.owner());
    await assert.rejects(passwords.consumeReset(reset.value, plain));
    assert.equal(f.credentials.size, 0);
    f.breachRows.clear();
    await passwords.consumeReset(reset.value, password());
    assert.ok(f.prefixes.every((prefix) => /^[A-F0-9]{5}$/.test(prefix)));
  } finally {
    await app.stop();
    f.close();
  }
});
test('Failed or ambiguous password transactions never consume a reset in a separate preparatory write', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  try {
    const reset = await passwords.createReset(f.owner(), f.owner());
    f.state.commitAvailable = false;
    await assert.rejects(passwords.consumeReset(reset.value, password()), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, 'EK_PASSWORD_RESET');
      assert.equal(error.details.outcome, 'unknown');
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(f.credentials.size, 0);
    assert.equal(f.epochs.size, 0);
    f.state.commitAvailable = true;
    await passwords.consumeReset(reset.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await app.stop();
    f.close();
  }
});
