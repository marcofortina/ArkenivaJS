// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixtureSettings, application } from './fixture.js';
import type { SecretValue } from '../../dist/index.js';
const password = () => randomBytes(24).toString('base64url');
const denied = { code: 'EK_PASSWORD_RESET' };

test('Password reset durable record discriminators, owner indexes and verifier fields reject corruption', async () => {
  const f = fixtureSettings(),
    { app, passwords } = await application(f.settings);
  try {
    const reset = await passwords.createReset(f.owner(), f.owner());
    const entry = JSON.stringify(['password.resets.v1', reset.requestId]),
      original = f.rows.get(entry)!;
    for (const patch of [
      { kind: 'unexpected-record' },
      { id: randomUUID() },
      { ownerKey: 'g'.repeat(64) },
      { digest: 'invalid' },
      { version: '' },
      { keyVersion: '' },
    ]) {
      f.rows.set(entry, { ...original, ...patch });
      await assert.rejects(passwords.consumeReset(reset.value, password()), denied);
      assert.equal(f.credentials.size, 0);
      f.rows.set(entry, original);
    }
    await passwords.consumeReset(reset.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password malformed rate and atomic issuance acknowledgments never return a one-time reset', async () => {
  for (const method of ['compareAndSet', 'atomicBatch'] as const)
    for (const receipt of [
      undefined,
      {},
      { committed: 'true' },
      { committed: true, version: '' },
    ]) {
      const f = fixtureSettings();
      f.store[method] = async () => receipt as never;
      const { app, passwords } = await application(f.settings);
      try {
        await assert.rejects(passwords.createReset(f.owner(), f.owner()), denied);
        assert.equal(
          [...f.rows.values()].filter((row) => row.kind === 'password-reset-v1').length,
          0,
        );
      } finally {
        await app.stop();
        f.close();
      }
    }
});

test('Password durable budget corruption and rejected admission writes cannot reset the shared rate limit', async () => {
  const f = fixtureSettings(),
    compare = f.store.compareAndSet;
  let reject = false,
    rejected = 0;
  f.store.compareAndSet = async (...args) => {
    if (reject) {
      rejected++;
      return { committed: false };
    }
    return Reflect.apply(compare, f.store, args);
  };
  const { app, passwords } = await application(f.settings);
  try {
    await passwords.createReset(f.owner(), f.owner());
    const entry = [...f.rows.entries()].find(
      ([key]) => JSON.parse(key)[0] === 'password.budgets.v1',
    )!;
    for (const patch of [
      { kind: 'unexpected-budget' },
      { ownerKey: '0'.repeat(64) },
      { bucket: -1 },
      { count: -1 },
      { count: 1001 },
      { expiresAt: new Date(Date.now() + 10800000).toISOString() },
    ]) {
      f.rows.set(entry[0], { ...entry[1], ...patch });
      await assert.rejects(passwords.createReset(f.owner(), f.owner()), denied);
      f.rows.set(entry[0], entry[1]);
    }
    reject = true;
    await assert.rejects(passwords.createReset(f.owner(), f.owner()), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    assert.equal(rejected, 8);
    reject = false;
    assert.ok((await passwords.createReset(f.owner(), f.owner())).value.startsWith('pr1.'));
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password reset secret expiry, shared memory, short and excessive key material fail without consuming valid state', async () => {
  const f = fixtureSettings(),
    get = f.settings.secretProvider.get;
  let patch: Partial<SecretValue> | undefined;
  f.settings.secretProvider.get = async (...args) => ({
    ...(await Reflect.apply(get, f.settings.secretProvider, args)),
    ...patch,
  });
  const { app, passwords } = await application(f.settings);
  try {
    for (patch of [
      { expiresAt: new Date(Date.now() - 1000).toISOString() },
      { bytes: new Uint8Array(new SharedArrayBuffer(32)) },
      { bytes: new Uint8Array(31) },
      { bytes: new Uint8Array(4097) },
      { bytes: [] as never },
      { keyVersion: '' },
    ])
      await assert.rejects(passwords.createReset(f.owner(), f.owner()), denied);
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'password-reset-v1').length, 0);
    patch = undefined;
    const reset = await passwords.createReset(f.owner(), f.owner());
    await passwords.consumeReset(reset.value, password());
    assert.equal(f.credentials.size, 1);
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password authority output must match the independently requested owner', async () => {
  const f = fixtureSettings(),
    require = f.settings.authority.require;
  let foreign = true;
  f.settings.authority.require = async (...args) => {
    const owner = await Reflect.apply(require, f.settings.authority, args);
    return foreign ? { ...owner, subject: randomUUID() } : owner;
  };
  const { app, passwords } = await application(f.settings);
  try {
    await assert.rejects(passwords.createReset(f.owner(), f.owner()), denied);
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'password-reset-v1').length, 0);
    foreign = false;
    assert.ok((await passwords.createReset(f.owner(), f.owner())).value.startsWith('pr1.'));
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password breach checks reject missing sources and malformed bounded range replies', async () => {
  const f = fixtureSettings();
  const rows = [null, new Array(1), Array.from({ length: 20001 }, () => null)];
  let result: unknown = [];
  f.settings.breaches!.lookup = async () => result as never;
  const { app, passwords } = await application({
    ...f.settings,
    policy: { ...f.settings.policy, blockBreachedPasswords: true },
  });
  try {
    for (result of rows)
      await assert.rejects(passwords.hash(password()), { code: 'EK_PASSWORD_POLICY' });
    result = [];
    const hashed = await passwords.hash(password());
    assert.equal(hashed.scheme, 'argon2id');
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password provider classifications reject accessors and unsupported labels before resource acquisition', async () => {
  const { passwordPlugin } = await import('../../dist/index.js');
  const f = fixtureSettings();
  let effects = 0;
  try {
    Object.defineProperty(f.settings.secretProvider, 'usage', {
      configurable: true,
      get() {
        effects++;
        throw new Error('Provider classification must not execute');
      },
    });
    assert.throws(() => passwordPlugin(f.settings), { code: 'EK_CONFIG_INVALID' });
    Object.defineProperty(f.settings.secretProvider, 'usage', { value: 'unsupported' });
    assert.throws(() => passwordPlugin(f.settings), { code: 'EK_CONFIG_INVALID' });
    const plain = fixtureSettings();
    try {
      const { breaches, ...withoutBreaches } = plain.settings;
      assert.ok(breaches);
      assert.doesNotThrow(() => passwordPlugin(withoutBreaches));
    } finally {
      plain.close();
    }
    assert.equal(effects, 0);
  } finally {
    f.close();
  }
});

test('Password bootstrap failures release the unpublished owner without persisting credentials', async () => {
  const { createApplication } = await import('@arkenivajs/core');
  const { loggingPlugin } = await import('@arkenivajs/logging');
  const { passwordPlugin } = await import('../../dist/index.js');
  const f = fixtureSettings();
  f.settings.secretProvider.get = async () => {
    throw new Error('Private bootstrap secret failure');
  };
  const app = await createApplication({
    service: { name: 'password-bootstrap-failure', version: '1.0.0', environment: 'test' },
    plugins: [loggingPlugin(), passwordPlugin(f.settings)],
    logging: { level: 'silent' },
  });
  try {
    await assert.rejects(app.start(), { code: 'EK_PLUGIN_FAILED' });
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
    f.close();
  }
});

test('Password operation ownership bounds unsettled work and enforces abort, closure and real deadlines', async () => {
  const { runtime, captureSettings } = await import('../../dist/runtime.js');
  const { setImmediate: nextTurn } = await import('node:timers/promises');
  const f = fixtureSettings(),
    owner = runtime(captureSettings(f.settings));
  let release: () => void = () => {},
    ready: () => void = () => {},
    entered = 0;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const controller = new AbortController();
  let pending: Promise<PromiseSettledResult<void>[]> | undefined;
  try {
    await assert.rejects(
      owner.run(undefined, false, async () => {
        throw new Error('Private unexpected operation failure');
      }),
      { code: 'EK_PASSWORD_INVALID' },
    );
    await assert.rejects(
      owner.run({ timeoutMs: 5 }, false, async (call) => {
        const end = performance.now() + 10;
        while (performance.now() < end) {
          /* Retain the real event loop until its monotonic deadline passes. */
        }
        call.check();
      }),
      { code: 'EK_TIMEOUT' },
    );
    pending = Promise.allSettled(
      Array.from({ length: 32 }, () =>
        owner.run({ signal: controller.signal }, false, async () => {
          if (++entered === 32) ready();
          await held;
        }),
      ),
    );
    await started;
    await assert.rejects(
      owner.run(undefined, false, async () => {}),
      { code: 'EK_BACKEND_UNAVAILABLE' },
    );
    controller.abort();
    for (const outcome of await pending) {
      assert.equal(outcome.status, 'rejected');
      if (outcome.status === 'rejected') assert.equal(outcome.reason.code, 'EK_ABORTED');
    }
    await assert.rejects(
      owner.run(undefined, false, async () => {}),
      { code: 'EK_BACKEND_UNAVAILABLE' },
    );
    release();
    await nextTurn();
    await owner.run(undefined, false, async () => {});
    await assert.rejects(
      owner.run(undefined, false, async (call) => {
        owner.close();
        call.check();
      }),
      { code: 'EK_ABORTED' },
    );
    await assert.rejects(
      owner.run(undefined, false, async () => {}),
      { code: 'EK_RESOURCE_CLOSED' },
    );
  } finally {
    release();
    if (pending) await pending;
    owner.close();
    f.close();
  }
});

test('Password date, array and abort-signal ingress rejects invalid or executable values', async () => {
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
    { app, passwords } = await application(f.settings);
  try {
    for (const name of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
      const signal = new AbortController().signal;
      Object.defineProperty(signal, name, {
        get() {
          effects++;
          throw new Error('Signal metadata must not run');
        },
      });
      await assert.rejects(passwords.createReset(f.owner(), f.owner(), { signal }), {
        code: 'EK_CONFIG_INVALID',
      });
    }
    assert.equal(effects, 0);
  } finally {
    await app.stop();
    f.close();
  }
});
