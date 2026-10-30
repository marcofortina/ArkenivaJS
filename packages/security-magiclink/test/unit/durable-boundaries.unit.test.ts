// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, application } from '../fixture.js';

const consume = { method: 'POST' as const, purpose: 'login' as const };

test('Magic link corrupted durable discriminator, state, owner and validity intervals fail closed', async () => {
  const f = fixture(),
    { app, magic } = await application({ ...f.settings, maxClaimsPerHour: 1000 });
  try {
    const issued = await magic.issue(f.owner, 'login');
    const entry = JSON.stringify(['magiclink.records.v1', issued.issueId]),
      original = f.rows.get(entry)!;
    for (const patch of [
      { kind: 'unexpected-record' },
      { id: randomUUID() },
      { state: 'unknown' },
      { ownerKey: 'g'.repeat(64) },
      { expiresAt: original.validUntil },
      { expiresAt: new Date(Date.parse(String(original.validUntil)) + 3600001).toISOString() },
      { validUntil: 'invalid' },
      { version: '' },
    ]) {
      f.rows.set(entry, { ...original, ...patch });
      await assert.rejects(magic.consume(issued.value, consume));
      f.rows.set(entry, original);
    }
    assert.equal((await magic.consume(issued.value, consume)).intent, 'login');
    await assert.rejects(magic.consume(issued.value, consume), { code: 'EK_MAGICLINK_REPLAY' });
  } finally {
    await app.stop();
  }
});

test('Magic link durable quota rows cannot fabricate ownership, hour or admission count', async () => {
  const f = fixture(),
    { app, magic } = await application({ ...f.settings, maxClaimsPerHour: 1000 });
  try {
    await magic.issue(f.owner, 'login');
    const quota = [...f.rows.entries()].find(([, row]) => row.kind === 'magic-link-quota-v1')!;
    for (const patch of [
      { kind: 'wrong-quota' },
      { ownerKey: '0'.repeat(64) },
      { hour: -1 },
      { count: -1 },
      { count: 1001 },
      { version: '' },
    ]) {
      f.rows.set(quota[0], { ...quota[1], ...patch });
      await assert.rejects(magic.issue(f.owner, 'login'));
      f.rows.set(quota[0], quota[1]);
    }
    assert.ok((await magic.issue(f.owner, 'login')).value.startsWith('ml1.'));
  } finally {
    await app.stop();
  }
});

test('Magic link malformed write acknowledgments never return a one-time credential', async () => {
  for (const receipt of [undefined, {}, { committed: 'true' }, { committed: true, version: '' }]) {
    const f = fixture();
    f.store.atomicBatch = async () => receipt as never;
    const { app, magic } = await application(f.settings);
    try {
      await assert.rejects(magic.issue(f.owner, 'login'));
      assert.equal([...f.rows.values()].filter((row) => row.kind === 'magic-link-v1').length, 0);
    } finally {
      await app.stop();
    }
  }
});

test('Magic link issuance, consumption and revocation bound rejected writes without fabricating success', async () => {
  const f = fixture(),
    batch = f.store.atomicBatch;
  let rejecting = false,
    rejected = 0;
  f.store.atomicBatch = async (...args) => {
    if (rejecting) {
      rejected++;
      return { committed: false };
    }
    return Reflect.apply(batch, f.store, args);
  };
  const { app, magic } = await application({ ...f.settings, maxClaimsPerHour: 1000 });
  try {
    const issued = await magic.issue(f.owner, 'login');
    rejecting = true;
    for (const work of [
      () => magic.issue(f.owner, 'login'),
      () => magic.consume(issued.value, consume),
      () => magic.revoke(issued.issueId),
    ]) {
      const before = rejected;
      await assert.rejects(work(), { code: 'EK_BACKEND_UNAVAILABLE' });
      assert.equal(rejected - before, 8);
    }
    rejecting = false;
    await magic.revoke(randomUUID());
    assert.equal((await magic.consume(issued.value, consume)).intent, 'login');
  } finally {
    await app.stop();
  }
});

test('Magic link canonical authorization cannot substitute another account or bypass original HMAC failure', async () => {
  const f = fixture(),
    require = f.settings.authority.require,
    verify = f.settings.hmac.verify;
  let foreign = true,
    malformed = false;
  f.settings.authority.require = async (...args) => {
    const subject = await Reflect.apply(require, f.settings.authority, args);
    return foreign ? { ...subject, subject: randomUUID() } : subject;
  };
  f.settings.hmac.verify = async (...args) =>
    malformed ? ('true' as never) : Reflect.apply(verify, f.settings.hmac, args);
  const { app, magic } = await application(f.settings);
  try {
    await assert.rejects(magic.issue(f.owner, 'login'), { code: 'EK_MAGICLINK_INVALID' });
    foreign = false;
    const issued = await magic.issue(f.owner, 'login');
    foreign = true;
    await assert.rejects(magic.consume(issued.value, consume), { code: 'EK_MAGICLINK_INVALID' });
    foreign = false;
    malformed = true;
    await assert.rejects(magic.consume(issued.value, consume), { code: 'EK_MAGICLINK_INVALID' });
    malformed = false;
    assert.equal((await magic.consume(issued.value, consume)).intent, 'login');
  } finally {
    await app.stop();
  }
});

test('Magic link late durable issuance cannot return an already expired credential', async (context) => {
  context.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixture(),
    batch = f.store.atomicBatch;
  f.store.atomicBatch = async (...args) => {
    const result = await Reflect.apply(batch, f.store, args);
    context.mock.timers.tick(1001);
    return result;
  };
  const { app, magic } = await application({ ...f.settings, ttlMs: 1000 });
  try {
    await assert.rejects(magic.issue(f.owner, 'login'), { code: 'EK_MAGICLINK_EXPIRED' });
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'magic-link-v1').length, 1);
  } finally {
    await app.stop();
  }
});

test('Magic link operation ownership checks readiness, real deadlines, cancellation and safe error codes', async () => {
  const { Calls } = await import('../../dist/runtime.js');
  const { capture } = await import('../../dist/settings.js');
  const { KitError } = await import('@arkenivajs/core');
  const f = fixture(),
    controller = new AbortController();
  let ready = false;
  const calls = new Calls(capture(f.settings), controller.signal, () => ready);
  try {
    await assert.rejects(
      calls.run(undefined, async () => {}),
      { code: 'EK_LIFECYCLE_STATE' },
    );
    ready = true;
    await assert.rejects(
      calls.run(undefined, async () => {
        throw new Error('Private untrusted failure');
      }),
      { code: 'EK_BACKEND_UNAVAILABLE' },
    );
    await assert.rejects(
      calls.run(undefined, async () => {
        throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Owned invalid call' });
      }),
      { code: 'EK_CONFIG_INVALID' },
    );
    await assert.rejects(
      calls.run({ timeoutMs: 5 }, async (call) => {
        const end = performance.now() + 10;
        while (performance.now() < end) {
          /* Hold the real event loop until the monotonic deadline passes. */
        }
        call.check();
      }),
      { code: 'EK_TIMEOUT' },
    );
    controller.abort();
    await assert.rejects(
      calls.run(undefined, async () => {}),
      { code: 'EK_RESOURCE_CLOSED' },
    );
  } finally {
    await calls.close();
  }
});

test('Magic link provider classifications and request descriptors reject executable or unsupported values', async () => {
  const { magicLinksPlugin } = await import('../../dist/index.js');
  const { fields, property, method, issueId } = await import('../../dist/validation.js');
  const f = fixture();
  Object.defineProperty(f.settings.authority, 'usage', { value: 'unsupported' });
  assert.throws(() => magicLinksPlugin(f.settings), { code: 'EK_CONFIG_INVALID' });
  let effects = 0;
  const accessor = Object.defineProperty({}, 'run', {
    get() {
      effects++;
      throw new Error('Executable provider field');
    },
  });
  assert.throws(() => fields({ [Symbol('untrusted')]: true }, []), { code: 'EK_CONFIG_INVALID' });
  for (const value of [null, accessor])
    assert.throws(() => property(value, 'run'), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => method({ run: false }, 'run'), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => issueId('invalid'), { code: 'EK_MAGICLINK_INVALID' });
  assert.equal(effects, 0);
});

test('Magic link observer exceptions cannot replace the expired outcome or disclose credentials', async () => {
  const { active, record } = await import('../../dist/observation.js');
  const { createLogger } = await import('@arkenivajs/logging');
  const { Writable } = await import('node:stream');
  const logger = createLogger({
    service: { name: 'magiclink-closed-observer', version: '1.0.0', environment: 'test' },
    level: 'debug',
    destination: new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
  });
  await logger.close();
  const observers = { logger };
  assert.doesNotThrow(() => active(observers, 1));
  assert.doesNotThrow(() =>
    record(
      observers,
      { operation: 'consume', purpose: 'login' },
      'EK_MAGICLINK_EXPIRED',
      1,
      randomUUID(),
    ),
  );
});
