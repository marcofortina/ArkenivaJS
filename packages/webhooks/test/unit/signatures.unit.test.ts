// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, randomBytes } from 'node:crypto';
import { setImmediate as immediate } from 'node:timers/promises';
import { fixture, fixtureSettings } from './fixture.js';
import { webhooksPlugin } from '../../dist/index.js';
import type { WebhookContext, WebhookEvent, WebhooksPluginSettings } from '../../dist/index.js';

test('The versioned raw-byte signature interoperates with the independent WebCrypto HMAC API', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const context = f.context({ timestamp: new Date().toISOString() }),
    body = Buffer.from(' {"raw":  "private-body"}\n');
  const signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  const framing = Buffer.from(
    JSON.stringify([
      'arkenivajs.webhooks.v1',
      'tenant-a',
      'receiver',
      'event-one',
      context.timestamp,
      context.nonce,
      'one',
    ]) + '\n',
  );
  const key = await webcrypto.subtle.importKey(
    'raw',
    new Uint8Array(f.keys.get('current')!.bytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const expected = await webcrypto.subtle.sign(
    'HMAC',
    key,
    new Uint8Array(Buffer.concat([framing, body])),
  );
  assert.equal(signature.signature, Buffer.from(expected).toString('base64url'));
  assert.equal(signature.algorithm, 'hmac-sha256');
  assert.ok(Object.isFrozen(signature));
  assert.equal(f.state.claimCalls, 0);
  const before = Date.now(),
    verified = await f.asTenant('tenant-a', () => f.service.verify(body, signature, context));
  assert.equal(verified.destinationId, 'receiver');
  assert.equal(verified.eventId, 'event-one');
  assert.ok(
    Date.parse(verified.verifiedAt) >= before && Date.parse(verified.verifiedAt) <= Date.now(),
  );
});

test('Body, context and tenant mutations fail before a durable nonce claim and cannot be bypassed with constructed objects', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const context = f.context(),
    body = Buffer.from('{"private":"payload"}'),
    signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  for (const changed of [Buffer.from('{ "private": "payload" }'), Buffer.from('{}')])
    await assert.rejects(
      f.asTenant('tenant-a', () => f.service.verify(changed, signature, context)),
      { code: 'EK_WEBHOOK_SIGNATURE' },
    );
  for (const changed of [
    { eventId: 'another-event' },
    { nonce: randomBytes(24).toString('base64url') },
    { timestamp: new Date(Date.now() - 1000).toISOString() },
    { keyId: 'other' },
  ])
    await assert.rejects(
      f.asTenant('tenant-a', () => f.service.verify(body, signature, { ...context, ...changed })),
      { code: 'EK_WEBHOOK_SIGNATURE' },
    );
  await assert.rejects(
    f.asTenant('tenant-b', () => f.service.verify(body, signature, context)),
    { code: 'EK_WEBHOOK_SIGNATURE' },
  );
  await assert.rejects(f.service.verify(body, signature, context), { code: 'EK_AUTH_FORBIDDEN' });
  await assert.rejects(
    f.asTenant('tenant-a', () =>
      f.service.sign(body, 'current', { ...context, tenant: 'tenant-b' } as WebhookContext),
    ),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(f.state.claimCalls, 0);
  await f.asTenant('tenant-a', () => f.service.verify(body, signature, context));
  assert.equal(f.state.claimCalls, 1);
  const log = f.logs.join('');
  assert.ok(!log.includes(signature.signature));
  assert.ok(!log.includes('payload'));
});

test('Atomic nonce claims admit exactly one concurrent verifier and remain consumed across key rotation', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const context = f.context(),
    body = Buffer.from('body'),
    signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  const results = await Promise.allSettled(
    Array.from({ length: 4 }, () =>
      f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    ),
  );
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(
    results.filter(
      (result) => result.status === 'rejected' && result.reason.code === 'EK_WEBHOOK_REPLAY',
    ).length,
    3,
  );
  f.keys.set('current', { bytes: randomBytes(32), keyVersion: 'two' });
  const rotated = { ...context, keyId: 'two' },
    fresh = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', rotated));
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, fresh, rotated)),
    { code: 'EK_WEBHOOK_REPLAY' },
  );
});

test('Retained verification references allow only an explicit unexpired key version and never permit retired-key signing', async (t) => {
  const settings = fixtureSettings(),
    before = settings.keys.get('current')!;
  settings.keys.set('previous', before);
  const profile = {
    ...settings.settings.destinations[0]!,
    verificationKeys: [
      {
        keyId: 'one',
        hmacKeyRef: 'previous',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      },
    ],
  };
  settings.settings = { ...settings.settings, destinations: [profile] };
  const f = await fixture(settings);
  t.after(f.close);
  const context = f.context(),
    body = Buffer.from('body'),
    signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  f.keys.set('current', { bytes: randomBytes(32), keyVersion: 'two' });
  await f.asTenant('tenant-a', () => f.service.verify(body, signature, context));
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.sign(body, 'previous', f.context({ keyId: 'one' }))),
    { code: 'EK_WEBHOOK_SIGNATURE' },
  );
  f.keys.delete('previous');
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    { code: 'EK_WEBHOOK_SIGNATURE' },
  );
});

test('Clock skew, provider outages and failed persistence never turn verification into success', async (t) => {
  const f = await fixture();
  t.after(f.close);
  for (const offset of [-600000, 600000])
    await assert.rejects(
      f.asTenant('tenant-a', () =>
        f.service.sign(
          Buffer.from('x'),
          'current',
          f.context({ timestamp: new Date(Date.now() + offset).toISOString() }),
        ),
      ),
      { code: 'EK_WEBHOOK_SIGNATURE' },
    );
  const context = f.context(),
    body = Buffer.from('x'),
    signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  f.state.authorityAvailable = false;
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    { code: 'EK_AUTH_FORBIDDEN' },
  );
  f.state.authorityAvailable = true;
  f.state.secretsAvailable = false;
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    { code: 'EK_WEBHOOK_SIGNATURE' },
  );
  f.state.secretsAvailable = true;
  f.state.storeAvailable = false;
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    (error: unknown) => {
      assert.equal((error as { code: string }).code, 'EK_WEBHOOK_REPLAY');
      assert.ok(!String(error).includes('Private fixture'));
      return true;
    },
  );
  assert.equal(f.claims.size, 0);
});

test('Canceled secret-provider work retains admission and cannot sign after its public waiter expires', async (t) => {
  const settings = fixtureSettings();
  settings.settings = {
    ...settings.settings,
    policy: { ...settings.settings.policy, maxConcurrent: 1 },
  };
  const f = await fixture(settings);
  t.after(f.close);
  let release!: () => void;
  f.state.holdKey = new Promise<void>((resolve) => {
    release = resolve;
  });
  const controller = new AbortController(),
    task = f.asTenant('tenant-a', () =>
      f.service.sign(Buffer.from('x'), 'current', f.context(), { signal: controller.signal }),
    );
  void task.catch(() => undefined);
  while (f.state.secretCalls === 0) await immediate();
  controller.abort();
  await assert.rejects(task, { code: 'EK_ABORTED' });
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.sign(Buffer.from('x'), 'current', f.context())),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  release();
  f.state.holdKey = undefined;
  await immediate();
  await f.asTenant('tenant-a', () => f.service.sign(Buffer.from('x'), 'current', f.context()));
});

test('parseEvent bounds native JSON, rejects pollution/cycles and returns immutable data without trusting payload identity', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const parsed = f.service.parseEvent(
    Buffer.from('{"id":"one","type":"order.created","payload":{"tenant":"untrusted"}}'),
  );
  assert.equal(parsed.id, 'one');
  assert.ok(Object.isFrozen(parsed));
  assert.ok(Object.isFrozen(parsed.payload));
  for (const input of [
    '{"id":"one","type":"x","payload":{"__proto__":{}}}',
    '{}',
    '[1]',
    '{',
    '{"id":"one","type":"x","payload":null,"extra":true}',
  ])
    assert.throws(() => f.service.parseEvent(Buffer.from(input)), { code: 'EK_WEBHOOK_DELIVERY' });
  assert.throws(() => f.service.parseEvent(new Uint8Array([255])), { code: 'EK_WEBHOOK_DELIVERY' });
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  await assert.rejects(
    f.asTenant('tenant-a', () =>
      f.service.send('receiver', { id: 'one', type: 'x', payload: cyclic } as WebhookEvent),
    ),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(f.state.secretCalls, 0);
});

test('Factory contracts reject missing providers, unsafe destinations and retries without an explicit receiver guarantee', () => {
  const f = fixtureSettings(),
    base = f.settings;
  for (const change of [
    { policy: { ...base.policy, timeoutMs: 0 } },
    { policy: { ...base.policy, maxConcurrent: Infinity } },
    { nonceStore: { ...base.nonceStore, store: { claimOnce: async () => true } } },
    { authority: {} },
    { unknown: true },
    { destinations: [{ ...base.destinations[0], maxRetries: 1 }] },
    { destinations: [{ ...base.destinations[0], origin: 'http://external.example' }] },
    { destinations: [{ ...base.destinations[0], allowedCidrs: ['127.0.0.1/129'] }] },
    { destinations: [{ ...base.destinations[0], allowedCidrs: [] }] },
  ])
    assert.throws(() => webhooksPlugin({ ...base, ...change } as WebhooksPluginSettings), {
      code: 'EK_CONFIG_INVALID',
    });
});
