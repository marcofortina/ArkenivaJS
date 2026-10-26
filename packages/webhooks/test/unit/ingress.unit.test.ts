// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import { createApplication } from '@arkenivajs/core';
import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '../../dist/index.js';
import type { WebhookService } from '../../dist/index.js';
import { fixture, fixtureSettings } from './fixture.js';

test('The runtime authority receives the validated destination and denies a configured but unauthorized resource before key access', async (t) => {
  const settings = fixtureSettings();
  settings.settings = {
    ...settings.settings,
    destinations: [
      ...settings.settings.destinations,
      { ...settings.settings.destinations[0]!, name: 'restricted' },
    ],
  };
  const f = await fixture(settings);
  t.after(f.close);
  await assert.rejects(
    f.asTenant('tenant-a', () =>
      f.service.send('restricted', { id: 'one', type: 'event', payload: null }),
    ),
    { code: 'EK_AUTH_FORBIDDEN' },
  );
  assert.equal(f.state.secretCalls, 0);
  assert.equal(f.state.claimCalls, 0);
});

test('Test-only stores are rejected in production and operations cannot run during plugin initialization', async () => {
  const f = fixtureSettings(),
    production = await createApplication({
      service: { name: 'webhook-production-guard', version: '1.0.0', environment: 'production' },
      plugins: [webhooksPlugin(f.settings)],
    });
  try {
    await assert.rejects(production.start());
  } finally {
    await production.stop();
  }
  let rejectedBeforeReady = false;
  const app = await createApplication({
    service: { name: 'webhook-initialization-guard', version: '1.0.0', environment: 'test' },
    plugins: [
      webhooksPlugin(f.settings),
      {
        id: 'webhook-initialization-probe',
        version: '1.0.0',
        capabilities: new Set(),
        dependencies: ['webhooks'],
        async init(context) {
          const service = context.require<WebhookService>(WEBHOOKS_CAPABILITY);
          await assert.rejects(
            f.asTenant('tenant-a', () => service.sign(Buffer.from('x'), 'current', f.context())),
            { code: 'EK_LIFECYCLE_STATE' },
          );
          rejectedBeforeReady = true;
        },
        close() {},
      },
    ],
  });
  try {
    await app.start();
    assert.equal(rejectedBeforeReady, true);
    assert.equal(f.state.secretCalls, 0);
  } finally {
    await app.stop();
  }
});

test('Binary and operation ingress rejects forged/shared bytes, getters, invalid deadlines and structural cancellation objects', async (t) => {
  const f = await fixture();
  t.after(f.close);
  for (const input of [
    Object.create(Uint8Array.prototype),
    new Uint8Array(new SharedArrayBuffer(32)),
    new Uint8Array(65537),
  ])
    await assert.rejects(
      f.asTenant('tenant-a', () => f.service.sign(input, 'current', f.context())),
      { code: 'EK_CONFIG_INVALID' },
    );
  for (const options of [
    { timeoutMs: 0 },
    { timeoutMs: -1 },
    { timeoutMs: 1.5 },
    { timeoutMs: Infinity },
    { signal: { aborted: false } },
  ])
    await assert.rejects(
      f.asTenant('tenant-a', () =>
        f.service.sign(
          Buffer.from('x'),
          'current',
          f.context(),
          options as Parameters<WebhookService['sign']>[3],
        ),
      ),
      { code: 'EK_CONFIG_INVALID' },
    );
  let read = false;
  const context = f.context();
  Object.defineProperty(context, 'eventId', {
    get() {
      read = true;
      return 'forged';
    },
  });
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.sign(Buffer.from('x'), 'current', context)),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(read, false);
  assert.equal(f.state.secretCalls, 0);
});

test('Input snapshots preserve raw bytes across provider waits and a structural byte getter cannot alter native copying', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const context = f.context(),
    body = Buffer.from('original'),
    saved = Buffer.from(body);
  let read = false;
  Object.defineProperty(body, 'byteLength', {
    get() {
      read = true;
      return 0;
    },
  });
  const pending = f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  body.fill(0);
  const signature = await pending;
  assert.equal(read, false);
  await f.asTenant('tenant-a', () => f.service.verify(saved, signature, context));
});

test('Canceling an in-flight nonce claim reports unknown, retains admission and never acknowledges a late claim', async (t) => {
  const settings = fixtureSettings(),
    original = settings.settings.nonceStore.store.claimOnce.bind(
      settings.settings.nonceStore.store,
    );
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    });
  settings.settings = {
    ...settings.settings,
    policy: { ...settings.settings.policy, maxConcurrent: 1 },
    nonceStore: {
      ...settings.settings.nonceStore,
      store: {
        ...settings.settings.nonceStore.store,
        async claimOnce(...args) {
          entered();
          await gate;
          return original(...args);
        },
      },
    },
  };
  const f = await fixture(settings);
  t.after(async () => {
    release();
    await f.close();
  });
  const body = Buffer.from('owned'),
    context = f.context(),
    signature = await f.asTenant('tenant-a', () => f.service.sign(body, 'current', context));
  const controller = new AbortController(),
    pending = f.asTenant('tenant-a', () =>
      f.service.verify(body, signature, context, { signal: controller.signal }),
    );
  void pending.catch(() => undefined);
  await started;
  controller.abort();
  await assert.rejects(pending, (error: unknown) => {
    assert.equal((error as { code: string }).code, 'EK_ABORTED');
    assert.equal((error as { details: { outcome: string } }).details.outcome, 'unknown');
    return true;
  });
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  release();
  await immediate();
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.verify(body, signature, context)),
    { code: 'EK_WEBHOOK_REPLAY' },
  );
});

test('Closed services reject synchronous parsing and asynchronous signing without reopening providers', async () => {
  const f = await fixture();
  await f.close();
  assert.throws(
    () => f.service.parseEvent(Buffer.from('{"id":"one","type":"event","payload":null}')),
    { code: 'EK_RESOURCE_CLOSED' },
  );
  await assert.rejects(
    f.asTenant('tenant-a', () => f.service.sign(Buffer.from('x'), 'current', f.context())),
    { code: 'EK_RESOURCE_CLOSED' },
  );
  assert.equal(f.state.secretCalls, 0);
});
