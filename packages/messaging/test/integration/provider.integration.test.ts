// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import nats from 'nats';
import { createApplication } from '@arkenivajs/core';
import type { MessageEnvelope } from '@arkenivajs/core';
import { createNatsBus, messagingPlugin } from '@arkenivajs/messaging';
import type { MessageFailure } from '@arkenivajs/messaging';
import { natsConfiguration } from '../../dist/config.js';

async function eventually(check: () => boolean | Promise<boolean>) {
  const until = performance.now() + 5000;
  while (!(await check())) {
    assert.ok(performance.now() < until, 'Messaging evidence did not settle within its budget');
    await delay(5);
  }
}
function fixture() {
  assert.equal(
    process.env.ARKENIVA_NATS_DISPOSABLE,
    '1',
    'Only an explicitly disposable NATS fixture is permitted',
  );
  assert.ok(process.env.ARKENIVA_NATS_URL);
  return 'orders.' + randomUUID().replaceAll('-', '');
}

test(
  'Actual NATS uses verified TLS and scoped credentials, captures checked JSON and returns no invented broker acknowledgment',
  { timeout: 20000 },
  async () => {
    const topic = fixture(),
      failures: MessageFailure[] = [],
      messages: MessageEnvelope<{ name: string }>[] = [];
    const bus = await createNatsBus({
      connectionStringEnv: 'ARKENIVA_NATS_URL',
      onError: async (failure) => {
        failures.push(failure);
      },
    });
    try {
      assert.equal(await bus.health(), true);
      const subscription = await bus.subscribe<{ name: string }>(topic, async (message) => {
        messages.push(message);
      });
      const payload = { name: 'Ada' },
        publication = bus.publish(topic, payload, { correlationId: 'request-42' });
      payload.name = 'Changed';
      const receipt = await publication;
      assert.equal(receipt.acknowledged, false);
      await eventually(() => messages.length === 1 && bus.stats().activeHandlers === 0);
      assert.equal(messages[0]!.messageId, receipt.messageId);
      assert.deepEqual(messages[0]!.payload, { name: 'Ada' });
      assert.equal(messages[0]!.correlationId, 'request-42');
      assert.equal(messages[0]!.tenant, undefined);
      assert.ok(Object.isFrozen(messages[0]) && Object.isFrozen(messages[0]!.payload));
      assert.equal(bus.stats().retainedBytes, 0);
      await subscription.close();
      await subscription.close();
      await bus.publish(topic, { name: 'After closure' });
      await delay(10);
      assert.equal(messages.length, 1);
      assert.deepEqual(failures, []);
    } finally {
      await bus.close();
    }
    await assert.rejects(bus.publish(topic, {}), { code: 'EK_RESOURCE_CLOSED' });
  },
);

test(
  'Actual NATS wire tenant spoofing reaches the configured error strategy and cannot construct verified tenant state',
  { timeout: 20000 },
  async () => {
    const topic = fixture(),
      failures: MessageFailure[] = [],
      messages: MessageEnvelope<unknown>[] = [];
    const bus = await createNatsBus({
      connectionStringEnv: 'ARKENIVA_NATS_URL',
      onError: async (failure) => {
        failures.push(failure);
      },
    });
    const configuration = natsConfiguration('ARKENIVA_NATS_URL'),
      native = await nats.connect({ ...configuration.native });
    try {
      const subscription = await bus.subscribe(topic, async (message) => {
        messages.push(message);
      });
      const envelope = {
        schemaVersion: 1,
        messageId: randomUUID(),
        topic,
        payload: { orderId: '42' },
        tenant: { tenantId: 'spoofed' },
      };
      native.publish(configuration.prefix + topic, Buffer.from(JSON.stringify(envelope)));
      await native.flush();
      await eventually(() => failures.length === 1);
      assert.equal(failures[0]!.kind, 'wire');
      assert.equal(failures[0]!.message, undefined);
      assert.equal(messages.length, 0);
      await bus.publish(topic, { orderId: 'valid' });
      await eventually(() => messages.length === 1);
      assert.equal(messages[0]!.tenant, undefined);
      await subscription.close();
    } finally {
      await native.close();
      await bus.close();
    }
  },
);

test(
  'Actual reusable messaging plugins preserve prepared facade and per-application connection lifetime',
  { timeout: 20000 },
  async () => {
    const topic = fixture(),
      failures: MessageFailure[] = [];
    const plugin = messagingPlugin({
      connectionStringEnv: 'ARKENIVA_NATS_URL',
      onError: async (failure) => {
        failures.push(failure);
      },
    });
    const options = {
      service: { name: 'messaging-reuse', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    };
    const first = await createApplication(options),
      second = await createApplication(options);
    const stale = first.messaging!;
    assert.ok(Object.isFrozen(stale));
    await assert.rejects(stale.publish(topic, {}), { code: 'EK_LIFECYCLE_STATE' });
    try {
      await first.start();
      await second.start();
      assert.notEqual(first.messaging, second.messaging);
      await first.stop();
      await assert.rejects(stale.publish(topic, {}), { code: 'EK_RESOURCE_CLOSED' });
      const messages: MessageEnvelope<unknown>[] = [];
      const subscription = await second.messaging!.subscribe(topic, async (message) => {
        messages.push(message);
      });
      assert.equal((await second.messaging!.publish(topic, { active: true })).acknowledged, false);
      await eventually(() => messages.length === 1);
      await subscription.close();
      assert.deepEqual(failures, []);
    } finally {
      await first.stop();
      await second.stop();
    }
  },
);

test('Actual NATS scoped accounts isolate identical logical topics and reject a foreign namespace', async () => {
  const topic = fixture();
  assert.ok(process.env.ARKENIVA_NATS_BETA_URL);
  const failures: MessageFailure[] = [],
    received: string[][] = [[], []],
    buses = [];
  try {
    for (const [index, variable] of ['ARKENIVA_NATS_URL', 'ARKENIVA_NATS_BETA_URL'].entries()) {
      const bus = await createNatsBus({
        connectionStringEnv: variable,
        onError: async (failure) => {
          failures.push(failure);
        },
      });
      buses.push(bus);
      await bus.subscribe<string>(topic, async (message) => {
        received[index]!.push(message.payload);
      });
    }
    await buses[0]!.publish(topic, 'alpha');
    await buses[1]!.publish(topic, 'beta');
    await eventually(() => received[0]!.length === 1 && received[1]!.length === 1);
    assert.deepEqual(received, [['alpha'], ['beta']]);
    assert.equal(failures.length, 0);
    const foreign = new URL(process.env.ARKENIVA_NATS_URL!),
      beta = new URL(process.env.ARKENIVA_NATS_BETA_URL);
    foreign.searchParams.set('prefix', beta.searchParams.get('prefix')!);
    const variable = 'ARKENIVA_NATS_FOREIGN_' + randomUUID().replaceAll('-', '').toUpperCase();
    process.env[variable] = foreign.href;
    try {
      const unauthorized = await createNatsBus({
        connectionStringEnv: variable,
        onError: async (failure) => {
          failures.push(failure);
        },
      });
      buses.push(unauthorized);
      await assert.rejects(
        unauthorized.subscribe(topic, async () => {}),
        { code: 'EK_BACKEND_UNAVAILABLE' },
      );
      await eventually(() => failures.length > 0);
      assert.ok(['subscription', 'connection'].includes(failures[0]!.kind));
      assert.equal(await unauthorized.health(), false);
    } finally {
      delete process.env[variable];
    }
  } finally {
    const results = await Promise.allSettled(buses.map((bus) => bus.close()));
    for (const result of results) assert.equal(result.status, 'fulfilled');
  }
});
