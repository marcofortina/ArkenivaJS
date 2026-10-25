import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createNatsBus } from '@arkenivajs/messaging';
import type { MessageFailure } from '@arkenivajs/messaging';
import { KitError } from '@arkenivajs/core';
import type { MessageEnvelope } from '@arkenivajs/core';
import { natsNetworkProxy } from '../fixtures/network-proxy.js';

async function eventually(check: () => boolean | Promise<boolean>) {
  const until = performance.now() + 5000;
  while (!(await check())) {
    assert.ok(performance.now() < until, 'Real NATS transport did not settle');
    await delay(5);
  }
}
test(
  'Real NATS lost round-trip replies remain uncertain and are never replayed when native subscriptions reconnect',
  { timeout: 20000 },
  async () => {
    const proxy = await natsNetworkProxy(),
      variable = 'ARKENIVA_NATS_RELAY_' + randomBytes(12).toString('hex').toUpperCase();
    const url = new URL(process.env.ARKENIVA_NATS_URL!);
    url.port = String(proxy.port);
    process.env[variable] = url.href;
    const failures: MessageFailure[] = [],
      delivered: MessageEnvelope<unknown>[] = [],
      replies: MessageEnvelope<unknown>[] = [];
    const writer = await createNatsBus({
      connectionStringEnv: variable,
      onError: async (failure) => {
        failures.push(failure);
      },
    });
    const reader = await createNatsBus({
      connectionStringEnv: 'ARKENIVA_NATS_URL',
      onError: async (failure) => {
        failures.push(failure);
      },
    });
    const topic = 'fault.' + randomBytes(12).toString('hex'),
      response = topic + '.response';
    try {
      const receiving = await reader.subscribe(topic, async (message) => {
        delivered.push(message);
      });
      const returning = await writer.subscribe(response, async (message) => {
        replies.push(message);
      });
      proxy.pauseReplies();
      await assert.rejects(
        writer.publish(topic, { effect: 'once' }, { timeoutMs: 200 }),
        (cause: unknown) =>
          cause instanceof KitError &&
          cause.code === 'EK_TIMEOUT' &&
          cause.details.outcome === 'unknown',
      );
      await eventually(() => delivered.length === 1);
      assert.equal(writer.stats().pendingPublications, 1);
      proxy.disconnect();
      await eventually(() => !writer.stats().connected && writer.stats().pendingPublications === 0);
      await assert.rejects(writer.publish(topic, { effect: 'must-not-queue' }), {
        code: 'EK_BACKEND_UNAVAILABLE',
      });
      proxy.resumeReplies();
      proxy.resume();
      await eventually(() => writer.stats().connected);
      // A separate publisher needs a broker round trip after native subscription restoration.
      assert.equal(await writer.health(), true);
      await reader.publish(response, { reconnected: true });
      await eventually(() => replies.length === 1);
      await writer.publish(topic, { effect: 'new' });
      await eventually(() => delivered.length === 2);
      assert.equal(new Set(delivered.map((message) => message.messageId)).size, 2);
      assert.deepEqual(
        delivered.map((message) => message.payload),
        [{ effect: 'once' }, { effect: 'new' }],
      );
      assert.equal(writer.stats().retainedBytes, 0);
      assert.deepEqual(failures, []);
      await receiving.close();
      await returning.close();
    } finally {
      proxy.resumeReplies();
      proxy.resume();
      try {
        await writer.close();
        await reader.close();
      } finally {
        delete process.env[variable];
        await proxy.close();
      }
    }
  },
);

test(
  'Real messaging startup rejects wrong TLS identity, untrusted authority, missing client certificate and invalid credentials',
  { timeout: 40000 },
  async () => {
    assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_NATS_URL);
    assert.ok(process.env.ARKENIVA_NATS_WRONG_SAN_URL);
    const authority = new URL(process.env.ARKENIVA_NATS_URL),
      certificate = new URL(process.env.ARKENIVA_NATS_URL),
      credentials = new URL(process.env.ARKENIVA_NATS_URL);
    authority.searchParams.delete('caFile');
    certificate.searchParams.delete('certFile');
    certificate.searchParams.delete('keyFile');
    credentials.password = 'disposable-invalid-password';
    const variable = 'ARKENIVA_NATS_NEGATIVE_' + randomBytes(12).toString('hex').toUpperCase();
    try {
      for (const value of [
        process.env.ARKENIVA_NATS_WRONG_SAN_URL,
        authority.href,
        certificate.href,
        credentials.href,
      ]) {
        process.env[variable] = value;
        await assert.rejects(
          createNatsBus({ connectionStringEnv: variable, onError: async () => {} }),
          (cause: unknown) =>
            cause instanceof KitError &&
            ['EK_BACKEND_UNAVAILABLE', 'EK_TIMEOUT'].includes(cause.code),
        );
      }
    } finally {
      delete process.env[variable];
    }
  },
);
