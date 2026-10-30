// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import nats from 'nats';

export function natsConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.equal(url.protocol, 'tls:');
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.ok(url.port && url.username && url.password);
    assert.ok(['', '/'].includes(url.pathname));
    for (const key of url.searchParams.keys()) {
      assert.ok(['prefix', 'caFile', 'certFile', 'keyFile'].includes(key));
      assert.equal(url.searchParams.getAll(key).length, 1);
    }
    assert.match(url.searchParams.get('prefix'), /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.$/);
    for (const key of ['caFile', 'certFile', 'keyFile'])
      assert.ok(url.searchParams.get(key)?.startsWith('/'));
    return url;
  } catch {
    throw new Error(
      'The owned NATS comparison requires scoped credentials and verified loopback mutual TLS',
    );
  }
}

export async function connectNats(fixture) {
  const url = natsConnection(fixture);
  try {
    return await nats.connect({
      servers: ['tls://' + url.host],
      user: decodeURIComponent(url.username),
      pass: decodeURIComponent(url.password),
      tls: {
        ca: await readFile(url.searchParams.get('caFile'), 'utf8'),
        cert: await readFile(url.searchParams.get('certFile'), 'utf8'),
        key: await readFile(url.searchParams.get('keyFile'), 'utf8'),
        handshakeFirst: true,
      },
      reconnect: false,
      timeout: 3000,
      ignoreClusterUpdates: true,
      noRandomize: true,
    });
  } catch {
    throw new Error('The owned native NATS comparison connection failed');
  }
}

/** This baseline handles only the declared valid JSON envelope, without duplicating framework policy. */
export async function nativeNats(fixture) {
  const client = await connectNats(fixture),
    prefix = natsConnection(fixture).searchParams.get('prefix');
  const tasks = new Set(),
    failures = [];
  return {
    async publish(topic, payload, options) {
      const messageId = randomUUID();
      client.publish(
        prefix + topic,
        Buffer.from(
          JSON.stringify({
            schemaVersion: 1,
            messageId,
            topic,
            payload,
            correlationId: options.correlationId,
          }),
        ),
      );
      await client.flush();
      return { messageId, acknowledged: false };
    },
    async subscribe(topic, handler) {
      const subscription = client.subscribe(prefix + topic, {
        callback(cause, message) {
          const task = Promise.resolve()
            .then(async () => {
              if (cause) throw cause;
              const { schemaVersion, ...envelope } = JSON.parse(
                Buffer.from(message.data).toString('utf8'),
              );
              assert.equal(schemaVersion, 1);
              await handler(envelope);
            })
            .catch((failure) => failures.push(failure))
            .finally(() => tasks.delete(task));
          tasks.add(task);
        },
      });
      await client.flush();
      return {
        close: async () => {
          subscription.unsubscribe();
          await client.flush();
          await Promise.all([...tasks]);
          assert.equal(failures.length, 0);
        },
      };
    },
    async close() {
      await client.drain();
      await Promise.all([...tasks]);
      assert.equal(failures.length, 0);
    },
  };
}

async function waitUntil(check, failures) {
  const until = performance.now() + 3000;
  while (!check()) {
    assert.equal(failures.length, 0);
    assert.ok(
      performance.now() < until,
      'The owned NATS message observations exceeded their deadline',
    );
    await delay(5);
  }
  assert.equal(failures.length, 0);
}

export async function verifyNats(service, fixture) {
  const observer = await connectNats(fixture),
    prefix = natsConnection(fixture).searchParams.get('prefix');
  const wires = [],
    received = [],
    failures = [];
  let subscription, nativeSubscription;
  try {
    nativeSubscription = observer.subscribe(prefix + fixture.topic, {
      callback(cause, message) {
        try {
          if (cause) throw cause;
          wires.push(JSON.parse(Buffer.from(message.data).toString('utf8')));
        } catch (failure) {
          failures.push(failure);
        }
      },
    });
    await observer.flush();
    subscription = await service.subscribe(fixture.topic, async (message) => {
      received.push(message);
    });
    const incomingId = randomUUID();
    observer.publish(
      prefix + fixture.topic,
      Buffer.from(
        JSON.stringify({
          schemaVersion: 1,
          messageId: incomingId,
          topic: fixture.topic,
          payload: { marker: fixture.marker, sequence: 1 },
          correlationId: fixture.correlation,
        }),
      ),
    );
    await observer.flush();
    await waitUntil(() => received.length === 1 && wires.length === 1, failures);
    const receipt = await service.publish(
      fixture.topic,
      { marker: fixture.marker, sequence: 2 },
      { correlationId: fixture.correlation },
    );
    assert.equal(receipt.acknowledged, false);
    await waitUntil(() => received.length === 2 && wires.length === 2, failures);
    for (let index = 0; index < 2; index++) {
      assert.deepEqual(wires[index], {
        schemaVersion: 1,
        messageId: index === 0 ? incomingId : receipt.messageId,
        topic: fixture.topic,
        payload: { marker: fixture.marker, sequence: index + 1 },
        correlationId: fixture.correlation,
      });
      const { schemaVersion, ...envelope } = wires[index];
      assert.equal(schemaVersion, 1);
      assert.deepEqual(received[index], envelope);
      assert.equal(received[index].tenant, undefined);
    }
    return {
      nativeToServiceVerified: true,
      serviceToNativeVerified: true,
      actualMessagesObserved: 2,
      exactEnvelopeVerified: true,
      correlationPreserved: true,
      inventedTenantAbsent: true,
      acknowledged: false,
    };
  } finally {
    try {
      await subscription?.close();
    } finally {
      nativeSubscription?.unsubscribe();
      await observer.drain();
    }
  }
}
