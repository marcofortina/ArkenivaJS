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

const workloads = new WeakMap();

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
    const state = {
      service,
      fixture,
      callbacks: 0,
      completed: 0,
      active: 0,
      peakActive: 0,
      nativeDeliveries: 0,
      serviceDeliveries: 0,
      observedBytes: 0,
      expectedBytes: 0,
      unacknowledgedReceipts: 0,
      pending: undefined,
      failure: undefined,
      observer: undefined,
      subscription: undefined,
      nativeSubscription: undefined,
      setup: undefined,
      closing: undefined,
    };
    workloads.set(service, state);
    workloads.set(fixture, state);
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

/** Exact independently observed bytes never establish broker durability or tenant authority. */
export function verifyNatsReceipt(wire, delivered, receipt, fixture, sequence, wireBytes) {
  assert.equal(receipt.acknowledged, false);
  assert.equal(typeof receipt.messageId, 'string');
  assert.match(receipt.messageId, /^[a-f0-9-]{36}$/);
  const expected = {
    schemaVersion: 1,
    messageId: receipt.messageId,
    topic: fixture.topic,
    payload: { marker: fixture.marker, sequence },
    correlationId: fixture.correlation,
  };
  assert.deepEqual(wire, expected);
  const { schemaVersion, ...envelope } = expected;
  assert.equal(schemaVersion, 1);
  assert.deepEqual(delivered, envelope);
  assert.equal(delivered.tenant, undefined);
  const expectedBytes = Buffer.byteLength(JSON.stringify(expected));
  assert.equal(wireBytes, expectedBytes);
  return expectedBytes;
}

async function prepareWorkload(state) {
  const observer = await connectNats(state.fixture),
    prefix = natsConnection(state.fixture).searchParams.get('prefix');
  state.observer = observer;
  const fail = () => {
    state.failure ??= new Error('The owned NATS smoke observation failed');
    state.pending?.reject(state.failure);
  };
  const accept = (kind, envelope, byteLength) => {
    try {
      const pending = state.pending;
      assert.ok(pending, 'No publication owns this delivery');
      assert.equal(pending[kind], undefined, 'A publication was delivered more than once');
      assert.equal(envelope.topic, state.fixture.topic);
      assert.equal(envelope.correlationId, state.fixture.correlation);
      assert.deepEqual(envelope.payload, {
        marker: state.fixture.marker,
        sequence: pending.sequence,
      });
      assert.equal(envelope.tenant, undefined);
      pending[kind] = envelope;
      if (kind === 'wire') {
        assert.ok(Number.isSafeInteger(byteLength) && byteLength > 0 && byteLength <= 4096);
        pending.wireBytes = byteLength;
        state.observedBytes += byteLength;
        state.nativeDeliveries++;
      } else state.serviceDeliveries++;
      if (pending.wire && pending.delivered) pending.resolve();
    } catch {
      fail();
    }
  };
  state.nativeSubscription = observer.subscribe(prefix + state.fixture.topic, {
    callback(cause, message) {
      try {
        if (cause) throw cause;
        assert.ok(message.data.byteLength <= 4096);
        accept(
          'wire',
          JSON.parse(Buffer.from(message.data).toString('utf8')),
          message.data.byteLength,
        );
      } catch {
        fail();
      }
    },
  });
  await observer.flush();
  state.subscription = await state.service.subscribe(state.fixture.topic, async (message) => {
    accept('delivered', message);
  });
}

/** Keep at most one private envelope while waiting for a flush and two actual observations. */
export function natsWorkload(service) {
  const state = workloads.get(service);
  assert.ok(state, 'NATS corpus verification must precede workload execution');
  return {
    'publish-flush-and-dual-observed-receipt': async () => {
      assert.equal(state.active, 0);
      assert.equal(state.closing, undefined);
      assert.equal(state.failure, undefined);
      state.callbacks++;
      state.active++;
      state.peakActive = Math.max(state.peakActive, state.active);
      let timer;
      try {
        // Lazy fixture subscriptions are created during the first warmup callback.
        state.setup ??= prepareWorkload(state);
        await state.setup;
        let resolve, reject;
        const observed = new Promise((done, fail) => {
          resolve = done;
          reject = fail;
        });
        void observed.catch(() => undefined);
        const pending = { sequence: state.callbacks, resolve, reject };
        state.pending = pending;
        timer = setTimeout(
          () => reject(new Error('The owned NATS smoke receipt exceeded its deadline')),
          3000,
        );
        const receipt = await service.publish(
          state.fixture.topic,
          { marker: state.fixture.marker, sequence: pending.sequence },
          { correlationId: state.fixture.correlation },
        );
        await observed;
        assert.equal(state.failure, undefined);
        state.expectedBytes += verifyNatsReceipt(
          pending.wire,
          pending.delivered,
          receipt,
          state.fixture,
          pending.sequence,
          pending.wireBytes,
        );
        state.unacknowledgedReceipts++;
        state.completed++;
        return true;
      } finally {
        clearTimeout(timer);
        state.pending = undefined;
        state.active--;
      }
    },
  };
}

/** Retire both subscriptions and the independently owned native connection on all exit paths. */
export async function closeNatsWorkload(owner) {
  const state = workloads.get(owner);
  if (!state) return;
  state.closing ??= (async () => {
    await state.setup?.catch(() => undefined);
    try {
      await state.subscription?.close();
      state.subscription = undefined;
    } finally {
      state.nativeSubscription?.unsubscribe();
      state.nativeSubscription = undefined;
      await state.observer?.drain();
      assert.ok(!state.observer || state.observer.isClosed());
      state.observer = undefined;
    }
  })();
  await state.closing;
}

export async function natsObservations(service, { measure, records }) {
  const state = workloads.get(service);
  assert.ok(state, 'NATS corpus verification must precede completion');
  await closeNatsWorkload(service);
  assert.equal(state.failure, undefined);
  assert.equal(state.completed, state.callbacks);
  assert.equal(state.nativeDeliveries, state.callbacks);
  assert.equal(state.serviceDeliveries, state.callbacks);
  assert.equal(state.unacknowledgedReceipts, state.callbacks);
  assert.equal(state.observedBytes, state.expectedBytes);
  assert.equal(state.active, 0);
  assert.equal(state.pending, undefined);
  assert.equal(state.subscription, undefined);
  assert.equal(state.nativeSubscription, undefined);
  assert.equal(state.observer, undefined);
  assert.ok(state.peakActive <= 1);
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'publish-flush-and-dual-observed-receipt');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
    assert.equal(state.callbacks, record.sampleCount + record.warmupIterations);
  } else assert.equal(records.length, 0);
  return {
    actualPublicationCallbacks: state.callbacks,
    completedPublications: state.completed,
    nativeObservedDeliveries: state.nativeDeliveries,
    serviceHandlerDeliveries: state.serviceDeliveries,
    observedEnvelopeBytes: state.observedBytes,
    unacknowledgedReceipts: state.unacknowledgedReceipts,
    activeCallbacks: state.active,
    pendingReceipts: state.pending ? 1 : 0,
    ownedSubscriptions: Number(!!state.subscription) + Number(!!state.nativeSubscription),
    independentConnections: Number(!!state.observer),
    peakConcurrentCallbacks: state.peakActive,
    acknowledged: false,
  };
}
