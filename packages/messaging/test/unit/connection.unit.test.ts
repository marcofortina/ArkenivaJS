import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import nats from 'nats';
import { KitError } from '@arkenivajs/core';
import type { MessageEnvelope, Subscription } from '@arkenivajs/core';
import type { Telemetry, UsageMeter } from '@arkenivajs/core';
import type { MessageFailure, NatsBusOptions } from '@arkenivajs/messaging';
import { NatsBus, messageOptions } from '../../dist/connection.js';
import { encodeMessage } from '../../dist/wire.js';
import { nativeDouble, deferred } from '../fixtures/native-double.js';

async function fixture(context: TestContext, options: Partial<NatsBusOptions> = {}) {
  const sdk = nativeDouble(),
    failures: MessageFailure[] = [];
  const bus = new NatsBus(
    { prefix: 'test.alpha.', native: {} },
    {
      onError: async (failure) => {
        failures.push(failure);
      },
      ...options,
    },
    sdk.connect,
  );
  await bus.start();
  context.after(async () => {
    await bus.close().catch(() => undefined);
  });
  return { sdk, bus, failures };
}
async function eventually(check: () => boolean) {
  const until = performance.now() + 2000;
  while (!check()) {
    assert.ok(performance.now() < until, 'Owned messaging work did not settle');
    await delay(1);
  }
}

test('Messaging public work is admitted once, captures JSON and never claims core NATS acknowledgment', async (context) => {
  const f = await fixture(context),
    messages: MessageEnvelope<{ value: number }>[] = [];
  const subscription = await f.bus.subscribe<{ value: number }>(
    'orders.created',
    async (message) => {
      messages.push(message);
    },
  );
  const payload = { value: 1 },
    pending = f.bus.publish('orders.created', payload, { correlationId: 'request-1' });
  payload.value = 2;
  const receipt = await pending;
  await eventually(() => messages.length === 1 && f.bus.stats().activeHandlers === 0);
  assert.equal(receipt.acknowledged, false);
  assert.equal(messages[0]!.messageId, receipt.messageId);
  assert.equal(messages[0]!.tenant, undefined);
  assert.deepEqual(messages[0]!.payload, { value: 1 });
  assert.equal(f.sdk.frames.length, 1);
  assert.equal(f.sdk.frames[0]!.subject, 'test.alpha.orders.created');
  await subscription.close();
  await subscription.close();
  assert.equal(f.bus.stats().subscriptions, 0);
  assert.equal(f.bus.stats().retainedBytes, 0);
});

test('Messaging retains interrupted native publications until actual settlement without replay or overlapping capacity', async (context) => {
  const f = await fixture(context),
    gate = deferred<void>();
  f.sdk.flushGate(gate.promise);
  context.after(() => {
    gate.resolve();
    f.sdk.flushGate();
  });
  const controllers = Array.from({ length: 64 }, () => new AbortController());
  const writes = controllers.map((controller) =>
    assert.rejects(
      f.bus.publish('bounded', {}, { signal: controller.signal }),
      (cause: unknown) =>
        cause instanceof KitError &&
        cause.code === 'EK_ABORTED' &&
        cause.details.outcome === 'unknown',
    ),
  );
  await eventually(() => f.sdk.frames.length === 64);
  for (const controller of controllers) controller.abort();
  await Promise.all(writes);
  assert.equal(f.sdk.frames.length, 64);
  assert.equal(f.bus.stats().pendingPublications, 64);
  await assert.rejects(f.bus.publish('overflow', {}), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(f.sdk.frames.length, 64);
  gate.resolve();
  f.sdk.flushGate();
  await eventually(() => f.bus.stats().pendingPublications === 0);
  assert.equal(f.bus.stats().retainedBytes, 0);
  await f.bus.publish('recovered', {});
  assert.equal(f.sdk.frames.length, 65);
});

test('Messaging fails new calls while disconnected and uses native reconnection only to restore future work', async (context) => {
  const f = await fixture(context);
  f.sdk.status(nats.Events.Disconnect);
  await eventually(() => !f.bus.stats().connected);
  await assert.rejects(f.bus.publish('offline', {}), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(await f.bus.health(), false);
  assert.equal(f.sdk.frames.length, 0);
  f.sdk.status(nats.Events.Reconnect);
  await eventually(() => f.bus.stats().connected);
  await f.bus.publish('after.reconnect', {});
  assert.equal(f.sdk.frames.length, 1);
  assert.equal(await f.bus.health(), true);
});

test('Messaging handlers report one failure to policy and continue subsequent messages without redelivery', async (context) => {
  const f = await fixture(context),
    messages: string[] = [];
  const subscription = await f.bus.subscribe<{ fail: boolean }>('events', async (message) => {
    messages.push(message.messageId);
    if (message.payload.fail) throw new Error('private-handler-fault');
  });
  await f.bus.publish('events', { fail: true });
  await eventually(() => f.failures.length === 1);
  assert.equal(f.failures[0]!.kind, 'handler');
  assert.equal(f.failures[0]!.message!.messageId, messages[0]);
  await f.bus.publish('events', { fail: false });
  await eventually(() => messages.length === 2 && f.bus.stats().activeHandlers === 0);
  assert.equal(f.failures.length, 1);
  assert.equal(f.sdk.frames.length, 2);
  await subscription.close();
});

test('Messaging rejects spoofed wire envelopes before handlers and bounds malformed incoming data', async (context) => {
  const f = await fixture(context);
  let handled = 0;
  const subscription = await f.bus.subscribe('wire', async () => {
    handled++;
  });
  for (const bytes of [
    Buffer.from('{'),
    Buffer.from([0xff]),
    Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        messageId: randomUUID(),
        topic: 'wire',
        payload: {},
        tenant: { tenantId: 'spoof' },
      }),
    ),
  ])
    f.sdk.deliver('test.alpha.wire', bytes);
  await eventually(() => f.failures.length === 3);
  assert.ok(f.failures.every((entry) => entry.kind === 'wire' && entry.message === undefined));
  assert.equal(handled, 0);
  f.sdk.deliver(
    'test.alpha.wire',
    encodeMessage({ schemaVersion: 1, messageId: randomUUID(), topic: 'wire', payload: null }),
  );
  await eventually(() => handled === 1);
  await subscription.close();
});

test('Messaging lifetime cancellation from its own handler unregisters without self-await deadlock', async (context) => {
  const f = await fixture(context),
    stop = new AbortController();
  let handled = 0;
  await f.bus.subscribe(
    'cancel',
    async () => {
      handled++;
      stop.abort();
    },
    { signal: stop.signal },
  );
  await f.bus.publish('cancel', {});
  await eventually(() => handled === 1 && f.bus.stats().subscriptions === 0);
  assert.equal(f.sdk.counts.subscriptions, 0);
  assert.equal(f.bus.stats().failed, 0);
});

test('Messaging self-awaited close is rejected explicitly and external closure remains usable', async (context) => {
  const f = await fixture(context);
  let completed = false;
  const subscription = await f.bus.subscribe('self.close', async () => {
    await assert.rejects(subscription.close(), { code: 'EK_LIFECYCLE_STATE' });
    await assert.rejects(f.bus.close(), { code: 'EK_LIFECYCLE_STATE' });
    completed = true;
  });
  await f.bus.publish('self.close', {});
  await eventually(() => completed);
  await subscription.close();
  await f.bus.close();
  assert.equal(f.sdk.counts.closes, 1);
});

test('Messaging invalid operations and payloads reject before native submission', async (context) => {
  const f = await fixture(context),
    baseline = f.sdk.counts.flushes;
  for (const input of [
    null,
    [],
    { extra: true },
    { timeoutMs: 0 },
    { timeoutMs: NaN },
    { signal: {} },
  ])
    assert.throws(() => messageOptions(input as never), { code: 'EK_CONFIG_INVALID' });
  for (const topic of ['', 'a.*', 'a.>', 'a..b', 'line\n', 'a'.repeat(257)])
    await assert.rejects(f.bus.publish(topic, {}), { code: 'EK_CONFIG_INVALID' });
  await assert.rejects(f.bus.publish('valid', { unsupported: 1n }), { code: 'EK_CONFIG_INVALID' });
  await assert.rejects(f.bus.publish('valid', {}, { correlationId: 'bad\n' }), {
    code: 'EK_CONFIG_INVALID',
  });
  await assert.rejects(f.bus.subscribe('valid', null as never), { code: 'EK_CONFIG_INVALID' });
  await assert.rejects(f.bus.publish('valid', {}, { signal: AbortSignal.abort() }), {
    code: 'EK_ABORTED',
  });
  assert.equal(f.sdk.counts.flushes, baseline);
  assert.equal(f.sdk.frames.length, 0);
});

test('Messaging startup is single flight, observes late acquisition and cannot restart a closed owner', async () => {
  const sdk = nativeDouble(),
    gate = deferred<void>();
  sdk.connectGate(gate.promise);
  const bus = new NatsBus(
    { prefix: 'test.alpha.', native: {} },
    { onError: async () => {} },
    sdk.connect,
  );
  await assert.rejects(bus.publish('before.start', {}), { code: 'EK_LIFECYCLE_STATE' });
  const starting = bus.start({ timeoutMs: 5 });
  assert.equal(starting, bus.start());
  const rejected = assert.rejects(starting, { code: 'EK_TIMEOUT' });
  await delay(10);
  gate.resolve();
  await rejected;
  assert.equal(sdk.counts.connects, 1);
  assert.equal(sdk.counts.closes, 1);
  await assert.rejects(bus.start(), { code: 'EK_RESOURCE_CLOSED' });
  await bus.close();
});

test('Messaging startup preserves acquisition and cleanup failure causes without reopening resources', async () => {
  const sdk = nativeDouble();
  sdk.faults.set('flush', new Error('Startup probe failed'));
  sdk.faults.set('drain', new Error('Native drain failed'));
  const bus = new NatsBus(
    { prefix: 'test.alpha.', native: {} },
    { onError: async () => {} },
    sdk.connect,
  );
  await assert.rejects(
    bus.start(),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.cause instanceof AggregateError &&
      cause.cause.errors.length === 2,
  );
  assert.equal(sdk.counts.closes, 1);
  await assert.rejects(bus.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(sdk.counts.closes, 1);
  const failed = nativeDouble();
  failed.faults.set('connect', undefined);
  const unavailable = new NatsBus(
    { prefix: 'test.alpha.', native: {} },
    { onError: async () => {} },
    failed.connect,
  );
  await assert.rejects(unavailable.start(), { code: 'EK_BACKEND_UNAVAILABLE' });
  await unavailable.close();
  assert.equal(failed.counts.closes, 0);
});

test('Messaging native failures and broker payload limits remain explicit without automatic publish replay', async (context) => {
  const f = await fixture(context);
  f.sdk.client.info!.max_payload = 10;
  await assert.rejects(f.bus.publish('limit', {}), { code: 'EK_CONFIG_INVALID' });
  assert.equal(f.sdk.frames.length, 0);
  f.sdk.client.info!.max_payload = 1048576;
  f.sdk.faults.set('publish', undefined);
  await assert.rejects(f.bus.publish('failure', {}), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(f.sdk.frames.length, 0);
  f.sdk.faults.delete('publish');
  f.sdk.faults.set('flush', new Error('Native round trip failed'));
  await assert.rejects(
    f.bus.publish('uncertain', {}),
    (cause: unknown) => cause instanceof KitError && cause.details.outcome === 'unknown',
  );
  assert.equal(f.sdk.frames.length, 1);
  assert.equal(await f.bus.health(), false);
  f.sdk.faults.delete('flush');
  await f.bus.close();
  assert.equal(f.sdk.counts.closes, 1);
});

test('Messaging diagnostics cannot replace acknowledged local completion or submit a late publication after cancellation', async (context) => {
  const gate = deferred<void>();
  let mode = 'throw';
  const telemetry = {
    async withSpan(_name: string, work: () => Promise<unknown>) {
      if (mode === 'before') await gate.promise;
      const result = await work();
      if (mode === 'after') await gate.promise;
      if (mode === 'throw') throw new Error('Span sink failed');
      return result;
    },
    recordHistogram() {
      throw new Error('Metric sink failed');
    },
  } as unknown as Telemetry;
  const f = await fixture(context, { telemetry });
  assert.equal((await f.bus.publish('observed', {})).acknowledged, false);
  assert.equal(f.sdk.frames.length, 1);
  mode = 'after';
  const completed = await f.bus.publish('completed', {}, { timeoutMs: 5 });
  assert.equal(completed.acknowledged, false);
  assert.equal(f.sdk.frames.length, 2);
  gate.resolve();
  await eventually(() => f.bus.stats().pendingPublications === 0);
  assert.ok(f.bus.stats().observerFailures >= 2);
  const delayed = deferred<void>();
  const guarded = await fixture(context, {
    telemetry: {
      async withSpan(_name: string, work: () => Promise<unknown>) {
        await delayed.promise;
        return work();
      },
    } as unknown as Telemetry,
  });
  await assert.rejects(guarded.bus.publish('never.submitted', {}, { timeoutMs: 5 }), {
    code: 'EK_TIMEOUT',
  });
  delayed.resolve();
  await eventually(() => guarded.bus.stats().pendingPublications === 0);
  assert.equal(guarded.sdk.frames.length, 0);
});

test('Messaging cannot enter background work through missing or falsely asynchronous meter scope controls', async () => {
  assert.throws(
    () =>
      new NatsBus(
        { prefix: 'test.alpha.', native: {} },
        { onError: async () => {}, meter: {} as UsageMeter },
      ),
    { code: 'EK_CONFIG_INVALID' },
  );
  for (const withoutScope of [() => undefined, (work: () => unknown) => work()]) {
    const sdk = nativeDouble();
    const meter = { withoutScope, markMissing() {}, current: () => ({}) } as unknown as UsageMeter;
    const bus = new NatsBus(
      { prefix: 'test.alpha.', native: {} },
      { onError: async () => {}, meter },
      sdk.connect,
    );
    await assert.rejects(bus.start(), { code: 'EK_METER_SESSION' });
    assert.equal(sdk.counts.closes, 1);
  }
});

test('Messaging native subscription errors are reported before the owning connection closes', async (context) => {
  const f = await fixture(context);
  await f.bus.subscribe('permission', async () => {});
  f.sdk.subscriptionError(new nats.NatsError('private-native-error', 'PERMISSIONS_VIOLATION'));
  await eventually(() => f.failures.length === 1 && f.sdk.counts.closes === 1);
  assert.equal(f.failures[0]!.kind, 'subscription');
  assert.equal(f.failures[0]!.topic, 'permission');
  assert.equal(f.bus.stats().connected, false);
  await f.bus.close();
});

test('Messaging rejected or synchronous error strategies poison the owner and retain cleanup evidence', async (context) => {
  for (const onError of [
    async () => {
      throw new Error('Error strategy failed');
    },
    (() => undefined) as never,
  ]) {
    const f = await fixture(context, { onError });
    await f.bus.subscribe('failure', async () => {
      throw new Error('Handler failed');
    });
    await f.bus.publish('failure', {});
    await eventually(() => !f.bus.stats().connected && f.sdk.counts.closes === 1);
    await assert.rejects(
      f.bus.close(),
      (cause: unknown) => cause instanceof KitError && cause.details.cleanupFailed === true,
    );
    assert.equal(f.sdk.frames.length, 1);
  }
});

test('Messaging receive count and byte admission remain bounded while an existing handler is pending', async (context) => {
  for (const payload of ['', 'x'.repeat(700000)]) {
    const f = await fixture(context),
      gate = deferred<void>();
    let handled = 0;
    const subscription = await f.bus.subscribe('pressure', async () => {
      handled++;
      await gate.promise;
    });
    const bytes = encodeMessage({
      schemaVersion: 1,
      messageId: randomUUID(),
      topic: 'pressure',
      payload,
    });
    try {
      for (let index = 0; index < 140 && f.bus.stats().connected; index++)
        f.sdk.deliver('test.alpha.pressure', bytes);
      assert.ok(f.bus.stats().retainedBytes <= 8388608);
      assert.ok(f.bus.stats().queuedMessages <= 128);
      assert.equal(f.bus.stats().dropped, 1);
      gate.resolve();
      await f.bus.close();
      assert.ok(handled > 0);
      assert.equal(f.failures[0]!.kind, 'overflow');
      assert.equal(f.bus.stats().retainedBytes, 0);
      assert.equal(f.bus.stats().queuedMessages, 0);
      await subscription.close();
    } finally {
      gate.resolve();
    }
  }
});

test('Messaging forced shutdown preserves one pending handler and never starts queued callbacks after its deadline', async (context) => {
  const f = await fixture(context),
    gate = deferred<void>();
  let handled = 0;
  await f.bus.subscribe('shutdown', async () => {
    handled++;
    await gate.promise;
  });
  const bytes = encodeMessage({
    schemaVersion: 1,
    messageId: randomUUID(),
    topic: 'shutdown',
    payload: {},
  });
  f.sdk.deliver('test.alpha.shutdown', bytes);
  f.sdk.deliver('test.alpha.shutdown', bytes);
  await eventually(() => handled === 1);
  try {
    await assert.rejects(
      f.bus.close({ timeoutMs: 20 }),
      (cause: unknown) => cause instanceof KitError && cause.details.cleanupFailed === true,
    );
    assert.equal(f.sdk.counts.closes, 1);
    assert.equal(f.bus.stats().activeHandlers, 1);
  } finally {
    gate.resolve();
  }
  await eventually(() => f.bus.stats().activeHandlers === 0 && f.bus.stats().queuedMessages === 0);
  assert.equal(handled, 1);
  assert.equal(f.bus.stats().dropped, 1);
});

test('Messaging cleanup preserves an undefined native unsubscribe failure and closes its remaining transport', async (context) => {
  const f = await fixture(context),
    subscription = await f.bus.subscribe('unsubscribe', async () => {});
  f.sdk.faults.set('unsubscribe', undefined);
  await assert.rejects(
    subscription.close(),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.details.cleanupFailed === true &&
      cause.cause === undefined,
  );
  await f.bus.close();
  assert.equal(f.sdk.counts.closes, 1);
  assert.equal(f.sdk.counts.subscriptions, 0);
});

test('Messaging caller cancellation forces bounded native drain without reopening the connection', async (context) => {
  const f = await fixture(context),
    gate = deferred<void>(),
    controller = new AbortController();
  f.sdk.drainGate(gate.promise);
  const closing = assert.rejects(
    f.bus.close({ signal: controller.signal }),
    (cause: unknown) => cause instanceof KitError && cause.details.cleanupFailed === true,
  );
  controller.abort();
  await closing;
  assert.equal(f.sdk.counts.closes, 1);
  gate.resolve();
  await assert.rejects(f.bus.publish('after.close', {}), { code: 'EK_RESOURCE_CLOSED' });
});

test('Messaging fails closed on native status errors, broken status iteration and unexpected transport closure', async (context) => {
  for (const trigger of ['status', 'iterator', 'closed']) {
    const f = await fixture(context);
    if (trigger === 'status') f.sdk.status(nats.Events.Error, 'PERMISSIONS_VIOLATION');
    else if (trigger === 'iterator') f.sdk.failStatus(new Error('Native status stream failed'));
    else await f.sdk.client.close();
    await eventually(() => f.failures.length === 1 && !f.bus.stats().connected);
    assert.equal(f.failures[0]!.kind, 'connection');
    await assert.rejects(f.bus.publish('after.failure', {}));
    assert.equal(f.sdk.frames.length, 0);
    await f.bus.close();
  }
});

test('Messaging failed native subscription allocation and cancelled setup release all unopened queues', async (context) => {
  const f = await fixture(context);
  f.sdk.faults.set('subscribe', new Error('Native allocation failed'));
  await assert.rejects(
    f.bus.subscribe('allocation', async () => {}),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  assert.equal(f.bus.stats().subscriptions, 0);
  f.sdk.faults.delete('subscribe');
  const gate = deferred<void>(),
    controller = new AbortController();
  f.sdk.flushGate(gate.promise);
  let handled = 0;
  const pending = assert.rejects(
    f.bus.subscribe(
      'opening',
      async () => {
        handled++;
      },
      { signal: controller.signal },
    ),
    { code: 'EK_ABORTED' },
  );
  await eventually(() => f.sdk.counts.subscriptions === 1);
  f.sdk.deliver(
    'test.alpha.opening',
    encodeMessage({ schemaVersion: 1, messageId: randomUUID(), topic: 'opening', payload: {} }),
  );
  assert.ok(f.bus.stats().retainedBytes > 0);
  controller.abort();
  await pending;
  assert.equal(f.bus.stats().queuedMessages, 0);
  assert.equal(f.bus.stats().retainedBytes, 0);
  assert.equal(f.bus.stats().dropped, 1);
  gate.resolve();
  f.sdk.flushGate();
  await eventually(() => f.sdk.counts.subscriptions === 0);
  assert.equal(handled, 0);
});

test('Messaging bounds native subscriptions and reports synchronous application handlers through its error policy', async (context) => {
  const f = await fixture(context),
    subscriptions: Subscription[] = [];
  for (let index = 0; index < 32; index++)
    subscriptions.push(await f.bus.subscribe('limit.' + index, async () => {}));
  await assert.rejects(
    f.bus.subscribe('overflow', async () => {}),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  assert.equal(f.sdk.counts.subscriptions, 32);
  await Promise.all(subscriptions.map((subscription) => subscription.close()));
  const subscription = await f.bus.subscribe('sync', (() => undefined) as never);
  await f.bus.publish('sync', {});
  await eventually(() => f.failures.length === 1);
  assert.equal(f.failures[0]!.kind, 'handler');
  assert.match(f.failures[0]!.error.message, /handler/);
  await subscription.close();
});

test('Messaging rechecks its monotonic admission budget after synchronous diagnostic delay', async (context) => {
  const f = await fixture(context, {
    telemetry: {
      async withSpan(_name: string, work: () => Promise<unknown>) {
        const until = performance.now() + 15;
        while (performance.now() < until) {
          /* Simulate synchronous observer latency. */
        }
        return work();
      },
    } as unknown as Telemetry,
  });
  await assert.rejects(f.bus.publish('expired', {}, { timeoutMs: 5 }), { code: 'EK_TIMEOUT' });
  assert.equal(f.sdk.frames.length, 0);
  assert.equal(f.bus.stats().retainedBytes, 0);
});

test('Messaging processing spans preserve a failed handler and successful following work when the span sink fails', async (context) => {
  const names: string[] = [],
    fault = new Error('Private business failure');
  const f = await fixture(context, {
    telemetry: {
      async withSpan(name: string, work: () => Promise<unknown>) {
        names.push(name);
        const answer = await work().catch((cause: unknown) => {
          if (name === 'messaging.process') throw new Error('Span sink failed');
          throw cause;
        });
        if (name === 'messaging.process') throw new Error('Span sink failed');
        return answer;
      },
      recordHistogram() {},
    } as unknown as Telemetry,
  });
  let calls = 0;
  const subscription = await f.bus.subscribe('processing', async () => {
    if (++calls === 1) throw fault;
  });
  await f.bus.publish('processing', {});
  await eventually(() => f.failures.length === 1);
  assert.equal(f.failures[0]!.error.cause, fault);
  await f.bus.publish('processing', {});
  await eventually(() => calls === 2 && f.bus.stats().activeHandlers === 0);
  assert.equal(f.failures.length, 1);
  assert.equal(names.filter((name) => name === 'messaging.process').length, 2);
  assert.ok(f.bus.stats().observerFailures >= 2);
  await subscription.close();
});
