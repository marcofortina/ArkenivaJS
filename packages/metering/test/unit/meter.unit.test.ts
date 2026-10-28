// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { VerifiedTenantContext, Telemetry, MeteringEvent } from '@arkenivajs/core';
import { createMeter } from '@arkenivajs/metering';
import type { MeterOptions, MeterExporter, TenantVerifier } from '@arkenivajs/metering';

const service = { name: 'meter-test', version: '1.0.0', environment: 'test' as const };
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
function fixture() {
  const trusted = new WeakSet<VerifiedTenantContext>();
  let valid = true;
  const auth: TenantVerifier = {
    isVerifiedTenant(value): value is VerifiedTenantContext {
      return (
        valid && !!value && typeof value === 'object' && trusted.has(value as VerifiedTenantContext)
      );
    },
  };
  const mint = (tenantId: string) => {
    const tenant: VerifiedTenantContext = Object.freeze({
      tenantId: tenantId as never,
      identity: Object.freeze({
        subject: 'test-user',
        issuer: 'https://issuer.invalid',
        audience: ['api'],
        scopes: [],
        claims: {},
      }),
      verifiedAt: new Date().toISOString(),
      source: 'oidc',
    });
    trusted.add(tenant);
    return tenant;
  };
  const events: MeteringEvent[] = [];
  let closes = 0;
  const exporter: MeterExporter = {
    kind: 'jsonl',
    async export(batch) {
      assert.ok(Object.isFrozen(batch));
      events.push(...batch);
    },
    async close() {
      closes++;
    },
  };
  return {
    auth,
    mint,
    events,
    exporter,
    revoke: () => {
      valid = false;
    },
    closes: () => closes,
    options: { service, auth, exporter, flushIntervalMs: 60_000 } satisfies MeterOptions,
  };
}

test('Background consumers detach request tenant scope and require an independent verified accounting operation', async () => {
  const f = fixture(),
    meter = createMeter(f.options),
    tenant = f.mint('tenant-A'),
    other = f.mint('tenant-B');
  const parent = meter.start({
    tenant,
    operation: 'request.publisher',
    requestId: 'publisher-request',
  });
  try {
    await meter.run(parent, async () => {
      assert.equal(meter.current(), parent);
      await meter.withoutScope(async () => {
        assert.equal(meter.current(), undefined);
        await delay(0);
        assert.equal(meter.current(), undefined);
        const background = meter.start({ tenant: other, operation: 'message.consumer' });
        meter.run(background, () => {
          background.recordOperation('messaging.publish');
          background.recordUsage('messaging.client.elapsed', {
            unit: 'milliseconds',
            source: 'observed',
            value: 2,
          });
          background.recordUsage('messaging.payload.bytes', {
            unit: 'bytes',
            source: 'observed',
            value: 64,
          });
        });
        background.end('ok');
      });
      assert.equal(meter.current(), parent);
    });
    parent.end('ok');
    await meter.flush();
    const background = f.events.find((entry) => entry.operation === 'message.consumer')!;
    assert.equal(background.tenantId, 'tenant-B');
    assert.equal(background.parentOperationId, undefined);
    assert.equal(background.requestId, undefined);
    assert.deepEqual(background.counters['messaging.publish'], {
      unit: 'operations',
      source: 'observed',
      value: 1,
    });
    assert.equal(
      f.events.find((entry) => entry.operation === 'request.publisher')!.tenantId,
      'tenant-A',
    );
    assert.throws(() => meter.withoutScope(null as never), { code: 'EK_METER_SESSION' });
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 immutable tenant events use independent UUIDs, actual duration and registered additive units', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const meter = createMeter({
    ...f.options,
    currentTraceId: () => '0123456789abcdef0123456789abcdef',
    workload: { namespace: 'test', pod: 'unit' },
    usageDefinitions: { 'business.items': 'items' },
  });
  try {
    assert.equal(meter.current(), undefined);
    const session = meter.start({ tenant, operation: 'orders.get', requestId: 'request-1' });
    assert.equal(meter.current(), undefined);
    meter.run(session, () => {
      assert.equal(meter.current(), session);
      session.recordOperation('db.query');
      session.recordOperation('db.query', 0);
      session.recordOperation('db.query', 2);
      session.recordUsage('business.items', { unit: 'items', source: 'observed', value: 2 });
      session.recordUsage('db.client.elapsed', {
        unit: 'milliseconds',
        source: 'observed',
        value: 1.25,
      });
    });
    assert.equal(f.events.length, 0);
    const receipt = session.end('ok');
    assert.equal(receipt.accepted, true);
    assert.ok(Object.isFrozen(receipt));
    assert.throws(() => session.end(), code('EK_METER_SESSION'));
    assert.throws(() => session.recordOperation('db.query'), code('EK_METER_SESSION'));
    await meter.flush();
    assert.equal(f.events.length, 1);
    const event = f.events[0]!;
    for (const id of [event.eventId, event.operationId])
      assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(event.eventId, event.operationId);
    assert.equal(event.traceId, '0123456789abcdef0123456789abcdef');
    assert.equal(event.requestId, 'request-1');
    assert.equal(event.schemaVersion, '1.0.0');
    assert.equal(event.tenantId, 'tenant-A');
    assert.equal(event.operation, 'orders.get');
    assert.equal(event.counters['db.query']!.value, 3);
    assert.equal(event.counters['business.items']!.value, 2);
    assert.equal(event.counters['db.client.elapsed']!.value, 1.25);
    assert.ok(event.durationMs >= 0);
    assert.ok(event.startedAt <= event.endedAt);
    assert.deepEqual(event.quality, { complete: true, droppedChildCount: 0, missing: [] });
    assert.ok(Object.isFrozen(event.counters['db.query']));
    assert.ok(Object.isFrozen(event.quality.missing));
    assert.equal(Object.hasOwn(event, 'claims'), false);
    assert.deepEqual(meter.snapshot(), { activeSessions: 0, queueDepth: 0, dropped: 0 });
    assert.deepEqual(meter.stats(), {
      enqueued: 1,
      exported: 1,
      dropped: 0,
      failedExports: 0,
      queueDepth: 0,
    });
  } finally {
    await meter.close();
  }
  assert.equal(f.closes(), 1);
  await meter.close();
  assert.equal(f.closes(), 1);
  assert.throws(() => meter.start({ tenant, operation: 'closed' }), code('EK_RESOURCE_CLOSED'));
  await assert.rejects(meter.flush(), code('EK_RESOURCE_CLOSED'));
});

test('EK-METER-001 tenant provenance, expiry, accessors and foreign sessions fail closed without event creation', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const meter = createMeter(f.options);
  const foreign = createMeter(f.options);
  try {
    for (const value of [null, undefined, { ...tenant }, { tenantId: 'forged' }])
      assert.throws(
        () => meter.start({ tenant: value as never, operation: 'orders.get' }),
        code('EK_TENANT_UNVERIFIED'),
      );
    assert.throws(() => meter.start(null as never), code('EK_TENANT_UNVERIFIED'));
    let accessed = false;
    const hostile = Object.defineProperty({ tenant, operation: 'valid' }, 'requestId', {
      get() {
        accessed = true;
        return 'forged';
      },
      enumerable: true,
    });
    assert.throws(() => meter.start(hostile), code('EK_METER_SESSION'));
    assert.equal(accessed, false);
    const session = meter.start({ tenant, operation: 'orders.get' });
    assert.throws(() => foreign.run(session, () => {}), code('EK_METER_SESSION'));
    assert.throws(() => meter.run(session, null as never), code('EK_METER_SESSION'));
    assert.throws(() => meter.markMissing(session, 'unknown' as never), code('EK_METER_SESSION'));
    meter.markMissing(session, 'driver_bytes_unavailable');
    f.revoke();
    assert.throws(() => meter.start({ tenant, operation: 'new' }), code('EK_TENANT_UNVERIFIED'));
    session.end('ok');
    await meter.flush();
    assert.deepEqual(f.events[0]!.quality.missing, ['driver_bytes_unavailable']);
  } finally {
    await meter.close();
    await foreign.close();
  }
});

test('EK-METER-001 nested asynchronous operations preserve tenant/request/trace DAG and independent contexts', async () => {
  const f = fixture();
  const a = f.mint('tenant-A'),
    b = f.mint('tenant-B');
  const meter = createMeter(f.options);
  try {
    await Promise.all(
      [a, b].map((tenant) =>
        meter.measure({ tenant, operation: 'parent', requestId: tenant.tenantId }, async () => {
          const parent = meter.current()!;
          await delay(1);
          await meter.measure({ tenant, operation: 'child' }, async () => {
            assert.notEqual(meter.current(), parent);
            await delay(1);
            assert.equal(meter.current()!.operationId !== parent.operationId, true);
          });
          assert.equal(meter.current(), parent);
          assert.throws(
            () => meter.start({ tenant, operation: 'child', requestId: 'other' }),
            code('EK_METER_SESSION'),
          );
          assert.throws(
            () => meter.start({ tenant: tenant === a ? b : a, operation: 'cross-tenant' }),
            code('EK_METER_SESSION'),
          );
        }),
      ),
    );
    await meter.flush();
    assert.equal(f.events.length, 4);
    for (const tenant of [a, b]) {
      const events = f.events.filter((e) => e.tenantId === tenant.tenantId);
      const parent = events.find((e) => e.operation === 'parent')!;
      const child = events.find((e) => e.operation === 'child')!;
      assert.equal(child.parentOperationId, parent.operationId);
      assert.ok(events.every((e) => e.requestId === tenant.tenantId && e.status === 'ok'));
    }
    assert.equal(meter.current(), undefined);
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 invalid quantities never mutate counters and arbitrary error objects remain private', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const meter = createMeter(f.options);
  try {
    const session = meter.start({ tenant, operation: 'validation' });
    for (const [name, usage] of [
      ['unregistered', { unit: 'bytes', source: 'observed', value: 1 }],
      ['db.query', { unit: 'bytes', source: 'observed', value: 1 }],
      ['db.query', { unit: 'operations', source: 'observed', value: -1 }],
      ['db.query', { unit: 'operations', source: 'observed', value: Infinity }],
      ['db.query', { unit: 'operations', source: 'unknown', value: 1 }],
      ['db.query', null],
      ['constructor', { unit: 'operations', source: 'observed', value: 1 }],
    ] as const)
      assert.throws(() => session.recordUsage(name, usage as never), code('EK_METER_SESSION'));
    for (const value of [-1, 1.5, NaN])
      assert.throws(() => session.recordOperation('db.query', value), code('EK_METER_SESSION'));
    session.recordUsage('db.client.elapsed', {
      unit: 'milliseconds',
      source: 'derived',
      value: Number.MAX_VALUE,
    });
    assert.throws(
      () =>
        session.recordUsage('db.client.elapsed', {
          unit: 'milliseconds',
          source: 'observed',
          value: 1,
        }),
      code('EK_METER_SESSION'),
    );
    assert.throws(
      () =>
        session.recordUsage('db.client.elapsed', {
          unit: 'milliseconds',
          source: 'derived',
          value: Number.MAX_VALUE,
        }),
      code('EK_METER_SESSION'),
    );
    assert.throws(() => session.end('invalid' as never), code('EK_METER_SESSION'));
    session.recordError(new Error('fake-private-token'));
    session.end();
    const secret = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('fake-private-prototype');
        },
      },
    );
    await assert.rejects(
      meter.measure({ tenant, operation: 'failure' }, () => {
        throw secret;
      }),
      (error) => error === secret,
    );
    const value = { value: 'preserved' };
    assert.equal(await meter.measure({ tenant, operation: 'success' }, () => value), value);
    const abort = new KitError({ code: 'EK_ABORTED', message: 'fake-private-abort' });
    await assert.rejects(
      meter.measure({ tenant, operation: 'abort' }, () => {
        throw abort;
      }),
      (error) => error === abort,
    );
    await meter.flush();
    assert.ok(!JSON.stringify(f.events).includes('fake-private'));
    assert.equal(f.events.find((e) => e.operation === 'abort')!.status, 'aborted');
    assert.equal(f.events.find((e) => e.operation === 'failure')!.status, 'error');
    assert.ok(
      f.events
        .find((e) => e.operation === 'abort')!
        .quality.missing.includes('aborted_before_close'),
    );
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 queue pressure is synchronous and bounded while retries preserve event IDs and delivery accounting', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  let attempt = 0;
  const ids: string[][] = [];
  const meter = createMeter({
    ...f.options,
    queueCapacity: 1,
    retryDelayMs: 0,
    exporter: {
      kind: 'http',
      async export(events) {
        ids.push(events.map((e) => e.eventId));
        if (++attempt === 1)
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Temporary rejection',
            retryable: true,
          });
        f.events.push(...events);
      },
      close: f.exporter.close,
    },
  });
  try {
    const a = meter.start({ tenant, operation: 'first' }),
      b = meter.start({ tenant, operation: 'overflow' });
    const accepted = a.end('ok');
    const rejected = b.end('ok');
    assert.equal(accepted.accepted, true);
    assert.equal(rejected.accepted, false);
    assert.equal(rejected.reason, 'capacity');
    assert.equal(attempt, 0);
    assert.equal(meter.snapshot().queueDepth, 1);
    await meter.flush();
    assert.deepEqual(ids, [[accepted.eventId], [accepted.eventId]]);
    assert.deepEqual(meter.stats(), {
      enqueued: 1,
      exported: 1,
      dropped: 1,
      failedExports: 1,
      queueDepth: 0,
    });
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 bounded export failures remain visible and short caller deadlines do not acknowledge delivery', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  let aborted = 0;
  const meter = createMeter({
    ...f.options,
    exportTimeoutMs: 20,
    maxAttempts: 2,
    retryDelayMs: 0,
    exporter: {
      kind: 'http',
      export(_events, options) {
        return new Promise<void>((_resolve, reject) =>
          options.signal!.addEventListener(
            'abort',
            () => {
              aborted++;
              reject(new Error('Transport aborted'));
            },
            { once: true },
          ),
        );
      },
      close: f.exporter.close,
    },
  });
  meter.start({ tenant, operation: 'timeout' }).end('ok');
  await assert.rejects(meter.flush({ timeoutMs: 1 }), code('EK_TIMEOUT'));
  await assert.rejects(meter.flush(), code('EK_METER_EXPORT'));
  assert.equal(aborted, 2);
  assert.deepEqual(meter.stats(), {
    enqueued: 1,
    exported: 0,
    dropped: 1,
    failedExports: 2,
    queueDepth: 0,
  });
  await assert.rejects(meter.close(), code('EK_METER_EXPORT'));
  assert.equal(f.closes(), 1);
});

test('EK-METER-001 disabled export and bounded active sessions preserve business callbacks and explicit loss receipts', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const disabled = createMeter({ service, auth: f.auth, enabled: false });
  try {
    const receipt = disabled.start({ tenant, operation: 'disabled' }).end();
    assert.deepEqual(
      { accepted: receipt.accepted, reason: receipt.reason },
      { accepted: false, reason: 'disabled' },
    );
    await disabled.flush();
    assert.equal(disabled.stats().dropped, 1);
  } finally {
    await disabled.close();
  }
  const meter = createMeter({ ...f.options, maxActiveSessions: 1 });
  try {
    await meter.measure({ tenant, operation: 'parent' }, async () => {
      let called = 0;
      const value = await meter.measure({ tenant, operation: 'child' }, () => {
        called++;
        assert.equal(meter.current(), undefined);
        return 'ok';
      });
      assert.equal(called, 1);
      assert.equal(value, 'ok');
    });
    await meter.flush();
    assert.equal(meter.stats().dropped, 1);
    assert.equal(f.events[0]!.quality.droppedChildCount, 1);
    assert.equal(f.events[0]!.quality.complete, false);
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 unfinished children and shutdown retain truthful local coverage without raw errors', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const meter = createMeter({
    ...f.options,
    telemetry: {
      addCounter() {
        throw new Error('fake-diagnostic');
      },
      setGauge() {
        throw new Error('fake-diagnostic');
      },
    } as unknown as Telemetry,
    currentTraceId: () => {
      throw new Error('fake-trace');
    },
  });
  const parent = meter.start({ tenant, operation: 'parent' });
  let child!: ReturnType<typeof meter.start>;
  meter.run(parent, () => {
    child = meter.start({ tenant, operation: 'child' });
  });
  parent.end('ok');
  assert.throws(() => meter.run(parent, () => {}), code('EK_METER_SESSION'));
  await meter.close();
  assert.equal(meter.snapshot().activeSessions, 0);
  assert.equal(f.events.length, 2);
  assert.ok(
    f.events
      .find((e) => e.operation === 'parent')!
      .quality.missing.includes('downstream_unobserved'),
  );
  assert.equal(f.events.find((e) => e.operation === 'child')!.status, 'aborted');
  assert.throws(() => child.end(), code('EK_METER_SESSION'));
});

test('EK-METER-001 malformed policy, session inputs and falsely asynchronous provenance are rejected', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  for (const policy of [
    { service: { name: true, version: '1.0.0', environment: 'test' } },
    { service: { name: 'valid', version: 'invalid', environment: 'test' } },
    { service: { name: 'valid', version: '1.0.0', environment: 'invalid' } },
    { auth: {} },
    { queueCapacity: 0 },
    { queueByteCapacity: 1 },
    { maxActiveSessions: 0 },
    { batchSize: 0 },
    { exportTimeoutMs: 0 },
    { maxAttempts: 6 },
    { retryDelayMs: -1 },
    { flushIntervalMs: 0 },
    { enabled: 'yes' },
    { exporter: {} },
    { currentTraceId: 1 },
    { instanceId: '' },
    { workload: { pod: 'bad\nvalue' } },
    { workload: { untrusted: 'value' } },
    { usageDefinitions: { bad: 'currency' } },
    { usageDefinitions: { '1invalid': 'items' } },
  ])
    assert.throws(
      () => createMeter({ ...f.options, ...policy } as MeterOptions),
      code('EK_CONFIG_INVALID'),
    );
  assert.throws(() => createMeter(null as never), code('EK_CONFIG_INVALID'));
  for (const isVerifiedTenant of [
    () => false,
    () => {
      throw new Error('fake-verifier');
    },
    () => Promise.reject(new Error('fake-async-verifier')),
  ]) {
    const meter = createMeter({
      ...f.options,
      auth: { isVerifiedTenant } as unknown as TenantVerifier,
    });
    try {
      assert.throws(
        () => meter.start({ tenant, operation: 'rejected' }),
        code('EK_TENANT_UNVERIFIED'),
      );
    } finally {
      await meter.close();
    }
  }
  const meter = createMeter({ ...f.options, currentTraceId: () => '0'.repeat(32) });
  try {
    for (const input of [
      { tenant, operation: '' },
      { tenant, operation: 'bad\noperation' },
      { tenant, operation: 'valid', requestId: '' },
      { tenant, operation: 'valid', extra: true },
    ])
      assert.throws(() => meter.start(input), code('EK_METER_SESSION'));
    await assert.rejects(
      meter.measure({ tenant, operation: 'valid' }, null as never),
      code('EK_METER_SESSION'),
    );
    const session = meter.start({ tenant, operation: 'valid' });
    session.recordError(new DOMException('fake-secret', 'AbortError'));
    session.end();
    await meter.flush();
    assert.equal(f.events.at(-1)!.traceId, undefined);
    assert.equal(f.events.at(-1)!.status, 'aborted');
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 permanent exporter rejection is not retried and accepted losses remain observable after recovery', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  let calls = 0;
  const meter = createMeter({
    ...f.options,
    exporter: {
      kind: 'http',
      async export(events) {
        if (++calls === 1)
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Unauthorized collector',
            retryable: false,
          });
        f.events.push(...events);
      },
      close: f.exporter.close,
    },
  });
  meter.start({ tenant, operation: 'lost' }).end('ok');
  await assert.rejects(meter.flush(), code('EK_METER_EXPORT'));
  assert.equal(calls, 1);
  meter.start({ tenant, operation: 'recovery' }).end('ok');
  await assert.rejects(meter.flush(), code('EK_METER_EXPORT'));
  assert.equal(calls, 2);
  assert.deepEqual(f.events[0]!.quality.missing, ['exporter_unavailable']);
  assert.deepEqual(meter.stats(), {
    enqueued: 2,
    exported: 1,
    dropped: 1,
    failedExports: 1,
    queueDepth: 0,
  });
  await assert.rejects(meter.close(), code('EK_METER_EXPORT'));
});

test('EK-METER-001 byte bounds reject oversized records and saturated queues without retaining ended sessions', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const dimensions = Object.fromEntries(
    Array.from({ length: 112 }, (_, index) => [
      'u.' + 'a'.repeat(70) + String(index).padStart(3, '0'),
      'milliseconds' as const,
    ]),
  );
  const meter = createMeter({
    ...f.options,
    usageDefinitions: dimensions,
    queueByteCapacity: 65_536,
  });
  try {
    const session = meter.start({ tenant, operation: 'oversized' });
    for (const name of Object.keys(dimensions))
      session.recordUsage(name, {
        unit: 'milliseconds',
        source: 'observed',
        value: Number.MAX_VALUE,
      });
    assert.equal(session.end('ok').reason, 'invalid');
    let dropped = 0;
    for (let index = 0; index < 200; index++) {
      const receipt = meter.start({ tenant, operation: 'queue-pressure' }).end('ok');
      if (!receipt.accepted) dropped++;
    }
    assert.ok(dropped > 0);
    assert.equal(meter.stats().dropped, dropped + 1);
    assert.equal(meter.snapshot().activeSessions, 0);
    await meter.flush();
    assert.equal(meter.stats().queueDepth, 0);
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 live parent reports rejected children while late child creation never revives an ended scope', async () => {
  const f = fixture();
  const tenant = f.mint('tenant-A');
  const meter = createMeter({ ...f.options, queueCapacity: 1 });
  try {
    const parent = meter.start({ tenant, operation: 'parent' });
    await meter.run(parent, async () => {
      meter.start({ tenant, operation: 'occupy' }).end('ok');
      const child = meter.start({ tenant, operation: 'dropped-child' });
      assert.equal(child.end('ok').reason, 'capacity');
      await meter.flush();
    });
    parent.end('ok');
    await meter.flush();
    const event = f.events.find((event) => event.operation === 'parent')!;
    assert.equal(event.quality.droppedChildCount, 1);
    assert.deepEqual(event.quality.missing, ['meter_queue_overflow']);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let late!: Promise<void>;
    await meter.measure({ tenant, operation: 'ended-parent' }, () => {
      late = (async () => {
        await gate;
        assert.throws(
          () => meter.start({ tenant, operation: 'late-child' }),
          code('EK_METER_SESSION'),
        );
      })();
      return 1;
    });
    release();
    await late;
  } finally {
    await meter.close();
  }
});

test('EK-METER-001 cleanup reports every thrown value as a typed failure and closes owned exporters once', async () => {
  const f = fixture();
  for (const primary of [undefined, false, 0, '', new Error('fake-private-cleanup')]) {
    let calls = 0;
    const meter = createMeter({
      ...f.options,
      exporter: {
        kind: 'jsonl',
        async export() {},
        async close() {
          calls++;
          throw primary;
        },
      },
    });
    await assert.rejects(meter.close(), (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, 'EK_METER_EXPORT');
      assert.equal(error.cause, primary);
      assert.ok(!JSON.stringify(error).includes('fake-private'));
      return true;
    });
    await assert.rejects(meter.close(), code('EK_METER_EXPORT'));
    assert.equal(calls, 1);
  }
});
