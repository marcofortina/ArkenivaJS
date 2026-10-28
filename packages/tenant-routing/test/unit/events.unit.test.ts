// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { RoutingEvents } from '../../dist/events.js';
import { TENANT_ROUTING_EVENT_SCHEMA_V1 } from '@arkenivajs/tenant-routing/event-schema';
import type { TenantRoutingEventV1 } from '../../dist/index.js';
import { captureSettings } from '../../dist/settings.js';
import { settings } from '../http-fixture.js';

function input() {
  return {
    requestId: 'request-owned',
    tenantId: 'north',
    operationId: 'orders.read',
    registryRevision: 'blue',
    registryActivationGeneration: 1,
    implementationId: 'north-orders',
    implementationKind: 'handler' as const,
    durationMs: 12,
    status: 'ok' as const,
  };
}
test('Routing event batches validate against the published independent schema and cannot expose executable input', async () => {
  const recorded: TenantRoutingEventV1[] = [],
    validate = new Ajv2020({ strict: true }).compile(
      JSON.parse(JSON.stringify(TENANT_ROUTING_EVENT_SCHEMA_V1)),
    ),
    events = new RoutingEvents(
      {
        async export(batch) {
          assert.ok(Object.isFrozen(batch));
          for (const event of batch) {
            assert.equal(validate(event), true);
            assert.ok(Object.isFrozen(event.quality.missing));
            recorded.push(event);
          }
        },
      },
      {},
    );
  try {
    events.complete(input());
    events.complete(input());
    await events.flush();
    assert.equal(recorded.length, 2);
    assert.equal(new Set(recorded.map((event) => event.eventId)).size, 2);
    let effects = 0;
    for (const value of [
      { ...input(), durationMs: -1 },
      { ...input(), status: 'private' },
      { ...input(), traceId: 'invalid' },
      { ...input(), upstreamUrl: 'private' },
      { ...input(), tenantId: 'x'.repeat(9000) },
      Object.defineProperty(input(), 'requestId', {
        enumerable: true,
        get() {
          effects++;
          return 'private';
        },
      }),
      new Proxy(input(), {
        ownKeys() {
          effects++;
          throw new Error('private');
        },
      }),
    ])
      events.complete(value as ReturnType<typeof input>);
    await assert.rejects(events.flush(), { code: 'EK_BACKEND_UNAVAILABLE' });
    assert.equal(effects, 0);
    assert.equal(events.stats().dropped, 7);
    assert.equal(recorded.length, 2);
    assert.equal(Object.isFrozen(TENANT_ROUTING_EVENT_SCHEMA_V1.properties.quality), true);
  } finally {
    await events.close();
  }
});

test('Exporter failures never retry an acknowledged identity and later batches declare earlier stream loss', async () => {
  const calls: TenantRoutingEventV1[][] = [];
  let fail = true;
  const events = new RoutingEvents(
    {
      async export(batch) {
        calls.push([...batch]);
        if (fail) throw new Error('private-exporter-failure');
      },
    },
    {},
  );
  try {
    events.complete(input());
    await assert.rejects(events.flush(), { code: 'EK_BACKEND_UNAVAILABLE' });
    fail = false;
    events.complete(input());
    await assert.rejects(events.flush(), { code: 'EK_BACKEND_UNAVAILABLE' });
    assert.equal(calls.length, 2);
    assert.notEqual(calls[0]![0]!.eventId, calls[1]![0]!.eventId);
    assert.equal(calls[1]![0]!.quality.complete, false);
    assert.deepEqual(calls[1]![0]!.quality.missing, ['prior_routing_events_lost']);
    assert.deepEqual(events.stats(), {
      queued: 0,
      inFlight: 0,
      exported: 1,
      dropped: 1,
      failedExports: 1,
    });
  } finally {
    await events.close();
  }
});

test('Exporter methods preserve their receiver and executable configuration cannot substitute a trusted callback', async () => {
  let effects = 0;
  const provider = {
      value: 'owned-exporter',
      async export() {
        assert.equal(this.value, 'owned-exporter');
        effects++;
      },
    },
    captured = captureSettings({ ...settings(), eventExporter: provider });
  provider.export = async () => {
    throw new Error('replaced-callback');
  };
  await captured.eventExporter!.export([], { signal: new AbortController().signal });
  assert.equal(effects, 1);
  for (const value of [
    null,
    {},
    { export: 'invalid' },
    Object.defineProperty({}, 'export', {
      enumerable: true,
      get() {
        effects++;
        return () => {};
      },
    }),
    new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          effects++;
          throw new Error('private');
        },
      },
    ),
  ])
    assert.throws(
      () =>
        captureSettings({ ...settings(), eventExporter: value } as Parameters<
          typeof captureSettings
        >[0]),
      { code: 'EK_TROUTE_CONFIG' },
    );
  assert.equal(effects, 1);
});

test('Queue admission includes the physically held batch and rejects overflow without a waiting queue', async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const recorded: TenantRoutingEventV1[] = [],
    events = new RoutingEvents(
      {
        async export(batch) {
          await gate;
          recorded.push(...batch);
        },
      },
      {},
    );
  try {
    for (let index = 0; index < 1100; index++)
      events.complete({ ...input(), requestId: 'request-' + index });
    assert.deepEqual(events.stats(), {
      queued: 1023,
      inFlight: 1,
      exported: 0,
      dropped: 76,
      failedExports: 0,
    });
    release();
    await assert.rejects(events.flush(), { code: 'EK_BACKEND_UNAVAILABLE' });
    assert.equal(recorded.length, 1024);
    assert.equal(new Set(recorded.map((event) => event.eventId)).size, 1024);
    assert.equal(events.stats().queued, 0);
    assert.equal(events.stats().inFlight, 0);
  } finally {
    release();
    await events.close();
  }
});

test('Encoded byte capacity rejects large queued events before the independent event-count ceiling', async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
      release = resolve;
    }),
    events = new RoutingEvents(
      {
        async export() {
          await gate;
        },
      },
      {},
    );
  try {
    for (let index = 0; index < 1000; index++)
      events.complete({ ...input(), tenantId: '€'.repeat(2000) });
    assert.ok(events.stats().queued + events.stats().inFlight < 1024);
    assert.ok(events.stats().dropped > 0);
    release();
    await assert.rejects(events.flush());
  } finally {
    release();
    await events.close();
  }
});

test(
  'An export deadline retains physical admission and never counts late success as acknowledged delivery',
  { timeout: 10000 },
  async () => {
    let release: () => void = () => {},
      calls = 0;
    const gate = new Promise<void>((resolve) => {
        release = resolve;
      }),
      events = new RoutingEvents(
        {
          async export() {
            calls++;
            if (calls === 1) await gate;
          },
        },
        {},
      );
    try {
      events.complete(input());
      await delay(5100);
      assert.equal(events.stats().failedExports, 1);
      assert.equal(events.stats().inFlight, 1);
      assert.equal(events.stats().exported, 0);
      events.complete(input());
      await nextTurn();
      assert.equal(calls, 1);
      assert.equal(events.stats().queued, 1);
      release();
      await assert.rejects(events.flush());
      assert.equal(calls, 2);
      assert.equal(events.stats().exported, 1);
      assert.equal(events.stats().dropped, 1);
    } finally {
      release();
      await events.close();
    }
  },
);

test('Shutdown aborts a cooperative exporter and invalid operation options cannot start another batch', async () => {
  let aborted = false;
  const events = new RoutingEvents(
    {
      async export(_batch, options) {
        await new Promise<void>((resolve) => {
          options.signal!.addEventListener(
            'abort',
            () => {
              aborted = true;
              resolve();
            },
            { once: true },
          );
        });
      },
    },
    {},
  );
  events.complete(input());
  await nextTurn();
  for (const timeoutMs of [0, -1, 1.5, 120001]) await assert.rejects(events.flush({ timeoutMs }));
  await events.close();
  assert.equal(aborted, true);
  assert.equal(events.stats().exported, 0);
  events.complete(input());
  assert.equal(events.stats().dropped, 2);
  await assert.rejects(events.flush());
  await events.close();
});
