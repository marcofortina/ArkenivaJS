// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  COMPONENTS,
  KitError,
  type Plugin,
  type UsageMeter,
  type MeterSession,
  type MeteringEvent,
} from '@arkenivajs/core';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { fixture, send, settings, registry } from '../http-fixture.js';
import { registryContentChecksum } from '../../dist/registry.js';
import type { TenantRoutingEventV1 } from '../../dist/index.js';

async function events(directory: string): Promise<MeteringEvent[]> {
  return (await readFile(join(directory, 'usage.jsonl'), 'utf8'))
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => parseMeteringEvent(JSON.parse(line)));
}

test('Real JSONL records verified tenant HTTP parents and logical operation children without repeating entity bytes', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-usage-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let current: () => MeterSession | undefined = () => undefined;
  const inherited = new Map<string, string | undefined>(),
    base = settings();
  const f = await fixture(
    {
      ...base,
      handlers: Object.fromEntries(
        ['north', 'south'].map((tenant) => [
          tenant,
          (context: Parameters<(typeof base.handlers)[string]>[0]) => {
            inherited.set(context.auth!.tenantId, current()?.operationId);
            return {
              tenant: context.auth!.tenantId,
              implementation: tenant,
              id: (context.body as { id: string }).id,
            };
          },
        ]),
      ),
    },
    {
      metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
      plugins: [meteringPlugin({ workspace: directory })],
    },
  );
  current = () => f.app.meter.current();
  try {
    assert.equal(f.service.events, undefined);
    const body = { id: 'private-business-data', tenant_id: 'spoofed-tenant' },
      results = await Promise.all(
        ['north', 'south'].map(async (tenant) =>
          send(f.origin, '/api/orders', {
            method: 'POST',
            body,
            headers: { authorization: await f.token(tenant) },
          }),
        ),
      );
    for (const result of results) assert.equal(result.status, 200, result.body);
    assert.equal((await send(f.origin, '/api/orders', { method: 'POST', body })).status, 401);
    await f.app.meter.flush();
    const recorded = await events(directory);
    assert.equal(recorded.length, 4);
    for (const [index, tenant] of ['north', 'south'].entries()) {
      const own = recorded.filter((event) => event.tenantId === tenant),
        parent = own.find((event) => event.operation === 'http.request'),
        child = own.find((event) => event.operation === 'orders.create');
      assert.ok(parent && child);
      assert.equal(child.parentOperationId, parent.operationId);
      assert.equal(child.requestId, parent.requestId);
      assert.equal(inherited.get(tenant), child.operationId);
      assert.equal(parent.counters['http.requests']?.value, 1);
      assert.equal(
        parent.counters['http.request.bytes']?.value,
        Buffer.byteLength(JSON.stringify(body)),
      );
      assert.equal(
        parent.counters['http.response.bytes']?.value,
        Buffer.byteLength(results[index]!.body),
      );
      assert.equal(child.counters['tenant.routing.operations']?.value, 1);
      assert.ok(Object.values(child.counters).every((quantity) => quantity.unit !== 'bytes'));
      assert.equal(parent.status, 'ok');
      assert.equal(child.status, 'ok');
      assert.equal(parent.quality.complete, true);
      assert.equal(child.quality.complete, true);
    }
    assert.equal((await stat(join(directory, 'usage.jsonl'))).mode & 0o777, 0o600);
    assert.doesNotMatch(
      JSON.stringify(recorded),
      /private-business-data|spoofed-tenant|Bearer |implementationId|registryRevision|pricing|currency/,
    );
    assert.equal(f.app.meter.snapshot().activeSessions, 0);
  } finally {
    await f.close();
  }
});

test('A timed-out handler retains its real accounting session and reports unknown execution after late completion', async (t) => {
  const routingEvents: TenantRoutingEventV1[] = [];
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-late-usage-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let release: () => void = () => {},
    entered: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    snapshot = registry();
  snapshot.operations.forEach((operation) => {
    operation.timeoutMs = 150;
  });
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  const base = settings(snapshot),
    f = await fixture(
      {
        ...base,
        eventExporter: {
          async export(batch) {
            routingEvents.push(...batch);
          },
        },
        handlers: {
          ...base.handlers,
          north: async () => {
            entered();
            await gate;
            return { id: 'late', tenant: 'north', implementation: 'north' };
          },
        },
      },
      {
        metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
        plugins: [meteringPlugin({ workspace: directory })],
      },
    );
  try {
    await f.tenant();
    const pending = send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('north') },
    });
    await started;
    const expired = await pending;
    assert.equal(expired.status, 504, expired.body);
    assert.equal(f.app.meter.snapshot().activeSessions, 1);
    await f.app.meter.flush();
    const early = await events(directory);
    assert.equal(early.length, 1);
    assert.equal(early[0]!.status, 'aborted');
    assert.equal(early[0]!.quality.complete, false);
    assert.equal(routingEvents.length, 0);
    release();
    for (let attempt = 0; f.app.meter.snapshot().activeSessions && attempt < 30; attempt++)
      await nextTurn();
    assert.equal(f.app.meter.snapshot().activeSessions, 0);
    await f.app.meter.flush();
    const recorded = await events(directory),
      child = recorded.find((event) => event.operation === 'orders.read');
    assert.equal(recorded.length, 2);
    assert.ok(child);
    assert.equal(child.status, 'unknown');
    assert.equal(child.parentOperationId, early[0]!.operationId);
    await f.service.events!.flush();
    assert.equal(routingEvents.length, 1);
    assert.equal(routingEvents[0]!.status, 'unknown');
    assert.equal(routingEvents[0]!.quality.complete, false);
    assert.deepEqual(routingEvents[0]!.quality.missing, ['execution_outcome_unknown']);
    assert.equal(routingEvents[0]!.requestId, child.requestId);
  } finally {
    release();
    await f.close();
  }
});

test('A real upstream contributes distinct client quantities to its logical child without modifying metering event v1', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-http-usage-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const wire = '{"id":"partner-order","tenant":"south","implementation":"partner"}';
  let effects = 0;
  const upstream = createServer((request, response) => {
    effects++;
    assert.equal(request.url, '/fixed');
    assert.equal(request.headers.authorization, undefined);
    response.setHeader('content-type', 'application/json');
    response.end(wire);
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    upstream.closeAllConnections();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });
  const address = upstream.address();
  assert.ok(address && typeof address === 'object');
  const snapshot = registry(),
    content = {
      ...snapshot,
      implementations: [
        snapshot.implementations[0]!,
        {
          id: 'south-orders',
          kind: 'http' as const,
          upstreamKey: 'partner',
          upstreamPath: '/fixed',
          method: 'GET' as const,
        },
      ],
    };
  const f = await fixture(
    {
      ...settings(),
      registry: {
        loadSnapshot: async () => ({
          ...content,
          contentChecksum: registryContentChecksum(content),
        }),
      },
      approvedUpstreams: [
        {
          key: 'partner',
          origin: 'http://127.0.0.1:' + address.port,
          allowedHostnames: ['127.0.0.1'],
          allowedCidrs: ['127.0.0.1/32'],
          connectionTimeoutMs: 1000,
          allowRedirects: false,
        },
      ],
    },
    {
      metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
      plugins: [meteringPlugin({ workspace: directory })],
    },
  );
  try {
    const result = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('south') },
    });
    assert.equal(result.status, 200, result.body);
    assert.equal(effects, 1);
    await f.app.meter.flush();
    const recorded = await events(directory),
      child = recorded.find((event) => event.operation === 'orders.read')!,
      parent = recorded.find((event) => event.operation === 'http.request')!;
    assert.equal(recorded.length, 2);
    assert.ok(child && parent);
    assert.equal(child.counters['http.client.requests']?.value, 1);
    assert.equal(child.counters['http.client.response.bytes']?.value, Buffer.byteLength(wire));
    assert.equal(child.counters['http.client.elapsed']?.unit, 'milliseconds');
    assert.equal(child.counters['http.response.bytes'], undefined);
    assert.equal(parent.counters['http.client.response.bytes'], undefined);
    assert.equal(parent.counters['http.response.bytes']?.value, Buffer.byteLength(result.body));
    assert.equal(child.quality.complete, true);
    assert.equal(parent.quality.complete, true);
    assert.doesNotMatch(
      JSON.stringify(recorded),
      /127\.0\.0\.1|upstreamKey|registryRevision|implementationId|Bearer/,
    );
  } finally {
    await f.close();
  }
});

test('Exporter outages remain observable without replaying a handler or admitting a denied operation', async () => {
  let effects = 0,
    attempts = 0,
    fail = true;
  const base = settings(),
    f = await fixture(
      {
        ...base,
        handlers: {
          ...base.handlers,
          north: () => {
            effects++;
            return { id: 'accepted', tenant: 'north', implementation: 'north' };
          },
        },
      },
      {
        metering: { enabled: true, exporter: 'jsonl' },
        plugins: [
          meteringPlugin({
            maxAttempts: 1,
            exporter: {
              kind: 'jsonl',
              async export() {
                attempts++;
                if (fail) throw new Error('private-exporter-failure');
              },
              async close() {},
            },
          }),
        ],
      },
    );
  try {
    const accepted = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('north') },
    });
    assert.equal(accepted.status, 200, accepted.body);
    await assert.rejects(f.app.meter.flush());
    assert.ok(attempts > 0 && f.app.meter.stats().failedExports > 0);
    assert.equal(
      (
        await send(f.origin, '/api/orders/id', {
          headers: { authorization: await f.token('north', 'unrelated') },
        })
      ).status,
      403,
    );
    assert.equal(effects, 1);
    assert.doesNotMatch(accepted.body + f.logs(), /private-exporter-failure/);
  } finally {
    fail = false;
    // An exhausted exporter has already lost events; recovery cannot erase that
    // failure from the existing meter's final completeness report.
    await assert.rejects(f.close(), { code: 'EK_PLUGIN_FAILED' });
  }
});

test('Accounting capacity cannot bypass operation policy and independently rejected provenance fails closed', async () => {
  for (const unverified of [false, true]) {
    let effects = 0;
    const meter: UsageMeter & {
      run<T>(session: MeterSession, work: () => T): T;
      markMissing(): void;
    } = {
      start() {
        throw new KitError({
          code: unverified ? 'EK_TENANT_UNVERIFIED' : 'EK_METER_CAPACITY',
          message: 'private-accounting-failure',
        });
      },
      measure: async (_input, work) => work(),
      current: () => undefined,
      flush: async () => {},
      stats: () => ({ enqueued: 0, exported: 0, dropped: 1, failedExports: 0, queueDepth: 0 }),
      snapshot: () => ({ activeSessions: 0, queueDepth: 0, dropped: 1 }),
      run: (_session, work) => work(),
      markMissing() {},
    };
    const provider: Plugin = {
      id: 'metering',
      version: '1.0.0',
      capabilities: new Set(['meter']),
      init(context) {
        context.provide(COMPONENTS.meter, meter);
      },
      close() {},
    };
    const base = settings(),
      f = await fixture(
        {
          ...base,
          handlers: {
            ...base.handlers,
            north: () => {
              effects++;
              return { id: 'accepted', tenant: 'north', implementation: 'north' };
            },
          },
        },
        { metering: { enabled: true }, plugins: [provider] },
      );
    try {
      const result = await send(f.origin, '/api/orders/id', {
        headers: { authorization: await f.token('north') },
      });
      assert.equal(result.status, unverified ? 401 : 200, result.body);
      const denied = await send(f.origin, '/api/orders/id', {
        headers: { authorization: await f.token('north', 'unrelated') },
      });
      assert.equal(denied.status, unverified ? 401 : 403, denied.body);
      assert.equal(effects, unverified ? 0 : 1);
      assert.doesNotMatch(result.body + denied.body + f.logs(), /private-accounting-failure/);
    } finally {
      await f.close();
    }
  }
});
