// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { MeteringEvent, MeterSession, UsageMeter, Plugin } from '@arkenivajs/core';
import { fixture, send } from '../fixture.js';

async function events(directory: string): Promise<MeteringEvent[]> {
  return (await readFile(join(directory, 'usage.jsonl'), 'utf8'))
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => parseMeteringEvent(JSON.parse(line)));
}

test(
  'Real JSONL tenant usage has one HTTP parent and one GraphQL child with actual fields, batch items and no repeated bytes',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-usage-'));
    let current: () => MeterSession | undefined = () => undefined;
    const inherited = new Map<string, string | undefined>();
    const f = await fixture(
      {
        schema: 'type Item { value: String! } type Query { tenant: String! items: [Item!]! }',
        resolvers: {
          Query: {
            tenant: (_parent, _args, context) => {
              inherited.set(context.auth!.tenantId, current()?.operationId);
              return context.auth!.tenantId;
            },
            items: () => [{ id: 1 }, { id: 2 }],
          },
        },
        loaders: {
          Item: {
            value: {
              load: async (requests, context) =>
                requests.map(
                  (request) => context.auth!.tenantId + ':' + (request.parent as { id: number }).id,
                ),
            },
          },
        },
        security: { authorizeField: () => true },
      },
      {
        metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
        plugins: [meteringPlugin({ workspace: directory })],
      },
    );
    current = () => f.app.meter.current();
    try {
      const body = { query: 'query NeverExportThisName { tenant items { value } }' };
      const [a, b] = await Promise.all(
        ['tenant-a', 'tenant-b'].map(async (tenant) =>
          send(f.origin, body, {
            headers: { authorization: await f.token(tenant), 'x-tenant-id': 'forged-tenant' },
          }),
        ),
      );
      assert.ok(a && b);
      assert.equal(a.status, 200, a.body);
      assert.equal(b.status, 200, b.body);
      assert.equal((await send(f.origin, body)).status, 401);
      await f.app.meter.flush();
      const recorded = await events(directory);
      assert.equal(recorded.length, 4);
      for (const [tenant, response] of [
        ['tenant-a', a],
        ['tenant-b', b],
      ] as const) {
        const own = recorded.filter((event) => event.tenantId === tenant);
        assert.equal(own.length, 2);
        const parent = own.find((event) => event.operation === 'POST /graphql')!,
          child = own.find((event) => event.operation === 'graphql.query')!;
        assert.ok(parent && child);
        assert.equal(parent.parentOperationId, undefined);
        assert.equal(child.parentOperationId, parent.operationId);
        assert.equal(inherited.get(tenant), child.operationId);
        assert.equal(child.requestId, parent.requestId);
        assert.equal(parent.counters['http.requests']?.value, 1);
        assert.equal(
          parent.counters['http.request.bytes']?.value,
          Buffer.byteLength(JSON.stringify(body)),
        );
        assert.equal(
          parent.counters['http.response.bytes']?.value,
          Buffer.byteLength(response.body),
        );
        assert.equal(child.counters['graphql.operations']?.value, 1);
        assert.equal(child.counters['graphql.resolved_fields']?.value, 4);
        assert.equal(child.counters['graphql.loader_batches']?.value, 1);
        assert.deepEqual(child.counters['graphql.loader_items'], {
          unit: 'items',
          source: 'observed',
          value: 2,
        });
        assert.ok(Object.values(child.counters).every((counter) => counter.unit !== 'bytes'));
        assert.equal(parent.status, 'ok');
        assert.equal(child.status, 'ok');
        assert.equal(parent.quality.complete, true);
        assert.equal(child.quality.complete, true);
      }
      assert.equal((await stat(join(directory, 'usage.jsonl'))).mode & 0o777, 0o600);
      assert.doesNotMatch(
        JSON.stringify(recorded),
        /NeverExportThisName|Bearer |forged-tenant|tenant-a:1|tenant-b:2/,
      );
      assert.equal(f.app.meter.snapshot().activeSessions, 0);
    } finally {
      await f.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('Public queries never create a synthetic tenant and denied fields never count as resolved usage', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-public-usage-'));
  let effects = 0;
  const f = await fixture(
    {
      schema: 'type Query { ping: String! privateValue: String }',
      resolvers: {
        Query: {
          ping: () => 'pong',
          privateValue: () => {
            effects++;
            return 'private';
          },
        },
      },
      security: {
        auth: {
          required: false,
          publicRootFields: ['Query.ping'],
          reason: 'Public availability query',
        },
        authorizeField: ({ field }) => field.fieldName !== 'privateValue',
      },
    },
    {
      metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
      plugins: [meteringPlugin({ workspace: directory })],
    },
  );
  try {
    assert.equal(
      (await send(f.origin, { query: '{ ping }' }, { headers: { 'x-tenant-id': 'forged-tenant' } }))
        .status,
      200,
    );
    assert.equal((await send(f.origin, { query: '{ privateValue }' })).status, 401);
    await f.app.meter.flush();
    assert.equal((await readFile(join(directory, 'usage.jsonl'))).length, 0);
    const denied = await send(
      f.origin,
      { query: '{ privateValue }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(denied.status, 200, denied.body);
    assert.match(denied.body, /EK_GQL_FORBIDDEN/);
    await f.app.meter.flush();
    const recorded = await events(directory),
      child = recorded.find((event) => event.operation === 'graphql.query');
    assert.equal(recorded.length, 2);
    assert.ok(recorded.every((event) => event.tenantId === 'tenant-a' && event.status === 'error'));
    assert.equal(child?.counters['graphql.resolved_fields']?.value, 0);
    assert.equal(effects, 0);
  } finally {
    await f.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('Meter failures preserve admission and field policy while rejected tenant provenance fails closed', async () => {
  for (const unverified of [false, true]) {
    let effects = 0;
    const meter: UsageMeter & {
      run<T>(session: MeterSession, work: () => T): T;
      markMissing(): void;
    } = {
      start() {
        throw new KitError({
          code: unverified ? 'EK_TENANT_UNVERIFIED' : 'EK_METER_CAPACITY',
          message: 'Private usage provider failure',
        });
      },
      measure: async (_input, work) => work(),
      current: () => undefined,
      flush: async () => {},
      stats: () => ({ enqueued: 0, exported: 0, dropped: 0, failedExports: 0, queueDepth: 0 }),
      snapshot: () => ({ activeSessions: 0, queueDepth: 0, dropped: 0 }),
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
    const f = await fixture(
      {
        schema: 'type Query { ping: String! } type Mutation { update: Int! denied: Int }',
        resolvers: {
          Query: { ping: () => 'pong' },
          Mutation: { update: () => ++effects, denied: () => ++effects },
        },
        security: { authorizeField: ({ field }) => field.fieldName !== 'denied' },
      },
      { metering: { enabled: true }, plugins: [provider] },
    );
    try {
      const headers = { authorization: await f.token() };
      const result = await send(f.origin, { query: 'mutation { update }' }, { headers });
      assert.equal(result.status, unverified ? 401 : 200, result.body);
      const denied = await send(f.origin, { query: 'mutation { denied }' }, { headers });
      assert.match(denied.body, unverified ? /EK_GQL_AUTH/ : /EK_GQL_FORBIDDEN/);
      assert.equal(effects, unverified ? 0 : 1);
      assert.doesNotMatch(result.body + denied.body + f.logs(), /Private usage provider failure/);
    } finally {
      await f.close();
    }
  }
});

test(
  'Timed-out mutation usage reports an incomplete HTTP parent and unknown child outcome until physical work settles',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-usage-timeout-'));
    let release!: () => void,
      entered!: () => void,
      effects = 0;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = await fixture(
      {
        schema: 'type Query { ping: String! } type Mutation { update: Boolean! }',
        resolvers: {
          Query: { ping: () => 'pong' },
          Mutation: {
            update: async () => {
              entered();
              await gate;
              effects++;
              return true;
            },
          },
        },
        security: { authorizeField: () => true, limits: { maxOperationMs: 1000 } },
      },
      {
        metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
        plugins: [meteringPlugin({ workspace: directory })],
      },
    );
    try {
      const pending = send(
        f.origin,
        { query: 'mutation { update }' },
        { headers: { authorization: await f.token() } },
      );
      await started;
      const response = await pending;
      assert.equal(response.status, 504, response.body);
      await f.app.meter.flush();
      const first = await events(directory);
      assert.equal(first.length, 1);
      assert.equal(first[0]?.operation, 'POST /graphql');
      assert.equal(first[0]?.status, 'aborted');
      assert.equal(first[0]?.quality.complete, false);
      assert.ok(first[0]?.quality.missing.includes('downstream_unobserved'));
      assert.equal(effects, 0);
      assert.equal(f.app.meter.snapshot().activeSessions, 1);
      release();
      for (let i = 0; i < 100 && f.service.stats().activeOperations; i++) await setImmediate();
      await f.app.meter.flush();
      const final = await events(directory),
        child = final.find((event) => event.operation === 'graphql.mutation');
      assert.equal(final.length, 2);
      assert.equal(child?.parentOperationId, first[0]?.operationId);
      assert.equal(child?.status, 'unknown');
      assert.equal(child?.counters['graphql.resolved_fields']?.value, 0);
      assert.equal(effects, 1);
      assert.equal(f.app.meter.snapshot().activeSessions, 0);
    } finally {
      release();
      await f.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
