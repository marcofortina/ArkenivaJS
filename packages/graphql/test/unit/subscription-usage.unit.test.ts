// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { createMeter, meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import type { ManagedUsageMeter, TenantVerifier } from '@arkenivajs/metering';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService, MeteringEvent, MeterSession } from '@arkenivajs/core';
import { fixture, tlsFiles, send } from '../fixture.js';
import { capture } from '../../dist/policy.js';
import { Operation } from '../../dist/operation.js';
import { SubscriptionUsage } from '../../dist/subscription-usage.js';
import { traceSubscriptionScope } from '../../dist/subscription-observation.js';

test(
  'Actual WSS tenant usage exports connection/source/event ownership with isolated live scopes and no invented wire bytes',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-subscription-usage-'));
    const tls = await tlsFiles();
    const collector = createServer(async (request, response) => {
      for await (const chunk of request) void chunk;
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    const traceIds = new Map<string, string>();
    let current: () => MeterSession | undefined = () => undefined;
    const acquired = new Map<string, string | undefined>();
    const resolved = new Map<string, (string | undefined)[]>();
    const f = await fixture(
      {
        schema:
          'type Query { ping: String } type Subscription { notice(tenantHint: String): String! }',
        resolvers: {
          Subscription: {
            notice: {
              subscribe(_parent, _args, context) {
                acquired.set(context.auth!.tenantId, current()?.operationId);
                return (async function* () {
                  yield 'private-event-one';
                  yield 'private-event-two';
                })();
              },
              resolve(parent, _args, context) {
                const tenant = context.auth!.tenantId;
                resolved.set(tenant, [...(resolved.get(tenant) ?? []), current()?.operationId]);
                return parent;
              },
            },
          },
        },
        security: { auth: { required: true }, authorizeField: () => true },
        subscriptions: {
          enabled: true,
          pubsub: {
            subscribe() {
              throw new Error('The fixture owns its sources');
            },
            async publish() {},
            async close() {},
          },
          maxConnections: 2,
          maxOperationsPerConnection: 2,
          maxQueuedEventsPerConnection: 4,
          revalidateIntervalMs: 100,
          allowedOrigins: ['https://portal.example.test'],
        },
      },
      {
        tls: tls.tls,
        telemetry: { mode: 'standard', samplingRatio: 1 },
        metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' },
        plugins: [
          telemetryPlugin({
            endpoint: `http://127.0.0.1:${address.port}`,
            allowInsecureLoopback: true,
            labelValues: { route: ['/graphql'] },
            exportIntervalMs: 60000,
          }),
          meteringPlugin({ workspace: directory, dependencies: ['telemetry'] }),
        ],
      },
    ).catch(async (error: unknown) => {
      await tls.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
      throw error;
    });

    current = () => f.app.meter.current();
    const sockets: WebSocket[] = [];
    try {
      assert.equal((await send(f.origin, { query: '{ ping }' }, { ca: tls.ca })).status, 401);
      await Promise.all(
        ['tenant-a', 'tenant-b'].map(async (tenant) => {
          const traceId = randomBytes(16).toString('hex');
          traceIds.set(tenant, traceId);
          const socket = new WebSocket(
            f.origin.replace('https:', 'wss:') + '/graphql',
            'graphql-transport-ws',
            {
              ca: tls.ca,
              origin: 'https://portal.example.test',
              headers: { traceparent: `00-${traceId}-${randomBytes(8).toString('hex')}-01` },
            },
          );
          sockets.push(socket);
          await once(socket, 'open');
          socket.on('message', (raw) => {
            if (JSON.parse(String(raw)).type === 'ping') socket.send('{"type":"pong"}');
          });
          const ack = once(socket, 'message');
          socket.send(
            JSON.stringify({
              type: 'connection_init',
              payload: { authorization: await f.token(tenant) },
            }),
          );
          assert.equal(JSON.parse(String((await ack)[0])).type, 'connection_ack');
          const payloads: unknown[] = [];
          const complete = new Promise<void>((resolve, reject) => {
            socket.on('message', (raw) => {
              const frame = JSON.parse(String(raw));
              if (frame.type === 'next') payloads.push(frame.payload);
              else if (frame.type === 'complete') resolve();
              else if (frame.type === 'error')
                reject(new Error('Unexpected native subscription rejection'));
            });
          });
          socket.send(
            JSON.stringify({
              type: 'subscribe',
              id: 'never-record-this-id',
              payload: {
                query:
                  'subscription NeverRecordName($tenantHint:String) { notice(tenantHint:$tenantHint) }',
                variables: { tenantHint: 'forged-tenant' },
              },
            }),
          );
          await complete;
          assert.deepEqual(payloads, [
            { data: { notice: 'private-event-one' } },
            { data: { notice: 'private-event-two' } },
          ]);
          const closed = once(socket, 'close');
          socket.close();
          await closed;
        }),
      );
      for (let index = 0; index < 100 && f.app.meter.snapshot().activeSessions; index++)
        await delay(5);
      assert.equal(f.app.meter.snapshot().activeSessions, 0);
      assert.equal(f.service.stats().activeSubscriptions, 0);
      assert.equal(current(), undefined);
      await f.app.meter.flush();
      const events = (await readFile(join(directory, 'usage.jsonl'), 'utf8'))
        .trim()
        .split('\n')
        .map((line) => parseMeteringEvent(JSON.parse(line)));
      assert.equal(events.length, 8);
      for (const tenant of ['tenant-a', 'tenant-b']) {
        const own = events.filter((event) => event.tenantId === tenant);
        assert.equal(own.length, 4);
        const parent = own.find((event) => event.operation === 'graphql.subscription.connection')!;
        const source = own.find((event) => event.operation === 'graphql.subscription.source')!;
        const deliveries = own.filter((event) => event.operation === 'graphql.subscription.event');
        assert.ok(parent && source);
        assert.ok(own.every((event) => event.traceId === traceIds.get(tenant)));
        assert.equal(parent.parentOperationId, undefined);
        assert.equal(parent.quality.complete, false);
        assert.deepEqual(parent.quality.missing, ['driver_bytes_unavailable']);
        assert.equal(parent.quality.droppedChildCount, 0);
        assert.equal(source.counters['graphql.operations']?.value, 1);
        assert.equal(source.counters['graphql.resolved_fields']?.value, 1);
        assert.equal(acquired.get(tenant), source.operationId);
        assert.equal(deliveries.length, 2);
        assert.deepEqual(
          new Set(resolved.get(tenant)),
          new Set(deliveries.map((event) => event.operationId)),
        );
        for (const child of [source, ...deliveries]) {
          assert.equal(child.parentOperationId, parent.operationId);
          assert.equal(child.requestId, parent.requestId);
          assert.equal(child.status, 'ok');
          assert.equal(child.quality.complete, true);
        }
        for (const event of deliveries) {
          assert.equal(event.counters['graphql.subscription_events']?.value, 1);
          assert.equal(event.counters['graphql.resolved_fields']?.value, 1);
          assert.equal(event.counters['graphql.operations'], undefined);
        }
        assert.ok(
          own.every((event) =>
            Object.values(event.counters).every((counter) => counter.unit !== 'bytes'),
          ),
        );
        assert.ok(own.every((event) => event.counters['http.requests'] === undefined));
      }
      assert.doesNotMatch(
        JSON.stringify(events) + f.logs(),
        /private-event|forged-tenant|NeverRecordName|never-record-this-id|Bearer /,
      );
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
      await tls.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);

for (const mode of [
  'before',
  'after',
  'twice',
  'capacity',
  'unverified',
  'late',
  'denied',
] as const)
  test(`Subscription accounting provider ${mode} preserves work ownership and explicit completeness`, async () => {
    const f = await fixture();
    const authority = f.app.resolve<AuthService & TenantVerifier>(COMPONENTS.auth);
    const principal = authority.tenantFrom(await authority.verifyBearer(await f.token()));
    const exported: MeteringEvent[] = [];
    const base = createMeter({
      service: { name: 'subscription-usage-test', version: '0.1.0', environment: 'test' },
      auth: authority,
      maxActiveSessions: mode === 'capacity' ? 1 : 8,
      exporter: {
        kind: 'jsonl',
        async export(events) {
          exported.push(...events);
        },
        async close() {},
      },
    });
    const meter: ManagedUsageMeter = {
      ...base,
      start(input) {
        if (mode === 'unverified' && input.operation.endsWith('.event'))
          return base.start({ ...input, tenant: { ...input.tenant } });
        return base.start(input);
      },
      run(session, work) {
        if (mode === 'before') throw new Error('Private accounting scope failure');
        const result = base.run(session, work);
        if (mode === 'twice') base.run(session, work);
        if (mode === 'after') throw new Error('Private accounting scope failure');
        return result;
      },
      withoutScope(work) {
        const result = base.withoutScope(work);
        if (mode === 'twice') base.withoutScope(work);
        return result;
      },
    };
    const limits = capture({
      schema: 'type Query { ping: String }',
      resolvers: {},
      security: { authorizeField: () => true },
    }).security.limits;
    const scope = new Operation(
      { requestId: 'owned-request', identity: principal.identity, auth: principal },
      limits,
      new AbortController().signal,
    );
    const usage = new SubscriptionUsage(meter, principal, 'owned-request');
    let captures = 0,
      business = 0;
    try {
      const prepare = () =>
        usage.scope(scope, 'event', async () => {
          captures++;
          await traceSubscriptionScope(undefined, undefined, scope);
        });
      if (mode === 'unverified') {
        await assert.rejects(prepare, { code: 'EK_GQL_AUTH' });
        assert.equal(captures, 0);
        assert.throws(() => new SubscriptionUsage(meter, { ...principal }, 'forged-request'), {
          code: 'EK_GQL_AUTH',
        });
      } else {
        await prepare();
        if (mode === 'late') {
          let release!: () => void, entered!: () => void;
          const physical = new Promise<void>((resolve) => {
            release = resolve;
          });
          const began = new Promise<void>((resolve) => {
            entered = resolve;
          });
          const pending = scope.run(async () => {
            business++;
            assert.ok(base.current());
            entered();
            await physical;
            assert.ok(base.current());
          });
          await began;
          scope.abort();
          scope.end();
          await assert.rejects(pending, { code: 'EK_GQL_TIMEOUT' });
          assert.equal(base.snapshot().activeSessions, 2);
          assert.equal(exported.length, 0);
          release();
        } else {
          await scope.run(() => {
            business++;
          });
          if (mode === 'denied') scope.failed = true;
        }
        assert.equal(captures, 1);
        assert.equal(business, 1);
      }
      scope.end();
      await scope.completion;
      await delay(0);
      usage.close();
      await base.flush();
      const root = exported.find((event) => event.operation === 'graphql.subscription.connection')!;
      assert.ok(root);
      assert.equal(base.snapshot().activeSessions, 0);
      assert.equal(root.quality.complete, false);
      assert.ok(root.quality.missing.includes('driver_bytes_unavailable'));
      assert.equal(
        exported.filter((event) => event.operation === 'graphql.subscription.connection').length,
        1,
      );
      if (mode === 'before' || mode === 'capacity' || mode === 'unverified') {
        assert.equal(exported.length, 1);
        if (mode !== 'unverified')
          assert.ok(root.quality.missing.includes('span_not_instrumented'));
      } else {
        assert.equal(exported.length, 2);
        const child = exported.find((event) => event.operation.endsWith('.event'))!;
        assert.equal(child.counters['graphql.subscription_events']?.value, 1);
        assert.equal(child.parentOperationId, root.operationId);
        assert.equal(
          child.status,
          mode === 'late' ? 'aborted' : mode === 'denied' ? 'error' : 'ok',
        );
      }
      if (mode === 'capacity') {
        assert.equal(root.quality.droppedChildCount, 1);
        assert.ok(root.quality.missing.includes('meter_queue_overflow'));
      }
      assert.equal(base.current(), undefined);
    } finally {
      scope.abort();
      scope.end();
      await scope.completion;
      usage.close();
      await base.close();
      await f.close();
    }
  });
