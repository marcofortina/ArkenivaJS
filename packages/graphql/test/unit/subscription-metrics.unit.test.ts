// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { COMPONENTS } from '@arkenivajs/core';
import type { Telemetry, Plugin } from '@arkenivajs/core';
import { fixture, tlsFiles, send } from '../fixture.js';

interface Point {
  asDouble?: number;
  asInt?: string;
  count?: string;
  sum?: number;
  attributes?: { key: string; value: { stringValue?: string } }[];
}
interface Metric {
  name: string;
  unit: string;
  gauge?: { dataPoints: Point[] };
  sum?: { dataPoints: Point[] };
  histogram?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: {
    scopeSpans: {
      spans: { name: string; traceId: string; spanId: string; parentSpanId?: string }[];
    }[];
  }[];
}

test(
  'Actual OpenTelemetry exports bounded subscription connection, queue and delivery/drop signals without payload labels',
  { timeout: 15000 },
  async () => {
    const envelopes: Envelope[] = [];
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk);
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString()) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    const tls = await tlsFiles();
    let emitted = 0;
    const f = await fixture(
      {
        schema: 'type Query { ping: String } type Subscription { notice: String! }',
        resolvers: {
          Subscription: {
            notice: {
              async *subscribe(_parent, _args, context) {
                assert.ok(context.auth);
                emitted++;
                yield context.auth.tenantId === 'tenant-a'
                  ? 'never-export-event-payload'
                  : 'x'.repeat(2048);
                if (!context.signal.aborted)
                  await new Promise<void>((resolve) =>
                    context.signal.addEventListener('abort', () => resolve(), { once: true }),
                  );
              },
              resolve: (parent) => telemetry.withSpan('subscription.resolver', async () => parent),
            },
          },
        },
        security: {
          auth: { required: true },
          authorizeField: () => true,
          limits: { maxResultBytes: 1024 },
        },
        subscriptions: {
          enabled: true,
          pubsub: {
            subscribe() {
              throw new Error('This fixture owns its source explicitly');
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
        telemetry: { mode: 'detailed', samplingRatio: 1 },
        plugins: [
          telemetryPlugin({
            endpoint: `http://127.0.0.1:${address.port}`,
            allowInsecureLoopback: true,
            exportTimeoutMs: 500,
            exportIntervalMs: 60000,
            labelValues: { route: ['/graphql'] },
          }),
        ],
      },
    ).catch(async (error: unknown) => {
      await tls.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      throw error;
    });
    const sockets: WebSocket[] = [];
    const telemetry: Telemetry = f.app.telemetry;
    const remote = new Map<string, { trace: string; parent: string }>();
    const connect = async (tenant: string) => {
      const trace = randomBytes(16).toString('hex'),
        parent = randomBytes(8).toString('hex');
      remote.set(tenant, { trace, parent });
      const socket = new WebSocket(
        f.origin.replace('https:', 'wss:') + '/graphql',
        'graphql-transport-ws',
        {
          ca: tls.ca,
          origin: 'https://portal.example.test',
          headers: { traceparent: `00-${trace}-${parent}-01` },
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
      return socket;
    };
    try {
      const a = await connect('tenant-a'),
        b = await connect('tenant-b');
      await f.app.telemetry.flush();
      const response = new Promise<unknown>((resolve) =>
        a.on('message', (raw) => {
          const frame = JSON.parse(String(raw));
          if (frame.type === 'next') resolve(frame.payload);
        }),
      );
      a.send(
        '{"type":"subscribe","id":"unrestricted-client-id","payload":{"query":"subscription NeverExportOperationName { notice }"}}',
      );
      assert.deepEqual(await response, { data: { notice: 'never-export-event-payload' } });
      const denied = once(b, 'close');
      b.send(
        '{"type":"subscribe","id":"other-client-id","payload":{"query":"subscription { notice }"}}',
      );
      await denied;
      assert.equal(emitted, 2);
      const closed = once(a, 'close');
      a.close();
      await closed;
      const invalid = await connect('tenant-c');
      const invalidClosed = once(invalid, 'close');
      invalid.send(
        JSON.stringify({ type: 'subscribe', id: 'invalid', payload: { query: '{broken' } }),
      );
      await invalidClosed;
      assert.equal(emitted, 2, 'Preflight rejection cannot allocate an application source');
      for (let index = 0; index < 100 && f.service.stats().activeSubscriptions; index++)
        await delay(5);
      assert.equal(f.service.stats().activeSubscriptions, 0);
      assert.equal(f.service.stats().operations, 3);
      assert.equal(f.service.stats().rejected, 2);
      await f.app.telemetry.flush();
      const spans = envelopes.flatMap(
        (envelope) =>
          envelope.resourceSpans?.flatMap((resource) =>
            resource.scopeSpans.flatMap((scope) => scope.spans),
          ) ?? [],
      );
      const parents = spans.filter((span) => span.name === 'http.server.request');
      assert.equal(parents.length, 3);
      const children = spans.filter((span) => span.name === 'graphql.subscription');
      assert.equal(children.length, 4, 'One source and one delivery scope per subscription');
      const resolvers = spans.filter((span) => span.name === 'subscription.resolver');
      assert.equal(resolvers.length, 2);
      for (const [tenant, { trace, parent }] of remote) {
        const roots = parents.filter((span) => span.traceId === trace);
        assert.equal(roots.length, 1);
        assert.equal(roots[0]!.parentSpanId, parent);
        const events = children.filter((span) => span.traceId === trace);
        assert.equal(events.length, tenant === 'tenant-c' ? 0 : 2);
        assert.ok(events.every((span) => span.parentSpanId === roots[0]!.spanId));
        const work = resolvers.filter((span) => span.traceId === trace);
        assert.equal(work.length, tenant === 'tenant-c' ? 0 : 1);
        if (work.length) assert.ok(events.some((span) => span.spanId === work[0]!.parentSpanId));
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics)
        .flatMap((scope) => scope.metrics);
      const points = (name: string) =>
        metrics
          .filter((metric) => metric.name === name)
          .flatMap((metric) => metric.gauge?.dataPoints ?? metric.sum?.dataPoints ?? []);
      const value = (point: Point) => point.asDouble ?? Number(point.asInt);
      assert.equal(
        points('arkenivajs.graphql.requests').reduce((sum, point) => sum + value(point), 0),
        3,
      );
      assert.equal(
        points('arkenivajs.graphql.denied').reduce((sum, point) => sum + value(point), 0),
        2,
      );
      const histograms = (name: string) =>
        metrics
          .filter((metric) => metric.name === name)
          .flatMap((metric) => metric.histogram?.dataPoints ?? []);
      assert.equal(
        histograms('arkenivajs.graphql.operation.complexity').reduce(
          (sum, point) => sum + Number(point.count),
          0,
        ),
        2,
      );
      assert.equal(
        histograms('arkenivajs.graphql.operation.duration').reduce(
          (sum, point) => sum + Number(point.count),
          0,
        ),
        3,
      );
      assert.equal(
        histograms('arkenivajs.graphql.field.duration').reduce(
          (sum, point) => sum + Number(point.count),
          0,
        ),
        4,
      );
      for (const [name, unit] of [
        ['active_subscriptions', '{connection}'],
        ['subscription.queued', '{event}'],
        ['subscription.events', '{event}'],
      ])
        assert.ok(
          metrics.some(
            (metric) => metric.name === 'arkenivajs.graphql.' + name && metric.unit === unit,
          ),
        );
      const active = points('arkenivajs.graphql.active_subscriptions');
      assert.ok(active.some((point) => value(point) === 2));
      assert.equal(value(active.at(-1)!), 0);
      const queued = points('arkenivajs.graphql.subscription.queued');
      assert.ok(queued.length >= 2);
      assert.ok(queued.every((point) => value(point) >= 0));
      const eventPoints = points('arkenivajs.graphql.subscription.events');
      const result = (point: Point) =>
        point.attributes?.find((attribute) => attribute.key === 'graphql.result')?.value
          .stringValue;
      assert.equal(
        eventPoints
          .filter((point) => result(point) === 'deliver')
          .reduce((sum, point) => sum + value(point), 0),
        1,
      );
      assert.equal(
        eventPoints
          .filter((point) => result(point) === 'drop')
          .reduce((sum, point) => sum + value(point), 0),
        1,
      );
      assert.equal(
        eventPoints.some((point) => result(point) === 'publish'),
        false,
      );
      assert.doesNotMatch(
        JSON.stringify(envelopes),
        /tenant-a|tenant-b|tenant-c|NeverExportOperationName|never-export-event-payload|unrestricted-client-id|other-client-id|Bearer |\{broken/,
      );
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
      await tls.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  },
);

for (const mode of ['before', 'after', 'twice', 'stall'] as const)
  test(
    `Failing subscription observers (${mode}) neither repeat business work nor bypass real identity checks`,
    { timeout: 10000 },
    async () => {
      const tls = await tlsFiles();
      let metrics = 0,
        allocations = 0,
        queries = 0;
      const fail = () => {
        metrics++;
        throw new Error('Private diagnostic provider failure');
      };
      const telemetry: Telemetry = {
        measure: async (_name, work) => work(),
        withSpan: async (_name, work) => {
          if (mode === 'stall')
            return _name === 'graphql.subscription' ? new Promise<never>(() => {}) : work();
          if (mode === 'before') throw new Error('Private diagnostic provider failure');
          const result = work();
          if (mode === 'twice') void Promise.resolve(work()).catch(() => undefined);
          void Promise.resolve(result).catch(() => undefined);
          throw new Error('Private diagnostic provider failure');
        },
        addCounter: fail,
        recordHistogram: fail,
        setGauge: fail,
        async flush() {},
      };
      const observer: Plugin = {
        id: 'telemetry',
        version: '0.1.0',
        capabilities: new Set(['telemetry']),
        init(context) {
          context.provide(COMPONENTS.telemetry, telemetry);
        },
        close() {},
      };
      const f = await fixture(
        {
          schema: 'type Query { ping: String } type Subscription { notice: String! }',
          resolvers: {
            Query: {
              ping: () => {
                queries++;
                return 'pong';
              },
            },
            Subscription: {
              notice: {
                async *subscribe(_parent, _args, context) {
                  allocations++;
                  yield context.auth!.tenantId;
                },
                resolve: (parent) => parent,
              },
            },
          },
          security: { auth: { required: true }, authorizeField: ({ context }) => !!context.auth },
          subscriptions: {
            enabled: true,
            pubsub: {
              subscribe() {
                throw new Error('This fixture owns its source explicitly');
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
        { tls: tls.tls, telemetry: { mode: 'standard' }, plugins: [observer] },
      );
      let socket: WebSocket | undefined;
      try {
        assert.equal((await send(f.origin, { query: '{ ping }' }, { ca: tls.ca })).status, 401);
        assert.equal(queries, 0);
        socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          { ca: tls.ca, origin: 'https://portal.example.test' },
        );
        await once(socket, 'open');
        const wire = socket;
        wire.on('message', (raw) => {
          if (JSON.parse(String(raw)).type === 'ping') wire.send('{"type":"pong"}');
        });
        const ack = once(wire, 'message');
        wire.send(
          JSON.stringify({ type: 'connection_init', payload: { authorization: await f.token() } }),
        );
        await ack;
        const received = new Promise<unknown>((resolve) =>
          wire.on('message', (raw) => {
            const frame = JSON.parse(String(raw));
            if (frame.type === 'next') resolve(frame.payload);
          }),
        );
        wire.send('{"type":"subscribe","id":"one","payload":{"query":"subscription { notice }"}}');
        assert.deepEqual(await received, { data: { notice: 'tenant-a' } });
        assert.equal(allocations, 1);
        const query = await send(
          f.origin,
          { query: '{ ping }' },
          { ca: tls.ca, headers: { authorization: await f.token() } },
        );
        assert.deepEqual(query.json(), { data: { ping: 'pong' } });
        assert.equal(queries, 1);
        assert.ok(metrics > 0);
      } finally {
        socket?.terminate();
        await f.close();
        await tls.close();
      }
    },
  );
