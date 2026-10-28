// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { COMPONENTS, type Plugin, type Telemetry } from '@arkenivajs/core';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { fixture, send, settings } from '../http-fixture.js';
import { registryContentChecksum } from '../../dist/registry.js';

interface Attribute {
  key: string;
  value: { stringValue?: string; intValue?: string | number };
}
interface Point {
  asDouble?: number;
  asInt?: string;
  count?: string;
  attributes?: Attribute[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
  histogram?: { dataPoints: Point[] };
}
interface Span {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  kind?: number;
  attributes?: Attribute[];
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: { scopeSpans: { spans: Span[] }[] }[];
}

test(
  'Actual OTLP routing evidence keeps private registry identities out of bounded metrics and preserves W3C parentage',
  { timeout: 15000 },
  async (t) => {
    const data: Envelope[] = [],
      collector = createServer(async (request, response) => {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(chunk);
        data.push(JSON.parse(Buffer.concat(chunks).toString()) as Envelope);
        response.setHeader('content-type', 'application/json');
        response.end('{}');
      });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    });
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    let upstreamCalls = 0,
      propagated: string | undefined;
    const upstream = createServer((request, response) => {
      upstreamCalls++;
      assert.equal(request.url, '/fixed');
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.headers.baggage, undefined);
      assert.equal(typeof request.headers.traceparent, 'string');
      propagated = String(request.headers.traceparent);
      response.setHeader('content-type', 'application/json');
      response.end('{"id":"partner-order","tenant":"south","implementation":"partner"}');
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    });
    const upstreamAddress = upstream.address();
    assert.ok(upstreamAddress && typeof upstreamAddress === 'object');
    const base = settings(),
      snapshot = await base.registry.loadSnapshot(),
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
        ...base,
        registry: {
          loadSnapshot: async () => ({
            ...content,
            contentChecksum: registryContentChecksum(content),
          }),
        },
        approvedUpstreams: [
          {
            key: 'partner',
            origin: 'http://127.0.0.1:' + upstreamAddress.port,
            allowedHostnames: ['127.0.0.1'],
            allowedCidrs: ['127.0.0.1/32'],
            connectionTimeoutMs: 1000,
            allowRedirects: false,
          },
        ],
      },
      {
        telemetry: { mode: 'standard', samplingRatio: 1 },
        plugins: [
          telemetryPlugin({
            endpoint: 'http://127.0.0.1:' + address.port,
            allowInsecureLoopback: true,
            exportTimeoutMs: 500,
            exportIntervalMs: 60000,
            labelValues: { route: ['/api/orders/:id'] },
          }),
        ],
      },
    );
    try {
      const traceId = randomBytes(16).toString('hex'),
        parent = randomBytes(8).toString('hex');
      for (const tenant of ['north', 'south']) {
        const result = await send(f.origin, '/api/orders/private-object-id', {
          headers: {
            authorization: await f.token(tenant),
            traceparent: `00-${traceId}-${parent}-01`,
            baggage: 'private-untrusted=baggage',
          },
        });
        assert.equal(result.status, 200, result.body);
      }
      assert.equal(
        (
          await send(f.origin, '/api/orders/private-object-id', {
            headers: { authorization: await f.token('unknown') },
          })
        ).status,
        404,
      );
      assert.equal(
        (
          await send(f.origin, '/api/orders/private-object-id', {
            headers: { authorization: await f.token('north', 'unrelated') },
          })
        ).status,
        403,
      );
      assert.equal((await send(f.origin, '/api/orders/private-object-id')).status, 401);
      await f.app.telemetry.flush();
      const metrics = data.flatMap(
        (envelope) =>
          envelope.resourceMetrics?.flatMap((resource) =>
            resource.scopeMetrics.flatMap((scope) => scope.metrics),
          ) ?? [],
      );
      const spans = data.flatMap(
        (envelope) =>
          envelope.resourceSpans?.flatMap((resource) =>
            resource.scopeSpans.flatMap((scope) => scope.spans),
          ) ?? [],
      );
      const sum = (name: string) =>
        metrics
          .filter((metric) => metric.name === name)
          .flatMap((metric) => metric.sum?.dataPoints ?? [])
          .reduce((total, point) => total + (point.asDouble ?? Number(point.asInt)), 0);
      assert.equal(sum('arkenivajs.routing.requests'), 5);
      assert.equal(sum('arkenivajs.routing.matches'), 4);
      assert.equal(sum('arkenivajs.routing.rejected'), 3);
      assert.equal(upstreamCalls, 1);
      for (const name of [
        'registry',
        'lookup',
        'authorization',
        'implementation',
        'operation',
        'upstream',
      ]) {
        const own = metrics.filter(
          (metric) => metric.name === `arkenivajs.routing.${name}.duration`,
        );
        assert.ok(own.length && own.every((metric) => metric.unit === 's'), name);
      }
      const selected = spans.filter((span) => span.name === 'tenant.routing.operation');
      assert.equal(selected.length, 2);
      const client = spans.filter((span) => span.name === 'http.client.request');
      assert.equal(client.length, 1);
      assert.equal(client[0]!.kind, 3);
      assert.equal(client[0]!.traceId, traceId);
      assert.ok(selected.some((span) => span.spanId === client[0]!.parentSpanId));
      assert.equal(propagated, `00-${traceId}-${client[0]!.spanId}-01`);
      for (const span of selected) {
        assert.equal(span.traceId, traceId);
        assert.ok(
          spans.some(
            (candidate) =>
              candidate.name === 'http.server.request' &&
              candidate.spanId === span.parentSpanId &&
              candidate.parentSpanId === parent,
          ),
        );
        const attributes = Object.fromEntries(
          span.attributes!.map((attribute) => [
            attribute.key,
            attribute.value.stringValue ?? attribute.value.intValue,
          ]),
        );
        assert.ok(['north', 'south'].includes(String(attributes['tenant.id'])));
        assert.equal(attributes['routing.operation'], 'orders.read');
        assert.equal(attributes['routing.revision'], 'stable-blue');
        assert.equal(Number(attributes['routing.activation_generation']), 1);
        assert.ok(
          ['north-orders', 'south-orders'].includes(String(attributes['routing.implementation'])),
        );
      }
      assert.doesNotMatch(
        JSON.stringify(metrics),
        /north|south|stable-blue|private-object-id|tenant\.id|routing\.(?:implementation|revision|operation)"/,
      );
      assert.doesNotMatch(
        JSON.stringify(data),
        /private-object-id|private-untrusted|Bearer |baggage/,
      );
      for (const attributes of [
        { 'tenant.id': 'north' },
        { 'routing.operation': 'orders.read' },
        { 'routing.revision': 'stable-blue' },
        { 'routing.implementation': 'north-orders' },
        { 'routing.activation_generation': 1 },
        { 'routing.kind': 'untrusted' },
        { 'routing.outcome': 'private-value' },
      ])
        assert.throws(
          () => f.app.telemetry.addCounter('arkenivajs.routing.requests', 1, attributes),
          { code: 'EK_CONFIG_INVALID' },
        );
    } finally {
      await f.close();
    }
  },
);

test('Throwing or repeated observer continuations never replay a handler or bypass authorization', async () => {
  for (const mode of ['before', 'after', 'twice', 'metrics'] as const) {
    let effects = 0;
    const telemetry: Telemetry & {
      withRemoteContext<T>(headers: Readonly<Record<string, string>>, work: () => T): T;
    } = {
      measure: async (_name, work) => work(),
      withSpan: async (_name, work) => {
        if (mode === 'before') throw new Error('private-observer-failure');
        const result = work();
        if (mode === 'after') throw new Error('private-observer-failure');
        return result;
      },
      addCounter() {
        if (mode === 'metrics') throw new Error('private-observer-failure');
      },
      recordHistogram() {
        if (mode === 'metrics') throw new Error('private-observer-failure');
      },
      setGauge() {},
      flush: async () => {},
      withRemoteContext(_headers, work) {
        const result = work();
        if (mode === 'twice') work();
        return result;
      },
    };
    const provider: Plugin = {
      id: 'telemetry',
      version: '1.0.0',
      capabilities: new Set(['telemetry']),
      init(context) {
        context.provide(COMPONENTS.telemetry, telemetry);
      },
      close() {},
    };
    const base = settings(),
      f = await fixture(
        {
          ...base,
          handlers: {
            ...base.handlers,
            north: () => ({ id: String(++effects), tenant: 'north', implementation: 'north' }),
          },
        },
        { plugins: [provider], telemetry: { mode: 'standard' } },
      );
    try {
      const accepted = await send(f.origin, '/api/orders', {
        method: 'POST',
        body: { id: 'private-object-id' },
        headers: { authorization: await f.token('north') },
      });
      assert.equal(accepted.status, 200, accepted.body);
      assert.equal(effects, 1);
      const denied = await send(f.origin, '/api/orders', {
        method: 'POST',
        body: { id: 'private-object-id' },
        headers: { authorization: await f.token('north', 'unrelated') },
      });
      assert.equal(denied.status, 403, denied.body);
      assert.equal(effects, 1);
      assert.doesNotMatch(accepted.body + denied.body + f.logs(), /private-observer-failure/);
    } finally {
      await f.close();
    }
  }
});
