// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, send } from '../fixture.js';

interface Attribute {
  key: string;
  value: { stringValue?: string; intValue?: number };
}
interface Span {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  attributes: Attribute[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: { attributes: Attribute[]; asDouble?: number; asInt?: string }[] };
  histogram?: { dataPoints: { attributes: Attribute[] }[] };
}
interface Envelope {
  resourceSpans?: { scopeSpans: { spans: Span[] }[] }[];
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(`Actual ${mode} SDK preserves proxy trace parentage without exporting URLs, credentials or identities`, async () => {
    const envelopes: Envelope[] = [],
      marker = 'private-' + randomUUID(),
      traceId = randomBytes(16).toString('hex'),
      parentId = randomBytes(8).toString('hex');
    let propagated: string | undefined;
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    let f: Awaited<ReturnType<typeof fixture>> | undefined;
    try {
      f = await fixture(
        {},
        (request, response) => {
          propagated =
            typeof request.headers.traceparent === 'string'
              ? request.headers.traceparent
              : undefined;
          assert.equal(request.headers.baggage, undefined);
          response.end('observed');
        },
        { telemetry: { mode, endpoint: 'http://127.0.0.1:' + address.port } },
      );
      const authorization = await f.token();
      const result = await send(f.origin, '/orders/' + marker + '?private=' + marker, 'GET', {
        authorization,
        cookie: marker,
        'x-tenant-id': marker,
        baggage: marker,
        traceparent: '00-' + traceId + '-' + parentId + '-01',
      });
      assert.equal(result.status, 200, result.body);
      assert.ok(propagated);
      await f.app.telemetry.flush();
      await f.app.logger.flush();
      const logs = f.logs();
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      const requests = metrics.find((metric) => metric.name === 'proxy.requests');
      assert.ok(requests);
      assert.equal(requests.unit, '{request}');
      assert.ok(
        requests.sum?.dataPoints.some((point) => (point.asDouble ?? Number(point.asInt)) === 1),
      );
      assert.ok(
        metrics.some((metric) => metric.name === 'proxy.response.bytes' && metric.unit === 'By'),
      );
      const spans = envelopes
        .flatMap((envelope) => envelope.resourceSpans ?? [])
        .flatMap((resource) => resource.scopeSpans.flatMap((scope) => scope.spans));
      const inbound = spans.find((span) => span.name === 'proxy.request'),
        outbound = spans.find((span) => span.name === 'proxy.upstream');
      assert.ok(inbound);
      assert.ok(outbound);
      assert.equal(inbound.traceId, traceId);
      assert.equal(inbound.parentSpanId, parentId);
      assert.equal(outbound.parentSpanId, inbound.spanId);
      assert.equal(propagated, '00-' + traceId + '-' + outbound.spanId + '-01');
      const serialized = JSON.stringify({ envelopes, logs });
      for (const forbidden of [marker, authorization, 'proxy-test-account', f.route.upstreamOrigin])
        assert.ok(
          !serialized.includes(forbidden),
          forbidden === authorization ? 'Credential must stay private' : forbidden,
        );
      const allowed = new Set(['route', 'peer.service', 'proxy.outcome', 'status_code']);
      for (const metric of metrics.filter((metric) => metric.name.startsWith('proxy.')))
        for (const point of [
          ...(metric.sum?.dataPoints ?? []),
          ...(metric.histogram?.dataPoints ?? []),
        ])
          for (const attribute of point.attributes) assert.ok(allowed.has(attribute.key));
    } finally {
      await f?.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  });
