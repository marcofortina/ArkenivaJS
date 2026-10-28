// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { fixture } from '../fixture.js';

interface Attribute {
  key: string;
  value: { stringValue?: string };
}
interface Metric {
  name: string;
  unit: string;
  histogram?: { dataPoints: { sum?: number; attributes: Attribute[] }[] };
}
interface Span {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: { scopeSpans: { spans: Span[] }[] }[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(
    `Actual gRPC payloads and assertions remain private in ${mode} SDK exports`,
    { timeout: 30000 },
    async () => {
      const envelopes: Envelope[] = [],
        logs: string[] = [],
        privateValue = 'private-payload-' + randomUUID();
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
      const destination = new Writable({
        write(chunk: Buffer, _encoding, done) {
          logs.push(chunk.toString('utf8'));
          done();
        },
      });
      const source = await fixture({
        mode,
        plugins: [
          loggingPlugin({ destination }),
          telemetryPlugin({
            endpoint: 'http://127.0.0.1:' + address.port,
            allowInsecureLoopback: true,
            exportIntervalMs: 60000,
            exportTimeoutMs: 1000,
          }),
        ],
      });
      const bearer = await source.bearer();
      try {
        const client = source.service.client('Echo');
        await source.client.telemetry.withSpan('grpc.example.request', () =>
          client.unary('Bounce', { value: privateValue }, { metadata: { authorization: bearer } }),
        );
        await assert.rejects(
          client.unary(
            'Bounce',
            {},
            { metadata: { authorization: 'Bearer invalid.assertion.value' } },
          ),
          { code: 'EK_GRPC_AUTH' },
        );
        await Promise.all([source.client.telemetry.flush(), source.server.telemetry.flush()]);
        await Promise.all([source.client.logger.flush(), source.server.logger.flush()]);
      } finally {
        await source.close();
        collector.closeAllConnections();
        await new Promise<void>((resolve) => collector.close(() => resolve()));
        destination.end();
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      const bytes = metrics.filter((metric) => metric.name === 'grpc.payload.request.bytes');
      const expected = source.definition.Bounce!.requestSerialize({ value: privateValue }).length;
      for (const side of ['client', 'server']) {
        const points = bytes
          .flatMap((metric) => metric.histogram?.dataPoints ?? [])
          .filter((point) =>
            point.attributes.some(
              (attribute) => attribute.key === 'grpc.side' && attribute.value.stringValue === side,
            ),
          );
        assert.ok(points.some((point) => point.sum === expected));
      }
      assert.ok(bytes.every((metric) => metric.unit === 'By'));
      assert.ok(envelopes.some((envelope) => (envelope.resourceSpans?.length ?? 0) > 0));
      const spans = envelopes
        .flatMap((envelope) => envelope.resourceSpans ?? [])
        .flatMap((resource) => resource.scopeSpans.flatMap((scope) => scope.spans));
      const parent = spans.find((span) => span.name === 'grpc.example.request');
      assert.ok(parent);
      const outbound = spans.find(
        (span) => span.name === 'grpc.unary' && span.parentSpanId === parent.spanId,
      );
      assert.ok(outbound);
      const inbound = spans.find(
        (span) => span.name === 'grpc.server' && span.parentSpanId === outbound.spanId,
      );
      assert.ok(inbound);
      assert.equal(inbound.traceId, parent.traceId);
      const exported = JSON.stringify({ logs, envelopes });
      for (const marker of [
        privateValue,
        bearer,
        'invalid.assertion.value',
        'tenant-A',
        'rpc-service',
        'BEGIN PRIVATE KEY',
      ])
        assert.ok(!exported.includes(marker));
      assert.ok(exported.includes('grpc.operation.duration.ms'));
      const allowed = new Set(['grpc.operation', 'grpc.side', 'grpc.outcome']);
      for (const metric of metrics.filter((metric) => metric.name.startsWith('grpc.')))
        for (const point of metric.histogram?.dataPoints ?? [])
          for (const attribute of point.attributes) assert.ok(allowed.has(attribute.key));
    },
  );
