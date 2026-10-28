// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import WebSocket from 'ws';
import { fixture, sseRequest } from '../fixture.js';

interface Attribute {
  key: string;
  value: unknown;
}
interface Point {
  attributes: Attribute[];
  asDouble?: number;
  asInt?: string;
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
  gauge?: { dataPoints: Point[] };
}
interface Envelope {
  resourceSpans?: { scopeSpans: { spans: { name: string; attributes: Attribute[] }[] }[] }[];
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(`Actual ${mode} SDK exports aggregate realtime activity without messages, cursors or identities`, async () => {
    const envelopes: Envelope[] = [],
      marker = 'private-' + randomUUID();
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
    let f: Awaited<ReturnType<typeof fixture>> | undefined, socket: WebSocket | undefined;
    try {
      f = await fixture({}, undefined, [], {
        telemetry: { mode, endpoint: 'http://127.0.0.1:' + address.port },
      });
      const authorization = await f.token();
      socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket?private=' + marker, {
        headers: { authorization, baggage: marker, 'x-tenant-id': marker },
      });
      await once(socket, 'open');
      const echoed = once(socket, 'message');
      socket.send(
        JSON.stringify({
          channel: marker,
          payload: Buffer.from(marker).toString('base64url'),
          id: marker,
        }),
      );
      await echoed;
      const closed = once(socket, 'close');
      socket.close();
      await closed;
      assert.equal((await sseRequest(f.origin, { authorization })).status, 200);
      await f.service.close();
      await f.app.telemetry.flush();
      await f.app.logger.flush();
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics))
        .filter((metric) => metric.name.startsWith('realtime.'));
      for (const name of [
        'realtime.connections.active',
        'realtime.queue.bytes',
        'realtime.sent.bytes',
        'realtime.received.bytes',
        'realtime.disconnects',
      ])
        assert.ok(
          metrics.some((metric) => metric.name === name),
          name,
        );
      assert.equal(metrics.find((metric) => metric.name === 'realtime.sent.bytes')!.unit, 'By');
      for (const metric of metrics)
        for (const point of [
          ...(metric.sum?.dataPoints ?? []),
          ...(metric.gauge?.dataPoints ?? []),
        ])
          for (const attribute of point.attributes)
            assert.ok(['realtime.protocol', 'realtime.reason'].includes(attribute.key));
      const active = metrics.find((metric) => metric.name === 'realtime.connections.active')!;
      assert.ok(
        active.gauge!.dataPoints.every((point) => (point.asDouble ?? Number(point.asInt)) === 0),
      );
      const spans = envelopes
        .flatMap((envelope) => envelope.resourceSpans ?? [])
        .flatMap((resource) => resource.scopeSpans.flatMap((scope) => scope.spans));
      assert.ok(spans.some((span) => span.name === 'realtime.admit'));
      const serialized = JSON.stringify({ envelopes, logs: f.logs() });
      for (const value of [
        marker,
        authorization,
        'tenant-a',
        'tenant-a_1',
        'realtime-test-account',
        f.issuer,
      ])
        assert.ok(
          !serialized.includes(value),
          value === authorization ? 'Credentials must remain private' : value,
        );
    } finally {
      socket?.terminate();
      await f?.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  });
