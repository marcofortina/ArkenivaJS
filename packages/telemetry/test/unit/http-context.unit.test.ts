// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { createApi, apiPlugin } from '@arkenivajs/api';
import { httpPlugin, createHttpClient } from '@arkenivajs/http';
import { loggingPlugin } from '@arkenivajs/logging';
import { createTelemetry, telemetryPlugin } from '@arkenivajs/telemetry';

async function port() {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}
const service = (name: string) => ({ name, version: '1.0.0', environment: 'test' as const });
const response = {
  type: 'object',
  properties: { value: { type: 'string' } },
  required: ['value'],
  additionalProperties: false,
};

test('EK-OTEL-001 explicit API/client dependencies propagate real spans across independent applications and correlate safe logs', async () => {
  const payloads: string[] = [],
    logs: string[] = [];
  const collector = createServer(async (request, reply) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    payloads.push(Buffer.concat(chunks).toString());
    reply.setHeader('content-type', 'application/json');
    reply.end('{}');
  });
  await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
  const address = collector.address();
  assert.ok(address && typeof address === 'object');
  const endpoint = `http://127.0.0.1:${address.port}`;
  const destination = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs.push(chunk.toString());
      done();
    },
  });
  const telemetry = (route: string) =>
    telemetryPlugin({
      endpoint,
      allowInsecureLoopback: true,
      exportTimeoutMs: 500,
      exportIntervalMs: 1000,
      labelValues: { route: [route] },
    });
  const childPort = await port(),
    parentPort = await port();
  const child = await createApplication({
    service: service('trace-child'),
    http: { host: '127.0.0.1', port: childPort },
    telemetry: { mode: 'detailed' },
    plugins: [
      loggingPlugin({ destination }),
      telemetry('/child'),
      apiPlugin({ dependencies: ['telemetry'] }),
    ],
  });
  const origin = `http://127.0.0.1:${childPort}`;
  const parent = await createApplication({
    service: service('trace-parent'),
    http: { host: '127.0.0.1', port: parentPort },
    telemetry: { mode: 'detailed' },
    plugins: [
      loggingPlugin({ destination }),
      telemetry('/call'),
      httpPlugin({
        allowedOrigins: [origin],
        allowPrivateNetwork: true,
        dependencies: ['telemetry'],
      }),
      apiPlugin({ dependencies: ['telemetry'] }),
    ],
  });
  child.api.get('/child', {
    schema: { response },
    auth: { required: false },
    handler: (ctx) => {
      assert.equal(ctx.auth, undefined);
      assert.equal(ctx.headers.baggage, undefined);
      assert.equal(ctx.headers.authorization, undefined);
      child.logger.info('Child handler completed');
      return { value: 'ok' };
    },
  });
  parent.api.get('/call', {
    schema: { response },
    auth: { required: false },
    handler: async (ctx) => {
      assert.equal(ctx.auth, undefined);
      parent.logger.info('Parent handler started');
      const reply = await parent.http.get(origin + '/child', { signal: ctx.signal });
      return reply.json();
    },
  });
  try {
    await child.start();
    await parent.start();
    const traceId = '1234567890abcdef1234567890abcdef';
    const result = await fetch(`http://127.0.0.1:${parentPort}/call`, {
      headers: {
        traceparent: `00-${traceId}-1234567890abcdef-01`,
        baggage: 'tenant_id=fake-untrusted-tenant',
        authorization: 'Bearer fake-private-token',
      },
    });
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { value: 'ok' });
    await parent.telemetry.flush();
    await child.telemetry.flush();
    await parent.logger.flush();
    await child.logger.flush();
    const frames = payloads.map(
      (value) =>
        JSON.parse(value) as {
          resourceSpans?: {
            resource: { attributes: { key: string; value: { stringValue?: string } }[] };
            scopeSpans: {
              spans: {
                name: string;
                traceId: string;
                spanId: string;
                parentSpanId?: string;
                kind: number;
              }[];
            }[];
          }[];
        },
    );
    const spans = frames
      .flatMap((frame) => frame.resourceSpans ?? [])
      .flatMap((group) =>
        group.scopeSpans
          .flatMap((scope) => scope.spans)
          .map((span) => ({
            ...span,
            service: group.resource.attributes.find((a) => a.key === 'service.name')?.value
              .stringValue,
          })),
      );
    const inbound = spans.find(
      (span) => span.name === 'http.server.request' && span.service === 'trace-parent',
    )!;
    const outbound = spans.find((span) => span.name === 'http.client.request')!;
    const downstream = spans.find(
      (span) => span.name === 'http.server.request' && span.service === 'trace-child',
    )!;
    assert.ok(inbound && outbound && downstream);
    assert.equal(inbound.kind, 2);
    assert.equal(downstream.kind, 2);
    assert.equal(outbound.kind, 3);
    assert.equal(inbound.parentSpanId, '1234567890abcdef');
    assert.equal(outbound.parentSpanId, inbound.spanId);
    assert.equal(downstream.parentSpanId, outbound.spanId);
    assert.ok(spans.every((span) => span.traceId === traceId));
    assert.ok(
      logs.some((line) => line.includes('Parent handler started') && line.includes(traceId)),
    );
    assert.ok(
      logs.some((line) => line.includes('Child handler completed') && line.includes(traceId)),
    );
    const wire = payloads.join('') + logs.join('');
    assert.ok(!wire.includes('fake-private-token'));
    assert.ok(!wire.includes('fake-untrusted-tenant'));
    assert.equal((parent.api as ReturnType<typeof createApi>).stats().observerFailures, 0);
    assert.equal((parent.http as ReturnType<typeof createHttpClient>).stats().observerFailures, 0);
    assert.equal((child.api as ReturnType<typeof createApi>).stats().observerFailures, 0);
    assert.ok(
      wire.includes('http.server.request.duration') &&
        wire.includes('http.client.request.duration') &&
        wire.includes('arkenivajs.http.body.bytes'),
    );
  } finally {
    try {
      await parent.stop();
      await child.stop();
    } finally {
      destination.destroy();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  }
});

test('EK-OTEL-001 unavailable diagnostics never repeat a POST or replace a successful handler', async () => {
  const telemetry = createTelemetry({ service: service('closed-diagnostics'), mode: 'off' });
  await telemetry.close();
  let calls = 0;
  const api = createApi({ service: service('diagnostic-failure'), port: 0, telemetry });
  api.post('/work', {
    schema: { response },
    auth: { required: false },
    handler() {
      calls++;
      return { value: 'ok' };
    },
  });
  await api.start();
  const client = createHttpClient({
    allowedOrigins: [api.address()!],
    allowPrivateNetwork: true,
    telemetry,
    traceHeaders: () => telemetry.traceHeaders(),
  });
  try {
    const result = await client.post(api.address() + '/work', {});
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { value: 'ok' });
    assert.equal(calls, 1);
    assert.ok(api.stats().observerFailures > 0 && client.stats().observerFailures > 0);
  } finally {
    await client.close();
    await api.close();
  }
});
