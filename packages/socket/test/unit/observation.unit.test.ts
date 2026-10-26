// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Writable } from 'node:stream';
import { createServer } from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import type { Plugin, VerifiedTenantContext, TenantId } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import type { ManagedLogger } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import type { ManagedTelemetry } from '@arkenivajs/telemetry';
import { createMeter } from '@arkenivajs/metering';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type { SocketService } from '../../dist/index.js';

interface Envelope {
  resourceSpans?: {
    scopeSpans: { spans: { name: string; traceId: string; parentSpanId?: string }[] }[];
  }[];
  resourceMetrics?: {
    scopeMetrics: {
      metrics: {
        name: string;
        unit: string;
        sum?: {
          dataPoints: {
            asDouble: number;
            attributes: { key: string; value: { stringValue?: string } }[];
          }[];
        };
      }[];
    }[];
  }[];
}
test(
  'Actual native socket observations detach log, OTel and tenant accounting scopes with exact payload units',
  { timeout: 5000 },
  async () => {
    const envelopes: Envelope[] = [],
      lines: string[] = [],
      collector = createServer(async (request, response) => {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(chunk);
        envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        response.setHeader('content-type', 'application/json');
        response.end('{}');
      });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const endpoint = collector.address();
    assert.ok(endpoint && typeof endpoint === 'object');
    const destination = new Writable({
        write(chunk: Buffer, _encoding, done) {
          lines.push(chunk.toString('utf8'));
          done();
        },
      }),
      serviceIdentity = {
        name: 'socket-observation',
        version: '1.0.0',
        environment: 'test' as const,
      },
      tenant: VerifiedTenantContext = Object.freeze({
        tenantId: 'owned-fixture-tenant' as TenantId,
        identity: {
          subject: 'fixture',
          issuer: 'https://issuer.invalid',
          audience: ['fixture'],
          scopes: [],
          claims: {},
        },
        verifiedAt: new Date().toISOString(),
        source: 'oidc',
      }),
      owned = new WeakSet<object>([tenant]),
      meter = createMeter({
        service: serviceIdentity,
        auth: {
          isVerifiedTenant(value): value is VerifiedTenantContext {
            return typeof value === 'object' && value !== null && owned.has(value);
          },
        },
        enabled: true,
        exporter: { kind: 'jsonl', async export() {}, async close() {} },
      }),
      meterOwner: Plugin = {
        id: 'meter-scope-fixture',
        version: '1.0.0',
        capabilities: new Set(['meter']),
        init(context) {
          context.provide(COMPONENTS.meter, meter);
        },
        async close() {
          await meter.close();
        },
      },
      app = await createApplication({
        service: serviceIdentity,
        logging: { level: 'debug' },
        telemetry: { mode: 'standard', samplingRatio: 1 },
        plugins: [
          socketPlugin(),
          loggingPlugin({ destination }),
          telemetryPlugin({
            endpoint: `http://127.0.0.1:${endpoint.port}`,
            allowInsecureLoopback: true,
            exportTimeoutMs: 1000,
            exportIntervalMs: 1000,
          }),
          meterOwner,
        ],
      });
    let calls = 0,
      isolated = false;
    try {
      await app.start();
      const logger = app.logger as ManagedLogger,
        telemetry = app.telemetry as ManagedTelemetry,
        sockets = app.resolve<SocketService>(SOCKET_CAPABILITY),
        session = meter.start({ tenant, operation: 'unrelated.request' });
      let outerTrace: string | undefined;
      const listener = await logger.run(
        { requestId: 'unrelated-private-request', tenantId: 'unrelated-private-tenant' },
        () =>
          telemetry.measure('outer.request', () =>
            meter.run(session, async () => {
              outerTrace = telemetry.currentTraceId();
              const handle = sockets.createTcpServer(
                { name: 'observed', port: 0 },
                async (peer) => {
                  calls++;
                  isolated =
                    meter.current() === undefined && telemetry.currentTraceId() !== outerTrace;
                  logger.info('socket.fixture.handler');
                  for await (const bytes of peer.chunks()) await peer.send(bytes);
                  await peer.end();
                },
              );
              await handle.start();
              return handle;
            }),
          ),
      );
      const client = net.connect(listener.boundAddress!.network!.port, '127.0.0.1');
      await once(client, 'connect');
      client.end(Buffer.from('private-raw-payload'));
      const received: Buffer[] = [];
      for await (const bytes of client) received.push(bytes);
      assert.equal(Buffer.concat(received).toString('utf8'), 'private-raw-payload');
      assert.equal(calls, 1);
      assert.equal(isolated, true);
      session.end();
      await listener.stop();
      await telemetry.flush();
      await logger.flush();
      const spans = envelopes
          .flatMap((value) => value.resourceSpans ?? [])
          .flatMap((value) => value.scopeSpans.flatMap((scope) => scope.spans)),
        handler = spans.find((value) => value.name === 'socket.handler');
      assert.ok(handler);
      assert.notEqual(handler.traceId, outerTrace);
      assert.ok(!handler.parentSpanId);
      const metrics = envelopes
          .flatMap((value) => value.resourceMetrics ?? [])
          .flatMap((value) => value.scopeMetrics.flatMap((scope) => scope.metrics)),
        payload = metrics.find((value) => value.name === 'socket.payload.bytes');
      assert.equal(payload?.unit, 'By');
      const data = payload!.sum!.dataPoints,
        read = data.filter((point) =>
          point.attributes.some(
            (attribute) =>
              attribute.key === 'socket.event' && attribute.value.stringValue === 'read',
          ),
        ),
        written = data.filter((point) =>
          point.attributes.some(
            (attribute) =>
              attribute.key === 'socket.event' && attribute.value.stringValue === 'write',
          ),
        );
      assert.equal(
        read.reduce((sum, value) => sum + value.asDouble, 0),
        19,
      );
      assert.equal(
        written.reduce((sum, value) => sum + value.asDouble, 0),
        19,
      );
      const output = JSON.stringify(envelopes) + lines.join('');
      assert.ok(!output.includes('private-raw-payload'));
      assert.ok(!output.includes('unrelated-private-tenant'));
      const handlerLogs = lines.filter((line) => line.includes('socket.fixture.handler'));
      assert.equal(handlerLogs.length, 1);
      assert.ok(!handlerLogs[0]!.includes('unrelated-private-request'));
      assert.equal(meter.stats().enqueued, 1);
    } finally {
      await app.stop({ timeoutMs: 1000 });
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      destination.end();
    }
  },
);

test(
  'Failing asynchronous diagnostics and a throwing span observer cannot replay or replace native handler work',
  { timeout: 5000 },
  async () => {
    let calls = 0,
      drops = 0;
    const trace: Telemetry & { withoutScope<T>(work: () => T): T } = {
        withoutScope: (work) => work(),
        async measure(_name, work) {
          return work();
        },
        async withSpan(_name, work) {
          await work();
          throw new Error('Private observer failure');
        },
        addCounter(name) {
          if (name === 'socket.observation.dropped') {
            drops++;
            return;
          }
          return Promise.reject(new Error('Private metrics failure')) as unknown as void;
        },
        recordHistogram() {
          throw new Error('Private histogram failure');
        },
        setGauge() {
          throw new Error('Private gauge failure');
        },
        async flush() {},
      },
      owner: Plugin = {
        id: 'observer-fixture',
        version: '1.0.0',
        capabilities: new Set(['telemetry']),
        init(context) {
          context.provide(COMPONENTS.telemetry, trace);
        },
        close() {},
      },
      app = await createApplication({
        service: { name: 'faulty-observer', version: '1.0.0', environment: 'test' },
        plugins: [socketPlugin(), owner],
      });
    try {
      await app.start();
      const listener = app
        .resolve<SocketService>(SOCKET_CAPABILITY)
        .createTcpServer({ name: 'safe', port: 0 }, async (peer) => {
          calls++;
          for await (const bytes of peer.chunks()) await peer.send(bytes);
          await peer.end();
        });
      await listener.start();
      const client = net.connect(listener.boundAddress!.network!.port, '127.0.0.1');
      client.end(Buffer.from('once'));
      const received: Buffer[] = [];
      for await (const bytes of client) received.push(bytes);
      assert.equal(Buffer.concat(received).toString('utf8'), 'once');
      assert.equal(calls, 1);
      await listener.stop();
      assert.ok(drops > 0);
      assert.equal(listener.stats().errors, 0);
    } finally {
      await app.stop({ timeoutMs: 1000 });
    }
  },
);
