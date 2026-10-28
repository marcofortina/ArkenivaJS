// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '../../dist/index.js';
import type { MagicLinkService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

interface Attribute {
  key: string;
  value: { stringValue?: string };
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
  histogram?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: unknown[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(
    `Magic link credentials remain private in actual ${mode} SDK exports`,
    { timeout: 30000 },
    async () => {
      const source = fixture(),
        envelopes: Envelope[] = [],
        logs: string[] = [],
        privateRef = 'private-reference-' + randomUUID(),
        privateError = 'private-provider-' + randomUUID();
      let available = true,
        rejectedProviderCalls = 0;
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
      let app: Awaited<ReturnType<typeof createApplication>> | undefined;
      const markers: string[] = [
        privateRef,
        privateError,
        source.owner.subject,
        source.owner.issuer,
      ];
      try {
        const hmac = {
          ...source.settings.hmac,
          async digest(...args: Parameters<typeof source.settings.hmac.digest>) {
            if (!available) {
              rejectedProviderCalls++;
              throw new Error(privateError);
            }
            return source.settings.hmac.digest(
              args[0],
              args[1],
              source.settings.signingKeyRef,
              args[3],
            );
          },
          async verify(...args: Parameters<typeof source.settings.hmac.verify>) {
            return source.settings.hmac.verify(
              args[0],
              args[1],
              args[2],
              source.settings.signingKeyRef,
              args[4],
            );
          },
        };
        app = await createApplication({
          service: { name: 'magiclink-observation', version: '1.0.0', environment: 'test' },
          logging: { level: 'debug' },
          telemetry: { mode, samplingRatio: 1 },
          plugins: [
            loggingPlugin({ destination }),
            telemetryPlugin({
              endpoint: 'http://127.0.0.1:' + address.port,
              allowInsecureLoopback: true,
              exportIntervalMs: 60000,
              exportTimeoutMs: 1000,
            }),
            magicLinksPlugin({ ...source.settings, hmac, signingKeyRef: privateRef }),
          ],
        });
        await app.start();
        const service = app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY),
          issued = await service.issue(source.owner, 'login');
        markers.push(issued.value, issued.value.split('.')[2]!, issued.redemptionUrl);
        await service.consume(issued.value, { method: 'POST', purpose: 'login' });
        await assert.rejects(service.consume(issued.value, { method: 'POST', purpose: 'login' }), {
          code: 'EK_MAGICLINK_REPLAY',
        });
        available = false;
        await assert.rejects(service.issue(source.owner, 'login'), {
          code: 'EK_BACKEND_UNAVAILABLE',
        });
        assert.equal(rejectedProviderCalls, 1);
        await app.telemetry.flush();
        await app.logger.flush();
      } finally {
        try {
          await app?.stop();
        } finally {
          collector.closeAllConnections();
          await new Promise<void>((resolve) => collector.close(() => resolve()));
          destination.end();
        }
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      for (const name of ['magiclink.issued', 'magiclink.consumed', 'magiclink.replays']) {
        const metric = metrics.find((metric) => metric.name === name);
        assert.ok(metric);
        assert.ok(
          metric.sum?.dataPoints.some((point) => (point.asDouble ?? Number(point.asInt)) === 1),
        );
      }
      assert.ok(
        metrics.some(
          (metric) => metric.name === 'magiclink.operation.duration.ms' && metric.unit === 'ms',
        ),
      );
      assert.ok(envelopes.some((envelope) => (envelope.resourceSpans?.length ?? 0) > 0));
      const serialized = JSON.stringify({ envelopes, logs });
      for (const marker of markers) assert.ok(!serialized.includes(marker));
      const allowed = new Set(['magiclink.operation', 'magiclink.intent', 'magiclink.outcome']);
      for (const metric of metrics.filter((metric) => metric.name.startsWith('magiclink.')))
        for (const point of [
          ...(metric.sum?.dataPoints ?? []),
          ...(metric.histogram?.dataPoints ?? []),
        ])
          for (const attribute of point.attributes) assert.ok(allowed.has(attribute.key));
    },
  );
