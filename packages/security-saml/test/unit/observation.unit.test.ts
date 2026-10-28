// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { samlPlugin, SAML_CAPABILITY } from '../../dist/index.js';
import type { SamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

interface Point {
  attributes: { key: string }[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
  histogram?: { dataPoints: Point[] };
  gauge?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: unknown[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(
    `SAML ${mode} SDK exports exclude identities, protocol messages and provider secrets`,
    { timeout: 30000 },
    async () => {
      const f = await fixture(),
        envelopes: Envelope[] = [],
        logs: string[] = [];
      let available = true,
        failures = 0;
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
      const markers = [
        'synthetic-account',
        'private-session-index',
        'untrusted-tenant-hint',
        'private-provider-credential',
        f.settings.entityId,
        f.settings.signingKeyRef!,
      ];
      try {
        app = await createApplication({
          service: { name: 'saml-observation', version: '1.0.0', environment: 'test' },
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
            samlPlugin({
              ...f.settings,
              secretProvider: {
                async get(...args) {
                  if (!available) {
                    failures++;
                    throw new Error('private-provider-credential');
                  }
                  return f.settings.secretProvider.get(...args);
                },
              },
            }),
          ],
        });
        await app.start();
        const service = app.resolve<SamlService>(SAML_CAPABILITY),
          request = await service.beginLogin({ returnPath: '/private-return-path' }),
          response = f.response(request.requestId),
          context = { inResponseTo: request.requestId, relayState: request.requestId };
        markers.push(request.requestId, response, '/private-return-path');
        const identity = await service.consumeResponse(context, response);
        await assert.rejects(service.consumeResponse(context, response), {
          code: 'EK_SAML_REPLAY',
        });
        await service.createMetadata();
        const logout = await service.beginLogout(identity);
        await service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
        available = false;
        await assert.rejects(service.createMetadata(), { code: 'EK_BACKEND_UNAVAILABLE' });
        assert.equal(failures, 1);
        await app.telemetry.flush();
        await app.logger.flush();
      } finally {
        try {
          await app?.stop();
        } finally {
          collector.closeAllConnections();
          await new Promise<void>((resolve) => collector.close(() => resolve()));
          destination.end();
          await f.close();
        }
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      for (const name of [
        'saml.operations',
        'saml.operation.duration.ms',
        'saml.operations.active',
      ])
        assert.ok(
          metrics.some((metric) => metric.name === name),
          name,
        );
      assert.ok(
        metrics.some(
          (metric) => metric.name === 'saml.operation.duration.ms' && metric.unit === 'ms',
        ),
      );
      assert.ok(envelopes.some((envelope) => (envelope.resourceSpans?.length ?? 0) > 0));
      const serialized = JSON.stringify({ envelopes, logs });
      for (const marker of markers)
        assert.ok(!serialized.includes(marker), 'Sensitive SAML data was exported');
      for (const metric of metrics.filter((metric) => metric.name.startsWith('saml.')))
        for (const point of [
          ...(metric.sum?.dataPoints ?? []),
          ...(metric.histogram?.dataPoints ?? []),
          ...(metric.gauge?.dataPoints ?? []),
        ])
          for (const attribute of point.attributes)
            assert.ok(['saml.operation', 'saml.outcome'].includes(attribute.key));
    },
  );
