// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { dnsPlugin, DNS_CAPABILITY } from '@arkenivajs/dns';
import type { DnsService } from '@arkenivajs/dns';
import { startDnsFixture } from '../dist/fixture.js';

test(
  'Native DNS exports real bounded SDK metrics and safe logs without query or server data',
  { timeout: 5000 },
  async () => {
    const fixture = await startDnsFixture(),
      envelopes: {
        resourceMetrics?: {
          scopeMetrics: {
            metrics: {
              name: string;
              unit: string;
              histogram?: { dataPoints: { sum: number }[] };
            }[];
          }[];
        }[];
      }[] = [],
      logs: string[] = [];
    const collector = createServer(async (request, response) => {
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
        logs.push(chunk.toString('utf8'));
        done();
      },
    });
    const app = await createApplication({
      service: { name: 'dns-observation-fixture', version: '1.0.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        dnsPlugin({
          resolvers: [{ name: 'lab', servers: [fixture.server] }],
          maxConcurrency: 4,
          timeoutMs: 1000,
        }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + endpoint.port,
          allowInsecureLoopback: true,
          exportTimeoutMs: 1000,
          exportIntervalMs: 1000,
          labelValues: { 'dns.resolver': ['lab', 'os'] },
        }),
        loggingPlugin({ destination }),
      ],
    });
    try {
      await app.start();
      const dns = app.resolve<DnsService>(DNS_CAPABILITY);
      await app.telemetry.measure('dns.fixture', () =>
        dns.resolve({ hostname: 'private.internal.test', type: 'A' }),
      );
      await app.telemetry.flush();
      await app.logger.flush();
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      const histogram = metrics.find((metric) => metric.name === 'dns.duration.ms');
      assert.equal(histogram?.unit, 'ms');
      assert.ok((histogram?.histogram?.dataPoints[0]?.sum ?? -1) >= 0);
      assert.ok(metrics.some((metric) => metric.name === 'dns.operation.count'));
      assert.ok(
        metrics.some(
          (metric) => metric.name === 'dns.response.records' && metric.unit === '{record}',
        ),
      );
      assert.ok(logs.some((line) => line.includes('dns.operation.complete')));
      const wire = JSON.stringify(envelopes) + logs.join('');
      assert.ok(!wire.includes('private.internal.test'));
      assert.ok(!wire.includes(fixture.server));
      assert.ok(!wire.includes('192.0.2.11'));
    } finally {
      await app.stop();
      await fixture.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      destination.end();
    }
  },
);
