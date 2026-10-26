// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { COMPRESSION_CAPABILITY, dataCompressionPlugin } from '@arkenivajs/data-compression';
import type { CompressionService } from '@arkenivajs/data-compression';

test('Native compression operations export real SDK metadata without archive contents or paths', async () => {
  const envelopes: {
      resourceMetrics?: {
        scopeMetrics: {
          metrics: { name: string; unit: string; histogram?: { dataPoints: { sum: number }[] } }[];
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
    }),
    app = await createApplication({
      service: { name: 'compression-observation', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        dataCompressionPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 5000 } }),
        loggingPlugin({ destination }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + endpoint.port,
          allowInsecureLoopback: true,
          exportTimeoutMs: 1000,
          exportIntervalMs: 1000,
        }),
      ],
    });
  try {
    await app.start();
    const compression = app.resolve<CompressionService>(COMPRESSION_CAPABILITY);
    const parts: Buffer[] = [];
    for await (const bytes of compression.gzip(Buffer.from('private-compression-fixture')))
      parts.push(Buffer.from(bytes));
    const image = Buffer.concat(parts);
    const restored: Buffer[] = [];
    for await (const bytes of compression.gunzip(image)) restored.push(Buffer.from(bytes));
    assert.equal(Buffer.concat(restored).toString('utf8'), 'private-compression-fixture');
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    const duration = metrics.find((metric) => metric.name === 'compression.duration.ms');
    assert.equal(duration?.unit, 'ms');
    assert.ok((duration?.histogram?.dataPoints[0]?.sum ?? -1) >= 0);
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'compression.compressed.bytes' && metric.unit === 'By',
      ),
    );
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'compression.process.cpu.ms' && metric.unit === 'ms',
      ),
    );
    assert.ok(logs.some((line) => line.includes('compression.operation.complete')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    assert.ok(!wire.includes('private-compression-fixture'));
    assert.ok(!wire.includes(Buffer.from(image).toString('base64')));
  } finally {
    try {
      await app.stop();
    } finally {
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      destination.end();
    }
  }
});
