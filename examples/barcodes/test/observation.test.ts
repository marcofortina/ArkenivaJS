// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { CODES_CAPABILITY, dataCodesPlugin } from '@arkenivajs/data-barcodes';
import type { CodeService } from '@arkenivajs/data-barcodes';

test('Native image operations export real SDK metadata without carrier contents or raw images', async () => {
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
      service: { name: 'codes-observation', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        dataCodesPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 5000 } }),
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
    const codes = app.resolve<CodeService>(CODES_CAPABILITY),
      image = await codes.generateQr('private-carrier-fixture');
    assert.equal((await codes.decode(image))[0]?.text, 'private-carrier-fixture');
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    const duration = metrics.find((metric) => metric.name === 'codes.duration.ms');
    assert.equal(duration?.unit, 'ms');
    assert.ok((duration?.histogram?.dataPoints[0]?.sum ?? -1) >= 0);
    assert.ok(
      metrics.some((metric) => metric.name === 'codes.output.bytes' && metric.unit === 'By'),
    );
    assert.ok(
      metrics.some((metric) => metric.name === 'codes.image.pixels' && metric.unit === '{pixel}'),
    );
    assert.ok(logs.some((line) => line.includes('codes.operation.complete')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    assert.ok(!wire.includes('private-carrier-fixture'));
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
