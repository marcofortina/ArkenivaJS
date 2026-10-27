// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { dataJsonPlugin, JSON_CAPABILITY } from '@arkenivajs/data-json';
import type { JsonService } from '@arkenivajs/data-json';
import { exampleSettings } from '../dist/main.js';

interface Point {
  sum: number;
  attributes: { key: string; value: { stringValue?: string } }[];
}
interface Metric {
  name: string;
  unit: string;
  histogram?: { dataPoints: Point[] };
}
for (const mode of ['standard', 'detailed'] as const)
  test('Actual native JSON decisions remain private in ' + mode + ' SDK exports', async () => {
    const envelopes: { resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[] }[] = [],
      logs: string[] = [],
      privateValue = 'private-json-' + randomUUID(),
      invalid = 'private-invalid-' + randomUUID(),
      unknownId = 'private-unknown-' + randomUUID();
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk);
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
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
    const app = await createApplication({
      service: { name: 'json-observations', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode, samplingRatio: 1 },
      plugins: [
        dataJsonPlugin(exampleSettings()),
        loggingPlugin({ destination }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + address.port,
          allowInsecureLoopback: true,
          exportIntervalMs: 60000,
          exportTimeoutMs: 1000,
        }),
      ],
    });
    const source = JSON.stringify({
        sku: privateValue,
        label: null,
        enabled: 'true',
        quantity: '2',
      }),
      malformed = '{"' + invalid + '":';
    try {
      await app.start();
      const json = app.resolve<JsonService>(JSON_CAPABILITY),
        value = json.parse(source);
      json.stringify(value);
      assert.equal(json.validate(value, 'inventory.input.v1').valid, true);
      assert.equal(
        json.validate({ sku: invalid, enabled: true, quantity: '2' }, 'inventory.input.v1').valid,
        false,
      );
      const output = json.transform(value, 'inventory.summary.v1') as Record<string, unknown>;
      assert.equal(output.label, 'Unnamed item');
      assert.throws(() => json.parse(malformed));
      assert.throws(() => json.transform(value, unknownId));
      await app.telemetry.flush();
      await app.logger.flush();
    } finally {
      try {
        await app.stop();
      } finally {
        collector.closeAllConnections();
        await new Promise<void>((resolve) => collector.close(() => resolve()));
        destination.end();
      }
    }
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    const input = metrics.filter((metric) => metric.name === 'json.input.bytes').at(-1);
    assert.equal(input?.unit, 'By');
    const parser = input?.histogram?.dataPoints.find((point) =>
      point.attributes.some(
        (attribute) =>
          attribute.key === 'json.operation' && attribute.value.stringValue === 'parse',
      ),
    );
    assert.equal(parser?.sum, Buffer.byteLength(source) + Buffer.byteLength(malformed));
    for (const [name, unit] of [
      ['json.worker.heap.used.bytes', 'By'],
      ['json.process.rss.bytes', 'By'],
      ['json.operation.duration.ms', 'ms'],
    ])
      assert.ok(metrics.some((metric) => metric.name === name && metric.unit === unit));
    assert.ok(metrics.some((metric) => metric.name === 'json.rejections'));
    assert.ok(
      logs.some((line) => line.includes('JSON operation completed') && line.includes('invalid')),
    );
    assert.ok(logs.some((line) => line.includes('inventory.summary.v1') && line.includes('1.0.0')));
    const metricWire = JSON.stringify(envelopes),
      wire = metricWire + logs.join('');
    for (const value of [privateValue, invalid, unknownId])
      assert.equal(wire.includes(value), false);
    assert.equal(metricWire.includes('inventory.summary.v1'), false);
  });
