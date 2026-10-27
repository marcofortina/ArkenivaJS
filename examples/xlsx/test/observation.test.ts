// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { XLSX_CAPABILITY, dataXlsxPlugin } from '@arkenivajs/data-xlsx';
import type { ExcelService } from '@arkenivajs/data-xlsx';

test('Native XLSX operations export actual memory, size and row timing without workbook contents or sheet names', async () => {
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
      service: { name: 'xlsx-observation', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        dataXlsxPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 10000 } }),
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
    const excel = app.resolve<ExcelService>(XLSX_CAPABILITY),
      writer = excel.create();
    await writer.addSheet('Private-XLSX-Fixture').addRows([['private-xlsx-value', 123]]);
    const parts: Buffer[] = [];
    const receipt = await writer.write(async (chunk) => {
      parts.push(Buffer.from(chunk));
    });
    const reader = await excel.open(Buffer.concat(parts));
    let rows = 0;
    for await (const row of reader.rows(reader.sheetNames[0]!)) {
      assert.equal(row.rowIndex, 1);
      rows++;
    }
    assert.equal(rows, 1);
    await reader.close();
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    const duration = metrics.find((metric) => metric.name === 'xlsx.operation.duration.ms');
    assert.equal(duration?.unit, 'ms');
    assert.ok((duration?.histogram?.dataPoints[0]?.sum ?? -1) >= 0);
    const output = metrics.find((metric) => metric.name === 'xlsx.output.bytes');
    assert.equal(output?.unit, 'By');
    assert.equal(output?.histogram?.dataPoints[0]?.sum, receipt.outputBytes);
    const memory = metrics.find(
      (metric) => metric.name === 'xlsx.worker.memory.sampled-peak.bytes',
    );
    assert.equal(memory?.unit, 'By');
    assert.ok((memory?.histogram?.dataPoints[0]?.sum ?? 0) > 0);
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'xlsx.first-row.duration.ms' && metric.unit === 'ms',
      ),
    );
    assert.ok(metrics.some((metric) => metric.name === 'xlsx.cells.per.second'));
    assert.ok(logs.some((line) => line.includes('Workbook operation completed')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    assert.ok(!wire.includes('private-xlsx-value'));
    assert.ok(!wire.includes('Private-XLSX-Fixture'));
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
