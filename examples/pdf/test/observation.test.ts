// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { PDF_CAPABILITY, documentsPdfPlugin } from '@arkenivajs/documents-pdf';
import type { PdfService } from '@arkenivajs/documents-pdf';

test('Native PDF operations export actual memory, size and CPU metadata without document contents or metadata', async () => {
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
      service: { name: 'pdf-observation', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        documentsPdfPlugin({
          defaults: {},
          fontAllowlist: ['Helvetica'],
          policy: { maxConcurrent: 1, timeoutMs: 10000 },
        }),
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
    const pdf = app.resolve<PdfService>(PDF_CAPABILITY),
      builder = pdf.create();
    builder.addText('private-pdf-content', 1, 40, 40, {
      font: 'Helvetica',
      size: 12,
      colorHex: '#000000',
    });
    const produced = await builder.save(),
      fixture = await PDFDocument.load(produced);
    fixture.setTitle('private-pdf-metadata');
    fixture.setAuthor('private-pdf-author');
    const bytes = new Uint8Array(await fixture.save());
    const info = await pdf.inspect(bytes),
      text = await pdf.extractText(bytes);
    assert.equal(info.pages, 1);
    assert.equal(info.title, 'private-pdf-metadata');
    assert.equal(info.author, 'private-pdf-author');
    assert.equal(text[0]!.items[0]!.text, 'private-pdf-content');
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    const duration = metrics.find((metric) => metric.name === 'pdf.operation.duration.ms');
    assert.equal(duration?.unit, 'ms');
    assert.ok((duration?.histogram?.dataPoints[0]?.sum ?? -1) >= 0);
    const output = metrics.find((metric) => metric.name === 'pdf.output.bytes');
    assert.equal(output?.unit, 'By');
    assert.equal(output?.histogram?.dataPoints[0]?.sum, produced.byteLength);
    const memory = metrics.find((metric) => metric.name === 'pdf.worker.memory.sampled-peak.bytes');
    assert.equal(memory?.unit, 'By');
    assert.ok((memory?.histogram?.dataPoints[0]?.sum ?? 0) > 0);
    assert.ok(
      metrics.some((metric) => metric.name === 'pdf.native.cpu.ms' && metric.unit === 'ms'),
    );
    assert.ok(metrics.some((metric) => metric.name === 'pdf.pages.per.second'));
    assert.ok(logs.some((line) => line.includes('Document operation completed')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    assert.ok(!wire.includes('private-pdf-content'));
    assert.ok(!wire.includes('private-pdf-metadata'));
    assert.ok(!wire.includes('private-pdf-author'));
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
