// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { networkInterfaces } from 'node:os';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { dataXmlPlugin, XML_CAPABILITY } from '@arkenivajs/data-xml';
import type { XmlService } from '@arkenivajs/data-xml';
import { fixtureSettings } from '../dist/main.js';

interface Metric {
  name: string;
  unit: string;
  histogram?: {
    dataPoints: { sum: number; attributes: { key: string; value: { stringValue?: string } }[] }[];
  };
}
export async function observeXml(
  xsd = false,
  mode: 'standard' | 'detailed' = 'standard',
): Promise<void> {
  if (xsd) {
    assert.equal(process.env.ARKENIVA_XML_NS_ACTIVE, '1');
    assert.notEqual(process.getuid?.(), 0);
    assert.ok(Object.keys(networkInterfaces()).every((name) => name === 'lo'));
  }
  const envelopes: { resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[] }[] = [],
    logs: string[] = [],
    privateValue = 'private-xml-' + randomUUID(),
    invalidValue = 'private-invalid-' + randomUUID(),
    schemaId = 'private-schema-' + randomUUID();
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
    }),
    base = fixtureSettings(xsd);
  const settings = {
    ...base,
    ...(xsd
      ? {
          xsdSchemaFiles: {
            [schemaId]: base.xsdSchemaFiles!.invoice!,
            ['private-types-' + randomUUID()]: base.xsdSchemaFiles!.invoiceTypes!,
          },
        }
      : {}),
  };
  const app = await createApplication({
    service: { name: 'xml-observation', version: '0.1.0', environment: 'test' },
    logging: { level: 'debug' },
    telemetry: { mode, samplingRatio: 1 },
    plugins: [
      dataXmlPlugin(settings),
      loggingPlugin({ destination }),
      telemetryPlugin({
        endpoint: 'http://127.0.0.1:' + address.port,
        allowInsecureLoopback: true,
        exportIntervalMs: 60000,
        exportTimeoutMs: 1000,
      }),
    ],
  });
  const source = '<r>' + privateValue + '</r>',
    valid =
      '<invoice xmlns="urn:arkenivajs:invoice"><id>' +
      privateValue +
      '</id><amount>12.50</amount></invoice>',
    invalid =
      '<invoice xmlns="urn:arkenivajs:invoice"><id>001</id><amount>' +
      invalidValue +
      '</amount></invoice>';
  try {
    await app.start();
    const xml = app.resolve<XmlService>(XML_CAPABILITY),
      document = await xml.parse(source);
    assert.ok(await xml.stringify(document));
    if (xsd) {
      assert.equal((await xml.validateXsd(Buffer.from(valid), schemaId)).valid, true);
      const result = await xml.validateXsd(Buffer.from(invalid), schemaId);
      assert.equal(result.valid, false);
      assert.equal(JSON.stringify(result).includes(invalidValue), false);
    }
    await assert.rejects(xml.parse('<r>' + privateValue));
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
    .flatMap((value) => value.resourceMetrics ?? [])
    .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
  const input = metrics.filter((metric) => metric.name === 'xml.input.bytes').at(-1);
  assert.equal(input?.unit, 'By');
  const parse = input?.histogram?.dataPoints.find((point) =>
    point.attributes.some(
      (attribute) => attribute.key === 'xml.operation' && attribute.value.stringValue === 'parse',
    ),
  );
  assert.equal(parse?.sum, Buffer.byteLength(source) + Buffer.byteLength('<r>' + privateValue));
  assert.ok(
    metrics.some((metric) => metric.name === 'xml.worker.heap.used.bytes' && metric.unit === 'By'),
  );
  assert.ok(
    metrics.some((metric) => metric.name === 'xml.process.rss.bytes' && metric.unit === 'By'),
  );
  assert.ok(
    metrics.some((metric) => metric.name === 'xml.operation.duration.ms' && metric.unit === 'ms'),
  );
  if (xsd) {
    const native = input?.histogram?.dataPoints.find((point) =>
      point.attributes.some(
        (attribute) =>
          attribute.key === 'xml.operation' && attribute.value.stringValue === 'validate-xsd',
      ),
    );
    assert.equal(native?.sum, Buffer.byteLength(valid) + Buffer.byteLength(invalid));
    assert.ok(metrics.some((metric) => metric.name === 'xml.rejections'));
    assert.ok(logs.some((line) => line.includes('invalid')));
  }
  assert.ok(logs.some((line) => line.includes('XML operation completed')));
  const wire = JSON.stringify(envelopes) + logs.join('');
  for (const value of [
    privateValue,
    invalidValue,
    schemaId,
    ...Object.keys(settings.xsdSchemaFiles ?? {}),
    ...Object.values(settings.xsdSchemaFiles ?? {}),
  ])
    assert.equal(wire.includes(value), false);
  assert.equal(wire.includes('/tmp/arkenivajs-xsd-'), false);
}
