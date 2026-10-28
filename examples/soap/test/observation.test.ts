// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { soapPlugin, SOAP_CAPABILITY } from '@arkenivajs/soap';
import type { SoapService, SoapPluginSettings } from '@arkenivajs/soap';
import { createFixture } from '../dist/fixture.js';

interface Attribute {
  key: string;
  value: { stringValue?: string };
}
interface Point {
  sum?: number;
  asDouble?: number;
  attributes: Attribute[];
}
interface Metric {
  name: string;
  unit: string;
  histogram?: { dataPoints: Point[] };
  sum?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: unknown[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(
    'Real SOAP decisions and native faults remain private in ' + mode + ' SDK exports',
    async () => {
      const fixture = await createFixture(),
        envelopes: Envelope[] = [],
        logs: string[] = [],
        privateSku = 'private-sku-' + randomUUID(),
        privateReference = 'private-ref-' + randomUUID(),
        privateError = 'private-provider-' + randomUUID();
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
      let available = true;
      const provider = {
        usage: 'test-only' as const,
        async get(reference: string) {
          if (!available) throw new Error(privateError);
          return fixture.settings.secretProvider.get(
            reference === privateReference ? 'auth' : 'ca',
          );
        },
      };
      const settings: SoapPluginSettings = {
        ...fixture.settings,
        secretProvider: provider,
        services: [{ ...fixture.settings.services[0]!, credentialsRef: privateReference }],
      };
      const destination = new Writable({
        write(chunk: Buffer, _encoding, done) {
          logs.push(chunk.toString('utf8'));
          done();
        },
      });
      const app = await createApplication({
        service: { name: 'soap-observation', version: '0.1.0', environment: 'test' },
        logging: { level: 'debug' },
        telemetry: { mode, samplingRatio: 1 },
        plugins: [
          soapPlugin(settings),
          loggingPlugin({ destination }),
          telemetryPlugin({
            endpoint: 'http://127.0.0.1:' + address.port,
            allowInsecureLoopback: true,
            exportIntervalMs: 60000,
            exportTimeoutMs: 1000,
          }),
        ],
      });
      try {
        await app.start();
        const client = await app.resolve<SoapService>(SOAP_CAPABILITY).createClient('stock.v1');
        try {
          assert.equal(
            (await client.call<{ quantity: number }>('ReadStock', { sku: privateSku })).data
              .quantity,
            42,
          );
          await assert.rejects(
            client.call('ReadStock', { sku: 'fault' }),
            (error: unknown) => error instanceof KitError && error.code === 'EK_SOAP_FAULT',
          );
          available = false;
          await assert.rejects(
            client.call('ReadStock', { sku: privateSku }),
            (error: unknown) =>
              error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
          );
          assert.equal(fixture.calls(), 2);
        } finally {
          await client.close();
        }
        await app.telemetry.flush();
        await app.logger.flush();
      } finally {
        try {
          await app.stop();
        } finally {
          collector.closeAllConnections();
          await new Promise<void>((resolve) => collector.close(() => resolve()));
          destination.end();
          await fixture.close();
        }
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      const bytes = metrics.filter((metric) => metric.name === 'soap.payload.request.bytes').at(-1);
      assert.equal(bytes?.unit, 'By');
      const call = bytes?.histogram?.dataPoints.find((point) =>
        point.attributes.some(
          (attribute) =>
            attribute.key === 'soap.operation' && attribute.value.stringValue === 'call',
        ),
      );
      assert.equal(call?.sum, fixture.requestBytes());
      assert.ok(metrics.some((metric) => metric.name === 'soap.faults'));
      assert.ok(
        metrics.some(
          (metric) => metric.name === 'soap.operation.duration.ms' && metric.unit === 'ms',
        ),
      );
      assert.ok(
        metrics.some(
          (metric) => metric.name === 'soap.payload.response.bytes' && metric.unit === 'By',
        ),
      );
      assert.ok(
        logs.some((line) => line.includes('SOAP operation completed') && line.includes('fault')),
      );
      assert.ok(envelopes.some((envelope) => envelope.resourceSpans?.length));
      const exported = JSON.stringify(envelopes) + logs.join('\n');
      for (const value of [privateSku, privateReference, privateError, ...fixture.privateMarkers])
        assert.ok(!exported.includes(value));
      for (const metric of metrics)
        for (const point of metric.histogram?.dataPoints ?? metric.sum?.dataPoints ?? [])
          for (const attribute of point.attributes)
            assert.ok(!/tenant|correlation|secret|endpoint|wsdl/i.test(attribute.key));
    },
  );
