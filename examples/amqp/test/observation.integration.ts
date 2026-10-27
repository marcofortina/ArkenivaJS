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
import { amqpPlugin, AMQP_CAPABILITY } from '@arkenivajs/messaging-amqp';
import type { AmqpService } from '@arkenivajs/messaging-amqp';
import { fixtureSettings } from '../dist/main.js';

test('Actual native AMQP diagnostics measure payload bytes while excluding credentials, topology and message contents', async () => {
  const envelopes: {
    resourceMetrics?: {
      scopeMetrics: {
        metrics: { name: string; unit: string; histogram?: { dataPoints: { sum: number }[] } }[];
      }[];
    }[];
  }[] = [];
  const logs: string[] = [],
    fixture = await fixtureSettings();
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
    service: { name: 'amqp-observation', version: '0.1.0', environment: 'test' },
    logging: { level: 'debug' },
    telemetry: { mode: 'standard', samplingRatio: 1 },
    plugins: [
      amqpPlugin(fixture.settings),
      loggingPlugin({ destination }),
      telemetryPlugin({
        endpoint: 'http://127.0.0.1:' + address.port,
        allowInsecureLoopback: true,
        exportTimeoutMs: 1000,
        exportIntervalMs: 1000,
      }),
    ],
  });
  let resolve!: () => void, reject!: (error: unknown) => void;
  const delivered = new Promise<void>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  void delivered.catch(() => undefined);
  const timer = setTimeout(
    () => reject(new Error('The owned diagnostics delivery deadline expired')),
    5000,
  );
  const payload = 'private-payload-' + randomUUID(),
    header = 'private-header-' + randomUUID(),
    messageId = randomUUID();
  try {
    await app.start();
    const service = app.resolve<AmqpService>(AMQP_CAPABILITY);
    await service.subscribe(
      {
        connection: 'events',
        queue: fixture.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          assert.equal(Buffer.from(message.body).toString('utf8'), payload);
          assert.equal(message.headers.private, header);
          await message.ack();
          resolve();
        } catch (error) {
          reject(error);
        }
      },
    );
    assert.equal(
      (
        await service.publish({
          connection: 'events',
          exchange: fixture.exchange,
          routingKey: 'created',
          messageId,
          body: Buffer.from(payload),
          headers: { private: header },
        })
      ).status,
      'confirmed',
    );
    await delivered;
    await assert.rejects(
      service.publish({
        connection: 'events',
        exchange: fixture.exchange,
        routingKey: 'private-unapproved-route',
        body: new Uint8Array(),
      }),
    );
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    for (const name of ['amqp.publish.bytes', 'amqp.delivery.bytes']) {
      const metric = metrics.find((value) => value.name === name);
      assert.equal(metric?.unit, 'By');
      assert.equal(metric?.histogram?.dataPoints[0]?.sum, Buffer.byteLength(payload));
    }
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'amqp.operation.duration.ms' && metric.unit === 'ms',
      ),
    );
    assert.ok(metrics.some((metric) => metric.name === 'amqp.publications'));
    assert.ok(metrics.some((metric) => metric.name === 'amqp.publish.inflight'));
    assert.ok(logs.some((line) => line.includes('AMQP operation completed')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    for (const sensitive of [
      ...fixture.sensitive,
      fixture.exchange,
      fixture.queue,
      payload,
      header,
      messageId,
      'private-unapproved-route',
      'fixture-broker-uri',
    ])
      assert.equal(wire.includes(sensitive), false);
    assert.equal(wire.includes('amqps://'), false);
  } finally {
    clearTimeout(timer);
    try {
      await app.stop();
    } finally {
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      destination.end();
    }
  }
});
