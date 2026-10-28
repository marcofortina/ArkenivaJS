// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { kafkaPlugin, KAFKA_CAPABILITY } from '../../dist/index.js';
import type { KafkaService } from '../../dist/index.js';

interface Point {
  attributes: { key: string }[];
}
interface Metric {
  name: string;
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
    `Actual ${mode} Kafka SDK exports omit wire identities, keys, payloads, client/group IDs and handler errors`,
    { timeout: 30000 },
    async () => {
      assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
      const broker = process.env.ARKENIVA_KAFKA_BROKER!;
      assert.match(broker, /^127\.0\.0\.1:[0-9]{1,5}$/);
      const envelopes: Envelope[] = [],
        logs: string[] = [],
        markers = Array.from({ length: 6 }, () => randomUUID());
      const collector = createServer(async (request, response) => {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Envelope);
        response.setHeader('content-type', 'application/json');
        response.end('{}');
      });
      await new Promise<void>((done) => collector.listen(0, '127.0.0.1', done));
      const address = collector.address();
      assert.ok(address && typeof address === 'object');
      const sink = new Writable({
        write(chunk: Buffer, _encoding, done) {
          logs.push(chunk.toString('utf8'));
          done();
        },
      });
      const app = await createApplication({
        service: { name: 'kafka-observation', version: '1.0.0', environment: 'test' },
        logging: { level: 'debug' },
        telemetry: { mode, samplingRatio: 1 },
        plugins: [
          loggingPlugin({ destination: sink }),
          telemetryPlugin({
            endpoint: 'http://127.0.0.1:' + address.port,
            allowInsecureLoopback: true,
            exportIntervalMs: 60000,
            exportTimeoutMs: 1000,
            labelValues: {
              'kafka.cluster': ['owned'],
              'kafka.topic': ['orders.created'],
              'kafka.partition': [0, 1],
            },
          }),
          kafkaPlugin({
            clusters: [
              {
                name: 'owned',
                brokers: [broker],
                clientId: markers[0]!,
                topics: ['orders.created'],
                maxBufferedMessages: 8,
                maxMessageBytes: 262144,
                acks: 'all',
                idempotentProducer: true,
              },
            ],
          }),
        ],
      });
      try {
        await app.start();
        const service = app.resolve<KafkaService>(KAFKA_CAPABILITY);
        await service.publish({
          cluster: 'owned',
          topic: 'orders.created',
          key: Buffer.from(markers[4]!),
          value: Buffer.from(markers[5]!),
          headers: { tenant_id: markers[2]!, repeated: [null, Buffer.from(markers[3]!)] },
          messageId: markers[1]!,
        });
        let handled = false;
        const subscription = await service.consume(
          {
            cluster: 'owned',
            topics: ['orders.created'],
            groupId: 'owned-privacy-' + markers[1],
            offsetReset: 'earliest',
          },
          async (record) => {
            if (Buffer.from(record.key ?? []).toString() !== markers[4]) return;
            handled = true;
            assert.equal(record.verifiedTenant, undefined);
            throw new Error(markers[3]);
          },
        );
        for (let i = 0; i < 200 && (!handled || (await service.health('owned')).available); i++)
          await delay(25);
        assert.equal(handled, true);
        await assert.rejects(subscription.close(), { code: 'EK_KAFKA_CONSUME' });
        await app.telemetry.flush();
        await app.logger.flush();
      } finally {
        try {
          await app.stop();
        } finally {
          collector.closeAllConnections();
          await new Promise<void>((done) => collector.close(() => done()));
          sink.end();
        }
      }
      const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
      for (const name of [
        'kafka.records.confirmed',
        'kafka.publish.value.bytes',
        'kafka.consume.inflight',
        'kafka.handler.duration.ms',
      ])
        assert.ok(
          metrics.some((metric) => metric.name === name),
          name,
        );
      assert.ok(envelopes.some((envelope) => (envelope.resourceSpans?.length ?? 0) > 0));
      const serialized = JSON.stringify({ envelopes, logs });
      for (const marker of markers)
        assert.ok(!serialized.includes(marker), 'Sensitive Kafka data was exported');
      for (const metric of metrics.filter((metric) => metric.name.startsWith('kafka.')))
        for (const point of [
          ...(metric.sum?.dataPoints ?? []),
          ...(metric.histogram?.dataPoints ?? []),
          ...(metric.gauge?.dataPoints ?? []),
        ])
          for (const attribute of point.attributes)
            assert.ok(
              ['kafka.cluster', 'kafka.topic', 'kafka.partition', 'kafka.outcome'].includes(
                attribute.key,
              ),
            );
    },
  );
