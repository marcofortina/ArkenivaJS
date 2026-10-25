// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createTelemetry, DURATION_BUCKETS_SECONDS } from '@arkenivajs/telemetry';
import { createNatsBus } from '@arkenivajs/messaging';

interface Envelope {
  resourceSpans?: { scopeSpans: { spans: { name: string; attributes: unknown[] }[] }[] }[];
  resourceMetrics?: {
    scopeMetrics: {
      metrics: {
        name: string;
        unit: string;
        histogram?: { dataPoints: { sum: number; explicitBounds: number[] }[] };
      }[];
    }[];
  }[];
}

test('Real NATS work exports actual SDK processing spans and second-based duration histograms without payload or subject labels', async () => {
  assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
  const observations: Envelope[] = [],
    receiver = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk);
      observations.push(JSON.parse(Buffer.concat(chunks).toString()) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const address = receiver.address();
  assert.ok(address && typeof address === 'object');
  const telemetry = createTelemetry({
    service: { name: 'message-observation-test', version: '1.0.0', environment: 'test' },
    endpoint: 'http://127.0.0.1:' + address.port,
    allowInsecureLoopback: true,
    samplingRatio: 1,
    exportTimeoutMs: 1000,
  });
  let bus: Awaited<ReturnType<typeof createNatsBus>> | undefined;
  const topic = 'private.topic.' + randomBytes(12).toString('hex'),
    payload = 'private-message-payload-' + randomBytes(12).toString('hex');
  try {
    bus = await createNatsBus({
      connectionStringEnv: 'ARKENIVA_NATS_URL',
      telemetry,
      onError: async () => {
        assert.fail('An ordinary observed message must not fail');
      },
    });
    let handled = false;
    const subscription = await bus.subscribe(topic, async (message) => {
      assert.equal(message.payload, payload);
      assert.ok(telemetry.currentTraceId());
      handled = true;
    });
    await bus.publish(topic, payload);
    const until = performance.now() + 5000;
    while (!handled || bus.stats().activeHandlers !== 0) {
      assert.ok(performance.now() < until, 'Observed message processing did not settle');
      await delay(5);
    }
    assert.equal(await bus.health(), true);
    await subscription.close();
    await telemetry.flush();
    const spans = observations
        .flatMap((body) => body.resourceSpans ?? [])
        .flatMap((resource) => resource.scopeSpans.flatMap((scope) => scope.spans)),
      metrics = observations
        .flatMap((body) => body.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    for (const name of ['publish', 'subscribe', 'health', 'process']) {
      assert.ok(spans.some((span) => span.name === 'messaging.' + name));
      const histogram = metrics.find((metric) => metric.name === 'messaging.' + name + '.duration');
      assert.ok(histogram);
      assert.equal(histogram.unit, 's');
      assert.ok(histogram.histogram!.dataPoints[0]!.sum > 0);
      assert.deepEqual(
        histogram.histogram!.dataPoints[0]!.explicitBounds,
        DURATION_BUCKETS_SECONDS,
      );
    }
    const wire = JSON.stringify(observations);
    assert.equal(wire.includes(topic), false);
    assert.equal(wire.includes(payload), false);
    assert.equal(wire.includes(process.env.ARKENIVA_NATS_URL!), false);
    assert.equal(telemetry.stats().activeSpans, 0);
  } finally {
    try {
      await bus?.close();
    } finally {
      try {
        await telemetry.close();
      } finally {
        receiver.closeAllConnections();
        await new Promise<void>((resolve) => receiver.close(() => resolve()));
      }
    }
  }
});
