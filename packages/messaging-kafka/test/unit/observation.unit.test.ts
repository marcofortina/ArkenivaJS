// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Logger, Telemetry } from '@arkenivajs/core';
import { recorder } from '../../dist/observation.js';

test('Kafka observations count actual bytes and fixed catalog dimensions without exporting message data', async () => {
  const events: unknown[] = [];
  const metric = (name: string, value: number, attributes?: Readonly<Record<string, unknown>>) => {
    events.push({ name, value, attributes });
  };
  const telemetry: Telemetry = {
    measure: async (_name, work) => work(),
    withSpan: async (_name, work) => work(),
    addCounter: metric,
    recordHistogram: metric,
    setGauge: metric,
    flush: async () => undefined,
  };
  const observed = recorder({
    telemetry,
    logger: {
      debug: (message: string, data: unknown) => events.push({ message, data }),
      warn: (message: string) => events.push({ message }),
    } as unknown as Logger,
  });
  observed.bytes('publish', 'owned', 'orders.created', Buffer.from([0, 255]), Buffer.from([128]), {
    duplicate: [null, Buffer.from([0, 255]), 'é'],
    tenant_id: 'private-wire-tenant',
  });
  observed.event('owned', 'native-uninstrumented');
  observed.consumerActive('owned', 1);
  observed.consumerActive('owned', -1);
  observed.latency('owned', 'orders.created', 'delivery', 3.5);
  observed.lag('owned', 'orders.created', 0, 9007199254740993n);
  observed.lag('owned', 'orders.created', 0, 2n);
  assert.equal(await observed.execute('owned', 'orders.created', 'publish', async () => 7), 7);
  const metrics = events.filter(
    (event): event is { name: string; value: number } =>
      !!event && typeof event === 'object' && Object.hasOwn(event, 'name'),
  );
  assert.equal(metrics.find((entry) => entry.name === 'kafka.publish.value.bytes')?.value, 2);
  assert.equal(metrics.find((entry) => entry.name === 'kafka.publish.key.bytes')?.value, 1);
  assert.equal(metrics.filter((entry) => entry.name === 'kafka.consumer.lag.records').length, 1);
  assert.equal(metrics.find((entry) => entry.name === 'kafka.consumer.lag.records')?.value, 2);
  const serialized = JSON.stringify(events);
  assert.ok(!serialized.includes('private-wire-tenant'));
  assert.ok(!serialized.includes('duplicate'));
  assert.ok(!serialized.includes('tenant_id'));
});

test('Kafka diagnostic provider failures cannot replace or repeat native operations', async () => {
  let calls = 0;
  const broken = () => {
    throw new Error('Private diagnostic provider failure');
  };
  const observed = recorder({
    telemetry: {
      measure: broken,
      withSpan: broken,
      addCounter: broken,
      recordHistogram: broken,
      setGauge: broken,
      flush: async () => broken(),
    },
    logger: { debug: broken, warn: broken } as unknown as Logger,
  });
  observed.event('owned', 'consumer-error');
  observed.latency('owned', 'orders.created', 'handler', 1);
  observed.consumerActive('owned', 1);
  assert.equal(
    await observed.execute('owned', 'orders.created', 'consume', async () => {
      calls++;
      return 9;
    }),
    9,
  );
  const failure = new Error('Private business failure');
  await assert.rejects(
    observed.execute('owned', 'orders.created', 'consume', async () => {
      calls++;
      throw failure;
    }),
    (error) => error === failure,
  );
  assert.equal(calls, 2);
});
