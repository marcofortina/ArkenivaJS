// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Bench } from 'tinybench';
import {
  kafkaConnection,
  kafkaValues,
  verifyKafka,
  kafkaWorkload,
  completeKafkaWorkload,
  kafkaIterations,
  kafkaWarmupIterations,
} from '../kafka-workload.mjs';

test('Kafka verification rejects foreign brokers, topic changes and relative credential paths before native loading', () => {
  const fixture = {
    broker: '127.0.0.1:19094',
    topic: 'orders.created',
    caFile: '/private/ca.pem',
    secretFile: '/private/fixture-allowed.json',
  };
  for (const change of [
    { broker: 'foreign.invalid:19094' },
    { broker: '127.0.0.1:0' },
    { broker: '127.0.0.1:65536' },
    { broker: 'user:pass@127.0.0.1:19094' },
    { topic: 'foreign' },
    { caFile: '../ca.pem' },
    { secretFile: '/private/../secret' },
  ])
    assert.throws(() => kafkaConnection({ ...fixture, ...change }));
});

const cpuFixture = () => ({
  topic: 'orders.created',
  marker: 'owned-cpu-profile',
  payload: 'cpu-fixture-value',
  tenantHint: 'untrusted-cpu-hint',
  observerUrl: 'http://127.0.0.1:1',
  observerKey: 'unit-only',
});

test('Kafka smoke reconciles actual Tinybench receipts, byte counts and independent confirmation without native loading', async (t) => {
  const fixture = cpuFixture(),
    requests = [],
    confirmations = [];
  let rejectObserver = false;
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    confirmations.push(JSON.parse(options.body));
    return new globalThis.Response('', { status: rejectObserver ? 400 : 200 });
  });
  let offset = 9007199254741000n;
  const service = {
    async publish(request) {
      requests.push(request);
      return {
        topic: request.topic,
        partition: 1,
        offset: String(offset++),
        status: 'acknowledged',
        messageId: request.messageId,
      };
    },
  };
  assert.throws(() => kafkaWorkload(service, fixture));
  await verifyKafka(service, fixture);
  assert.equal(confirmations.length, 1);
  assert.equal(confirmations[0].phase, 'verification');
  assert.equal(confirmations[0].receipts.length, 3);
  assert.equal(
    (await completeKafkaWorkload(service, { fixture, measure: false, records: [] }))
      .independentConsumerReceiptMatches,
    0,
  );
  const work = kafkaWorkload(service, fixture).publishReceipt,
    bench = new Bench({
      time: 0,
      iterations: kafkaIterations,
      warmupTime: 0,
      warmupIterations: kafkaWarmupIterations,
      retainSamples: true,
      throws: true,
    });
  bench.add('publishReceipt', async () => {
    await work();
  });
  await bench.run();
  const samples = bench.tasks[0].result.latency.samples,
    records = [
      {
        operation: 'publishReceipt',
        sampleCount: samples.length,
        warmupIterations: kafkaWarmupIterations,
        rawLatency: { unit: 'milliseconds', values: [...samples] },
      },
    ];
  const completion = await completeKafkaWorkload(service, { fixture, measure: true, records });
  const total = samples.length + kafkaWarmupIterations;
  assert.equal(samples.length, kafkaIterations);
  assert.equal(requests.length, 3 + total);
  assert.equal(confirmations.length, 2);
  assert.equal(confirmations[1].phase, 'sampling');
  assert.equal(confirmations[1].receipts.length, total);
  for (let index = 0; index < requests.length; index++)
    assert.deepEqual(requests[index].value, kafkaValues(fixture)[index % 3]);
  for (let index = 1; index < confirmations[1].receipts.length; index++)
    assert.ok(
      BigInt(confirmations[1].receipts[index].offset) >
        BigInt(confirmations[1].receipts[index - 1].offset),
    );
  assert.equal(completion.sampledBrokerAcknowledgments, samples.length);
  assert.equal(completion.warmupBrokerAcknowledgments, kafkaWarmupIterations);
  assert.equal(completion.independentConsumerReceiptMatches, total);
  const binaryBytes = kafkaValues(fixture)[0].byteLength;
  assert.equal(completion.sampledValueBytes, 33 * binaryBytes);
  assert.equal(completion.warmupValueBytes, 7 * binaryBytes);
  await assert.rejects(work());
  assert.equal(requests.length, 3 + total, 'Exhausting the bound must reject before producer work');
  rejectObserver = true;
  await assert.rejects(completeKafkaWorkload(service, { fixture, measure: true, records }));
});

test('Kafka timed work awaits the producer receipt and rejects malformed or nonordered acknowledgments', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new globalThis.Response(''));
  const fixture = cpuFixture();
  let release,
    enter,
    held = false,
    override,
    offset = 0;
  const gate = new Promise((resolve) => {
      release = resolve;
    }),
    entered = new Promise((resolve) => {
      enter = resolve;
    });
  const service = {
    async publish(request) {
      if (held) {
        enter();
        await gate;
      }
      return {
        topic: request.topic,
        partition: 0,
        offset: String(offset++),
        status: 'acknowledged',
        messageId: request.messageId,
        ...override,
      };
    },
  };
  await verifyKafka(service, fixture);
  held = true;
  let settled = false;
  const work = kafkaWorkload(service, fixture).publishReceipt,
    pending = work().then(() => {
      settled = true;
    });
  try {
    await entered;
    await nextTurn();
    assert.equal(settled, false, 'A submitted publication is not a completed broker receipt');
  } finally {
    release();
  }
  await pending;
  assert.equal(settled, true);
  held = false;
  for (override of [
    { status: 'submitted' },
    { topic: 'unapproved' },
    { partition: 1 },
    { offset: '3' },
    { offset: '-1' },
    { offset: '1.5' },
  ])
    await assert.rejects(work());
});
