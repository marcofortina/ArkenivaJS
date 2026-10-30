// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';

const require = createRequire(import.meta.url);
const workloads = new WeakMap();
export const kafkaIterations = 100;
export const kafkaWarmupIterations = 20;
const quiet = {
  info() {},
  error() {},
  warn() {},
  debug() {},
  setLogLevel() {},
  namespace() {
    return this;
  },
};

/** The reference uses only the explicitly owned TLS/SASL fixture and the pinned native SDK. */
export function kafkaConnection(fixture) {
  assert.match(fixture.broker, /^127\.0\.0\.1:[1-9][0-9]{0,4}$/);
  assert.ok(Number(fixture.broker.split(':')[1]) <= 65535);
  assert.equal(fixture.topic, 'orders.created');
  for (const path of [fixture.caFile, fixture.secretFile]) {
    assert.ok(isAbsolute(path) && resolve(path) === path);
  }
}

export async function nativeKafkaClient(fixture, clientId) {
  kafkaConnection(fixture);
  const ca = await readFile(fixture.caFile, 'utf8'),
    encoded = await readFile(fixture.secretFile, 'utf8');
  assert.ok(ca.length > 0 && ca.length <= 1048576 && encoded.length <= 16384);
  const credential = JSON.parse(encoded);
  assert.equal(credential.mechanism, 'plain');
  assert.equal(typeof credential.username, 'string');
  assert.equal(typeof credential.password, 'string');
  const { KafkaJS } = require('@confluentinc/kafka-javascript');
  const binding = createRequire(require.resolve('@confluentinc/kafka-javascript/package.json'))(
    './librdkafka.js',
  );
  assert.equal(binding.arkenivajsNativeCompatibilityVersion, 2);
  return new KafkaJS.Kafka({
    log_level: 0,
    'security.protocol': 'sasl_ssl',
    'enable.ssl.certificate.verification': true,
    'ssl.endpoint.identification.algorithm': 'https',
    'ssl.cipher.suites': 'ECDHE+AESGCM:ECDHE+CHACHA20',
    'ssl.ca.pem': ca,
    'sasl.mechanisms': 'PLAIN',
    'sasl.username': credential.username,
    'sasl.password': credential.password,
    'socket.timeout.ms': 5000,
    'socket.connection.setup.timeout.ms': 2000,
    'allow.auto.create.topics': false,
    kafkaJS: { brokers: [fixture.broker], clientId, logger: quiet, logLevel: 0 },
  });
}

export function kafkaSettings(fixture) {
  kafkaConnection(fixture);
  const resolveSecret = Object.assign(
    async (reference) => {
      assert.equal(reference, 'owned-kafka-comparison');
      const encoded = await readFile(fixture.secretFile, 'utf8');
      assert.ok(Buffer.byteLength(encoded) <= 16384);
      return encoded;
    },
    { usage: 'test-only' },
  );
  return {
    clusters: [
      {
        name: 'owned',
        brokers: [fixture.broker],
        clientId: fixture.marker,
        topics: [fixture.topic],
        credentialSecretRef: 'owned-kafka-comparison',
        tlsCaFile: fixture.caFile,
        maxBufferedMessages: 8,
        maxMessageBytes: 65536,
        acks: 'all',
        idempotentProducer: true,
      },
    ],
    resolveSecret,
  };
}

export const kafkaValues = (fixture) => [
  Buffer.concat([Buffer.from(fixture.payload), Buffer.from([0, 128, 255])]),
  Buffer.alloc(0),
  null,
];
export const kafkaHeaders = (fixture) => ({
  duplicate: [Buffer.from('first'), Buffer.from([0, 255]), null, Buffer.alloc(0)],
  tenant_id: fixture.tenantHint,
  constructor: Buffer.from('inert'),
  ...JSON.parse('{"__proto__":"inert-prototype"}'),
});

export async function nativeKafka(fixture) {
  fixture.marker = fixture.markers[0];
  const client = await nativeKafkaClient(fixture, fixture.marker),
    producer = client.producer({
      kafkaJS: { idempotent: true, acks: -1, allowAutoTopicCreation: false },
      'message.timeout.ms': 10000,
      'queue.buffering.max.messages': 8,
    });
  try {
    await producer.connect();
    return {
      async publish(request) {
        const rows = await producer.send({
          topic: request.topic,
          messages: [{ key: request.key, value: request.value, headers: request.headers }],
        });
        assert.equal(rows.length, 1);
        const row = rows[0];
        assert.equal(row.errorCode, 0);
        assert.equal(typeof row.baseOffset, 'string');
        return {
          topic: row.topicName,
          partition: row.partition,
          offset: row.baseOffset,
          status: 'acknowledged',
          messageId: request.messageId,
        };
      },
      close: () => producer.disconnect(),
    };
  } catch (cause) {
    await producer.disconnect();
    throw cause;
  }
}

export async function waitKafka(check, timeoutMs = 10000) {
  const deadline = performance.now() + timeoutMs;
  while (!check()) {
    assert.ok(performance.now() < deadline, 'The owned Kafka observation exceeded its deadline');
    await delay(20);
  }
}

export async function verifyKafka(service, fixture) {
  const receipts = [];
  for (const value of kafkaValues(fixture)) {
    const receipt = await service.publish(
      {
        cluster: 'owned',
        topic: fixture.topic,
        key: Buffer.from(fixture.marker),
        value,
        headers: kafkaHeaders(fixture),
        messageId: fixture.marker,
      },
      { timeoutMs: 10000 },
    );
    assert.equal(receipt.status, 'acknowledged');
    assert.equal(receipt.topic, fixture.topic);
    assert.equal(receipt.messageId, fixture.marker);
    assert.ok(Number.isSafeInteger(receipt.partition) && receipt.partition >= 0);
    assert.match(receipt.offset, /^(?:0|[1-9][0-9]*)$/);
    receipts.push({ partition: receipt.partition, offset: receipt.offset });
  }
  assert.ok(receipts.every((receipt) => receipt.partition === receipts[0].partition));
  assert.ok(BigInt(receipts[0].offset) < BigInt(receipts[1].offset));
  assert.ok(BigInt(receipts[1].offset) < BigInt(receipts[2].offset));
  await confirmKafkaReceipts(fixture, 'verification', receipts);
  workloads.set(service, { previous: receipts.at(-1), receipts: [] });
  return {
    actualBrokerAcknowledgments: 3,
    independentConsumerReceiptMatches: 3,
    binaryEmptyAndTombstonePreserved: true,
    repeatedNullableHeadersPreserved: true,
    exactOffsetOrderVerified: true,
    wireTenantHintRemainsUntrusted: true,
  };
}

async function confirmKafkaReceipts(fixture, phase, receipts) {
  const response = await globalThis.fetch(fixture.observerUrl + '/receipts', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(12000),
    headers: { authorization: 'Bearer ' + fixture.observerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ marker: fixture.marker, phase, receipts }),
  });
  assert.equal(response.status, 200);
  await response.arrayBuffer();
}

/** Each timed callback awaits an actual broker receipt; observer commits occur outside timing. */
export function kafkaWorkload(service, fixture) {
  const state = workloads.get(service);
  assert.ok(state, 'The Kafka verification corpus must pass before sampling');
  return {
    async publishReceipt() {
      const index = state.receipts.length;
      assert.ok(
        index < kafkaIterations + kafkaWarmupIterations,
        'The bounded Kafka sampling corpus is exhausted',
      );
      const value = kafkaValues(fixture)[index % 3];
      const receipt = await service.publish(
        {
          cluster: 'owned',
          topic: fixture.topic,
          key: Buffer.from(fixture.marker),
          value,
          headers: kafkaHeaders(fixture),
          messageId: fixture.marker,
        },
        { timeoutMs: 10000 },
      );
      assert.equal(receipt.status, 'acknowledged');
      assert.equal(receipt.topic, fixture.topic);
      assert.equal(receipt.messageId, fixture.marker);
      assert.equal(receipt.partition, state.previous.partition);
      assert.match(receipt.offset, /^(?:0|[1-9][0-9]*)$/);
      assert.ok(BigInt(receipt.offset) > BigInt(state.previous.offset));
      const row = {
        partition: receipt.partition,
        offset: receipt.offset,
        valueBytes: value?.byteLength ?? 0,
      };
      state.receipts.push(row);
      state.previous = row;
      return receipt;
    },
  };
}

export async function completeKafkaWorkload(service, { fixture, measure, records }) {
  const state = workloads.get(service);
  assert.ok(state);
  let samples = 0,
    warmup = 0;
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'publishReceipt');
    assert.equal(record.sampleCount, kafkaIterations);
    assert.equal(record.warmupIterations, kafkaWarmupIterations);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    samples = record.sampleCount;
    warmup = record.warmupIterations;
  } else assert.deepEqual(records, []);
  assert.equal(
    state.receipts.length,
    samples + warmup,
    'Actual broker receipts must reconcile with Tinybench samples and warmup',
  );
  if (measure)
    await confirmKafkaReceipts(
      fixture,
      'sampling',
      state.receipts.map(({ partition, offset }) => ({ partition, offset })),
    );
  const bytes = (rows) => rows.reduce((total, row) => total + row.valueBytes, 0);
  return {
    sampledBrokerAcknowledgments: samples,
    warmupBrokerAcknowledgments: warmup,
    independentConsumerReceiptMatches: state.receipts.length,
    sampledValueBytes: bytes(state.receipts.slice(warmup)),
    warmupValueBytes: bytes(state.receipts.slice(0, warmup)),
    receiptSemantics:
      'Broker acknowledgment only; independent observer offset commits are not application commitment or end-to-end exactly once',
  };
}
