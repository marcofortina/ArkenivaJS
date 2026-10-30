// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  kafkaConnection,
  nativeKafkaClient,
  kafkaValues,
  waitKafka,
  kafkaIterations,
  kafkaWarmupIterations,
} from './kafka-workload.mjs';

/** A separate native consumer verifies actual wire bytes and offsets before acknowledging each profile. */
export async function startKafkaFixture(measure = false) {
  assert.equal(typeof measure, 'boolean');
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_KAFKA_SECRETS);
  const token = randomBytes(16).toString('hex');
  const fixture = {
    broker: '127.0.0.1:19094',
    topic: 'orders.created',
    caFile: join(process.env.ARKENIVA_KAFKA_SECRETS, 'ca.pem'),
    secretFile: join(process.env.ARKENIVA_KAFKA_SECRETS, 'fixture-allowed.json'),
    markers: Array.from({ length: 4 }, (_, index) => 'owned-kafka-' + token + '-' + index),
    payload: 'owned-kafka-private-payload',
    tenantHint: 'untrusted-kafka-' + token,
    observerKey: randomBytes(32).toString('base64url'),
  };
  kafkaConnection(fixture);
  const credential = JSON.parse(await readFile(fixture.secretFile, 'utf8')),
    privacyValues = [
      fixture.broker,
      fixture.topic,
      fixture.caFile,
      fixture.secretFile,
      ...fixture.markers,
      fixture.payload,
      fixture.tenantHint,
      fixture.observerKey,
      credential.username,
      credential.password,
      '127.0.0.1',
    ];
  const observed = new Map(fixture.markers.map((marker) => [marker, []])),
    confirmed = new Set(),
    sampledConfirmed = new Set(),
    tasks = new Set();
  const samplingRecords = measure ? kafkaIterations + kafkaWarmupIterations : 0,
    recordsPerProfile = 3 + samplingRecords,
    observedKinds = { binary: 0, empty: 0, tombstone: 0 };
  let observedValueBytes = 0;
  let consumer, bridge, fault;
  const close = async () => {
    if (bridge?.listening) {
      bridge.closeAllConnections();
      await new Promise((done) => bridge.close(done));
    }
    await Promise.allSettled([...tasks]);
    await consumer?.disconnect();
  };
  try {
    const client = await nativeKafkaClient(fixture, 'owned-observer-' + token);
    consumer = client.consumer({
      kafkaJS: {
        groupId: 'owned-secure-compare-' + token,
        fromBeginning: true,
        autoCommit: false,
        allowAutoTopicCreation: false,
      },
      'enable.auto.commit': false,
      'group.protocol': 'classic',
      'js.consumer.max.cache.messages': 8,
      'session.timeout.ms': 10000,
      'heartbeat.interval.ms': 3000,
    });
    await consumer.connect();
    await consumer.subscribe({ topics: [fixture.topic] });
    await consumer.run({
      partitionsConsumedConcurrently: 1,
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const rows = observed.get(message.key?.toString());
          if (!rows) return;
          assert.equal(topic, fixture.topic);
          assert.ok(rows.length < recordsPerProfile);
          const expected = kafkaValues(fixture)[rows.length % 3];
          assert.deepEqual(message.value, expected);
          assert.equal(Object.getPrototypeOf(message.headers), null);
          assert.deepEqual(message.headers.duplicate, [
            Buffer.from('first'),
            Buffer.from([0, 255]),
            null,
            Buffer.alloc(0),
          ]);
          assert.deepEqual(message.headers.tenant_id, Buffer.from(fixture.tenantHint));
          assert.deepEqual(message.headers.constructor, Buffer.from('inert'));
          assert.deepEqual(message.headers['__proto__'], Buffer.from('inert-prototype'));
          assert.ok(!Object.hasOwn(message, 'verifiedTenant'));
          assert.match(message.offset, /^(?:0|[1-9][0-9]*)$/);
          await consumer.commitOffsets([
            { topic, partition, offset: (BigInt(message.offset) + 1n).toString() },
          ]);
          rows.push({ partition, offset: message.offset });
          observedValueBytes += message.value?.byteLength ?? 0;
          observedKinds[
            expected === null ? 'tombstone' : expected.length === 0 ? 'empty' : 'binary'
          ]++;
        } catch (cause) {
          fault = cause;
          throw cause;
        }
      },
    });
    await waitKafka(() => consumer.assignment().length === 2);
    bridge = createServer((request, response) => {
      if (tasks.size >= 8) {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
      const task = (async () => {
        assert.equal(request.method, 'POST');
        assert.equal(request.url, '/receipts');
        const actual = Buffer.from(request.headers.authorization ?? ''),
          expected = Buffer.from('Bearer ' + fixture.observerKey);
        assert.equal(actual.length, expected.length);
        assert.ok(timingSafeEqual(actual, expected));
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          assert.ok(bytes <= 16384);
          chunks.push(chunk);
        }
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.ok(observed.has(value.marker));
        assert.ok(['verification', 'sampling'].includes(value.phase));
        const sampling = value.phase === 'sampling',
          phaseConfirmed = sampling ? sampledConfirmed : confirmed,
          expectedCount = sampling ? samplingRecords : 3,
          end = sampling ? recordsPerProfile : 3;
        assert.ok(!phaseConfirmed.has(value.marker));
        if (sampling) assert.ok(measure && confirmed.has(value.marker));
        assert.ok(Array.isArray(value.receipts) && value.receipts.length === expectedCount);
        await waitKafka(() => fault || observed.get(value.marker).length === end);
        if (fault) throw fault;
        assert.deepEqual(value.receipts, observed.get(value.marker).slice(sampling ? 3 : 0, end));
        phaseConfirmed.add(value.marker);
        response.writeHead(200).end();
      })()
        .catch(() => response.writeHead(400).end())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    });
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    fixture.observerUrl = 'http://127.0.0.1:' + bridge.address().port;
    privacyValues.push(fixture.observerUrl);
    return {
      fixture,
      privacyValues,
      close,
      verify(expectedRecords = 4 * recordsPerProfile) {
        assert.equal(fault, undefined);
        assert.equal(confirmed.size, 4);
        assert.equal(sampledConfirmed.size, measure ? 4 : 0);
        assert.ok([...observed.values()].every((rows) => rows.length === recordsPerProfile));
        const actualObservedRecords = [...observed.values()].reduce(
          (sum, rows) => sum + rows.length,
          0,
        );
        assert.equal(actualObservedRecords, expectedRecords);
        return {
          actualObservedRecords,
          matchedProfileReceipts: confirmed.size,
          matchedSamplingProfiles: sampledConfirmed.size,
          observedValueBytes,
          observedKinds: { ...observedKinds },
          maximumRetainedReceiptRows: 4 * recordsPerProfile,
          observerResources: null,
          brokerResources: null,
          receiptSemantics:
            'Replication-policy broker receipts and independent observer commits are distinct; no application commitment or end-to-end exactly-once claim',
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
