// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { kafkaConnection, nativeKafkaClient, kafkaValues, waitKafka } from './kafka-workload.mjs';

/** A separate native consumer verifies actual wire bytes and offsets before acknowledging each profile. */
export async function startKafkaFixture() {
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
    tasks = new Set();
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
          assert.ok(rows.length < 3);
          const expected = kafkaValues(fixture)[rows.length];
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
        } catch (cause) {
          fault = cause;
          throw cause;
        }
      },
    });
    await waitKafka(() => consumer.assignment().length === 2);
    bridge = createServer((request, response) => {
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
        assert.ok(observed.has(value.marker) && !confirmed.has(value.marker));
        assert.ok(Array.isArray(value.receipts) && value.receipts.length === 3);
        await waitKafka(() => fault || observed.get(value.marker).length === 3);
        if (fault) throw fault;
        assert.deepEqual(value.receipts, observed.get(value.marker));
        confirmed.add(value.marker);
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
      verify() {
        assert.equal(fault, undefined);
        assert.equal(confirmed.size, 4);
        assert.ok([...observed.values()].every((rows) => rows.length === 3));
        return { actualObservedRecords: 12, matchedProfileReceipts: 4, releaseGate: false };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
