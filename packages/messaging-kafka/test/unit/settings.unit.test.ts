// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { settings } from '../../dist/settings.js';

const cluster = {
  name: 'owned',
  brokers: ['127.0.0.1:19092'],
  clientId: 'owned',
  topics: ['orders.created'],
  maxBufferedMessages: 100,
  maxMessageBytes: 262144,
  acks: 'all',
  idempotentProducer: true,
};

test('Static Kafka policy captures exact topic and broker catalogs without opening resources', () => {
  const source = {
    ...cluster,
    brokers: ['localhost:19092', '[::1]:19093'],
    topics: ['orders.created', 'orders.deleted'],
    tlsCaFile: '/owned/ca.crt',
    credentialSecretRef: 'owned-credentials',
  };
  let resolutions = 0;
  const result = settings({
    clusters: [source],
    resolveSecret: async () => {
      resolutions++;
      throw new Error('Bootstrap has not started');
    },
  });
  source.topics.push('unapproved');
  source.brokers.push('unapproved:1');
  assert.deepEqual(result.clusters[0]!.topics, ['orders.created', 'orders.deleted']);
  assert.deepEqual(result.clusters[0]!.brokers, ['localhost:19092', '[::1]:19093']);
  assert.equal(resolutions, 0);
  assert.ok(Object.isFrozen(result.clusters) && Object.isFrozen(result.clusters[0]));
});

test('Kafka reliability, native buffer budgets, topic catalogs and credential configuration fail closed', () => {
  for (const change of [
    { name: 'bad/name' },
    { clientId: '' },
    { acks: 'leader' },
    { idempotentProducer: false },
    { topics: [] },
    { topics: ['same', 'same'] },
    { topics: ['bad/topic'] },
    { topics: Array.from({ length: 65 }, (_, i) => 't' + i) },
    { brokers: [] },
    { brokers: ['localhost:1', 'localhost:1'] },
    { brokers: ['https://localhost:9092'] },
    { brokers: ['[127.0.0.1]:9092'] },
    { brokers: ['localhost:0'] },
    { brokers: ['localhost:65536'] },
    { brokers: ['-invalid:9092'] },
    { brokers: ['host..invalid:9092'] },
    { maxBufferedMessages: 0 },
    { maxMessageBytes: 0 },
    { maxBufferedMessages: 10001 },
    { maxMessageBytes: 16777217 },
    { maxBufferedMessages: 10000, maxMessageBytes: 262144 },
    { tlsCaFile: './relative' },
    { credentialSecretRef: 'owned-without-resolver' },
    { unknown: true },
  ])
    assert.throws(() => settings({ clusters: [{ ...cluster, ...change }] }), {
      code: 'EK_KAFKA_CONFIG',
    });
  for (const value of [
    { clusters: [] },
    { clusters: [cluster, cluster] },
    { clusters: [cluster], resolveSecret: 'invalid' },
    { clusters: [cluster], unknown: true },
  ])
    assert.throws(() => settings(value), { code: 'EK_KAFKA_CONFIG' });
  let executed = 0;
  const accessor = Object.defineProperty({ ...cluster }, 'topics', {
    get() {
      executed++;
      return ['unapproved'];
    },
  });
  assert.throws(() => settings({ clusters: [accessor] }), { code: 'EK_KAFKA_CONFIG' });
  assert.equal(executed, 0);
});
