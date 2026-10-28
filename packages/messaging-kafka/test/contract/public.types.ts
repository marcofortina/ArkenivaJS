// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  KafkaClusterConfig,
  KafkaPublishRequest,
  KafkaConsumeSettings,
  KafkaRecord,
} from '../../dist/index.js';

const cluster: KafkaClusterConfig = {
  name: 'owned',
  brokers: ['127.0.0.1:19092'],
  clientId: 'owned-consumer',
  topics: ['orders.created'],
  maxBufferedMessages: 100,
  maxMessageBytes: 262144,
  acks: 'all',
  idempotentProducer: true,
};
const tombstone: KafkaPublishRequest = {
  cluster: cluster.name,
  topic: 'orders.created',
  key: new Uint8Array([1]),
  value: null,
  headers: { repeated: ['first', new Uint8Array([0]), null] },
};
const consume: KafkaConsumeSettings = {
  cluster: cluster.name,
  topics: cluster.topics,
  groupId: 'owned-group',
  offsetReset: 'earliest',
  maxInFlightPerPartition: 1,
  failurePolicy: 'stop',
};
void tombstone;
void consume;
// @ts-expect-error Producer reliability cannot be downgraded.
const unreliable: KafkaClusterConfig = { ...cluster, acks: 'leader' };
// @ts-expect-error Consumer concurrency requires a separate contiguous-offset coordinator.
const unsafe: KafkaConsumeSettings = { ...consume, maxInFlightPerPartition: 2 };
const numeric: KafkaRecord = {
  topic: 'orders.created',
  partition: 0,
  // @ts-expect-error Offsets are decimal strings rather than JavaScript numbers.
  offset: 1,
  value: null,
  headers: {},
};
// @ts-expect-error Runtime ownership requires a startup topic catalog.
const uncatalogued: KafkaClusterConfig = {
  name: 'owned',
  brokers: ['127.0.0.1:19092'],
  clientId: 'owned',
  maxBufferedMessages: 1,
  maxMessageBytes: 1,
  acks: 'all',
  idempotentProducer: true,
};
void unreliable;
void unsafe;
void numeric;
void uncatalogued;
