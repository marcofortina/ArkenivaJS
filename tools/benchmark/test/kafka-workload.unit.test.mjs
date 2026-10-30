// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { kafkaConnection } from '../kafka-workload.mjs';

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
