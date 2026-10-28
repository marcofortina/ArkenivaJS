// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { open } from 'node:fs/promises';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';

assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
assert.equal(typeof process.send, 'function');
const broker = process.env.ARKENIVA_KAFKA_BROKER!,
  group = process.env.ARKENIVA_KAFKA_CRASH_GROUP!;
const marker = process.env.ARKENIVA_KAFKA_CRASH_KEY!,
  path = process.env.ARKENIVA_KAFKA_CRASH_EFFECT!;
assert.match(broker, /^127\.0\.0\.1:[0-9]{1,5}$/);
assert.match(group, /^owned-crash-[a-f0-9-]{36}$/);
assert.ok(path.startsWith('/tmp/owned-kafka-crash-'));
const owner = managedService(
  settings({
    clusters: [
      {
        name: 'owned',
        brokers: [broker],
        clientId: 'owned-crash-process',
        topics: ['orders.created'],
        maxBufferedMessages: 8,
        maxMessageBytes: 262144,
        acks: 'all',
        idempotentProducer: true,
      },
    ],
  }),
  new AbortController().signal,
  () => true,
  'test',
);
await owner.init();
await owner.service.consume(
  { cluster: 'owned', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
  async (record) => {
    if (Buffer.from(record.key ?? []).toString() !== marker) return;
    const file = await open(path, 'a', 0o600);
    try {
      await file.writeFile('effect\n');
      await file.sync();
    } finally {
      await file.close();
    }
    process.send!({ phase: 'effect-persisted', offset: record.offset });
    // The parent terminates this process after the actual side effect and before this handler can return.
    await new Promise<void>(() => undefined);
  },
);
