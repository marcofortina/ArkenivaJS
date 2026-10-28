// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';

const execute = promisify(execFile);
test(
  'Actual broker loss preserves publication uncertainty and restart redelivers a canceled uncommitted handler',
  { timeout: 60000 },
  async () => {
    assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
    assert.equal(process.env.ARKENIVA_KAFKA_CONTROL, '1');
    assert.equal(process.env.ARKENIVA_KAFKA_BROKER, '127.0.0.1:19092');
    const group = 'owned-restart-' + randomUUID(),
      marker = randomUUID();
    const owner = managedService(
      settings({
        clusters: [
          {
            name: 'owned',
            brokers: ['127.0.0.1:19092'],
            clientId: 'owned-restart',
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
    let entered = false,
      release!: () => void;
    const held = new Promise<void>((done) => {
      release = done;
    });
    let stopped = false;
    try {
      await owner.init();
      const receipt = await owner.service.publish({
        cluster: 'owned',
        topic: 'orders.created',
        key: Buffer.from(marker),
        value: Buffer.from([1]),
      });
      const subscription = await owner.service.consume(
        { cluster: 'owned', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          entered = true;
          await held;
        },
        { timeoutMs: 30000 },
      );
      for (let i = 0; i < 200 && !entered; i++) await delay(50);
      assert.equal(entered, true);
      await execute('/usr/bin/docker', ['stop', '--timeout', '5', 'arkenivajs-kafka-test'], {
        timeout: 15000,
      });
      stopped = true;
      await assert.rejects(
        owner.service.publish(
          {
            cluster: 'owned',
            topic: 'orders.created',
            key: Buffer.from(randomUUID()),
            value: Buffer.from([2]),
          },
          { timeoutMs: 200 },
        ),
        (error: unknown) => {
          const value = error as { code?: string; details?: { outcome?: string } };
          return (
            ['EK_TIMEOUT', 'EK_KAFKA_PUBLISH'].includes(value.code ?? '') &&
            value.details?.outcome === 'unknown'
          );
        },
      );
      await assert.rejects(subscription.close({ timeoutMs: 100 }), { code: 'EK_TIMEOUT' });
      release();
      await execute('/usr/bin/docker', ['start', 'arkenivajs-kafka-test'], { timeout: 15000 });
      stopped = false;
      await subscription.close({ timeoutMs: 30000 });
      assert.equal(
        (
          await owner.service.publish(
            {
              cluster: 'owned',
              topic: 'orders.created',
              key: Buffer.from(randomUUID()),
              value: Buffer.from([3]),
            },
            { timeoutMs: 30000 },
          )
        ).status,
        'acknowledged',
      );
      let redelivered = false;
      const replacement = await owner.service.consume(
        { cluster: 'owned', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          assert.equal(record.offset, receipt.offset);
          redelivered = true;
        },
      );
      for (let i = 0; i < 300 && !redelivered; i++) await delay(50);
      assert.equal(redelivered, true);
      await replacement.close();
      assert.equal((await owner.service.health('owned')).available, true);
    } finally {
      release();
      if (stopped)
        await execute('/usr/bin/docker', ['start', 'arkenivajs-kafka-test'], { timeout: 15000 });
      await owner.close({ timeoutMs: 30000 });
    }
  },
);
