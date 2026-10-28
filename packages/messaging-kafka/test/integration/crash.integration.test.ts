// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtemp, readFile, appendFile, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';

test(
  'An actual consumer process crash after a durable side effect leaves its uncommitted record redeliverable',
  { timeout: 45000 },
  async () => {
    assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
    const broker = process.env.ARKENIVA_KAFKA_BROKER!;
    assert.match(broker, /^127\.0\.0\.1:[0-9]{1,5}$/);
    const directory = await mkdtemp('/tmp/owned-kafka-crash-'),
      path = join(directory, 'effects');
    const group = 'owned-crash-' + randomUUID(),
      marker = randomUUID();
    const owner = managedService(
      settings({
        clusters: [
          {
            name: 'owned',
            brokers: [broker],
            clientId: 'owned-crash-parent',
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
    let child: ReturnType<typeof fork> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await owner.init();
      const receipt = await owner.service.publish({
        cluster: 'owned',
        topic: 'orders.created',
        key: Buffer.from(marker),
        value: Buffer.from([1]),
      });
      child = fork(resolve(import.meta.dirname, '../fixtures/crash-consumer.js'), [], {
        stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
        env: {
          ...process.env,
          ARKENIVA_KAFKA_CRASH_GROUP: group,
          ARKENIVA_KAFKA_CRASH_KEY: marker,
          ARKENIVA_KAFKA_CRASH_EFFECT: path,
        },
      });
      const terminated = new Promise<string | null>((done) =>
        child!.once('exit', (_code, signal) => done(signal)),
      );
      const effect = await new Promise<unknown>((done, reject) => {
        child!.once('message', done);
        child!.once('error', reject);
        child!.once('exit', () =>
          reject(new Error('The consumer fixture exited before persisting its side effect')),
        );
        timer = setTimeout(
          () => reject(new Error('The consumer fixture did not persist its side effect')),
          10000,
        );
      });
      clearTimeout(timer);
      assert.deepEqual(effect, { phase: 'effect-persisted', offset: receipt.offset });
      assert.equal(await readFile(path, 'utf8'), 'effect\n');
      assert.equal(child.kill('SIGKILL'), true);
      assert.equal(await terminated, 'SIGKILL');
      let received = false;
      const subscription = await owner.service.consume(
        { cluster: 'owned', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          assert.equal(record.offset, receipt.offset);
          await appendFile(path, 'effect\n');
          received = true;
        },
      );
      for (let i = 0; i < 400 && !received; i++) await delay(50);
      assert.equal(received, true);
      assert.equal(await readFile(path, 'utf8'), 'effect\neffect\n');
      await subscription.close();
    } finally {
      clearTimeout(timer);
      if (child?.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await owner.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
