// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { managedService } from '../../dist/service.js';
import { Connection } from '../../dist/native.js';
import { settings } from '../../dist/settings.js';

const execute = promisify(execFile);
async function permission(group: string, deny: boolean): Promise<void> {
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  assert.equal(process.env.ARKENIVA_KAFKA_CONTROL, '1');
  assert.match(group, /^owned-secure-offset-[a-f0-9-]{36}$/);
  await execute(
    '/usr/bin/docker',
    [
      'exec',
      'arkenivajs-kafka-secure',
      '/opt/kafka/bin/kafka-acls.sh',
      '--bootstrap-server',
      '127.0.0.1:19096',
      deny ? '--add' : '--remove',
      ...(deny ? [] : ['--force']),
      '--deny-principal',
      'User:fixture-allowed',
      '--operation',
      'Read',
      '--group',
      group,
    ],
    { timeout: 10000, maxBuffer: 65536 },
  );
}

test(
  'An actual broker ACL rejection reports offset uncertainty and redelivers an already processed record',
  { timeout: 45000 },
  async () => {
    const directory = process.env.ARKENIVA_KAFKA_SECRETS!;
    assert.ok(directory?.startsWith('/'));
    const group = 'owned-secure-offset-' + randomUUID(),
      marker = randomUUID(),
      reports: string[] = [];
    const owner = managedService(
      settings({
        clusters: [
          {
            name: 'secure',
            brokers: ['127.0.0.1:19094'],
            clientId: 'owned-offset-' + randomUUID(),
            topics: ['orders.created'],
            credentialSecretRef: 'fixture-allowed',
            tlsCaFile: directory + '/ca.pem',
            maxBufferedMessages: 8,
            maxMessageBytes: 262144,
            acks: 'all',
            idempotentProducer: true,
          },
        ],
        resolveSecret: async () => readFile(directory + '/fixture-allowed.json', 'utf8'),
      }),
      new AbortController().signal,
      () => true,
      'production',
      (code) => reports.push(code),
    );
    const original = Connection.prototype.consumer;
    let armed = false,
      changed = false,
      effects = 0;
    Connection.prototype.consumer = function (...args) {
      const client = original.apply(this, args),
        commit = client.commitOffsets.bind(client);
      client.commitOffsets = async (offsets) => {
        if (armed && !changed) {
          changed = true;
          // The real broker changes authorization at the dispatch boundary; commit still calls the native client.
          await permission(group, true);
        }
        return commit(offsets);
      };
      return client;
    };
    try {
      await owner.init();
      const receipt = await owner.service.publish({
        cluster: 'secure',
        topic: 'orders.created',
        key: Buffer.from(marker),
        value: Buffer.from([0, 255]),
      });
      const subscription = await owner.service.consume(
        { cluster: 'secure', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          assert.equal(record.offset, receipt.offset);
          effects++;
          armed = true;
        },
      );
      for (let i = 0; i < 200 && !reports.includes('EK_KAFKA_OFFSET'); i++) await setTimeout(50);
      assert.ok(
        reports.includes('EK_KAFKA_OFFSET'),
        'Expected an actual offset error; observed ' +
          reports.join(',') +
          '; effects=' +
          effects +
          '; authorizationChanged=' +
          changed,
      );
      await assert.rejects(subscription.close(), (error: unknown) => {
        const value = error as { code?: string; details?: { outcome?: string } };
        return value.code === 'EK_KAFKA_OFFSET' && value.details?.outcome === 'unknown';
      });
      assert.equal(effects, 1);
      await permission(group, false);
      changed = false;
      armed = false;
      Connection.prototype.consumer = original;
      const next = await owner.service.consume(
        { cluster: 'secure', topics: ['orders.created'], groupId: group, offsetReset: 'earliest' },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          assert.equal(record.offset, receipt.offset);
          effects++;
        },
      );
      for (let i = 0; i < 200 && effects < 2; i++) await setTimeout(50);
      assert.equal(effects, 2);
      await next.close();
    } finally {
      Connection.prototype.consumer = original;
      if (changed) await permission(group, false);
      await owner.close();
    }
  },
);
