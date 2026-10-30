// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { connectAmqp, amqpConnection } from './amqp-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; AMQP performance accounting remains separate',
);
assert.ok(
  process.env.ARKENIVA_AMQP_FIXTURE,
  'The owned disposable AMQP fixture metadata is required',
);
const metadata = JSON.parse(await readFile(process.env.ARKENIVA_AMQP_FIXTURE, 'utf8'));
assert.match(metadata.container, /^arkenivajs-amqp-[a-z0-9_-]+$/);
const suffix = randomBytes(16).toString('hex');
const fixture = {
  url: metadata.uris.service,
  caFile: metadata.caFile,
  exchange: 'fixture.comparison.exchange.' + suffix,
  serviceQueue: 'fixture.comparison.service.' + suffix,
  nativeQueue: 'fixture.comparison.native.' + suffix,
  marker: 'owned-amqp-private-body',
};
const url = amqpConnection(fixture);
const admin = await connectAmqp({ ...fixture, url: metadata.uris.admin });
let channel;
const queues = [],
  exchanges = [];
try {
  channel = await admin.createChannel();
  channel.on('error', () => undefined);
  exchanges.push(fixture.exchange);
  await channel.assertExchange(fixture.exchange, 'direct', { durable: false });
  for (const [queue, routingKey] of [
    [fixture.serviceQueue, 'service'],
    [fixture.nativeQueue, 'native'],
  ]) {
    queues.push(queue);
    await channel.assertQueue(queue, { durable: false, autoDelete: false });
    await channel.bindQueue(queue, fixture.exchange, routingKey);
  }
  await runPureComparison(
    {
      scenarioId: 'amqp-native-confirm-and-return-verification',
      fixture,
      privacyValues: [
        ...Object.values(fixture),
        decodeURIComponent(url.username),
        decodeURIComponent(url.password),
        metadata.uris.admin,
        metadata.uris.denied,
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./amqp-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'amqplib@2.2.0 with the same reviewed upstream codec patch',
        messagesPerProfile: 3,
        prefetch: 1,
        maxInFlightPublishes: 2,
        samplingSupported: false,
      },
      observationCoverage:
        'Four real AMQPS profiles use restricted service credentials and pre-existing trusted topology. An independent native observer verifies byte/header interoperability, actual publisher confirms, mandatory returns, manual acknowledgments and drained queues. Actual SDK exports exclude topology and message data.',
      limitations:
        'Bounded valid binary and scalar-header corpus. Parent administrator provisions and removes only random owned test resources; child profiles cannot provision topology. Native baseline omits framework hostile-field validation, single-use acknowledgment guards, admission, recovery and lifecycle policy. A broker confirm is not consumer/business commitment; local ack submission is not an acknowledgment receipt. No unknown-outcome retry, broker restart, multi-pod, complete broker/client CPU, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  for (const queue of queues) {
    const state = await channel.checkQueue(queue);
    assert.equal(state.messageCount, 0);
    assert.equal(state.consumerCount, 0);
  }
} finally {
  try {
    const failures = [];
    for (const [kind, name] of [
      ...[...queues].reverse().map((name) => ['queue', name]),
      ...exchanges.map((name) => ['exchange', name]),
    ]) {
      let cleanup;
      try {
        cleanup = await admin.createChannel();
        cleanup.on('error', () => undefined);
        if (kind === 'queue') await cleanup.deleteQueue(name);
        else await cleanup.deleteExchange(name);
      } catch (cause) {
        if (cause.code !== 404) failures.push(cause);
      } finally {
        if (cleanup)
          try {
            await cleanup.close();
          } catch (cause) {
            if (cause.name !== 'IllegalOperationError') failures.push(cause);
          }
      }
    }
    if (channel)
      try {
        await channel.close();
      } catch (cause) {
        if (cause.name !== 'IllegalOperationError') failures.push(cause);
      }
    assert.equal(failures.length, 0, 'The owned AMQP topology cleanup failed');
  } finally {
    await admin.close();
  }
}
await writeFile(
  resolve(args[1], 'protocol-observation.json'),
  JSON.stringify(
    {
      ownedMessagesRemaining: 0,
      ownedConsumersRemaining: 0,
      ownedResourcesRemoved: true,
      releaseGate: false,
    },
    null,
    2,
  ) + '\n',
  { mode: 0o600, flag: 'wx' },
);
