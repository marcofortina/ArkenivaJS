// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { amqpPlugin, AMQP_CAPABILITY } from '@arkenivajs/messaging-amqp';
import type { AmqpService, AmqpPluginSettings, AmqpDelivery } from '@arkenivajs/messaging-amqp';

/** Fixture secrets come only from private deployment-owned metadata, never request parameters. */
export async function fixtureSettings() {
  const path = process.env.ARKENIVA_AMQP_FIXTURE;
  if (!path) throw new Error('The owned AMQPS fixture metadata path is required');
  const value = JSON.parse(await readFile(path, 'utf8')) as {
    container: string;
    caFile: string;
    uris: { admin: string };
    users: Record<string, { username: string; password: string }>;
  };
  if (!value.container.startsWith('arkenivajs-amqp-'))
    throw new Error('An owned AMQPS fixture is required');
  const suffix = randomUUID(),
    exchange = 'fixture.example.' + suffix,
    queue = 'fixture.example.queue.' + suffix;
  const settings: AmqpPluginSettings = {
    connections: [
      {
        name: 'events',
        connectionUriSecretRef: 'fixture-broker-uri',
        tlsCaFile: value.caFile,
        maxInFlightPublishes: 8,
        maxMessageBytes: 65536,
        allowTopologyProvisioning: true,
        topology: {
          exchanges: [{ name: exchange, type: 'direct', routingKeys: ['created', 'absent'] }],
          queues: [{ name: queue }],
          bindings: [{ exchange, queue, routingKey: 'created' }],
        },
      },
    ],
    resolveSecret: Object.assign(async () => value.uris.admin, { usage: 'test-only' as const }),
  };
  return {
    settings,
    exchange,
    queue,
    sensitive: [
      value.uris.admin,
      value.caFile,
      ...Object.values(value.users).flatMap((user) => [user.username, user.password]),
    ],
  };
}

/** Explicit native AMQP confirms and manual acknowledgments retain their distinct meanings. */
export async function runAmqpExample(
  settings: AmqpPluginSettings,
  exchange: string,
  queue: string,
) {
  const app = await createApplication({
    service: { name: 'amqp-example', version: '0.1.0', environment: 'test' },
    plugins: [amqpPlugin(settings)],
  });
  let resolve!: (message: AmqpDelivery) => void, reject!: (error: unknown) => void;
  const delivery = new Promise<AmqpDelivery>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  void delivery.catch(() => undefined);
  const timer = setTimeout(
    () => reject(new Error('The owned AMQP delivery deadline expired')),
    5000,
  );
  try {
    await app.start();
    const service = app.resolve<AmqpService>(AMQP_CAPABILITY);
    const subscription = await service.subscribe(
      { connection: 'events', queue, prefetch: 1, maxMessageBytes: 65536, failurePolicy: 'reject' },
      async (message) => {
        try {
          await message.ack();
          resolve(message);
        } catch (error) {
          reject(error);
        }
      },
    );
    const body = Uint8Array.of(0, 128, 255);
    const receipt = await service.publish({
      connection: 'events',
      exchange,
      routingKey: 'created',
      body,
      mandatory: true,
      headers: {
        large: 9007199254740993n,
        date: new Date('2026-10-27T12:00:00Z'),
        bytes: body,
        tenant_id: 'untrusted-wire-tenant',
      },
    });
    const message = await delivery;
    const returned = await service.publish({
      connection: 'events',
      exchange,
      routingKey: 'absent',
      body,
      mandatory: true,
    });
    await subscription.close();
    return { receipt, returned, message };
  } finally {
    clearTimeout(timer);
    await app.stop();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const fixture = await fixtureSettings();
  const result = await runAmqpExample(fixture.settings, fixture.exchange, fixture.queue);
  console.log(
    JSON.stringify({
      status: result.receipt.status,
      returnedStatus: result.returned.status,
      deliveredBytes: result.message.body.length,
    }),
  );
}
