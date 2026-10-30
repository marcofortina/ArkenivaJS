// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import amqp from 'amqplib';

export function amqpConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.equal(url.protocol, 'amqps:');
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.ok(url.port && url.username && url.password && !url.search && !url.hash);
    assert.ok(fixture.caFile?.startsWith('/'));
    return url;
  } catch {
    throw new Error(
      'The owned AMQP comparison requires verified loopback AMQPS and external credentials',
    );
  }
}

export async function connectAmqp(fixture, wrongName = false) {
  const url = amqpConnection(fixture);
  try {
    const connection = await amqp.connect(
      {
        protocol: 'amqps',
        hostname: url.hostname,
        port: Number(url.port),
        username: decodeURIComponent(url.username),
        password: decodeURIComponent(url.password),
        vhost: url.pathname.slice(1) || '%2F',
        heartbeat: 10,
        channelMax: 128,
        frameMax: 131072,
        locale: 'en_US',
      },
      {
        ca: await readFile(fixture.caFile),
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        timeout: 3000,
        noDelay: true,
        ...(wrongName ? { servername: 'wrong.invalid' } : {}),
        recovery: false,
      },
    );
    connection.on('error', () => undefined);
    return connection;
  } catch {
    throw new Error('The owned native AMQPS comparison connection failed');
  }
}

export function amqpSettings(fixture) {
  amqpConnection(fixture);
  return {
    connections: [
      {
        name: 'events',
        connectionUriSecretRef: 'owned-comparison-uri',
        tlsCaFile: fixture.caFile,
        maxInFlightPublishes: 2,
        maxMessageBytes: 65536,
        allowTopologyProvisioning: false,
        topology: {
          exchanges: [
            {
              name: fixture.exchange,
              type: 'direct',
              durable: false,
              routingKeys: ['service', 'native', 'absent'],
            },
          ],
          queues: [fixture.serviceQueue, fixture.nativeQueue].map((name) => ({
            name,
            durable: false,
          })),
          bindings: [
            { exchange: fixture.exchange, queue: fixture.serviceQueue, routingKey: 'service' },
            { exchange: fixture.exchange, queue: fixture.nativeQueue, routingKey: 'native' },
          ],
        },
      },
    ],
    resolveSecret: async () => fixture.url,
  };
}

/** Native confirms and mandatory returns remain distinct from consumer acknowledgment submission. */
export async function nativeAmqp(fixture) {
  const connection = await connectAmqp(fixture);
  const channels = [],
    failures = [];
  let producer;
  try {
    producer = await connection.createConfirmChannel();
    channels.push(producer);
    producer.on('error', (cause) => failures.push(cause));
    await producer.checkExchange(fixture.exchange);
    await producer.checkQueue(fixture.serviceQueue);
    await producer.checkQueue(fixture.nativeQueue);
  } catch {
    await connection.close();
    throw new Error('The owned native AMQP topology check failed');
  }
  const returned = new Set();
  producer.on('return', (message) => returned.add(message.properties.messageId));
  return {
    async publish(request) {
      assert.equal(request.connection, 'events');
      const messageId = request.messageId ?? randomUUID();
      await new Promise((done, reject) =>
        producer.publish(
          request.exchange,
          request.routingKey,
          Buffer.from(request.body),
          { messageId, mandatory: request.mandatory, persistent: false, headers: request.headers },
          (cause) => (cause ? reject(cause) : done()),
        ),
      );
      const unroutable = returned.delete(messageId);
      return { messageId, status: unroutable ? 'unroutable' : 'confirmed' };
    },
    async subscribe(config, handler) {
      assert.equal(config.connection, 'events');
      const channel = await connection.createChannel();
      channels.push(channel);
      channel.on('error', (cause) => failures.push(cause));
      await channel.prefetch(config.prefetch);
      const tasks = new Set();
      const consumer = await channel.consume(
        config.queue,
        (message) => {
          const task = Promise.resolve()
            .then(async () => {
              assert.ok(message);
              await handler({
                messageId: message.properties.messageId,
                exchange: message.fields.exchange,
                routingKey: message.fields.routingKey,
                redelivered: message.fields.redelivered,
                body: message.content,
                headers: message.properties.headers ?? {},
                ack: async () => channel.ack(message),
              });
            })
            .catch((cause) => failures.push(cause))
            .finally(() => tasks.delete(task));
          tasks.add(task);
        },
        { noAck: false },
      );
      return {
        close: async () => {
          await channel.cancel(consumer.consumerTag);
          await Promise.all([...tasks]);
          assert.equal(failures.length, 0);
        },
      };
    },
    async close() {
      try {
        for (const channel of [...channels].reverse()) await channel.close();
      } finally {
        await connection.close();
      }
      assert.equal(failures.length, 0);
    },
  };
}

export async function verifyAmqp(service, fixture) {
  const observer = await connectAmqp(fixture);
  let channel, subscription;
  const received = [],
    failures = [];
  const body = Buffer.concat([Buffer.from([0, 255, 128]), Buffer.from(fixture.marker)]),
    headers = { note: fixture.marker, sequence: 7, enabled: true };
  try {
    channel = await observer.createConfirmChannel();
    channel.on('error', (cause) => failures.push(cause));
    subscription = await service.subscribe(
      {
        connection: 'events',
        queue: fixture.serviceQueue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (delivery) => {
        try {
          assert.deepEqual(Buffer.from(delivery.body), body);
          assert.deepEqual({ ...delivery.headers }, headers);
          assert.equal(delivery.exchange, fixture.exchange);
          assert.equal(delivery.routingKey, 'service');
          assert.equal(delivery.verifiedTenant, undefined);
          await delivery.ack();
          received.push(delivery.messageId);
        } catch (cause) {
          failures.push(cause);
        }
      },
    );
    const incomingId = randomUUID();
    await new Promise((done, reject) =>
      channel.publish(
        fixture.exchange,
        'service',
        body,
        { messageId: incomingId, mandatory: true, headers },
        (cause) => (cause ? reject(cause) : done()),
      ),
    );
    const until = performance.now() + 3000;
    while (received.length !== 1) {
      assert.equal(failures.length, 0);
      assert.ok(performance.now() < until, 'The owned AMQP delivery exceeded its deadline');
      await delay(5);
    }
    assert.equal(received[0], incomingId);
    const request = {
      connection: 'events',
      exchange: fixture.exchange,
      routingKey: 'native',
      body,
      headers,
      mandatory: true,
    };
    const receipt = await service.publish(request);
    assert.equal(receipt.status, 'confirmed');
    const message = await channel.get(fixture.nativeQueue, { noAck: false });
    assert.ok(message);
    assert.equal(message.properties.messageId, receipt.messageId);
    assert.deepEqual(message.content, body);
    assert.deepEqual({ ...message.properties.headers }, headers);
    channel.ack(message);
    const absent = await service.publish({ ...request, routingKey: 'absent' });
    assert.equal(absent.status, 'unroutable');
    await subscription.close();
    subscription = undefined;
    for (const queue of [fixture.serviceQueue, fixture.nativeQueue]) {
      const state = await channel.checkQueue(queue);
      assert.equal(state.messageCount, 0);
      assert.equal(state.consumerCount, 0);
    }
    assert.equal(failures.length, 0);
    return {
      nativeToServiceVerified: true,
      serviceToNativeVerified: true,
      exactHeadersAndBodyVerified: true,
      brokerConfirmObserved: true,
      mandatoryReturnObserved: true,
      queuesDrained: true,
      inventedTenantAbsent: true,
    };
  } finally {
    try {
      await subscription?.close();
    } finally {
      try {
        await channel?.close();
      } finally {
        await observer.close();
      }
    }
  }
}
