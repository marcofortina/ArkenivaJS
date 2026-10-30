// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { ChannelModel } from 'amqplib';
import type { Duplex } from 'node:stream';
import { execFile } from 'node:child_process';
import { createApplication, KitError } from '@arkenivajs/core';
import { AMQP_CAPABILITY, amqpPlugin } from '../../dist/index.js';
import type { AmqpService, AmqpPluginSettings, AmqpDelivery } from '../../dist/index.js';
import { Connection } from '../../dist/connection.js';
import { capture } from '../../dist/settings.js';
import { Task } from '../../dist/operation.js';

const metadataPath = process.env.ARKENIVA_AMQP_FIXTURE;
if (!metadataPath) throw new Error('The owned AMQPS fixture metadata path is required');
const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as {
  container: string;
  caFile: string;
  uris: { admin: string; service: string; denied: string };
  restartCommand: string[];
};
if (!metadata.container.startsWith('arkenivajs-amqp-'))
  throw new Error('An owned disposable AMQP fixture is required');
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
async function fixture(maxInFlightPublishes = 8) {
  const suffix = randomUUID(),
    exchange = 'fixture.exchange.' + suffix,
    queue = 'fixture.queue.' + suffix;
  const settings: AmqpPluginSettings = {
    connections: [
      {
        name: 'events',
        connectionUriSecretRef: 'fixture-uri',
        tlsCaFile: metadata.caFile,
        maxInFlightPublishes,
        maxMessageBytes: 65536,
        allowTopologyProvisioning: true,
        topology: {
          exchanges: [{ name: exchange, type: 'direct', routingKeys: ['created', 'absent'] }],
          queues: [{ name: queue }],
          bindings: [{ exchange, queue, routingKey: 'created' }],
        },
      },
    ],
    resolveSecret: async () => metadata.uris.admin,
  };
  const app = await createApplication({
    service: { name: 'amqp-fixture', version: '1.0.0', environment: 'test' },
    plugins: [amqpPlugin(settings)],
  });
  await app.start();
  return { app, service: app.resolve<AmqpService>(AMQP_CAPABILITY), exchange, queue, settings };
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  const timer = setTimeout(
    () => reject(new Error('The owned AMQP integration did not complete')),
    5000,
  );
  void promise.catch(() => undefined);
  return {
    promise,
    resolve,
    reject,
    close() {
      clearTimeout(timer);
    },
  };
}
test('Actual RabbitMQ authentication retains the captured secret resolver without callable metadata access', async () => {
  const f = await fixture();
  let effects = 0,
    calls = 0;
  const settings = {
    ...f.settings,
    async resolveSecret(this: unknown, reference: string) {
      assert.equal(this, settings);
      assert.equal(reference, 'fixture-uri');
      calls++;
      return metadata.uris.admin;
    },
  };
  for (const field of ['bind', 'name', 'length'])
    Object.defineProperty(settings.resolveSecret, field, {
      get() {
        effects++;
        throw new Error('Callable metadata must not execute');
      },
    });
  const app = await createApplication({
    service: { name: 'amqp-owned-resolver', version: '1.0.0', environment: 'test' },
    plugins: [amqpPlugin(settings)],
  });
  settings.resolveSecret = async () => {
    throw new Error('Later resolver replacement must not execute');
  };
  try {
    await app.start();
    assert.equal(
      (await app.resolve<AmqpService>(AMQP_CAPABILITY).health('events')).available,
      true,
    );
    assert.ok(calls > 0);
    assert.equal(effects, 0);
  } finally {
    await app.stop();
    await f.app.stop();
  }
});
test('Actual RabbitMQ health checks retain captured cancellation cleanup after caller hook replacement', async () => {
  const f = await fixture(),
    controller = new AbortController();
  let effects = 0;
  try {
    const pending = f.service.health('events', { signal: controller.signal });
    Object.defineProperty(controller.signal, 'removeEventListener', {
      value() {
        effects++;
      },
    });
    assert.equal((await pending).available, true);
    assert.equal(effects, 0);
    assert.equal((await f.service.health('events')).available, true);
  } finally {
    await f.app.stop();
  }
});
test('The public AMQPS plugin confirms actual publications and delivers lossless headers with single-use manual acknowledgments', async () => {
  const f = await fixture(),
    delivery = deferred<AmqpDelivery>();
  try {
    const subscription = await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          await message.ack();
          await assert.rejects(message.ack(), code('EK_AMQP_ACK_STATE'));
          delivery.resolve(message);
        } catch (error) {
          delivery.reject(error);
        }
      },
    );
    const body = Uint8Array.of(0, 255, 128),
      headers = {
        maximum: (1n << 63n) - 1n,
        minimum: -(1n << 63n),
        date: new Date('2026-10-27T12:00:00.000Z'),
        bytes: Uint8Array.of(0, 255),
        tenant_id: 'untrusted-wire-tenant',
        verifiedTenant: { tenantId: 'untrusted' },
      };
    const receipt = await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body,
      headers,
      mandatory: true,
    });
    assert.equal(receipt.status, 'confirmed');
    assert.ok(receipt.confirmedAt);
    const message = await delivery.promise;
    assert.deepEqual(message.body, body);
    assert.equal(message.headers.maximum, headers.maximum);
    assert.equal(message.headers.minimum, headers.minimum);
    assert.deepEqual(message.headers.bytes, headers.bytes);
    assert.equal(message.verifiedTenant, undefined);
    assert.ok(Object.isFrozen(message));
    assert.ok(message.headers.date instanceof Date);
    assert.equal(message.headers.date.getTime(), headers.date.getTime());
    assert.equal((await f.service.health('events')).available, true);
    const native = f.service.native('events');
    assert.ok(native && typeof native === 'object' && 'createChannel' in native);
    await subscription.close();
  } finally {
    delivery.close();
    await f.app.stop();
  }
});
test('Mandatory returns remain unroutable even when concurrent requests share the same application message ID', async () => {
  const f = await fixture();
  try {
    const [routed, returned] = await Promise.all([
      f.service.publish({
        connection: 'events',
        exchange: f.exchange,
        routingKey: 'created',
        body: new Uint8Array(),
        messageId: 'shared-id',
        mandatory: true,
      }),
      f.service.publish({
        connection: 'events',
        exchange: f.exchange,
        routingKey: 'absent',
        body: Uint8Array.of(1),
        messageId: 'shared-id',
        mandatory: true,
      }),
    ]);
    assert.equal(routed.status, 'confirmed');
    assert.equal(returned.status, 'unroutable');
    assert.equal(returned.confirmedAt, undefined);
    await assert.rejects(
      f.service.publish({
        connection: 'events',
        exchange: f.exchange,
        routingKey: 'undeclared',
        body: new Uint8Array(),
      }),
      code('EK_AMQP_PUBLISH'),
    );
  } finally {
    await f.app.stop();
  }
});
test('Explicit requeue produces a real redelivery while duplicate acknowledgments remain forbidden', async () => {
  const f = await fixture(),
    done = deferred<void>();
  let attempts = 0;
  try {
    const subscription = await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          attempts++;
          if (!message.redelivered) {
            await message.nack({ requeue: true });
            await assert.rejects(message.ack(), code('EK_AMQP_ACK_STATE'));
          } else {
            await message.ack();
            done.resolve();
          }
        } catch (error) {
          done.reject(error);
        }
      },
    );
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
      mandatory: true,
    });
    await done.promise;
    assert.equal(attempts, 2);
    await subscription.close();
  } finally {
    done.close();
    await f.app.stop();
  }
});

test('Pre-aborted calls, unsupported fields and publication saturation fail without resetting a healthy peer', async () => {
  const f = await fixture(),
    controller = new AbortController();
  controller.abort();
  try {
    const message = {
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
    };
    await assert.rejects(
      f.service.publish(message, { signal: controller.signal }),
      code('EK_ABORTED'),
    );
    await assert.rejects(f.service.publish(message, { timeoutMs: 0 }), code('EK_CONFIG_INVALID'));
    await assert.rejects(
      f.service.publish({ ...message, headers: { invalid: Infinity } }),
      code('EK_AMQP_PUBLISH'),
    );
    await assert.rejects(
      f.service.publish({ ...message, body: new Uint8Array(new SharedArrayBuffer(4)) }),
      code('EK_AMQP_PUBLISH'),
    );
    const pending = Array.from({ length: 8 }, () => f.service.publish(message));
    const excess = f.service.publish(message);
    await assert.rejects(excess, code('EK_AMQP_PUBLISH'));
    const receipts = await Promise.all(pending);
    assert.ok(receipts.every((receipt) => receipt.status === 'confirmed'));
    assert.equal((await f.service.health('events')).available, true);
  } finally {
    await f.app.stop();
  }
});

test('Least-privilege peers can use existing topology and cannot obtain provisioning rights through settings', async () => {
  const f = await fixture();
  await f.app.stop();
  const connection = f.settings.connections[0]!,
    settings = {
      ...f.settings,
      connections: [{ ...connection, allowTopologyProvisioning: false }],
      resolveSecret: async () => metadata.uris.service,
    };
  const app = await createApplication({
    service: { name: 'amqp-restricted', version: '1.0.0', environment: 'test' },
    plugins: [amqpPlugin(settings)],
  });
  try {
    await app.start();
    const service = app.resolve<AmqpService>(AMQP_CAPABILITY);
    assert.equal(
      (
        await service.publish({
          connection: 'events',
          exchange: f.exchange,
          routingKey: 'created',
          body: new Uint8Array(),
        })
      ).status,
      'confirmed',
    );
  } finally {
    await app.stop();
  }
  const denied = await createApplication({
    service: { name: 'amqp-provision-denied', version: '1.0.0', environment: 'test' },
    plugins: [
      amqpPlugin({
        ...settings,
        connections: [{ ...connection, allowTopologyProvisioning: true }],
      }),
    ],
  });
  try {
    await assert.rejects(
      denied.start(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_AMQP_CONNECT',
    );
  } finally {
    await denied.stop();
  }
});

test('The native AMQPS peer is rejected without its private fixture CA', async () => {
  const f = await fixture();
  await f.app.stop();
  const { tlsCaFile, ...connection } = f.settings.connections[0]!;
  void tlsCaFile;
  const app = await createApplication({
    service: { name: 'amqp-untrusted', version: '1.0.0', environment: 'test' },
    plugins: [amqpPlugin({ ...f.settings, connections: [connection] })],
  });
  try {
    await assert.rejects(
      app.start(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_AMQP_CONNECT',
    );
  } finally {
    await app.stop();
  }
});

test('A failed handler rejects without requeue by default and releases prefetch for the next message', async () => {
  const f = await fixture(),
    done = deferred<void>(),
    firstId = randomUUID(),
    secondId = randomUUID();
  let failures = 0;
  try {
    const subscription = await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        if (message.messageId === firstId) {
          failures++;
          throw new Error('The owned handler deliberately fails');
        }
        try {
          assert.equal(message.messageId, secondId);
          await message.ack();
          done.resolve();
        } catch (error) {
          done.reject(error);
        }
      },
    );
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
      messageId: firstId,
    });
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(2),
      messageId: secondId,
    });
    await done.promise;
    assert.equal(failures, 1);
    await subscription.close();
  } finally {
    done.close();
    await f.app.stop();
  }
});

test('An oversized inbound body never reaches a handler and cannot cause an endless poison-message reconnect loop', async () => {
  const f = await fixture();
  let calls = 0;
  try {
    await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 16,
        failurePolicy: 'reject',
      },
      async () => {
        calls++;
      },
    );
    const receipt = await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: new Uint8Array(32),
    });
    assert.ok(['confirmed', 'unknown'].includes(receipt.status));
    for (let i = 0; i < 100; i++) {
      if (!(await f.service.health('events')).available) break;
      await delay(10);
    }
    assert.equal((await f.service.health('events')).available, false);
    assert.equal(calls, 0);
    await delay(50);
    assert.equal((await f.service.health('events')).available, false);
  } finally {
    await f.app.stop();
  }
});

test('Connection recovery restores exactly one consumer without republishing previous messages', async () => {
  const f = await fixture(),
    first = deferred<void>(),
    second = deferred<void>(),
    firstId = randomUUID(),
    secondId = randomUUID();
  let originalDeliveries = 0,
    subsequentDeliveries = 0;
  try {
    const subscription = await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          if (message.messageId === firstId) {
            originalDeliveries++;
            if (originalDeliveries > 1) assert.equal(message.redelivered, true);
          } else {
            assert.equal(message.messageId, secondId);
            subsequentDeliveries++;
          }
          await message.ack();
          if (message.messageId === firstId) first.resolve();
          else second.resolve();
        } catch (error) {
          second.reject(error);
        }
      },
    );
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
      messageId: firstId,
    });
    await first.promise;
    const old = f.service.native('events') as ChannelModel & { connection: { stream: Duplex } };
    old.connection.stream.destroy(new Error('The owned transport is deliberately interrupted'));
    let restored = false;
    for (let i = 0; i < 200; i++) {
      if ((await f.service.health('events')).available) {
        restored = true;
        break;
      }
      await delay(10);
    }
    assert.equal(restored, true);
    const native = f.service.native('events') as ChannelModel,
      channel = await native.createChannel();
    try {
      assert.equal((await channel.checkQueue(f.queue)).consumerCount, 1);
    } finally {
      await channel.close();
    }
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(2),
      messageId: secondId,
    });
    await second.promise;
    // A locally submitted acknowledgment can remain uncertain at the forced disconnect.
    assert.ok(originalDeliveries >= 1 && originalDeliveries <= 2);
    assert.equal(subsequentDeliveries, 1);
    await subscription.close();
  } finally {
    first.close();
    second.close();
    await f.app.stop();
  }
});

test('Shutdown before manual acknowledgment permits broker redelivery to a second application instance', async () => {
  const f = await fixture(),
    first = deferred<AmqpDelivery>(),
    second = deferred<AmqpDelivery>();
  const other = await createApplication({
    service: { name: 'amqp-second-pod', version: '1.0.0', environment: 'test' },
    plugins: [amqpPlugin(f.settings)],
  });
  try {
    await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        first.resolve(message);
      },
    );
    const receipt = await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
    });
    const old = await first.promise;
    await other.start();
    const service = other.resolve<AmqpService>(AMQP_CAPABILITY);
    await service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          await message.ack();
          second.resolve(message);
        } catch (error) {
          second.reject(error);
        }
      },
    );
    await f.app.stop();
    const message = await second.promise;
    assert.equal(message.messageId, receipt.messageId);
    assert.equal(message.redelivered, true);
    await assert.rejects(old.ack(), code('EK_AMQP_ACK_STATE'));
  } finally {
    first.close();
    second.close();
    await f.app.stop();
    await other.stop();
  }
});

test('A shutdown deadline closes transport while retaining an uncooperative handler until its actual settlement', async () => {
  const f = await fixture(),
    entered = deferred<void>();
  let release!: () => void;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async () => {
        entered.resolve();
        await hold;
      },
    );
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
    });
    await entered.promise;
    await assert.rejects(f.service.close({ timeoutMs: 20 }), code('EK_TIMEOUT'));
    assert.throws(() => f.service.native('events'), code('EK_RESOURCE_CLOSED'));
    release();
    await f.service.close({ timeoutMs: 2000 });
  } finally {
    release();
    entered.close();
    await f.app.stop();
  }
});

test('A submitted publication interrupted before reading its confirmation remains unknown and is never replayed', async () => {
  const f = await fixture();
  try {
    const native = f.service.native('events') as ChannelModel & { connection: { stream: Duplex } };
    native.connection.stream.pause();
    const pending = f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(9),
      messageId: 'interrupted-publication',
    });
    await Promise.resolve();
    native.connection.stream.destroy(
      new Error('The owned confirmation transport is deliberately interrupted'),
    );
    const receipt = await pending;
    assert.equal(receipt.status, 'unknown');
    assert.equal(receipt.confirmedAt, undefined);
    let restored = false;
    for (let i = 0; i < 200; i++) {
      if ((await f.service.health('events')).available) {
        restored = true;
        break;
      }
      await delay(10);
    }
    assert.equal(restored, true);
    const channel = await (f.service.native('events') as ChannelModel).createChannel();
    try {
      const queued = await channel.checkQueue(f.queue);
      assert.ok(queued.messageCount <= 1);
      const message = await channel.get(f.queue, { noAck: false });
      if (message) {
        assert.equal(message.properties.messageId, receipt.messageId);
        channel.ack(message);
      }
      assert.equal(await channel.get(f.queue, { noAck: true }), false);
    } finally {
      await channel.close();
    }
  } finally {
    await f.app.stop();
  }
});

test('Graceful shutdown permits an active handler to submit its acknowledgment before transport closure', async () => {
  const f = await fixture(),
    entered = deferred<void>(),
    acknowledged = deferred<void>();
  let release!: () => void;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        entered.resolve();
        await hold;
        try {
          await assert.rejects(
            message.nack({ requeue: 'invalid' } as unknown as { requeue: boolean }),
            code('EK_AMQP_ACK_STATE'),
          );
          await message.ack();
          acknowledged.resolve();
        } catch (error) {
          acknowledged.reject(error);
        }
      },
    );
    await f.service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(1),
    });
    await entered.promise;
    const closed = f.service.close({ timeoutMs: 2000 });
    await delay(10);
    release();
    await acknowledged.promise;
    await closed;
    await f.service.close();
  } finally {
    release();
    entered.close();
    acknowledged.close();
    await f.app.stop();
  }
});

test('An early acknowledgment cannot exceed the configured local handler concurrency', async () => {
  const f = await fixture(),
    entered = deferred<void>(),
    finished = deferred<void>();
  let release!: () => void,
    calls = 0,
    concurrent = 0,
    maximum = 0;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        concurrent++;
        maximum = Math.max(maximum, concurrent);
        calls++;
        try {
          await message.ack();
          if (calls === 1) {
            entered.resolve();
            await hold;
          }
          if (calls === 3) finished.resolve();
        } catch (error) {
          finished.reject(error);
        } finally {
          concurrent--;
        }
      },
    );
    for (let i = 0; i < 3; i++)
      await f.service.publish({
        connection: 'events',
        exchange: f.exchange,
        routingKey: 'created',
        body: Uint8Array.of(i),
      });
    await entered.promise;
    await delay(30);
    assert.equal(calls, 1);
    release();
    await finished.promise;
    assert.equal(calls, 3);
    assert.equal(maximum, 1);
  } finally {
    release();
    entered.close();
    finished.close();
    await f.app.stop();
  }
});

test('An owned real broker restart restores one native consumer and redelivers its unacknowledged persistent message', async () => {
  const f = await fixture(),
    first = deferred<void>();
  let resolve!: () => void,
    reject!: (error: unknown) => void,
    attempts = 0;
  const redelivery = new Promise<void>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  void redelivery.catch(() => undefined);
  const timer = setTimeout(
    () => reject(new Error('The owned broker restart recovery deadline expired')),
    60000,
  );
  try {
    assert.ok(
      Array.isArray(metadata.restartCommand) &&
        metadata.restartCommand.length >= 2 &&
        metadata.restartCommand.every(
          (part) =>
            typeof part === 'string' &&
            part.length > 0 &&
            part.length <= 1024 &&
            !part.includes('\0'),
        ),
    );
    const subscription = await f.service.subscribe(
      {
        connection: 'events',
        queue: f.queue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async (message) => {
        try {
          attempts++;
          if (attempts === 1) first.resolve();
          else {
            assert.equal(message.redelivered, true);
            await message.ack();
            resolve();
          }
        } catch (error) {
          reject(error);
        }
      },
    );
    assert.equal(
      (
        await f.service.publish({
          connection: 'events',
          exchange: f.exchange,
          routingKey: 'created',
          persistent: true,
          body: Uint8Array.of(1),
        })
      ).status,
      'confirmed',
    );
    await first.promise;
    const [command, ...args] = metadata.restartCommand;
    await new Promise<void>((resolve, reject) =>
      execFile(command!, args, { timeout: 60000, maxBuffer: 65536 }, (error) =>
        error ? reject(new Error('The owned broker restart controller failed')) : resolve(),
      ),
    );
    await redelivery;
    assert.equal(attempts, 2);
    const channel = await (f.service.native('events') as ChannelModel).createChannel();
    try {
      assert.equal((await channel.checkQueue(f.queue)).consumerCount, 1);
    } finally {
      await channel.close();
    }
    await subscription.close();
    assert.equal(
      (
        await f.service.publish({
          connection: 'events',
          exchange: f.exchange,
          routingKey: 'created',
          body: Uint8Array.of(2),
        })
      ).status,
      'confirmed',
    );
  } finally {
    first.close();
    clearTimeout(timer);
    await f.app.stop();
  }
});

test('Actual native write backpressure bounds admission without fabricating confirmations or replaying submissions', async () => {
  const f = await fixture(64);
  try {
    const body = new Uint8Array(65536);
    const results = await Promise.allSettled(
      Array.from({ length: 64 }, () =>
        f.service.publish({
          connection: 'events',
          exchange: f.exchange,
          routingKey: 'created',
          body,
        }),
      ),
    );
    const accepted = results.filter((result) => result.status === 'fulfilled');
    const blocked = results.filter((result) => result.status === 'rejected');
    assert.ok(accepted.length > 0);
    assert.ok(blocked.length > 0);
    for (const result of accepted) assert.equal(result.value.status, 'confirmed');
    for (const result of blocked)
      assert.ok(result.reason instanceof KitError && result.reason.code === 'EK_AMQP_CONNECT');
    assert.equal((await f.service.health('events')).available, true);
    assert.equal(
      (
        await f.service.publish({
          connection: 'events',
          exchange: f.exchange,
          routingKey: 'created',
          body: Uint8Array.of(1),
        })
      ).status,
      'confirmed',
    );
    const channel = await (f.service.native('events') as ChannelModel).createChannel();
    try {
      assert.equal((await channel.checkQueue(f.queue)).messageCount, accepted.length + 1);
    } finally {
      await channel.close();
    }
  } finally {
    await f.app.stop();
  }
});

test('A failed consumer uses the broker-configured dead-letter policy without an implicit requeue loop', async () => {
  const f = await fixture(),
    suffix = randomUUID(),
    deadExchange = 'fixture.dead.' + suffix,
    deadQueue = 'fixture.dead.queue.' + suffix,
    workQueue = 'fixture.work.queue.' + suffix;
  const channel = await (f.service.native('events') as ChannelModel).createChannel();
  let other: Awaited<ReturnType<typeof createApplication>> | undefined;
  let calls = 0;
  try {
    // Trusted fixture administration configures DLX before the application passively checks topology.
    await channel.assertExchange(deadExchange, 'fanout', { durable: true });
    await channel.assertQueue(deadQueue, { durable: true });
    await channel.bindQueue(deadQueue, deadExchange, '');
    await channel.assertQueue(workQueue, {
      durable: true,
      arguments: { 'x-dead-letter-exchange': deadExchange },
    });
    await channel.bindQueue(workQueue, f.exchange, 'created');
    const connection = f.settings.connections[0]!;
    other = await createApplication({
      service: { name: 'amqp-dlx', version: '1.0.0', environment: 'test' },
      plugins: [
        amqpPlugin({
          ...f.settings,
          connections: [
            {
              ...connection,
              allowTopologyProvisioning: false,
              topology: {
                ...connection.topology,
                queues: [{ name: workQueue }],
                bindings: [{ exchange: f.exchange, queue: workQueue, routingKey: 'created' }],
              },
            },
          ],
        }),
      ],
    });
    await other.start();
    const service = other.resolve<AmqpService>(AMQP_CAPABILITY);
    await service.subscribe(
      {
        connection: 'events',
        queue: workQueue,
        prefetch: 1,
        maxMessageBytes: 65536,
        failurePolicy: 'reject',
      },
      async () => {
        calls++;
        throw new Error('The owned consumer deliberately rejects');
      },
    );
    const receipt = await service.publish({
      connection: 'events',
      exchange: f.exchange,
      routingKey: 'created',
      body: Uint8Array.of(7),
    });
    assert.equal(receipt.status, 'confirmed');
    let dead = await channel.get(deadQueue, { noAck: true });
    for (let i = 0; !dead && i < 100; i++) {
      await delay(10);
      dead = await channel.get(deadQueue, { noAck: true });
    }
    assert.ok(dead);
    assert.equal(dead.properties.messageId, receipt.messageId);
    assert.deepEqual(dead.content, Buffer.from([7]));
    const deaths = dead.properties.headers?.['x-death'] as { reason: string; queue: string }[];
    assert.equal(deaths[0]?.reason, 'rejected');
    assert.equal(deaths[0]?.queue, workQueue);
    assert.equal(calls, 1);
    assert.equal(await channel.get(deadQueue, { noAck: true }), false);
  } finally {
    await other?.stop();
    await channel.close().catch(() => undefined);
    await f.app.stop();
  }
});

test('Closing the actual native producer channel triggers bounded reconnection instead of leaving a stale publisher', async () => {
  const f = await fixture(),
    settings = capture(f.settings),
    owner = new Connection(settings, settings.connections[0]!);
  try {
    const task = new Task<void>(
      undefined,
      new AbortController().signal,
      () => {
        void owner.close();
      },
      (task) => owner.init(task),
    );
    await task.result;
    const previous = owner.producer;
    assert.ok(previous);
    await previous.close();
    for (let i = 0; !owner.available && i < 200; i++) await delay(10);
    assert.equal(owner.available, true);
    assert.ok(owner.producer);
    assert.notEqual(owner.producer, previous);
  } finally {
    await owner.close();
    await f.app.stop();
  }
});
