// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';
import { messagingPlugin } from '@arkenivajs/messaging';
import type { MessageFailure } from '@arkenivajs/messaging';

/** Wire JSON types do not replace runtime validation of business data. */
export function orderDTO(input: unknown) {
  const value = copyData(input);
  if (
    !value ||
    typeof value !== 'object' ||
    !('orderId' in value) ||
    typeof value.orderId !== 'string' ||
    !value.orderId
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'An order requires a nonempty string identity',
    });
  return Object.freeze({ orderId: value.orderId });
}

/** Exercise one owned disposable subject without claiming durable delivery or trusting a wire tenant. */
export async function runMessagingExample() {
  if (process.env.ARKENIVA_NATS_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The messaging example requires an explicitly disposable NATS server',
    });
  if (!process.env.ARKENIVA_NATS_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_NATS_URL is required' });
  const failures: MessageFailure[] = [],
    topic = 'example.orders.' + randomBytes(12).toString('hex'),
    delivered: { id: string; correlation?: string }[] = [],
    app = await createApplication({
      service: { name: 'messaging-example', version: '1.0.0', environment: 'test' },
      plugins: [
        messagingPlugin({
          connectionStringEnv: 'ARKENIVA_NATS_URL',
          onError: async (failure) => {
            failures.push(failure);
          },
        }),
      ],
    });
  try {
    await app.start();
    const subscription = await app.messaging!.subscribe(topic, async (message) => {
      const order = orderDTO(message.payload);
      assert.equal(message.tenant, undefined);
      delivered.push({
        id: order.orderId,
        ...(message.correlationId ? { correlation: message.correlationId } : {}),
      });
    });
    const receipt = await app.messaging!.publish(
      topic,
      { orderId: 'order-42' },
      { correlationId: 'example-request' },
    );
    await app.messaging!.publish(topic, { orderId: 42 });
    const until = performance.now() + 5000;
    while (delivered.length !== 1 || failures.length !== 1) {
      assert.ok(performance.now() < until, 'The messaging example did not settle');
      await delay(5);
    }
    assert.equal(receipt.acknowledged, false);
    assert.deepEqual(delivered, [{ id: 'order-42', correlation: 'example-request' }]);
    assert.equal(failures[0]!.kind, 'handler');
    await subscription.close();
    return {
      acknowledged: receipt.acknowledged,
      received: delivered.length,
      correlated: true,
      handlerFailures: failures.length,
    };
  } finally {
    await app.stop();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runMessagingExample()));
  } catch (cause) {
    console.error(
      JSON.stringify(
        cause instanceof KitError
          ? cause.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The messaging example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
