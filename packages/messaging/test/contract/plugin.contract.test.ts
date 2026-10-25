// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import { messagingPlugin } from '@arkenivajs/messaging';
import { Socket } from 'node:net';

const service = { name: 'messaging-contract', version: '1.0.0', environment: 'test' as const };
test('Messaging factories and prepared facades allocate no native transport and reject stale lifecycle access', async (context) => {
  const connect = context.mock.method(Socket.prototype, 'connect');
  const app = await createApplication({
    service,
    plugins: [
      messagingPlugin({
        connectionStringEnv: 'ARKENIVA_UNUSED_NATS_CONTRACT',
        onError: async () => {},
      }),
    ],
  });
  const bus = app.messaging!;
  assert.ok(bus && Object.isFrozen(bus));
  assert.equal(connect.mock.callCount(), 0);
  await assert.rejects(bus.publish('orders', {}), { code: 'EK_LIFECYCLE_STATE' });
  await assert.rejects(
    bus.subscribe('orders', async () => {}),
    { code: 'EK_LIFECYCLE_STATE' },
  );
  await app.stop();
  await assert.rejects(bus.publish('orders', {}), { code: 'EK_RESOURCE_CLOSED' });
  assert.equal(connect.mock.callCount(), 0);
});

test('Messaging requires explicit error policy and rejects unsupported plugin wiring before native allocation', async (context) => {
  const connect = context.mock.method(Socket.prototype, 'connect');
  for (const input of [
    null,
    [],
    {},
    { onError: false },
    { onError: async () => {}, dependencies: false },
    { onError: async () => {}, dependencies: [1] },
    { onError: async () => {}, logger: {} },
    { onError: async () => {}, connectionStringEnv: 'lowercase' },
  ])
    assert.throws(() => messagingPlugin(input as never), { code: 'EK_CONFIG_INVALID' });
  const app = await createApplication({
    service,
    plugins: [
      messagingPlugin({
        connectionStringEnv: 'ARKENIVA_UNUSED_NATS_CONTRACT',
        onError: async () => {},
      }),
    ],
  });
  const bus = app.messaging!;
  await assert.rejects(app.start());
  assert.equal(app.state, 'CLOSED');
  await assert.rejects(bus.publish('orders', {}), { code: 'EK_RESOURCE_CLOSED' });
  assert.equal(connect.mock.callCount(), 0);
});
