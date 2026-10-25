// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import type { MessageBus, Plugin } from '@arkenivajs/core';
import { createNatsBus, messagingPlugin } from '@arkenivajs/messaging';
import type { ManagedMessageBus, NatsBusOptions } from '@arkenivajs/messaging';

/** Compile against packed public exports with an unmodified native SDK dependency. */
export async function portableConsumer(policy: NatsBusOptions) {
  const plugin: Plugin = messagingPlugin({ onError: policy.onError });
  const app = await createApplication({
    service: { name: 'portable-consumer', version: '1.0.0', environment: 'test' },
    plugins: [plugin],
  });
  const managed: ManagedMessageBus = await createNatsBus(policy),
    bus: MessageBus = managed;
  const receipt: { messageId: string; acknowledged: boolean } = await bus.publish(
    'orders.created',
    { id: '42' },
  );
  const subscription = await bus.subscribe<{ id: string }>('orders.created', async (message) => {
    message.payload.id.toUpperCase();
  });
  await subscription.close();
  await managed.close();
  await app.stop();
  return receipt;
}
