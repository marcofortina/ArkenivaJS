// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AMQP_CAPABILITY } from '../../dist/index.js';
import type {
  AmqpService,
  AmqpDelivery,
  AmqpPluginSettings,
  AmqpPublishRequest,
} from '../../dist/index.js';
export function contracts(amqp: AmqpService, delivery: AmqpDelivery, settings: AmqpPluginSettings) {
  const message: AmqpPublishRequest = {
    connection: 'events',
    exchange: 'events',
    routingKey: 'created',
    body: new Uint8Array(),
    headers: { id: 9007199254740993n, when: new Date(0), binary: Uint8Array.of(1) },
  };
  const result = amqp.publish(message);
  // @ts-expect-error AMQP requires explicit binary bodies, without implicit string conversion.
  amqp.publish({ ...message, body: 'invalid' });
  // @ts-expect-error A broker confirmation is not a delivery acknowledgment method.
  delivery.confirm();
  // @ts-expect-error Tenant provenance cannot be replaced through readonly delivery metadata.
  delivery.verifiedTenant = undefined;
  const native: unknown = amqp.native('events');
  // @ts-expect-error Native handles require deliberate consumer-side type narrowing.
  native.createChannel();
  return { capability: AMQP_CAPABILITY, result, settings };
}
