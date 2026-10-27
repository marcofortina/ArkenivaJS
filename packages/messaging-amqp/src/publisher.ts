// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import type { AmqpPublishRequest, AmqpPublishReceipt, AmqpHeaders } from './contracts.js';
import type { Connection } from './connection.js';
import type { Task } from './operation.js';
import { fields, failure } from './validation.js';
import { protocolText } from './settings.js';
import { outgoing, ownedBytes } from './headers.js';

export function publication(input: AmqpPublishRequest, owner: Connection) {
  const value = fields(input, [
      'connection',
      'exchange',
      'routingKey',
      'body',
      'messageId',
      'headers',
      'persistent',
      'mandatory',
    ]),
    exchange = protocolText(value.exchange, 128),
    routingKey = protocolText(value.routingKey, 255, true);
  if (
    !owner.config.topology.exchanges.some(
      (entry) => entry.name === exchange && entry.routingKeys.includes(routingKey),
    )
  )
    throw failure('EK_AMQP_PUBLISH');
  for (const key of ['persistent', 'mandatory'])
    if (value[key] !== undefined && typeof value[key] !== 'boolean')
      throw failure('EK_AMQP_PUBLISH');
  return Object.freeze({
    exchange,
    routingKey,
    body: ownedBytes(value.body, owner.config.maxMessageBytes),
    messageId: value.messageId === undefined ? randomUUID() : protocolText(value.messageId, 255),
    headers: outgoing(value.headers as AmqpHeaders | undefined),
    persistent: value.persistent !== false,
    mandatory: value.mandatory !== false,
  });
}
export type Publication = ReturnType<typeof publication>;
export const unknownReceipt = (messageId: string): AmqpPublishReceipt =>
  Object.freeze({ messageId, status: 'unknown' });
/** A write boolean never substitutes for the native publisher confirmation callback. */
export async function publish(
  owner: Connection,
  value: Publication,
  task: Task<AmqpPublishReceipt>,
): Promise<AmqpPublishReceipt> {
  const channel = owner.producer;
  if (!owner.available || !channel || owner.writeBlocked || owner.brokerBlocked)
    throw failure('EK_AMQP_CONNECT');
  task.check();
  const correlationId = randomUUID();
  const result = new Promise<AmqpPublishReceipt>((resolve) => {
    let finished = false;
    const pending = {
      messageId: value.messageId,
      returned: false,
      finish(status: AmqpPublishReceipt['status']) {
        if (finished) return;
        finished = true;
        owner.pending.delete(correlationId);
        const actual = pending.returned && status === 'confirmed' ? 'unroutable' : status;
        resolve(
          Object.freeze({
            messageId: value.messageId,
            status: actual,
            ...(actual === 'confirmed' ? { confirmedAt: new Date().toISOString() } : {}),
          }),
        );
      },
    };
    owner.pending.set(correlationId, pending);
    try {
      task.submitted = true;
      const writable = channel.publish(
        value.exchange,
        value.routingKey,
        value.body,
        {
          headers: value.headers.native,
          messageId: value.messageId,
          correlationId,
          persistent: value.persistent,
          mandatory: value.mandatory,
        },
        (error) => pending.finish(error ? 'unknown' : 'confirmed'),
      );
      if (!writable) owner.writeBlocked = true;
    } catch {
      pending.finish('unknown');
    }
  });
  return task.wait(result);
}
