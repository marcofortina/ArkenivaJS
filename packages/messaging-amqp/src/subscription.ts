// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Channel } from 'amqplib';
import type { AmqpConsumeSettings, AmqpDelivery } from './contracts.js';
import type { Connection } from './connection.js';
import { fields, integer, failure } from './validation.js';
import { protocolText } from './settings.js';
import { guardMessages } from './native.js';

export function consumption(input: AmqpConsumeSettings, owner: Connection) {
  const value = fields(input, [
      'connection',
      'queue',
      'prefetch',
      'maxMessageBytes',
      'failurePolicy',
    ]),
    queue = protocolText(value.queue, 128);
  if (
    !owner.config.topology.queues.some((entry) => entry.name === queue) ||
    (value.failurePolicy !== undefined &&
      !['reject', 'requeue'].includes(value.failurePolicy as string))
  )
    throw failure('EK_AMQP_CONSUME');
  const prefetch = integer(value.prefetch, 1024),
    maxMessageBytes = integer(value.maxMessageBytes, owner.config.maxMessageBytes);
  if (prefetch * maxMessageBytes > 64 * 1024 * 1024) throw failure('EK_AMQP_CONSUME');
  return Object.freeze({
    queue,
    prefetch,
    maxMessageBytes,
    failurePolicy: value.failurePolicy === 'requeue' ? 'requeue' : 'reject',
  });
}
export type Consumption = ReturnType<typeof consumption>;
type Outcome = 'delivered' | 'acked' | 'nacked' | 'redelivered' | 'handler-error' | 'ack-uncertain';
/** One subscription owns one channel generation; acknowledgments cannot migrate across reconnects. */
export class Subscription {
  channel: Channel | undefined;
  tag: string | undefined;
  closed = false;
  readonly running = new Set<Promise<void>>();
  readonly unacknowledged = new Set<() => void>();
  readonly opening = new Set<Promise<void>>();
  readonly restore = async () => {
    await Promise.allSettled([...this.running]);
    if (!this.closed) await this.open();
  };
  constructor(
    readonly owner: Connection,
    readonly config: Consumption,
    readonly handler: (message: AmqpDelivery) => Promise<void>,
    readonly observe: (outcome: Outcome, bytes: number) => void = () => undefined,
  ) {}
  async open(): Promise<void> {
    const work = this.#open();
    this.opening.add(work);
    try {
      await work;
    } finally {
      this.opening.delete(work);
    }
  }
  async #open(): Promise<void> {
    const model = this.owner.model;
    if (this.closed || !model || model.connection.stream.destroyed || this.owner.stopped)
      throw failure('EK_RESOURCE_CLOSED');
    const channel = await model.createChannel();
    channel.on('error', () => undefined);
    channel.on('handler-error', () => undefined);
    const guard = guardMessages(channel, this.config.maxMessageBytes, () => this.owner.halt());
    const waiting: (() => void)[] = [];
    channel.once('close', () => {
      waiting.length = 0;
      if (this.channel === channel) {
        this.channel = undefined;
        this.tag = undefined;
        if (!this.closed && !this.owner.stopped) this.owner.reset();
      }
      for (const invalidate of [...this.unacknowledged]) invalidate();
    });
    channel.on('cancel', () => {
      if (!this.closed && this.channel === channel) this.owner.reset();
    });
    try {
      await channel.prefetch(this.config.prefetch, false);
      if (this.closed || this.owner.stopped || this.owner.model !== model)
        throw failure('EK_RESOURCE_CLOSED');
      this.channel = channel;
      const reply = await channel.consume(
        this.config.queue,
        (message) => {
          if (!message) {
            if (!this.closed) this.owner.reset();
            return;
          }
          if (this.closed || this.channel !== channel) return;
          const deliver = () => {
            try {
              const body = new Uint8Array(message.content);
              if (body.length > this.config.maxMessageBytes) throw failure('EK_AMQP_CONSUME');
              const headers = guard.headers(message.properties),
                exchange = protocolText(message.fields.exchange, 255, true),
                routingKey = protocolText(message.fields.routingKey, 255, true),
                messageId =
                  message.properties.messageId === undefined
                    ? undefined
                    : protocolText(message.properties.messageId, 255);
              let state: 'pending' | 'submitted' | 'invalid' = 'pending';
              const invalidate = () => {
                state = 'invalid';
                this.unacknowledged.delete(invalidate);
              };
              this.unacknowledged.add(invalidate);
              const submit = (kind: 'ack' | 'nack', requeue = false) => {
                if (state !== 'pending' || this.channel !== channel || this.owner.stopped)
                  throw failure('EK_AMQP_ACK_STATE');
                state = 'submitted';
                this.unacknowledged.delete(invalidate);
                try {
                  if (kind === 'ack') channel.ack(message);
                  else channel.nack(message, false, requeue);
                  this.observe(kind === 'ack' ? 'acked' : 'nacked', body.length);
                } catch {
                  state = 'invalid';
                  this.observe('ack-uncertain', body.length);
                  throw failure('EK_AMQP_ACK_STATE', true);
                }
              };
              const delivery = Object.freeze<AmqpDelivery>(
                Object.assign(Object.create(null), {
                  exchange,
                  routingKey,
                  ...(messageId === undefined ? {} : { messageId }),
                  body,
                  headers,
                  redelivered: message.fields.redelivered === true,
                  async ack() {
                    submit('ack');
                  },
                  async nack(options: Readonly<{ requeue: boolean }>) {
                    const value = fields(options, ['requeue']);
                    if (typeof value.requeue !== 'boolean') throw failure('EK_AMQP_ACK_STATE');
                    submit('nack', value.requeue);
                  },
                }),
              );
              this.observe('delivered', body.length);
              if (delivery.redelivered) this.observe('redelivered', body.length);
              const running = Promise.resolve()
                .then(() => this.handler(delivery))
                .catch(() => {
                  this.observe('handler-error', body.length);
                  if (state === 'pending') {
                    try {
                      submit('nack', this.config.failurePolicy === 'requeue');
                    } catch {
                      /* A closed channel leaves acknowledgment uncertain. */
                    }
                  }
                })
                .finally(() => {
                  this.running.delete(running);
                  if (!this.closed && !this.owner.stopped && this.channel === channel)
                    waiting.shift()?.();
                });
              this.running.add(running);
            } catch {
              this.owner.halt();
            }
          };
          // Early acknowledgments do not release a still-running application's handler slot.
          // Waiting deliveries remain unacknowledged and are bounded by native prefetch.
          if (this.running.size >= this.config.prefetch) {
            if (waiting.length >= this.config.prefetch) this.owner.halt();
            else waiting.push(deliver);
          } else deliver();
        },
        { noAck: false, exclusive: false },
      );
      this.tag = reply.consumerTag;
      if (this.closed || this.channel !== channel) {
        await channel.cancel(reply.consumerTag);
        throw failure('EK_RESOURCE_CLOSED');
      }
    } catch {
      await channel.close().catch(() => undefined);
      throw failure('EK_AMQP_CONSUME');
    }
  }
  async cancel(): Promise<void> {
    this.closed = true;
    this.owner.restored.delete(this.restore);
    const channel = this.channel,
      tag = this.tag;
    if (channel && tag) await channel.cancel(tag).catch(() => undefined);
  }
  async drain(): Promise<void> {
    await Promise.allSettled([...this.opening]);
    await Promise.allSettled([...this.running]);
    const channel = this.channel;
    this.channel = undefined;
    this.tag = undefined;
    for (const invalidate of [...this.unacknowledged]) invalidate();
    await channel?.close().catch(() => undefined);
  }
}
