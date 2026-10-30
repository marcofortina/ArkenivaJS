// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncResource } from 'node:async_hooks';
import type {
  MessageBus,
  OperationOptions,
  Subscription,
  VerifiedTenantContext,
} from '@arkenivajs/core';
import type { RealtimeMessage } from './contracts.js';
import type { Connection } from './runtime.js';
import { tenantKey } from './identity.js';
import { bytes, cursor, failure, fields, name, text } from './validation.js';
import type { RedisProvider } from '@arkenivajs/core';
import type { RedisPubsubProvider } from '@arkenivajs/database-redis/pubsub';

export interface BroadcastBackend {
  subscribe(
    topic: string,
    handler: (input: unknown) => Promise<void>,
    options: OperationOptions,
    failed: () => void,
  ): Promise<Subscription>;
  publish(
    topic: string,
    input: Readonly<{ channel: string; payload: string }>,
    options: OperationOptions,
  ): Promise<void>;
}
export function redisBackend(
  commands: RedisProvider,
  subscriptions: RedisPubsubProvider,
): BroadcastBackend {
  return {
    subscribe: (topic, handler, options, failed) =>
      subscriptions.subscribe(topic, async (message) => handler(JSON.parse(message) as unknown), {
        ...options,
        onFailure: failed,
      }),
    async publish(topic, input, options) {
      await commands.publish(topic, JSON.stringify(input), options);
    },
  };
}
export function natsBackend(bus: MessageBus): BroadcastBackend {
  return {
    subscribe: (topic, handler, options) =>
      bus.subscribe(topic, async (envelope) => handler(envelope.payload), options),
    async publish(topic, input, options) {
      // Core NATS flush confirms transport submission, not persistence or consumer delivery.
      await bus.publish(topic, input, options);
    },
  };
}
type Member = { connection: Connection; deliver?: (message: RealtimeMessage) => Promise<void> };
type Bucket = {
  readonly controller: AbortController;
  readonly members: Map<Connection, Member>;
  readonly ready: Promise<Subscription>;
};
/** One exact broker subject per verified issuer/tenant; payloads never select an identity. */
export class Broadcast {
  private readonly buckets = new Map<string, Bucket>();
  private readonly scope = new AsyncResource('RealtimeBroadcast');
  private readonly retiring = new Set<Promise<void>>();
  private cleanupFailed = false;
  private closed = false;
  constructor(
    private readonly backend: BroadcastBackend,
    private readonly maximum: number,
    private readonly timeoutMs: number,
    private readonly track: <T>(task: Promise<T>) => Promise<T>,
  ) {}
  private topic(tenant: VerifiedTenantContext): string {
    return 'realtime.v1.' + tenantKey(tenant);
  }
  private retire(bucket: Bucket): Promise<void> {
    bucket.controller.abort();
    const task = this.track(
      bucket.ready.then(
        (subscription) => subscription.close(),
        () => undefined,
      ),
    );
    this.retiring.add(task);
    void task.then(
      () => this.retiring.delete(task),
      () => {
        this.retiring.delete(task);
        this.cleanupFailed = true;
      },
    );
    return task;
  }
  async join(connection: Connection): Promise<void> {
    if (this.closed) throw failure('EK_REALTIME_CLOSED');
    if (this.cleanupFailed) throw failure('EK_BACKEND_UNAVAILABLE');
    const topic = this.topic(connection.tenant);
    let bucket = this.buckets.get(topic);
    if (!bucket) {
      if (this.buckets.size >= 32) throw failure('EK_REALTIME_BACKPRESSURE');
      const controller = new AbortController(),
        members = new Map<Connection, Member>();
      const ready = this.track(
        Promise.resolve().then(() =>
          this.backend.subscribe(
            topic,
            async (input) => {
              try {
                const value = fields(input, ['channel', 'payload', 'id']);
                const channel = name(value.channel),
                  encoded = text(value.payload, this.maximum * 2);
                if (!/^[A-Za-z0-9_-]*$/.test(encoded)) throw failure();
                const payload = Buffer.from(encoded, 'base64url');
                if (payload.toString('base64url') !== encoded) throw failure();
                const message: RealtimeMessage = Object.freeze({
                  channel,
                  payload: bytes(payload, this.maximum),
                  ...(value.id === undefined ? {} : { id: cursor(value.id) }),
                });
                await Promise.allSettled(
                  [...members.values()].map(async (member) => {
                    if (!member.deliver || member.connection.signal.aborted) return;
                    try {
                      await member.deliver(message);
                    } catch {
                      member.connection.close();
                    }
                  }),
                );
              } catch {
                // An invalid broker frame terminates the affected streams without logging its contents.
                for (const member of members.values()) member.connection.close();
              }
            },
            { signal: controller.signal, timeoutMs: this.timeoutMs },
            () => {
              for (const member of members.values()) member.connection.close();
            },
          ),
        ),
      );
      bucket = { controller, members, ready };
      this.buckets.set(topic, bucket);
    }
    const selected = bucket;
    selected.members.set(connection, { connection });
    const leave = () => {
      selected.members.delete(connection);
      if (selected.members.size || this.buckets.get(topic) !== selected) return;
      this.buckets.delete(topic);
      // Subscription close must run outside the native subscription handler's async context.
      this.scope.runInAsyncScope(() => {
        void this.retire(selected).catch(() => undefined);
      });
    };
    connection.signal.addEventListener('abort', leave, { once: true });
    if (connection.signal.aborted) leave();
    try {
      await connection.run(async () => {
        await selected.ready;
      });
    } catch {
      connection.close();
      throw failure('EK_BACKEND_UNAVAILABLE');
    }
  }
  bind(connection: Connection, deliver: (message: RealtimeMessage) => Promise<void>): void {
    if (this.cleanupFailed) throw failure('EK_BACKEND_UNAVAILABLE');
    const member = this.buckets.get(this.topic(connection.tenant))?.members.get(connection);
    if (!member || this.closed) throw failure('EK_REALTIME_CLOSED');
    member.deliver = deliver;
  }
  async publish(
    channel: string,
    payload: Uint8Array,
    tenant: VerifiedTenantContext,
    options: OperationOptions,
  ): Promise<void> {
    if (this.closed) throw failure('EK_REALTIME_CLOSED');
    if (this.cleanupFailed) throw failure('EK_BACKEND_UNAVAILABLE');
    await this.backend.publish(
      this.topic(tenant),
      Object.freeze({ channel, payload: Buffer.from(payload).toString('base64url') }),
      options,
    );
  }
  async close(): Promise<void> {
    this.closed = true;
    const buckets = [...this.buckets.values()];
    this.buckets.clear();
    for (const bucket of buckets) void this.retire(bucket).catch(() => undefined);
    try {
      await Promise.allSettled([...this.retiring]);
      if (this.cleanupFailed) throw failure('EK_BACKEND_UNAVAILABLE');
    } finally {
      this.scope.emitDestroy();
    }
  }
}
