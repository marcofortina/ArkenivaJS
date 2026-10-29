// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncResource } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type {
  AuthService,
  MessageBus,
  Subscription,
  VerifiedTenantContext,
} from '@arkenivajs/core';
import type { GraphqlSubscriptionPubSub } from '../dist/index.js';

const failure = () =>
  new KitError({
    code: 'EK_GQL_SUBSCRIPTION',
    message: 'The isolated subscription provider is unavailable',
  });

/** Test application adapter over the real authenticated broker; it grants no production approval. */
export class NatsPubSubFixture {
  readonly port: GraphqlSubscriptionPubSub;
  private authority: AuthService | undefined;
  private bus: MessageBus | undefined;
  private readonly scope = new AsyncResource('GraphqlPubSubFixture');
  private readonly sources = new Set<() => Promise<void>>();
  private readonly opening = new Set<Promise<Subscription>>();
  private closed = false;
  private closing: Promise<void> | undefined;
  private failures = 0;
  private acquired = 0;
  private retired = 0;

  constructor(private readonly namespace: string) {
    if (!/^[0-9a-f]{24}$/.test(namespace)) throw failure();
    this.port = {
      subscribe: (topic, tenant, options = {}) => {
        const subject = this.subject(topic, tenant),
          bus = this.bus!;
        const controller = new AbortController();
        let stopped = false,
          failed = false,
          cleanup: Promise<void> | undefined;
        let wake:
          | { resolve(value: IteratorResult<unknown>): void; reject(error: unknown): void }
          | undefined;
        const queue: unknown[] = [];
        const signal = options.signal;
        const stop = (error = false): Promise<void> => {
          if (cleanup) return cleanup;
          stopped = true;
          failed ||= error;
          controller.abort();
          signal?.removeEventListener('abort', abort);
          if (failed) wake?.reject(failure());
          else wake?.resolve({ done: true, value: undefined });
          wake = undefined;
          queue.length = 0;
          cleanup = ready
            .then(
              (subscription) => this.scope.runInAsyncScope(() => subscription.close()),
              () => undefined,
            )
            .then(
              () => {
                this.sources.delete(close);
                this.retired++;
              },
              () => {
                this.failures++;
                this.sources.delete(close);
                throw failure();
              },
            );
          void cleanup.catch(() => undefined);
          return cleanup;
        };
        const close = () => stop();
        const abort = () => {
          void stop();
        };
        const ready = Promise.resolve().then(() =>
          bus.subscribe(
            subject,
            async (envelope) => {
              if (stopped) return;
              if (
                envelope.topic !== subject ||
                typeof envelope.payload !== 'string' ||
                Buffer.byteLength(envelope.payload) > 1024 ||
                (!wake && queue.length >= 4)
              ) {
                void stop(true);
                return;
              }
              if (wake) {
                const pending = wake;
                wake = undefined;
                pending.resolve({ done: false, value: envelope.payload });
              } else queue.push(envelope.payload);
            },
            { signal: controller.signal, timeoutMs: 2000 },
          ),
        );
        this.sources.add(close);
        this.opening.add(ready);
        this.acquired++;
        void ready.then(
          () => this.opening.delete(ready),
          () => {
            this.opening.delete(ready);
            void stop(true);
          },
        );
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) void stop();
        const source: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return this;
          },
          async next() {
            try {
              await ready;
            } catch {
              throw failure();
            }
            if (failed) throw failure();
            if (stopped) return { done: true, value: undefined };
            if (queue.length) return { done: false, value: queue.shift() };
            if (wake) throw failure();
            return new Promise((resolve, reject) => {
              wake = { resolve, reject };
            });
          },
          async return() {
            await stop();
            return { done: true, value: undefined };
          },
        };
        return source;
      },
      publish: async (topic, payload, tenant, options) => {
        const subject = this.subject(topic, tenant);
        if (typeof payload !== 'string' || Buffer.byteLength(payload) > 1024) throw failure();
        await this.bus!.publish(subject, payload, options);
      },
      close: () => this.close(),
    };
  }

  bind(authority: AuthService, bus: MessageBus) {
    if (this.authority || this.closed) throw failure();
    this.authority = authority;
    this.bus = bus;
  }
  private subject(topic: string, tenant: VerifiedTenantContext) {
    if (
      this.closed ||
      !this.authority ||
      !this.bus ||
      topic !== 'notices' ||
      !tenant ||
      types.isProxy(tenant)
    )
      throw failure();
    const identity = Object.getOwnPropertyDescriptor(tenant, 'identity');
    if (!identity || !('value' in identity)) throw failure();
    try {
      if (this.authority.tenantFrom(identity.value) !== tenant) throw failure();
    } catch {
      throw failure();
    }
    const suffix = createHash('sha256')
      .update(JSON.stringify([tenant.identity.issuer, tenant.tenantId]))
      .digest('hex');
    return 'graphql.fixture.v1.' + this.namespace + '.' + suffix;
  }
  async ready() {
    await Promise.all([...this.opening]);
  }
  stats() {
    return Object.freeze({
      active: this.sources.size,
      acquired: this.acquired,
      retired: this.retired,
      failures: this.failures,
    });
  }
  private close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    return (this.closing = (async () => {
      try {
        await Promise.all([...this.sources].map((close) => close()));
      } finally {
        this.scope.emitDestroy();
      }
      if (this.failures) throw failure();
    })());
  }
}
