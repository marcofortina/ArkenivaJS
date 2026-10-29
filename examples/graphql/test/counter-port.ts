// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { types } from 'node:util';
import type { AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import type { GraphqlSubscriptionPubSub } from '@arkenivajs/graphql';

/** Bounded process-local test delivery; never classify this fixture for production. */
export function counterPort(authority: () => AuthService) {
  const sources = new Set<{
    tenant: string;
    deliver(value: number): void;
    close(): void;
  }>();
  let closed = false;
  function tenantKey(topic: string, tenant: VerifiedTenantContext) {
    assert.equal(closed, false);
    assert.equal(topic, 'counter');
    assert.ok(tenant && !types.isProxy(tenant));
    const identity = Object.getOwnPropertyDescriptor(tenant, 'identity');
    assert.ok(identity && 'value' in identity);
    assert.equal(authority().tenantFrom(identity.value), tenant);
    return JSON.stringify([tenant.identity.issuer, tenant.tenantId]);
  }
  const port: GraphqlSubscriptionPubSub = {
    distribution: 'process',
    securityLevel: 'test-only',
    subscribe(topic, tenant, options = {}) {
      const key = tenantKey(topic, tenant),
        queue: number[] = [];
      let stopped = false;
      let waiting: ((result: IteratorResult<number>) => void) | undefined;
      const source = {
        tenant: key,
        deliver(value: number) {
          if (stopped) return;
          if (waiting) {
            const next = waiting;
            waiting = undefined;
            next({ done: false, value });
          } else {
            assert.ok(queue.length < 4, 'The counter fixture queue is full');
            queue.push(value);
          }
        },
        close() {
          if (stopped) return;
          stopped = true;
          options.signal?.removeEventListener('abort', source.close);
          sources.delete(source);
          queue.length = 0;
          waiting?.({ done: true, value: undefined });
          waiting = undefined;
        },
      };
      sources.add(source);
      options.signal?.addEventListener('abort', source.close, { once: true });
      if (options.signal?.aborted) source.close();
      const iterator: AsyncIterableIterator<number> = {
        [Symbol.asyncIterator]() {
          return this;
        },
        async next(): Promise<IteratorResult<number>> {
          if (stopped) return { done: true, value: undefined };
          if (queue.length) return { done: false, value: queue.shift()! };
          assert.equal(waiting, undefined);
          return new Promise((resolve) => {
            waiting = resolve;
          });
        },
        async return() {
          source.close();
          return { done: true as const, value: undefined };
        },
      };
      return iterator;
    },
    async publish(topic, payload, tenant) {
      const key = tenantKey(topic, tenant);
      assert.ok(Number.isSafeInteger(payload));
      for (const source of sources) if (source.tenant === key) source.deliver(payload as number);
    },
    async close() {
      closed = true;
      for (const source of sources) source.close();
    },
  };
  return { port, active: () => sources.size };
}
