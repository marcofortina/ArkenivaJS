// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { GraphqlPluginSettings, GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';

function provider(): GraphqlSubscriptionPubSub {
  return {
    subscribe() {
      throw new Error('Configuration capture must not acquire subscriptions');
    },
    async publish() {},
    async close() {},
  };
}

function settings(pubsub: unknown): GraphqlPluginSettings {
  return {
    schema: 'type Query { ping: Boolean! } type Subscription { notice: String! }',
    resolvers: {},
    security: { authorizeField: () => true },
    subscriptions: {
      enabled: true,
      pubsub: pubsub as GraphqlSubscriptionPubSub,
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 4,
      revalidateIntervalMs: 1000,
      allowedOrigins: ['https://portal.example.test'],
    },
  };
}

const invalid = (pubsub: unknown) =>
  assert.throws(
    () => capture(settings(pubsub)),
    (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_CONFIG',
  );

test('Unclassified subscription providers retain test compatibility and fail-closed classification', () => {
  const captured = capture(settings(provider())).subscriptions!.pubsub;
  assert.equal(captured.distribution, undefined);
  assert.equal(captured.securityLevel, 'test-only');
  assert.ok(Object.isFrozen(captured));
});

test('Subscription classification and bound methods are captured before caller mutation', async () => {
  let closed = 0;
  const original = {
    ...provider(),
    distribution: 'shared' as const,
    securityLevel: 'production' as const,
    async close() {
      assert.equal(this, original);
      closed++;
    },
  };
  const captured = capture(settings(original)).subscriptions!.pubsub;
  Object.assign(original, {
    distribution: 'process',
    securityLevel: 'test-only',
    close() {
      throw new Error('The replacement method must not be called');
    },
  });
  assert.equal(captured.distribution, 'shared');
  assert.equal(captured.securityLevel, 'production');
  await captured.close();
  assert.equal(closed, 1);
});

test('Subscription provider capture rejects invalid or contradictory deployment declarations', () => {
  for (const distribution of [null, '', 'distributed', 1, true, {}])
    invalid({ ...provider(), distribution });
  for (const securityLevel of [null, '', 'verified', 1, true, {}])
    invalid({ ...provider(), securityLevel });
  invalid({
    ...provider(),
    distribution: 'shared',
    securityLevel: 'production',
    usage: 'test-only',
  });
  for (const distribution of ['process', 'shared'] as const)
    assert.equal(
      capture(settings({ ...provider(), distribution })).subscriptions!.pubsub.distribution,
      distribution,
    );
});

test('Provider reflection never executes accessors, proxy traps or custom function binding', async () => {
  let invoked = 0;
  const trap = () => {
    invoked++;
    throw new Error('Untrusted reflection must not execute');
  };
  for (const key of ['distribution', 'securityLevel', 'usage', 'subscribe', 'publish', 'close']) {
    const candidate = provider();
    Object.defineProperty(candidate, key, { get: trap });
    invalid(candidate);
  }
  invalid(new Proxy(provider(), { get: trap, getPrototypeOf: trap }));
  invalid(Object.create(new Proxy(provider(), { getPrototypeOf: trap })));
  invalid({ ...provider(), close: new Proxy(async () => {}, { apply: trap }) });
  const close = async () => {};
  Object.defineProperty(close, 'bind', { get: trap });
  await capture(settings({ ...provider(), close })).subscriptions!.pubsub.close();
  assert.equal(invoked, 0);
});

test('Provider prototypes are bounded while ordinary class methods remain compatible', async () => {
  class Port {
    readonly distribution = 'shared' as const;
    readonly securityLevel = 'production' as const;
    readonly delegate = provider();
    subscribe(...args: Parameters<GraphqlSubscriptionPubSub['subscribe']>) {
      return this.delegate.subscribe(...args);
    }
    async publish() {}
    async close() {}
  }
  const captured = capture(settings(new Port())).subscriptions!.pubsub;
  assert.equal(captured.distribution, 'shared');
  await captured.close();
  let deep = provider();
  for (let depth = 0; depth < 33; depth++) deep = Object.create(deep);
  invalid(deep);
});
