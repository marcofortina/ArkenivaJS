// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { GraphqlPluginSettings, GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { fixture, send, tlsFiles } from '../fixture.js';
import { productionAuthority } from '../production-fixture.js';

function settings(pubsub: GraphqlSubscriptionPubSub): GraphqlPluginSettings {
  return {
    schema: 'type Query { ping: String! } type Subscription { notice: String! }',
    resolvers: { Query: { ping: () => 'pong' } },
    security: { auth: { required: true }, authorizeField: ({ context }) => !!context.auth },
    subscriptions: {
      enabled: true,
      pubsub,
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 4,
      revalidateIntervalMs: 1000,
      allowedOrigins: ['https://portal.example.test'],
    },
  };
}

const provider = (): GraphqlSubscriptionPubSub => ({
  subscribe() {
    throw new Error('Startup must not acquire a subscription');
  },
  async publish() {},
  async close() {},
});

function graphqlFailure(error: unknown) {
  return (
    error instanceof KitError &&
    error.code === 'EK_PLUGIN_FAILED' &&
    error.cause instanceof KitError &&
    error.cause.code === 'EK_GQL_CONFIG'
  );
}

test(
  'Production rejects unclassified, process-only and test-only providers after real HTTPS authority initialization',
  { timeout: 15000 },
  async () => {
    const tls = await tlsFiles(),
      authority = productionAuthority();
    try {
      for (const declaration of [
        {},
        { distribution: 'process' as const, securityLevel: 'production' as const },
        { distribution: 'shared' as const },
        { distribution: 'shared' as const, securityLevel: 'test-only' as const },
      ])
        await assert.rejects(
          fixture(settings({ ...provider(), ...declaration }), {
            environment: 'production',
            tls: tls.tls,
            authority,
          }),
          graphqlFailure,
        );
    } finally {
      await tls.close();
    }
  },
);

test(
  'Explicit development process providers require HTTPS and real authenticated tenant authority',
  { timeout: 15000 },
  async () => {
    const tls = await tlsFiles(),
      config = settings({ ...provider(), distribution: 'process' });
    try {
      const f = await fixture(config, { environment: 'development', tls: tls.tls });
      try {
        const response = await send(
          f.origin,
          { query: '{ ping }' },
          {
            ca: tls.ca,
            headers: { authorization: await f.token() },
          },
        );
        assert.deepEqual(response.json(), { data: { ping: 'pong' } });
        assert.equal(f.service.health().subscriptionsReady, true);
      } finally {
        await f.close();
      }
      await assert.rejects(fixture(config, { environment: 'development' }), graphqlFailure);
      await assert.rejects(
        fixture(config, { environment: 'development', tls: tls.tls, authenticated: false }),
        graphqlFailure,
      );
      await assert.rejects(
        fixture(
          {
            ...config,
            security: {
              auth: {
                required: false,
                publicRootFields: ['Query.ping'],
                reason: 'Explicit public query',
              },
              authorizeField: () => true,
            },
          },
          { environment: 'development', tls: tls.tls },
        ),
        graphqlFailure,
      );
    } finally {
      await tls.close();
    }
  },
);
