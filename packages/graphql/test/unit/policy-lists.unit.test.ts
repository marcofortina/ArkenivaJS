// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { graphqlPlugin } from '../../dist/index.js';
import type { GraphqlPluginSettings } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';

function settings(
  boundary: 'scopes' | 'publicRoots' | 'origins',
  input: unknown,
): GraphqlPluginSettings {
  const values = input as readonly string[];
  return {
    schema: 'type Query { ping: String! } type Subscription { notice: String! }',
    resolvers: { Query: { ping: () => 'pong' } },
    security: {
      authorizeField: () => false,
      auth:
        boundary === 'publicRoots'
          ? { required: false, publicRootFields: values, reason: 'Public health check' }
          : { required: true, ...(boundary === 'scopes' ? { scopes: values } : {}) },
    },
    ...(boundary === 'origins'
      ? {
          subscriptions: {
            enabled: true,
            pubsub: {
              subscribe() {
                throw new Error('Invalid configuration must not acquire sources');
              },
              async publish() {},
              async close() {},
            },
            maxConnections: 1,
            maxOperationsPerConnection: 1,
            maxQueuedEventsPerConnection: 1,
            revalidateIntervalMs: 1000,
            allowedOrigins: values,
          },
        }
      : {}),
  };
}

for (const boundary of ['scopes', 'publicRoots', 'origins'] as const)
  test(`Public GraphQL ${boundary} rejects malformed and revoked lists without executing application hooks`, () => {
    let calls = 0;
    const trap = () => {
      calls++;
      throw new Error('Private configuration accessor');
    };
    const valid =
      boundary === 'scopes'
        ? 'graphql:read'
        : boundary === 'publicRoots'
          ? 'Query.ping'
          : 'https://portal.example.test';
    const revoked = Proxy.revocable([valid], {});
    revoked.revoke();
    const accessor = Object.defineProperty([valid], '0', { get: trap });
    const inherited = new Array<string>(1);
    Object.setPrototypeOf(inherited, Object.create(Array.prototype, { '0': { get: trap } }));
    const candidates: unknown[] = [
      null,
      false,
      valid,
      { length: 1, 0: valid },
      new Array<string>(1),
      inherited,
      accessor,
      [valid, valid],
      [1],
      [''],
      ['\0'],
      Object.assign([valid], { extra: true }),
      Object.assign([valid], { [Symbol('extra')]: true }),
      new Proxy([valid], { get: trap, getPrototypeOf: trap, ownKeys: trap }),
      revoked.proxy,
    ];
    for (const candidate of candidates)
      assert.throws(
        () => graphqlPlugin(settings(boundary, candidate)),
        (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_CONFIG',
      );
    assert.equal(calls, 0);
    const values = [valid];
    assert.equal(graphqlPlugin(settings(boundary, values)).id, 'graphql');
    const captured = capture(settings(boundary, values));
    values[0] = 'changed';
    const actual =
      boundary === 'origins'
        ? captured.subscriptions!.allowedOrigins
        : captured.security.auth.required
          ? captured.security.auth.scopes
          : captured.security.auth.publicRootFields;
    assert.deepEqual(actual, [valid]);
    assert.ok(Object.isFrozen(actual));
  });
