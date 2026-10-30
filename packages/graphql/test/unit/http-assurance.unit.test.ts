// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { MfaAssurance } from '@arkenivajs/core';
import { fixture, send, tlsFiles } from '../fixture.js';

for (const required of ['mfa', 'phishing-resistant'] as const)
  test(`Direct HTTPS GraphQL requires current trusted ${required} assurance before mutation or field effects`, async () => {
    let strength: MfaAssurance = 'single-factor',
      unavailable = false,
      degradeDuringAuthorization = false,
      checks = 0;
    let authorizations = 0,
      reads = 0;
    const effects = new Map<string, number>();
    const tls = await tlsFiles();
    const f = await fixture(
      {
        schema: 'type Query { ping: String! } type Mutation { update: Int! }',
        resolvers: {
          Query: {
            ping: () => {
              reads++;
              return 'pong';
            },
          },
          Mutation: {
            update: (_parent, _args, context) => {
              const tenant = context.auth!.tenantId;
              assert.equal(
                context.identity!.assurance,
                tenant === 'tenant-b' ? 'phishing-resistant' : required,
              );
              assert.ok(Object.isFrozen(context));
              effects.set(tenant, (effects.get(tenant) ?? 0) + 1);
              return effects.get(tenant);
            },
          },
        },
        security: {
          auth: { required: true, scopes: ['graphql:read'], assurance: required },
          authorizeField: () => {
            authorizations++;
            return true;
          },
        },
      },
      {
        tls: tls.tls,
        assuranceResolver(identity) {
          if (identity.claims.tenant_id === 'tenant-b') return 'phishing-resistant';
          checks++;
          if (unavailable) throw new Error('Private HTTP assurance authority failure');
          // The second real authority evaluation occurs at authorization after signature verification.
          return degradeDuringAuthorization && checks > 1 ? 'single-factor' : strength;
        },
      },
    ).catch(async (error: unknown) => {
      await tls.close();
      throw error;
    });
    try {
      const authorization = await f.token();
      const headers = {
        authorization,
        'x-tenant-id': 'tenant-b',
        'x-assurance': required,
        'x-mfa': 'true',
        baggage: 'assurance=' + required,
      };
      const mutation = {
        query: 'mutation Update { update }',
        operationName: 'Update',
        variables: { assurance: required, identity: { assurance: required, tenantId: 'tenant-b' } },
      };
      const refused = async (query = mutation) => {
        checks = 0;
        const previousAuthorizations = authorizations,
          previousEffects = effects.get('tenant-a') ?? 0;
        const result = await send(f.origin, query, { headers, ca: tls.ca });
        assert.equal(result.status, 401, result.body);
        assert.match(result.body, /EK_GQL_AUTH/);
        assert.equal(authorizations, previousAuthorizations);
        assert.equal(effects.get('tenant-a') ?? 0, previousEffects);
        for (let turn = 0; turn < 100 && f.service.stats().activeOperations; turn++)
          await setImmediate();
        assert.equal(f.service.stats().activeOperations, 0);
        assert.doesNotMatch(
          result.body + f.logs(),
          /Private HTTP assurance authority failure|Bearer /,
        );
      };
      await refused();
      assert.equal(reads, 0);
      if (required === 'phishing-resistant') {
        strength = 'mfa';
        await refused();
      }
      strength = required;
      checks = 0;
      const first = await send(f.origin, mutation, { headers, ca: tls.ca });
      assert.equal(first.status, 200, first.body);
      assert.deepEqual(first.json(), { data: { update: 1 } });
      assert.equal(checks, 2);
      degradeDuringAuthorization = true;
      await refused();
      assert.equal(checks, 2);
      degradeDuringAuthorization = false;
      strength = 'single-factor';
      await refused();
      unavailable = true;
      await refused({ ...mutation, query: 'query Update { ping }' });
      assert.equal(reads, 0);
      const other = await send(f.origin, mutation, {
        headers: {
          ...headers,
          authorization: await f.token('tenant-b'),
          'x-tenant-id': 'tenant-a',
        },
        ca: tls.ca,
      });
      assert.equal(other.status, 200, other.body);
      assert.deepEqual(other.json(), { data: { update: 1 } });
      assert.equal(effects.get('tenant-b'), 1);
      assert.equal(effects.get('tenant-a'), 1);
      unavailable = false;
      strength = required;
      checks = 0;
      const recovered = await send(f.origin, mutation, { headers, ca: tls.ca });
      assert.equal(recovered.status, 200, recovered.body);
      assert.deepEqual(recovered.json(), { data: { update: 2 } });
      assert.equal(checks, 2);
      assert.equal(f.service.stats().activeOperations, 0);
    } finally {
      await f.close();
      await tls.close();
    }
  });

test('GraphQL assurance requirements reject a missing trusted policy during startup', async () => {
  for (const assurance of ['mfa', 'phishing-resistant'] as const)
    await assert.rejects(
      fixture({
        schema: 'type Query { ping: String! }',
        resolvers: { Query: { ping: () => 'pong' } },
        security: { auth: { required: true, assurance }, authorizeField: () => true },
      }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_GQL_CONFIG',
    );
});
