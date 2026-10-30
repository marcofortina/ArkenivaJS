// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { MfaAssurance } from '@arkenivajs/core';
import { fixture, send, tlsFiles } from '../fixture.js';

for (const required of ['mfa', 'phishing-resistant'] as const)
  test(
    `GraphQL IDE HTML and assets require current trusted ${required} assurance in addition to administrator scope`,
    { timeout: 20000 },
    async () => {
      let strength: MfaAssurance = 'single-factor',
        unavailable = false,
        downgrade = false,
        checks = 0,
        resolverCalls = 0,
        fieldChecks = 0;
      const tls = await tlsFiles();
      const f = await fixture(
        {
          schema: 'type Query { ping: String! }',
          resolvers: {
            Query: {
              ping: () => {
                resolverCalls++;
                return 'pong';
              },
            },
          },
          security: {
            auth: { required: true, assurance: required },
            developerIDE: true,
            introspection: 'authenticated',
            introspectionScope: 'graphql:admin',
            authorizeField: () => {
              fieldChecks++;
              return true;
            },
          },
        },
        {
          tls: tls.tls,
          assuranceResolver(identity) {
            if (identity.claims.tenant_id === 'tenant-b') return 'phishing-resistant';
            checks++;
            if (unavailable) throw new Error('Private IDE assurance authority failure');
            return downgrade && checks > 1 ? 'single-factor' : strength;
          },
        },
      ).catch(async (error: unknown) => {
        await tls.close();
        throw error;
      });
      try {
        const administrator = await f.token('tenant-a', 'graphql:admin');
        const otherAdministrator = await f.token('tenant-b', 'graphql:admin');
        const paths = ['/graphql/ide', '/graphql/ide/assets/app.css'];
        const visit = async (authorization: string, expected: number) => {
          for (const path of paths) {
            checks = 0;
            const response = await send(f.origin, undefined, {
              method: 'GET',
              path,
              ca: tls.ca,
              headers: {
                authorization,
                'x-tenant-id': 'tenant-b',
                'x-assurance': required,
                baggage: 'assurance=' + required,
              },
            });
            assert.equal(response.status, expected, response.body.slice(0, 512));
            if (expected === 200) {
              assert.ok(response.body.length > 0);
              if (path === paths[0]) assert.match(response.body, /ArkenivaJS GraphQL IDE/);
            } else {
              assert.doesNotMatch(response.body, /ArkenivaJS GraphQL IDE/);
              assert.match(response.body, /EK_GQL_AUTH/);
            }
            assert.ok(!response.body.includes(authorization));
            assert.doesNotMatch(
              response.body + f.logs(),
              /Private IDE assurance authority failure|Bearer /,
            );
          }
        };
        await visit(administrator, 401);
        if (required === 'phishing-resistant') {
          strength = 'mfa';
          await visit(administrator, 401);
        }
        strength = required;
        await visit(administrator, 200);
        assert.equal(checks, 2);
        await visit(await f.token('tenant-a', 'graphql:read'), 401);
        downgrade = true;
        await visit(administrator, 401);
        assert.equal(checks, 2);
        downgrade = false;
        unavailable = true;
        await visit(administrator, 401);
        await visit(otherAdministrator, 200);
        unavailable = false;
        await visit(administrator, 200);
        assert.equal(resolverCalls, 0);
        assert.equal(fieldChecks, 0);
        assert.equal(f.service.stats().operations, 0);
        assert.equal(f.service.stats().activeOperations, 0);
      } finally {
        await f.close();
        await tls.close();
      }
    },
  );
