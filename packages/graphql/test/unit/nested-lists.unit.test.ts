// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { fixture, send } from '../fixture.js';

test('Seeded authenticated HTTP nested lists enforce every collection bound before child getters and preserve tenant-local values', async () => {
  let shape: readonly [number, number] = [2, 2];
  let roots = 0,
    reads = 0;
  const f = await fixture({
    schema: 'type Item { label: String! } type Query { matrix(first: Int!): [[Item!]!]! }',
    resolvers: {
      Query: {
        matrix(_parent, _args, context) {
          roots++;
          return Array.from({ length: shape[0] }, () =>
            Array.from({ length: shape[1] }, () => ({
              get label() {
                reads++;
                return context.auth!.tenantId;
              },
            })),
          );
        },
      },
    },
    security: {
      authorizeField: () => true,
      limits: { maxCollectionItems: 2, maxComplexity: 8, maxFieldExecutions: 5 },
    },
  });
  try {
    const owners = await Promise.all(
      ['tenant-a', 'tenant-b'].map(async (tenant) => ({
        tenant,
        authorization: await f.token(tenant),
      })),
    );
    const check = async (outer: number, inner: number) => {
      shape = [outer, inner];
      const priorRoots = roots,
        priorReads = reads;
      const results = await Promise.all(
        owners.map(async ({ tenant, authorization }) => ({
          tenant,
          response: await send(
            f.origin,
            {
              query: 'query Grid($n: Int!) { matrix(first: $n) { label } }',
              variables: { n: 2 },
            },
            { headers: { authorization, 'x-tenant-id': 'forged-nested-tenant' } },
          ),
        })),
      );
      const permitted = outer <= 2 && (outer === 0 || inner <= 2);
      for (const { tenant, response } of results) {
        assert.equal(response.status, 200, response.body);
        if (permitted)
          assert.deepEqual(response.json(), {
            data: {
              matrix: Array.from({ length: outer }, () =>
                Array.from({ length: inner }, () => ({ label: tenant })),
              ),
            },
          });
        else {
          assert.equal(response.json().data, null);
          assert.match(response.body, /EK_GQL_COMPLEXITY/);
        }
      }
      assert.equal(roots - priorRoots, owners.length);
      assert.equal(reads - priorReads, permitted ? owners.length * outer * inner : 0);
      assert.equal(f.service.stats().activeOperations, 0);
    };
    for (const [outer, inner] of [
      [0, 3],
      [1, 0],
      [1, 1],
      [2, 2],
      [3, 1],
      [1, 3],
      [2, 3],
    ] as const)
      await check(outer, inner);
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 5 }), fc.integer({ min: 0, max: 5 }), check),
      { seed: 6238, numRuns: 32 },
    );
    await check(2, 2);
    assert.doesNotMatch(f.logs(), /forged-nested-tenant|Bearer /);
  } finally {
    await f.close();
  }
});

test('Nested-list pagination and weighted fragment budgets reject before root effects while excluded selections remain inert', async () => {
  let roots = 0,
    reads = 0;
  const f = await fixture({
    schema:
      'type Item { label: String! } type Query { ping: String! matrix(first: Int!): [[Item!]!]! }',
    resolvers: {
      Query: {
        ping: () => 'pong',
        matrix() {
          roots++;
          return [
            [
              {
                get label() {
                  reads++;
                  return 'owned-nested-value';
                },
              },
            ],
          ];
        },
      },
    },
    security: { authorizeField: () => true, limits: { maxCollectionItems: 2, maxComplexity: 8 } },
  });
  try {
    const headers = { authorization: await f.token() };
    const query =
      'query Grid($n: Int = 2, $show: Boolean = true) { ping ...Visible @include(if: $show) } fragment Visible on Query { grid: matrix(first: $n) { label } }';
    for (const variables of [{}, { n: 3 }, { n: 1000 }]) {
      const response = await send(f.origin, { query, variables }, { headers });
      assert.equal(response.status, 400, response.body);
      assert.match(response.body, /EK_GQL_COMPLEXITY/);
      assert.equal(roots, 0);
      assert.equal(reads, 0);
    }
    const skipped = await send(
      f.origin,
      { query, variables: { n: 1000, show: false } },
      { headers },
    );
    assert.deepEqual(skipped.json(), { data: { ping: 'pong' } });
    assert.equal(roots, 0);
    assert.equal(reads, 0);
    const recovered = await send(
      f.origin,
      {
        query: 'query Grid($n: Int!) { matrix(first: $n) { label } }',
        variables: { n: 2 },
      },
      { headers },
    );
    assert.deepEqual(recovered.json(), { data: { matrix: [[{ label: 'owned-nested-value' }]] } });
    assert.equal(roots, 1);
    assert.equal(reads, 1);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(f.logs(), /owned-nested-value|Bearer /);
  } finally {
    await f.close();
  }
});
