// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execute, subscribe, parse } from 'graphql';
import type { ExecutionResult } from 'graphql';
import { capture } from '../../dist/policy.js';
import { compileSchema } from '../../dist/schema.js';
import { protectFields } from '../../dist/fields.js';
import { OwnedContexts } from '../../dist/contexts.js';
import type { Operation } from '../../dist/operation.js';
import { fixture, send } from '../fixture.js';

test('The actual native executor cannot bypass protected field or subscription ownership with a manually constructed context', async () => {
  let policies = 0,
    resolutions = 0,
    acquisitions = 0;
  const settings = capture({
    schema: 'type Query { ping: String } type Subscription { notice: String }',
    resolvers: {
      Query: {
        ping: () => {
          resolutions++;
          return 'private';
        },
      },
      Subscription: {
        notice: {
          async *subscribe() {
            acquisitions++;
            yield 'private';
          },
        },
      },
    },
    security: {
      authorizeField: () => {
        policies++;
        return true;
      },
    },
  });
  const schema = compileSchema(settings),
    scopes = new OwnedContexts<Operation>();
  protectFields(schema, settings, scopes);
  const context = { requestId: 'forged-request', auth: { tenantId: 'foreign-tenant' } };
  const query = await execute({ schema, document: parse('{ ping }'), contextValue: context });
  assert.equal(query.data?.ping, null);
  assert.equal(query.errors?.[0]?.extensions.code, 'EK_GQL_FORBIDDEN');
  const subscription = await subscribe({
    schema,
    document: parse('subscription { notice }'),
    contextValue: { ...context },
  });
  assert.equal(Symbol.asyncIterator in subscription, false);
  assert.equal((subscription as ExecutionResult).errors?.[0]?.extensions.code, 'EK_GQL_FORBIDDEN');
  assert.equal(policies, 0);
  assert.equal(resolutions, 0);
  assert.equal(acquisitions, 0);
});

test('Actual authenticated HTTP rejects noniterable list results, preserves nullable lists and recovers without leaking resolver values', async () => {
  let value: unknown = 9;
  const f = await fixture({
    schema: 'type Query { values: [Int] }',
    resolvers: { Query: { values: () => value } },
    security: { authorizeField: () => true },
  });
  try {
    const headers = { authorization: await f.token() };
    for (const invalid of [9, {}, 'private-invalid-list']) {
      value = invalid;
      const response = await send(f.origin, { query: '{ values }' }, { headers });
      const result = response.json() as {
        data: unknown;
        errors: { extensions: { code: string } }[];
      };
      assert.deepEqual(result.data, { values: null });
      assert.equal(result.errors[0]?.extensions.code, 'EK_GQL_EXECUTION');
      assert.doesNotMatch(response.body, /private-invalid-list|Symbol.iterator|not iterable/);
    }
    for (const valid of [null, [1, 2]]) {
      value = valid;
      const response = await send(f.origin, { query: '{ values }' }, { headers });
      assert.equal(response.status, 200);
      assert.deepEqual(response.json(), { data: { values: valid } });
    }
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(f.logs(), /private-invalid-list/);
  } finally {
    await f.close();
  }
});
