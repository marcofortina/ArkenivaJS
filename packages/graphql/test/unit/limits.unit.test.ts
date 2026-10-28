// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import { base, fixture, send } from '../fixture.js';
import type { GraphqlExecutionLimits } from '../../dist/index.js';

test('GraphQL rejects document, variables, fragment, alias and list estimates before dispatch', async () => {
  const cases: {
    limits: Partial<GraphqlExecutionLimits>;
    query: string;
    variables?: object;
    code: string;
  }[] = [
    {
      limits: { maxDocumentBytes: 10 },
      query: 'query Public { ping }',
      code: 'EK_GQL_INPUT_LIMIT',
    },
    {
      limits: { maxVariablesBytes: 5 },
      query: '{ ping }',
      variables: { unexpected: 'oversized' },
      code: 'EK_GQL_INPUT_LIMIT',
    },
    {
      limits: { maxAliases: 1 },
      query: '{ a: ping ...Repeated } fragment Repeated on Query { b: ping }',
      code: 'EK_GQL_COMPLEXITY',
    },
    { limits: { maxDepth: 1 }, query: '{ items { label } }', code: 'EK_GQL_COMPLEXITY' },
    { limits: { maxComplexity: 2 }, query: '{ items { label } }', code: 'EK_GQL_COMPLEXITY' },
    {
      limits: { maxCollectionItems: 2 },
      query: 'query Items($count: Int!) { items(first: $count) { label } }',
      variables: { count: 3 },
      code: 'EK_GQL_COMPLEXITY',
    },
    {
      limits: {},
      query: 'query Items($count: Int!) { items(first: $count) { label } }',
      variables: { count: 'wrong' },
      code: 'EK_GQL_VALIDATION',
    },
    {
      limits: {},
      query: '{ ...Cycle } fragment Cycle on Query { ...Cycle }',
      code: 'EK_GQL_VALIDATION',
    },
  ];
  for (const candidate of cases) {
    let dispatches = 0;
    const f = await fixture({
      schema:
        'type Item { label: String! } type Query { ping: String! items(first: Int): [Item!]! }',
      resolvers: {
        Query: {
          ping: () => {
            dispatches++;
            return 'pong';
          },
          items: () => {
            dispatches++;
            return [];
          },
        },
      },
      security: { authorizeField: () => true, limits: candidate.limits },
    });
    try {
      const response = await send(
        f.origin,
        {
          query: candidate.query,
          ...(candidate.variables ? { variables: candidate.variables } : {}),
        },
        { headers: { authorization: await f.token() } },
      );
      assert.ok(response.status >= 400, response.body);
      assert.match(response.body, new RegExp(candidate.code));
      assert.equal(dispatches, 0);
    } finally {
      await f.close();
    }
  }
});

test('GraphQL standard variable defaults and directives participate in bounded preflight', async () => {
  let dispatches = 0;
  const f = await fixture({
    schema: 'type Item { label: String! } type Query { ping: String! items(first: Int): [Item!]! }',
    resolvers: {
      Query: {
        ping: () => 'pong',
        items: () => {
          dispatches++;
          return [];
        },
      },
    },
    security: { authorizeField: () => true, limits: { maxCollectionItems: 2 } },
  });
  try {
    const headers = { authorization: await f.token() };
    const invalid = await send(
      f.origin,
      { query: 'query Items($count: Int = 3) { items(first: $count) { label } }' },
      { headers },
    );
    assert.match(invalid.body, /EK_GQL_COMPLEXITY/);
    assert.equal(dispatches, 0);
    const skipped = await send(
      f.origin,
      {
        query:
          'query Items($skip: Boolean = true) { ping items(first: 100) @skip(if: $skip) { label } }',
      },
      { headers },
    );
    assert.deepEqual(skipped.json(), { data: { ping: 'pong' } });
    assert.equal(dispatches, 0);
  } finally {
    await f.close();
  }
});

test('GraphQL does not silently truncate runtime lists or oversized serialized results', async () => {
  const f = await fixture({
    schema: 'type Query { values: [Int!] payload: String }',
    resolvers: { Query: { values: () => [1, 2, 3], payload: () => 'x'.repeat(5000) } },
    security: {
      authorizeField: () => true,
      limits: { maxCollectionItems: 2, maxResultBytes: 256 },
    },
  });
  try {
    const headers = { authorization: await f.token() };
    const list = await send(f.origin, { query: '{ values }' }, { headers });
    assert.equal(list.status, 200, list.body);
    assert.deepEqual((list.json() as { data: unknown }).data, { values: null });
    assert.match(list.body, /EK_GQL_COMPLEXITY/);
    const result = await send(f.origin, { query: '{ payload }' }, { headers });
    assert.equal(result.status, 500, result.body);
    assert.match(result.body, /EK_GQL_RESPONSE_LIMIT/);
    assert.doesNotMatch(result.body, /xxxxx/);
  } finally {
    await f.close();
  }
});

test('GraphQL every default property and repeated list element consumes the runtime field budget', async () => {
  let reads = 0;
  const f = await fixture({
    schema: 'type Item { label: String } type Query { items: [Item!]! }',
    resolvers: {
      Query: {
        items: () => [
          {
            get label() {
              reads++;
              return 'one';
            },
          },
          {
            get label() {
              reads++;
              return 'two';
            },
          },
        ],
      },
    },
    security: { authorizeField: () => true, limits: { maxFieldExecutions: 2 } },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ items { label } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(result.status, 200, result.body);
    assert.equal(reads, 1);
    assert.match(result.body, /EK_GQL_COMPLEXITY/);
  } finally {
    await f.close();
  }
});

test('GraphQL an error envelope exceeding the response cap becomes an empty transport failure', async () => {
  const f = await fixture({
    ...base(),
    security: { authorizeField: () => true, limits: { maxResultBytes: 1 } },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ ping }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(result.status, 500);
    assert.equal(result.body, '');
  } finally {
    await f.close();
  }
});

test('GraphQL authorization errors and truthy nonboolean decisions fail closed without exposing causes', async () => {
  for (const decision of [
    () => {
      throw new Error('private-provider-password');
    },
    () => 'allow',
    () => 1,
  ]) {
    let calls = 0;
    const f = await fixture({
      ...base(),
      resolvers: {
        Query: {
          ping: () => {
            calls++;
            return 'pong';
          },
        },
      },
      security: { authorizeField: decision as unknown as () => boolean },
    });
    try {
      const result = await send(
        f.origin,
        { query: '{ ping }' },
        { headers: { authorization: await f.token() } },
      );
      assert.equal(result.status, 200, result.body);
      assert.match(result.body, /EK_GQL_FORBIDDEN/);
      assert.equal(calls, 0);
      assert.doesNotMatch(result.body + f.logs(), /private-provider-password/);
    } finally {
      await f.close();
    }
  }
});

test('GraphQL timed-out mutation retains physical ownership until the admitted effect really settles', async () => {
  let release!: () => void,
    enter!: () => void,
    effects = 0;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  const f = await fixture({
    schema: 'type Query { ping: String! } type Mutation { update: Boolean! }',
    resolvers: {
      Query: { ping: () => 'pong' },
      Mutation: {
        update: async () => {
          enter();
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          effects++;
          return true;
        },
      },
    },
    security: { authorizeField: () => true, limits: { maxOperationMs: 1000 } },
  });
  try {
    const pending = send(
      f.origin,
      { query: 'mutation { update }' },
      { headers: { authorization: await f.token() } },
    );
    await entered;
    const result = await pending;
    assert.equal(result.status, 504, result.body);
    assert.match(result.body, /EK_GQL_TIMEOUT/);
    assert.equal(effects, 0);
    assert.equal(f.service.stats().activeOperations, 1);
    release();
    for (let i = 0; i < 100 && f.service.stats().activeOperations; i++) await immediate();
    assert.equal(effects, 1);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(result.body, /rollback|rolled.back|retry/);
  } finally {
    release?.();
    await f.close();
  }
});

test('GraphQL only declared public roots are usable anonymously and forged bearer assertions never become public', async () => {
  let effects = 0;
  const f = await fixture({
    schema: 'type Query { ping: String! privateValue: String! } type Mutation { update: Boolean! }',
    resolvers: {
      Query: {
        ping: () => 'pong',
        privateValue: () => {
          effects++;
          return 'private';
        },
      },
      Mutation: {
        update: () => {
          effects++;
          return true;
        },
      },
    },
    security: {
      authorizeField: () => true,
      auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public ping' },
    },
  });
  try {
    for (const query of [
      '{ privateValue }',
      'mutation { update }',
      '{ ping privateValue }',
      '{ ...Private } fragment Private on Query { privateValue }',
    ]) {
      const result = await send(f.origin, { query });
      assert.equal(result.status, 401, result.body);
    }
    assert.equal(effects, 0);
    const forged = await send(
      f.origin,
      { query: '{ ping }' },
      { headers: { authorization: 'Bearer forged' } },
    );
    assert.equal(forged.status, 401);
    const allowed = await send(
      f.origin,
      { query: '{ privateValue }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(allowed.status, 200, allowed.body);
    assert.equal(effects, 1);
  } finally {
    await f.close();
  }
});
