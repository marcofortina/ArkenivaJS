// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, send } from '../fixture.js';

test('GraphQL native loader batches retain order, nulls, field paths and bounds without reading private parent properties', async () => {
  let privateReads = 0;
  const batches: number[][] = [],
    paths: (readonly (string | number)[])[] = [];
  const parents = Array.from({ length: 5 }, (_, id) => ({
    id,
    get privateValue() {
      privateReads++;
      throw new Error('Unauthorized parent access');
    },
  }));
  const f = await fixture({
    schema: 'type Item { label: String } type Query { items(first: Int!): [Item!]! }',
    resolvers: { Query: { items: () => parents } },
    loaders: {
      Item: {
        label: {
          maxBatchSize: 2,
          load: async (requests, context) => {
            assert.equal(context.auth?.tenantId, 'tenant-a');
            assert.ok(Object.isFrozen(requests));
            batches.push(requests.map((request) => (request.parent as { id: number }).id));
            for (const request of requests) {
              assert.equal(request.info.parentType, 'Item');
              assert.equal(request.info.fieldName, 'label');
              assert.equal(request.info.operation, 'query');
              assert.ok(Object.isFrozen(request));
              paths.push([...request.info.path]);
            }
            return requests.map((request) => {
              const id = (request.parent as { id: number }).id;
              return id === 2 ? null : `item-${id}`;
            });
          },
        },
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ items(first: 5) { label } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(result.status, 200, result.body);
    assert.deepEqual(result.json(), {
      data: {
        items: [
          { label: 'item-0' },
          { label: 'item-1' },
          { label: null },
          { label: 'item-3' },
          { label: 'item-4' },
        ],
      },
    });
    assert.deepEqual(batches, [[0, 1], [2, 3], [4]]);
    assert.equal(privateReads, 0);
    assert.deepEqual(
      paths,
      parents.map((_, index) => ['items', index, 'label']),
    );
    assert.equal(f.service.stats().loaderBatches, 3);
  } finally {
    await f.close();
  }
});

test('GraphQL loader cache is request-local, preserves tenant isolation and never skips authorization on a cache hit', async () => {
  const parent = { id: 'shared' };
  let loaded = 0,
    authorized = 0;
  const f = await fixture({
    schema: 'type Item { value: String! } type Query { item: Item! }',
    resolvers: { Query: { item: () => parent } },
    loaders: {
      Item: {
        value: {
          load: async (requests, context) => {
            loaded += requests.length;
            return requests.map(() => context.auth!.tenantId);
          },
        },
      },
    },
    security: {
      authorizeField: ({ field }) => {
        if (field.fieldName === 'value') authorized++;
        return true;
      },
    },
  });
  try {
    await Promise.all(
      ['tenant-a', 'tenant-b'].map(async (tenant) => {
        const result = await send(
          f.origin,
          { query: '{ first: item { value } second: item { value } }' },
          { headers: { authorization: await f.token(tenant) } },
        );
        assert.deepEqual(result.json(), {
          data: { first: { value: tenant }, second: { value: tenant } },
        });
      }),
    );
    assert.equal(loaded, 2);
    assert.equal(authorized, 4);
    assert.equal(f.service.stats().loaderBatches, 2);
  } finally {
    await f.close();
  }
});

test('GraphQL explicitly uncached loaders retain distinct alias requests in the same native batch', async () => {
  const parent = { id: 1 };
  let requestsSeen = 0;
  const f = await fixture({
    schema: 'type Item { value: String! } type Query { item: Item! }',
    resolvers: { Query: { item: () => parent } },
    loaders: {
      Item: {
        value: {
          cache: false,
          load: async (requests) => {
            requestsSeen += requests.length;
            return requests.map((request) => String(request.info.path[0]));
          },
        },
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ left: item { value } right: item { value } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.deepEqual(result.json(), {
      data: { left: { value: 'left' }, right: { value: 'right' } },
    });
    assert.equal(requestsSeen, 2);
    assert.equal(f.service.stats().loaderBatches, 1);
  } finally {
    await f.close();
  }
});

test('GraphQL serial mutation root fields invalidate request loader results before observing the next effect', async () => {
  const parent = { id: 1 };
  let current = '',
    batches = 0;
  const f = await fixture({
    schema:
      'type Item { value: String! } type Query { ping: String! } type Mutation { update(value: String!): Item! }',
    resolvers: {
      Query: { ping: () => 'pong' },
      Mutation: {
        update: (_parent, args) => {
          current = args.value as string;
          return parent;
        },
      },
    },
    loaders: {
      Item: {
        value: {
          load: async (requests) => {
            batches++;
            return requests.map(() => current);
          },
        },
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const result = await send(
      f.origin,
      {
        query:
          'mutation { first: update(value: "one") { value } second: update(value: "two") { value } }',
      },
      { headers: { authorization: await f.token() } },
    );
    assert.deepEqual(result.json(), {
      data: { first: { value: 'one' }, second: { value: 'two' } },
    });
    assert.equal(batches, 2);
  } finally {
    await f.close();
  }
});

test('GraphQL denied loader fields do not enqueue work or read any parent values', async () => {
  let loads = 0,
    reads = 0;
  const f = await fixture({
    schema: 'type Item { value: String } type Query { item: Item! }',
    resolvers: {
      Query: {
        item: () => ({
          get id() {
            reads++;
            return 1;
          },
        }),
      },
    },
    loaders: {
      Item: {
        value: {
          load: async (requests) => {
            loads++;
            return requests.map(() => 'private');
          },
        },
      },
    },
    security: { authorizeField: ({ field }) => field.fieldName !== 'value' },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ item { value } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.match(result.body, /EK_GQL_FORBIDDEN/);
    assert.equal(loads, 0);
    assert.equal(reads, 0);
    assert.equal(f.service.stats().loaderBatches, 0);
  } finally {
    await f.close();
  }
});

test('GraphQL validates every native loader result count and sanitizes provider failures', async () => {
  for (const result of [
    [],
    ['one', 'extra'],
    null,
    { length: 1, 0: 'fake-array' },
    new Error('private-loader-password'),
  ]) {
    const f = await fixture({
      schema: 'type Item { value: String } type Query { item: Item! }',
      resolvers: { Query: { item: () => ({}) } },
      loaders: {
        Item: {
          value: {
            load: async () => {
              if (result instanceof Error) throw result;
              return result as unknown as readonly unknown[];
            },
          },
        },
      },
      security: { authorizeField: () => true },
    });
    try {
      const response = await send(
        f.origin,
        { query: '{ item { value } }' },
        { headers: { authorization: await f.token() } },
      );
      assert.equal(response.status, 200, response.body);
      assert.match(response.body, /EK_GQL_EXECUTION/);
      assert.deepEqual((response.json() as { data: unknown }).data, { item: { value: null } });
      assert.doesNotMatch(response.body + f.logs(), /private-loader-password|fake-array/);
    } finally {
      await f.close();
    }
  }
});

test('GraphQL cache hits cannot bypass a later field denial and distinct arguments retain distinct values', async () => {
  const parent = { id: 1 };
  let loads = 0;
  const f = await fixture({
    schema: 'type Item { value(label: String!): String } type Query { item: Item! }',
    resolvers: { Query: { item: () => parent } },
    loaders: {
      Item: {
        value: {
          load: async (requests) => {
            loads += requests.length;
            return requests.map((request) => request.args.label);
          },
        },
      },
    },
    security: {
      authorizeField: ({ field }) => field.fieldName !== 'value' || field.path[0] !== 'denied',
    },
  });
  try {
    const result = await send(
      f.origin,
      {
        query:
          '{ one: item { value(label: "one") } two: item { value(label: "two") } denied: item { value(label: "one") } }',
      },
      { headers: { authorization: await f.token() } },
    );
    assert.match(result.body, /EK_GQL_FORBIDDEN/);
    assert.deepEqual((result.json() as { data: unknown }).data, {
      one: { value: 'one' },
      two: { value: 'two' },
      denied: { value: null },
    });
    assert.equal(loads, 2);
  } finally {
    await f.close();
  }
});

test('GraphQL primitive loader parents and per-item errors preserve ordering without leaking causes', async () => {
  const f = await fixture({
    schema: 'type Item { value: String } type Query { items: [Item!]! }',
    resolvers: { Query: { items: () => [1, 2, 1] } },
    loaders: {
      Item: {
        value: {
          load: async (requests) =>
            requests.map((request) =>
              request.parent === 2 ? new Error('private-item-cause') : 'one',
            ),
        },
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ items { value } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.deepEqual((result.json() as { data: unknown }).data, {
      items: [{ value: 'one' }, { value: null }, { value: 'one' }],
    });
    assert.match(result.body, /EK_GQL_EXECUTION/);
    assert.doesNotMatch(result.body + f.logs(), /private-item-cause/);
    assert.equal(f.service.stats().loaderBatches, 1);
  } finally {
    await f.close();
  }
});
