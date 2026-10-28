// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSchema, getIntrospectionQuery, graphql, TypeNameMetaFieldDef } from 'graphql';
import { base, fixture, send } from '../fixture.js';

test('GraphQL schema introspection requires current admin scope before any business resolver runs', async () => {
  let effects = 0;
  const f = await fixture({
    ...base(),
    resolvers: {
      Query: {
        ping: () => {
          effects++;
          return 'pong';
        },
      },
    },
    security: {
      authorizeField: () => true,
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
    },
  });
  try {
    const response = await send(
      f.origin,
      { query: '{ ping __schema { queryType { name } } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(response.status, 403, response.body);
    assert.match(response.body, /EK_GQL_FORBIDDEN/);
    assert.equal(effects, 0);
    const ordinary = await send(
      f.origin,
      { query: '{ ping }' },
      { headers: { authorization: await f.token() } },
    );
    assert.deepEqual(ordinary.json(), { data: { ping: 'pong' } });
    const admin = await send(
      f.origin,
      { query: '{ __schema { queryType { name } } }' },
      { headers: { authorization: await f.token('tenant-a', 'graphql:admin') } },
    );
    assert.deepEqual(admin.json(), { data: { __schema: { queryType: { name: 'Query' } } } });
    assert.equal(effects, 1);
  } finally {
    await f.close();
  }
});

test('GraphQL standard full introspection authorizes every actual metadata field and list element', async () => {
  let authorized = 0;
  const f = await fixture({
    ...base(),
    security: {
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
      authorizeField: ({ context, field }) => {
        assert.equal(context.auth?.tenantId, 'tenant-a');
        assert.ok(context.identity);
        assert.ok(Object.isFrozen(field.path));
        authorized++;
        return true;
      },
      limits: {
        maxComplexity: 100000000,
        maxDepth: 50,
        maxCollectionItems: 100,
        maxFieldExecutions: 100000,
      },
    },
  });
  try {
    const response = await send(
      f.origin,
      { query: getIntrospectionQuery() },
      { headers: { authorization: await f.token('tenant-a', 'graphql:admin') } },
    );
    assert.equal(response.status, 200, response.body);
    const result = response.json();
    assert.equal(result.errors, undefined, response.body);
    const count = (value: unknown): number => {
      if (Array.isArray(value)) return value.reduce((total, item) => total + count(item), 0);
      if (!value || typeof value !== 'object') return 0;
      return Object.entries(value).reduce((total, [, item]) => total + 1 + count(item), 0);
    };
    assert.ok(authorized > 100);
    assert.equal(authorized, count(result.data));
    const schema = (result.data as { __schema: { queryType: { name: string } } }).__schema;
    assert.equal(schema.queryType.name, 'Query');
  } finally {
    await f.close();
  }
});

test('GraphQL metadata field denial is awaited and retains normal nullable error semantics', async () => {
  const paths: (readonly (string | number)[])[] = [];
  const f = await fixture({
    ...base(),
    security: {
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
      authorizeField: async ({ field }) => {
        await Promise.resolve();
        paths.push(field.path);
        return !(field.parentType === '__Type' && field.fieldName === 'name');
      },
    },
  });
  try {
    const response = await send(
      f.origin,
      { query: '{ inspected: __type(name: "Query") { name kind } }' },
      { headers: { authorization: await f.token('tenant-a', 'graphql:admin') } },
    );
    assert.equal(response.status, 200, response.body);
    assert.deepEqual(response.json().data, { inspected: { name: null, kind: 'OBJECT' } });
    assert.match(response.body, /EK_GQL_FORBIDDEN/);
    assert.deepEqual(paths, [['inspected'], ['inspected', 'name'], ['inspected', 'kind']]);
  } finally {
    await f.close();
  }
});

test('GraphQL typename uses per-field policy while independently owned applications and native schemas stay isolated', async () => {
  const first = await fixture({
    ...base(),
    security: { authorizeField: ({ field }) => field.fieldName !== '__typename' },
  });
  const second = await fixture(base());
  try {
    const [denied, allowed] = await Promise.all([
      send(
        first.origin,
        { query: '{ __typename }' },
        { headers: { authorization: await first.token() } },
      ),
      send(
        second.origin,
        { query: '{ __typename }' },
        { headers: { authorization: await second.token() } },
      ),
    ]);
    assert.equal(denied.status, 200, denied.body);
    assert.match(denied.body, /EK_GQL_FORBIDDEN/);
    assert.deepEqual(denied.json().data, null);
    assert.deepEqual(allowed.json(), { data: { __typename: 'Query' } });
    const unrelated = await graphql({
      schema: buildSchema('type Query { ping: String }'),
      source: '{ __typename __schema { queryType { name } } }',
    });
    assert.equal(unrelated.errors, undefined);
    assert.deepEqual(JSON.parse(JSON.stringify(unrelated)), {
      data: { __typename: 'Query', __schema: { queryType: { name: 'Query' } } },
    });
  } finally {
    await first.close();
    await second.close();
  }
});

test('GraphQL anonymous metadata cannot gain schema authority from caller objects or forged tenant fields', async () => {
  const f = await fixture({
    ...base(),
    security: {
      auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public ping' },
      authorizeField: () => true,
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
    },
  });
  try {
    for (const query of [
      '{ __schema { queryType { name } } }',
      '{ __type(name: "Query") { name } }',
    ]) {
      const response = await send(
        f.origin,
        { query, variables: { identity: { scopes: ['graphql:admin'] }, tenantId: 'tenant-a' } },
        { headers: { 'x-tenant-id': 'tenant-a', 'x-scope': 'graphql:admin' } },
      );
      assert.equal(response.status, 403, response.body);
      assert.match(response.body, /EK_GQL_FORBIDDEN/);
    }
    const publicPing = await send(f.origin, { query: '{ ping }' });
    assert.deepEqual(publicPing.json(), { data: { ping: 'pong' } });
  } finally {
    await f.close();
  }
});

test('GraphQL rejects replacement of a metadata guard before executing any selected field', async () => {
  let business = 0,
    replaced = 0;
  const f = await fixture({
    ...base(),
    resolvers: {
      Query: {
        ping: () => {
          business++;
          return 'pong';
        },
      },
    },
  });
  const original = TypeNameMetaFieldDef.resolve;
  assert.ok(original);
  try {
    TypeNameMetaFieldDef.resolve = () => {
      replaced++;
      return 'policy-bypass';
    };
    const response = await send(
      f.origin,
      { query: '{ ping __typename }' },
      { headers: { authorization: await f.token() } },
    );
    assert.ok(response.status >= 400, response.body);
    assert.equal(business, 0);
    assert.equal(replaced, 0);
    assert.doesNotMatch(response.body, /policy-bypass/);
  } finally {
    TypeNameMetaFieldDef.resolve = original;
    await f.close();
  }
});
