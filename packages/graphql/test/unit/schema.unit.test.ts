// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { GraphqlPluginSettings } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { compileSchema } from '../../dist/schema.js';

const settings = (): GraphqlPluginSettings => ({
  schema: 'type Query { ping: String! }',
  resolvers: { Query: { ping: () => 'pong' } },
  security: { authorizeField: () => false },
});
const invalid = (work: () => unknown, code = 'EK_GQL_CONFIG') =>
  assert.throws(work, (error: unknown) => error instanceof KitError && error.code === code);

test('GraphQL startup captures immutable defaults and schema without executing business code', () => {
  let calls = 0;
  const input = settings();
  const resolver = () => {
    calls++;
    return 'pong';
  };
  const resolvers = { Query: { ping: resolver } };
  const captured = capture({ ...input, resolvers });
  resolvers.Query.ping = () => 'changed';
  assert.equal(captured.resolvers.Query?.ping, resolver);
  assert.equal(captured.path, '/graphql');
  assert.deepEqual(captured.security.auth, { required: true });
  assert.equal(captured.security.introspection, 'disabled');
  assert.deepEqual(captured.security.limits, {
    maxDocumentBytes: 65536,
    maxVariablesBytes: 65536,
    maxResultBytes: 1048576,
    maxDepth: 8,
    maxComplexity: 500,
    maxAliases: 20,
    maxFieldExecutions: 2000,
    maxCollectionItems: 100,
    maxOperationMs: 30000,
  });
  assert.ok(Object.isFrozen(captured));
  assert.ok(Object.isFrozen(captured.resolvers.Query));
  assert.equal(compileSchema(captured).getQueryType()?.name, 'Query');
  assert.equal(calls, 0);
});

test('GraphQL startup rejects accessors, proxies, symbols and unknown fields without calling them', () => {
  let calls = 0;
  invalid(() =>
    capture(
      Object.defineProperty(settings(), 'schema', {
        get() {
          calls++;
          return '';
        },
      }),
    ),
  );
  invalid(() =>
    capture(
      new Proxy(settings(), {
        ownKeys() {
          calls++;
          return [];
        },
      }),
    ),
  );
  invalid(() => capture({ ...settings(), [Symbol('unknown')]: true }));
  invalid(() => capture({ ...settings(), unexpected: true } as GraphqlPluginSettings));
  invalid(() =>
    capture({
      ...settings(),
      resolvers: {
        Query: Object.defineProperty({}, 'ping', {
          enumerable: true,
          get() {
            calls++;
            return () => 'pong';
          },
        }),
      },
    }),
  );
  assert.equal(calls, 0);
});

test('GraphQL every limit must be a positive safe integer and unknown limits fail closed', () => {
  for (const key of Object.keys(capture(settings()).security.limits)) {
    for (const value of [0, -1, 1.2, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '10', null])
      invalid(() =>
        capture({
          ...settings(),
          security: { authorizeField: () => true, limits: { [key]: value } },
        } as GraphqlPluginSettings),
      );
    assert.equal(
      capture({ ...settings(), security: { authorizeField: () => true, limits: { [key]: 1 } } })
        .security.limits[key as keyof ReturnType<typeof capture>['security']['limits']],
      1,
    );
  }
  invalid(() =>
    capture({
      ...settings(),
      security: { authorizeField: () => true, limits: { ignored: 1 } },
    } as GraphqlPluginSettings),
  );
});

test('GraphQL requires explicit anonymous roots, field authorization and administrative introspection policy', () => {
  const input = settings();
  for (const security of [
    {},
    { authorizeField: true },
    { authorizeField: () => true, auth: { required: false } },
    {
      authorizeField: () => true,
      auth: { required: false, publicRootFields: [], reason: 'Public ping' },
    },
    {
      authorizeField: () => true,
      auth: { required: false, publicRootFields: ['Mutation.ping'], reason: 'Public ping' },
    },
    { authorizeField: () => true, auth: { required: true, publicRootFields: ['Query.ping'] } },
    { authorizeField: () => true, auth: { required: true, assurance: 'invented' } },
    { authorizeField: () => true, introspection: 'authenticated' },
    { authorizeField: () => true, introspectionScope: 'admin' },
    { authorizeField: () => true, allowBatchedHttpRequests: true },
    { authorizeField: () => true, allowGetQueries: 'true' },
    { authorizeField: () => true, developerIDE: 1 },
  ])
    invalid(() => capture({ ...input, security } as GraphqlPluginSettings));
  const captured = capture({
    ...input,
    security: {
      authorizeField: () => true,
      auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public health signal' },
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
    },
  });
  assert.equal(captured.security.introspectionScope, 'graphql:admin');
  assert.ok(compileSchema(captured));
});

test('GraphQL rejects malformed SDL, incompatible coordinates and unsafe anonymous declarations', () => {
  for (const schema of [
    'type Query {',
    'type Mutation { update: Boolean }',
    'type Query { ping: Missing }',
    'type Query { ping: String } type Query { other: Int }',
  ])
    invalid(() => compileSchema(capture({ ...settings(), schema })), 'EK_GQL_SCHEMA');
  for (const resolvers of [
    { Missing: { ping: () => true } },
    { Query: { absent: () => true } },
    { String: { value: () => true } },
    { __Schema: { description: () => true } },
    {
      Query: {
        ping: {
          subscribe: async function* () {
            yield true;
          },
        },
      },
    },
  ])
    invalid(() => compileSchema(capture({ ...settings(), resolvers })), 'EK_GQL_SCHEMA');
  invalid(
    () =>
      compileSchema(
        capture({
          ...settings(),
          security: {
            authorizeField: () => true,
            auth: { required: false, publicRootFields: ['Query.absent'], reason: 'Public ping' },
          },
        }),
      ),
    'EK_GQL_SCHEMA',
  );
  try {
    compileSchema(
      capture({ ...settings(), schema: 'type Query { privateBackendName: SecretInternalType }' }),
    );
  } catch (error) {
    assert.ok(error instanceof KitError);
    assert.doesNotMatch(
      JSON.stringify(error.toSafeJSON()),
      /privateBackendName|SecretInternalType|stack/,
    );
  }
});

test('GraphQL captures bounded loaders and rejects incompatible or ambiguous field mappings', () => {
  const load = async () => [null];
  const input = { ...settings(), resolvers: {}, loaders: { Query: { ping: { load } } } };
  const captured = capture(input);
  assert.equal(captured.loaders?.Query?.ping?.maxBatchSize, 100);
  assert.equal(captured.loaders?.Query?.ping?.cache, true);
  assert.ok(compileSchema(captured));
  for (const maxBatchSize of [0, 1.1, 1001])
    invalid(() => capture({ ...input, loaders: { Query: { ping: { load, maxBatchSize } } } }));
  invalid(() => compileSchema(capture({ ...settings(), loaders: input.loaders })), 'EK_GQL_SCHEMA');
  invalid(
    () => compileSchema(capture({ ...input, loaders: { Query: { absent: { load } } } })),
    'EK_GQL_SCHEMA',
  );
  invalid(() =>
    capture({
      ...input,
      loaders: { Query: { ping: { load, cache: 'true' } } },
    } as unknown as GraphqlPluginSettings),
  );
});

test('GraphQL subscription declarations snapshot bounded transport and bind a trusted provider without invoking it', () => {
  let calls = 0;
  class Provider {
    label = 'original';
    async *subscribe() {
      calls++;
      yield this.label;
    }
    async publish() {
      calls++;
    }
    async close() {
      calls++;
    }
  }
  const provider = new Provider();
  const subscriptions = {
    enabled: true as const,
    pubsub: provider,
    maxConnections: 1000,
    maxOperationsPerConnection: 50,
    maxQueuedEventsPerConnection: 10,
    revalidateIntervalMs: 1000,
    allowedOrigins: ['https://example.com'],
  };
  const captured = capture({ ...settings(), subscriptions });
  subscriptions.allowedOrigins.push('https://other.example');
  assert.deepEqual(captured.subscriptions?.allowedOrigins, ['https://example.com']);
  assert.equal(calls, 0);
  for (const change of [
    { maxConnections: 1001 },
    { maxOperationsPerConnection: 51 },
    { maxQueuedEventsPerConnection: 0 },
    { revalidateIntervalMs: 0 },
    { allowedOrigins: ['*'] },
    { allowedOrigins: [] },
    { allowedOrigins: ['https://example.com/path'] },
    { pubsub: {} },
    {
      pubsub: Object.defineProperty({}, 'subscribe', {
        get() {
          calls++;
          return () => null;
        },
      }),
    },
  ])
    invalid(() =>
      capture({
        ...settings(),
        subscriptions: { ...subscriptions, ...change },
      } as GraphqlPluginSettings),
    );
  assert.equal(calls, 0);
});
