// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSchema, parse } from 'graphql';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlPluginSettings, GraphqlRequestContext } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { operationInput } from '../../dist/input.js';
import { subscriptionDocument } from '../../dist/subscription-document.js';
import { budget } from '../../dist/budget.js';
import { fixture } from '../fixture.js';

const rejected = (work: () => unknown, code: string) =>
  assert.throws(work, (error: unknown) => error instanceof KitError && error.code === code);

function declarations(): GraphqlPluginSettings {
  return {
    schema: `
      type Notice { text: String! }
      type Query { ping: Boolean! }
      type Mutation { change: Boolean! }
      type Subscription { notices(first: Int!): [Notice!]! }
    `,
    resolvers: {},
    security: {
      auth: { required: true, scopes: ['graphql:read'] },
      authorizeField: () => true,
      limits: { maxCollectionItems: 2, maxDepth: 2, maxAliases: 1 },
    },
    subscriptions: {
      enabled: true,
      pubsub: {
        subscribe() {
          throw new Error('Preflight must not acquire a source');
        },
        async publish() {
          throw new Error('Preflight must not publish');
        },
        async close() {},
      },
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 2,
      revalidateIntervalMs: 1000,
      allowedOrigins: ['https://portal.example.test'],
    },
  };
}

test('Shared operation input preserves HTTP GET decoding and rejects malformed or oversized WebSocket payloads before parse', () => {
  const limits = capture(declarations()).security.limits;
  assert.deepEqual(
    operationInput(
      { query: 'query Q { ping }', variables: '{"n":1}', operationName: 'Q' },
      limits,
      'GET',
    ),
    { query: 'query Q { ping }', variables: { n: 1 }, operationName: 'Q' },
  );
  for (const input of [
    [],
    null,
    { query: {} },
    { query: '' },
    { query: '\ud800' },
    { query: '{ ping }', operationName: null },
    { query: '{ ping }', operationName: 'bad-name' },
    { query: '{ ping }', variables: [] },
    { query: '{ ping }', variables: null },
    { query: '{ ping }', variables: '{}' },
    { query: '{ ping }', extensions: { connectionInit: { tenant: 'tenant-b' } } },
  ])
    rejected(() => operationInput(input, limits, 'WEBSOCKET'), 'EK_GQL_VALIDATION');
  rejected(
    () => operationInput({ query: ' '.repeat(limits.maxDocumentBytes) + '[' }, limits, 'WEBSOCKET'),
    'EK_GQL_INPUT_LIMIT',
  );
  rejected(
    () =>
      operationInput(
        { query: '{ ping }', variables: { n: 'x'.repeat(limits.maxVariablesBytes) } },
        limits,
        'WEBSOCKET',
      ),
    'EK_GQL_INPUT_LIMIT',
  );
  rejected(
    () =>
      operationInput(
        { query: '{ ping }', variables: 'x'.repeat(limits.maxVariablesBytes + 1) },
        limits,
        'GET',
      ),
    'EK_GQL_INPUT_LIMIT',
  );
  rejected(
    () => operationInput({ query: '{ ping }', variables: '{' }, limits, 'GET'),
    'EK_GQL_VALIDATION',
  );
});

test('Subscription preflight verifies actual identity provenance and constrains native ASTs, variables, fragments and transport kind', async () => {
  const f = await fixture();
  try {
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth);
    const identity = await authority.verifyBearer(await f.token());
    const context: GraphqlRequestContext = Object.freeze({
      requestId: 'subscription-preflight',
      signal: new AbortController().signal,
      identity,
      auth: authority.tenantFrom(identity),
    });
    const settings = capture(declarations()),
      schema = buildSchema(settings.schema);
    const valid = {
      query:
        'subscription Chosen($n: Int!) { notices(first: $n) { ...Text } } fragment Text on Notice { text }',
      variables: { n: 2 },
      operationName: 'Chosen',
    };
    const result = subscriptionDocument(valid, schema, settings, context, authority);
    assert.equal(result.document.kind, 'Document');
    assert.equal(result.complexity, 4);
    for (const input of [
      { query: '{ ping }' },
      { query: 'mutation { change }' },
      { query: 'subscription { missing }' },
      { query: 'subscription { a: notices(first: 1) { text } b: notices(first: 1) { text } }' },
      {
        query:
          'subscription { notices(first: 1) { ...Cycle } } fragment Cycle on Notice { ...Cycle }',
      },
      { ...valid, operationName: 'Missing' },
      { ...valid, variables: { n: '2' } },
      { query: JSON.stringify({ kind: 'Document', definitions: [] }) },
    ])
      rejected(
        () => subscriptionDocument(input, schema, settings, context, authority),
        'EK_GQL_VALIDATION',
      );
    rejected(
      () =>
        subscriptionDocument(
          { ...valid, variables: { n: 3 } },
          schema,
          settings,
          context,
          authority,
        ),
      'EK_GQL_COMPLEXITY',
    );
    rejected(
      () => budget(schema, result.document, valid.variables, context, settings, 'POST'),
      'EK_GQL_VALIDATION',
    );
    rejected(
      () =>
        subscriptionDocument(
          valid,
          schema,
          settings,
          { requestId: 'anonymous', signal: context.signal },
          authority,
        ),
      'EK_GQL_AUTH',
    );
    rejected(
      () =>
        subscriptionDocument(
          valid,
          schema,
          settings,
          { ...context, identity: { ...identity } },
          authority,
        ),
      'EK_GQL_AUTH',
    );
    rejected(
      () =>
        subscriptionDocument(
          valid,
          schema,
          settings,
          { ...context, auth: { ...context.auth! } },
          authority,
        ),
      'EK_GQL_AUTH',
    );
    const other = await authority.verifyBearer(await f.token('tenant-b'));
    rejected(
      () =>
        subscriptionDocument(valid, schema, settings, { ...context, identity: other }, authority),
      'EK_GQL_AUTH',
    );
    const unscoped = await authority.verifyBearer(await f.token('tenant-a', 'other:scope'));
    rejected(
      () =>
        subscriptionDocument(
          valid,
          schema,
          settings,
          { ...context, identity: unscoped, auth: authority.tenantFrom(unscoped) },
          authority,
        ),
      'EK_GQL_AUTH',
    );
    rejected(
      () =>
        budget(
          schema,
          parse('subscription { notices(first: 1) { text } }'),
          undefined,
          { requestId: 'anonymous', signal: context.signal },
          settings,
          'WEBSOCKET',
        ),
      'EK_GQL_AUTH',
    );
    rejected(
      () =>
        subscriptionDocument(
          valid,
          schema,
          settings,
          { ...context, signal: AbortSignal.abort() },
          authority,
        ),
      'EK_GQL_TIMEOUT',
    );
    const declared = declarations();
    const disabled = capture({
      schema: declared.schema,
      resolvers: declared.resolvers,
      security: declared.security,
    });
    rejected(
      () => subscriptionDocument(valid, schema, disabled, context, authority),
      'EK_GQL_VALIDATION',
    );
  } finally {
    await f.close();
  }
});
