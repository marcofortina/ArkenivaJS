// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { graphqlPlugin } from '../../dist/index.js';
import { base, fixture, send, tlsFiles } from '../fixture.js';

test('GraphQL serves authenticated queries over the existing HTTP listener and refuses forged tenant authority', async () => {
  const seen: string[] = [];
  const f = await fixture({
    ...base(),
    schema: 'type Query { tenant: String! }',
    resolvers: {
      Query: {
        tenant: (_parent, _args, context) => {
          seen.push(context.auth!.tenantId);
          return context.auth!.tenantId;
        },
      },
    },
  });
  try {
    assert.equal(f.service.health().ready, true);
    const accepted = await send(
      f.origin,
      { query: '{ tenant }' },
      { headers: { authorization: await f.token(), 'x-tenant-id': 'foreign-tenant' } },
    );
    assert.equal(accepted.status, 200, accepted.body);
    assert.deepEqual(accepted.json(), { data: { tenant: 'tenant-a' } });
    const absent = await send(
      f.origin,
      { query: '{ tenant }', variables: { tenantId: 'tenant-a' } },
      { headers: { 'x-tenant-id': 'tenant-a' } },
    );
    assert.equal(absent.status, 401, absent.body);
    assert.deepEqual(seen, ['tenant-a']);
    assert.equal(f.api.stats().completed, 2);
    assert.deepEqual(f.service.stats(), {
      operations: 2,
      rejected: 1,
      activeOperations: 0,
      activeSubscriptions: 0,
      loaderBatches: 0,
    });
  } finally {
    await f.close();
  }
});

test('GraphQL explicit public ping works without an authority over direct verified HTTPS', async () => {
  const tls = await tlsFiles();
  const f = await fixture(
    {
      ...base(),
      security: {
        authorizeField: () => true,
        auth: {
          required: false,
          publicRootFields: ['Query.ping'],
          reason: 'Public availability check',
        },
      },
    },
    { authenticated: false, tls: tls.tls },
  );
  try {
    const accepted = await send(f.origin, { query: '{ ping }' }, { ca: tls.ca });
    assert.equal(accepted.status, 200, accepted.body);
    assert.deepEqual(accepted.json(), { data: { ping: 'pong' } });
    await assert.rejects(send(f.origin, { query: '{ ping }' }));
    const invalid = await send(
      f.origin,
      { query: '{ ping }' },
      { ca: tls.ca, headers: { authorization: 'Bearer forged' } },
    );
    assert.equal(invalid.status, 401);
  } finally {
    await f.close();
    await tls.close();
  }
});

test('GraphQL awaits authorization before explicit and nested default property reads', async () => {
  let read = 0,
    root = 0;
  const parent = {
    visible: 'safe',
    get secret() {
      read++;
      return 'never-disclose';
    },
  };
  const f = await fixture({
    schema: 'type Item { visible: String! secret: String } type Query { item: Item! }',
    resolvers: {
      Query: {
        item: () => {
          root++;
          return parent;
        },
      },
    },
    security: {
      authorizeField: async ({ field, context }) => {
        assert.ok(context.identity);
        assert.ok(context.auth);
        await Promise.resolve();
        return field.fieldName !== 'secret';
      },
    },
  });
  try {
    const accepted = await send(
      f.origin,
      { query: '{ item { visible secret } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(accepted.status, 200, accepted.body);
    const result = accepted.json() as { data: unknown; errors: { extensions: { code: string } }[] };
    assert.deepEqual(result.data, { item: { visible: 'safe', secret: null } });
    assert.equal(result.errors[0]?.extensions.code, 'EK_GQL_FORBIDDEN');
    assert.equal(read, 0);
    assert.equal(root, 1);
    assert.doesNotMatch(accepted.body + f.logs(), /never-disclose/);
  } finally {
    await f.close();
  }
});

test('GraphQL direct HTTPS verifies authentication, variables, selected operation and the server certificate', async () => {
  const tls = await tlsFiles();
  const f = await fixture(
    {
      schema: 'type Query { echo(value: String!): String! }',
      resolvers: {
        Query: {
          echo: (_parent, args, context, info) => {
            assert.equal(context.auth?.tenantId, 'tenant-b');
            assert.equal(info.operationName, 'Selected');
            return args.value;
          },
        },
      },
      security: { authorizeField: () => true, auth: { required: true, scopes: ['graphql:read'] } },
    },
    { tls: tls.tls },
  );
  try {
    const response = await send(
      f.origin,
      {
        query:
          'query Ignored { echo(value: "unused") } query Selected($value: String!) { echo(value: $value) }',
        operationName: 'Selected',
        variables: { value: 'verified-https' },
      },
      { ca: tls.ca, headers: { authorization: await f.token('tenant-b') } },
    );
    assert.equal(response.status, 200, response.body);
    assert.deepEqual(response.json(), { data: { echo: 'verified-https' } });
    const denied = await send(
      f.origin,
      { query: '{ echo(value: "denied") }' },
      { ca: tls.ca, headers: { authorization: await f.token('tenant-b', 'unrelated') } },
    );
    assert.equal(denied.status, 401, denied.body);
  } finally {
    await f.close();
    await tls.close();
  }
});

test('GraphQL identical queries isolate tenant data and reject known foreign row identifiers', async () => {
  const rows = new Map([
    ['known-a', { id: 'known-a', tenant: 'tenant-a', value: 'private-a' }],
    ['known-b', { id: 'known-b', tenant: 'tenant-b', value: 'private-b' }],
  ]);
  let calls = 0;
  const f = await fixture({
    schema: 'type Row { value: String! } type Query { row(id: ID!): Row }',
    resolvers: {
      Query: {
        row: (_parent, args, context) => {
          calls++;
          const row = rows.get(args.id as string);
          return row?.tenant === context.auth?.tenantId ? row : null;
        },
      },
    },
    security: {
      authorizeField: ({ field, args, context, parent }) => {
        if (field.parentType === 'Query')
          return rows.get(args.id as string)?.tenant === context.auth?.tenantId;
        return (parent as { tenant: string }).tenant === context.auth?.tenantId;
      },
    },
  });
  try {
    const document = {
      query: 'query Row($id: ID!) { row(id: $id) { value } }',
      variables: { id: 'known-b' },
    };
    const foreign = await send(f.origin, document, {
      headers: { authorization: await f.token(), 'x-tenant-id': 'tenant-b' },
    });
    assert.match(foreign.body, /EK_GQL_FORBIDDEN/);
    assert.doesNotMatch(foreign.body, /private-b/);
    assert.equal(calls, 0);
    const allowed = await send(f.origin, document, {
      headers: { authorization: await f.token('tenant-b') },
    });
    assert.deepEqual(allowed.json(), { data: { row: { value: 'private-b' } } });
    assert.equal(calls, 1);
    const deniedAgain = await send(f.origin, document, {
      headers: { authorization: await f.token() },
    });
    assert.match(deniedAgain.body, /EK_GQL_FORBIDDEN/);
    assert.equal(calls, 1);
    assert.doesNotMatch(f.logs(), /private-a|private-b|known-a|known-b/);
  } finally {
    await f.close();
  }
});

test('GraphQL rejects invalid documents, arrays, introspection, CSRF and GET mutations before business effects', async () => {
  let effects = 0;
  const f = await fixture({
    schema: 'type Query { ping: String! } type Mutation { update: Boolean! }',
    resolvers: {
      Query: {
        ping: () => {
          effects++;
          return 'pong';
        },
      },
      Mutation: {
        update: () => {
          effects++;
          return true;
        },
      },
    },
    security: { authorizeField: () => true, allowGetQueries: true },
  });
  try {
    const headers = { authorization: await f.token() };
    for (const body of [
      { query: '{ missing }' },
      [{ query: '{ ping }' }],
      { query: '{ __schema { queryType { name } } }' },
      { query: 'query A { ping } query B { ping }' },
      { query: '{ ping }', unknown: true },
    ]) {
      const rejected = await send(f.origin, body, { headers });
      assert.ok(rejected.status >= 400, rejected.body);
    }
    const get = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql?query=' + encodeURIComponent('mutation { update }'),
      headers,
    });
    assert.equal(get.status, 400, get.body);
    for (const extra of [
      { cookie: 'session=untrusted' },
      { origin: 'https://foreign.example' },
      { 'sec-fetch-site': 'cross-site' },
      { 'content-type': 'text/plain' },
    ]) {
      const rejected = await send(
        f.origin,
        { query: '{ ping }' },
        { headers: { ...headers, ...extra } },
      );
      assert.ok(rejected.status >= 400, rejected.body);
    }
    assert.equal(effects, 0);
    const valid = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql?query=' + encodeURIComponent('{ ping }'),
      headers,
    });
    assert.equal(valid.status, 200, valid.body);
    assert.equal(effects, 1);
  } finally {
    await f.close();
  }
});

test('GraphQL missing HTTP, absent authentication and route collisions fail without an active listener', async () => {
  const app = await createApplication({
    service: { name: 'graphql-missing-http', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), apiPlugin(), graphqlPlugin(base())],
  });
  try {
    await assert.rejects(app.start());
  } finally {
    await app.stop();
  }
  await assert.rejects(fixture(base(), { authenticated: false }));
  await assert.rejects(
    fixture(base(), {
      plugins: [
        {
          id: 'conflict',
          version: '1.0.0',
          capabilities: new Set(),
          dependencies: ['api'],
          init(context) {
            context.require<ManagedApiServer>(COMPONENTS.api).post('/graphql', {
              auth: { required: false },
              schema: { response: {} },
              handler: () => ({}),
            });
          },
          close() {},
        },
      ],
    }),
  );
});

test('GraphQL default property methods receive the public authenticated context without native transport handles', async () => {
  const f = await fixture({
    schema: 'type Item { label: String! } type Query { item: Item! }',
    resolvers: {
      Query: {
        item: () => ({
          label(_args: unknown, context: Record<string, unknown>) {
            assert.ok(Object.isFrozen(context));
            assert.deepEqual(Object.keys(context).sort(), [
              'auth',
              'identity',
              'requestId',
              'signal',
            ]);
            return 'public-context';
          },
        }),
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const response = await send(
      f.origin,
      { query: '{ item { label } }' },
      { headers: { authorization: await f.token() } },
    );
    assert.deepEqual(response.json(), { data: { item: { label: 'public-context' } } });
    assert.deepEqual(Object.keys(f.service).sort(), ['health', 'schemaSdl', 'stats']);
    assert.equal(Object.hasOwn(f.api.native(), 'graphql'), false);
  } finally {
    await f.close();
  }
});

test('GraphQL rejects malformed Unicode, malformed JSON and JSON-encoded AST without resolver effects', async () => {
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
  });
  try {
    const headers = { authorization: await f.token() };
    for (const body of [
      Buffer.from([0x7b, 0xff, 0x7d]),
      '{',
      JSON.stringify({ query: '\ud800' }),
      JSON.stringify({ query: JSON.stringify({ kind: 'Document', definitions: [] }) }),
    ]) {
      const response = await send(f.origin, body, { headers, raw: true });
      assert.equal(response.status, 400, response.body);
      assert.match(response.body, /EK_GQL_VALIDATION/);
    }
    assert.equal(calls, 0);
  } finally {
    await f.close();
  }
});
