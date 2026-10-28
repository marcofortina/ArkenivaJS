// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { once } from 'node:events';
import { setImmediate } from 'node:timers/promises';
import fc from 'fast-check';
import { fixture, send } from '../fixture.js';

test(
  'Seeded real HTTP fuzz refuses cyclic fragments, alias amplification and excessive pagination before resolver effects',
  { timeout: 15000 },
  async () => {
    let calls = 0;
    const f = await fixture({
      schema: 'type Query { ping: String! items(first: Int): [String!]! }',
      resolvers: {
        Query: {
          ping: () => {
            calls++;
            return 'pong';
          },
          items: () => {
            calls++;
            return [];
          },
        },
      },
      security: { authorizeField: () => true },
    });
    try {
      const headers = { authorization: await f.token() };
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 24 }),
          fc.integer({ min: 21, max: 48 }),
          fc.integer({ min: 101, max: 10000 }),
          async (length, aliases, first) => {
            const cycle =
              'query Circular { ...CyclePart0 } ' +
              Array.from(
                { length },
                (_, i) =>
                  `fragment CyclePart${i} on Query { ping ...CyclePart${(i + 1) % length} }`,
              ).join(' ');
            const amplification =
              '{ ' + Array.from({ length: aliases }, (_, i) => `a${i}: ping`).join(' ') + ' }';
            for (const body of [
              { query: cycle },
              { query: amplification },
              { query: 'query Page($first: Int!) { items(first: $first) }', variables: { first } },
            ]) {
              const response = await send(f.origin, body, { headers });
              assert.equal(response.status, 400, response.body);
              assert.match(response.body, /EK_GQL_VALIDATION|EK_GQL_COMPLEXITY/);
              assert.equal(calls, 0);
            }
          },
        ),
        { seed: 6238, numRuns: 40 },
      );
      assert.equal(f.service.stats().activeOperations, 0);
    } finally {
      await f.close();
    }
  },
);

test('Malformed JSON, prototype-like inputs and invalid UTF8 never reach the data layer or disclose parser diagnostics', async () => {
  let calls = 0;
  const f = await fixture({
    schema:
      'input Filter { needle: String child: Filter } type Query { search(input: Filter): String! }',
    resolvers: {
      Query: {
        search: () => {
          calls++;
          return 'found';
        },
      },
    },
    security: { authorizeField: () => true },
  });
  try {
    const authorization = await f.token();
    const query = 'query Search($input: Filter) { search(input: $input) }';
    const encoded = (input: string) =>
      '{"query":' + JSON.stringify(query) + ',"variables":{"input":' + input + '}}';
    const bodies: (string | Buffer)[] = [
      '{"query":',
      'null',
      'false',
      '[]',
      encoded('{"__proto__":{"arkenivaPolluted":true}}'),
      encoded('{"constructor":{"prototype":{"arkenivaPolluted":true}}}'),
      encoded('{"prototype":{"arkenivaPolluted":true}}'),
      '{"query":"\\ud800"}',
      JSON.stringify({ query: JSON.stringify({ kind: 'Document', definitions: [] }) }),
      Buffer.concat([
        Buffer.from(encoded('{"needle":"').slice(0, -2)),
        Buffer.from([0xc0, 0xaf]),
        Buffer.from('"}}}'),
      ]),
    ];
    for (const body of bodies) {
      const response = await send(f.origin, body, { raw: true, headers: { authorization } });
      assert.equal(response.status, 400, response.body);
      assert.match(response.body, /EK_GQL_VALIDATION/);
      assert.doesNotMatch(response.body, /arkenivaPolluted|__proto__|SyntaxError|Variable \$/);
      assert.equal(calls, 0);
      assert.equal(
        Object.getOwnPropertyDescriptor(Object.prototype, 'arkenivaPolluted'),
        undefined,
      );
    }
    const good = await send(
      f.origin,
      { query, variables: { input: { needle: 'normal' } } },
      { headers: { authorization } },
    );
    assert.equal(good.status, 200, good.body);
    assert.equal(calls, 1);
  } finally {
    await f.close();
  }
});

test('Adversarial variable text remains a literal value and cannot add mutations, introspection or tenant authority', async () => {
  let reads = 0,
    writes = 0;
  const f = await fixture({
    schema: 'type Query { echo(value: String!): String! } type Mutation { reset: Int! }',
    resolvers: {
      Query: {
        echo: (_parent, args, context) => {
          assert.equal(context.auth!.tenantId, 'tenant-a');
          reads++;
          return args.value;
        },
      },
      Mutation: { reset: () => ++writes },
    },
    security: { authorizeField: ({ field }) => field.operation !== 'mutation' },
  });
  try {
    const headers = {
      authorization: await f.token(),
      'x-tenant-id': 'tenant-b',
      baggage: 'tenant_id=tenant-b,role=administrator',
    };
    const values = [
      '" } mutation { reset } #',
      '{ __schema { types { name } } }',
      "'; DROP TABLE customers; --",
      '{"tenantId":"tenant-b","scope":"admin"}',
      '__proto__.constructor.prototype',
      '🙂\\\u0000',
    ];
    for (const value of values) {
      const result = await send(
        f.origin,
        { query: 'query Literal($value: String!) { echo(value: $value) }', variables: { value } },
        { headers },
      );
      assert.equal(result.status, 200, result.body);
      assert.deepEqual(result.json(), { data: { echo: value } });
      assert.equal(writes, 0);
    }
    assert.equal(reads, values.length);
    assert.doesNotMatch(f.logs(), /DROP TABLE|constructor.prototype|tenant-b|Bearer /);
  } finally {
    await f.close();
  }
});

test(
  'An incomplete HTTP body releases the shared request without entering a resolver',
  { timeout: 10000 },
  async () => {
    let calls = 0;
    const f = await fixture({
      schema: 'type Query { ping: String! }',
      resolvers: {
        Query: {
          ping: () => {
            calls++;
            return 'pong';
          },
        },
      },
      security: { authorizeField: () => true },
    });
    const url = new URL(f.origin),
      socket = connect(Number(url.port), url.hostname);
    socket.on('error', () => {});
    try {
      await once(socket, 'connect');
      socket.write(
        'POST /graphql HTTP/1.1\r\nHost: ' +
          url.host +
          '\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"query":',
      );
      for (let i = 0; i < 100 && f.api.stats().active === 0; i++) await setImmediate();
      assert.equal(f.api.stats().active, 1);
      socket.destroy();
      for (let i = 0; i < 100 && f.api.stats().active; i++) await setImmediate();
      assert.equal(f.api.stats().active, 0);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(calls, 0);
    } finally {
      socket.destroy();
      await f.close();
    }
  },
);
