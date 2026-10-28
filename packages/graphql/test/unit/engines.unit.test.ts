// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import mercurius from 'mercurius';

test('The pinned upstream engines execute variables and reject invalid documents on the existing Fastify major', async () => {
  const server = Fastify({ logger: false });
  let executed = 0;
  try {
    await server.register(mercurius, {
      schema: 'type Query { echo(value: String!): String! }',
      resolvers: {
        Query: {
          echo: (_parent, args: { value: string }) => {
            executed++;
            return args.value;
          },
        },
      },
      graphiql: false,
      jit: 0,
      allowBatchedQueries: false,
    });
    const accepted = await server.inject({
      method: 'POST',
      url: '/graphql',
      payload: {
        query: 'query Echo($value: String!) { echo(value: $value) }',
        variables: { value: 'owned-engine-probe' },
        operationName: 'Echo',
      },
    });
    assert.equal(accepted.statusCode, 200);
    assert.deepEqual(accepted.json(), { data: { echo: 'owned-engine-probe' } });
    const rejected = await server.inject({
      method: 'POST',
      url: '/graphql',
      payload: { query: 'query { unknownField }' },
    });
    assert.equal(rejected.statusCode, 400);
    assert.ok(rejected.json<{ errors: unknown[] }>().errors.length > 0);
    assert.equal(executed, 1, 'Schema validation must reject before resolver execution');
  } finally {
    await server.close();
  }
});
