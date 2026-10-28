// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import type { Application } from '@arkenivajs/core';
import { fixture, send } from '../fixture.js';

if (!process.env.ARKENIVA_POSTGRES_URL || process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
  throw new Error(
    'GraphQL PostgreSQL integration requires an explicitly disposable verified endpoint',
  );

test(
  'GraphQL loads 100 tenant-isolated customers and orders using exactly two real PostgreSQL statements',
  { timeout: 30000 },
  async (context) => {
    const schema = `gql_${randomBytes(12).toString('hex')}`;
    assert.match(schema, /^gql_[0-9a-f]{24}$/);
    const marker = `/* ${schema} */`;
    const native = pg.Client.prototype.query;
    let statements = 0;
    // Observe actual native dispatch; every result still comes from the real PostgreSQL server.
    context.mock.method(
      pg.Client.prototype,
      'query',
      function (this: pg.Client, ...args: unknown[]) {
        const query = args[0];
        const text =
          typeof query === 'string'
            ? query
            : query && typeof query === 'object' && 'text' in query
              ? query.text
              : undefined;
        if (typeof text === 'string' && text.includes(marker)) statements++;
        return Reflect.apply(native, this, args);
      },
    );
    const f = await fixture(
      {
        schema:
          'type Order { description: String! } type Customer { id: Int! orders(first: Int!): [Order!]! } type Query { customers(first: Int!): [Customer!]! customer(id: Int!): Customer }',
        resolvers: {
          Query: {
            customers: async (_parent, args, request) =>
              (
                await sql.query<{ id: number }>(
                  'main',
                  {
                    text: `${marker} SELECT id FROM ${schema}.customers WHERE tenant = :tenant ORDER BY id LIMIT :count`,
                    bindings: { tenant: request.auth!.tenantId, count: args.first as number },
                  },
                  { signal: request.signal },
                )
              ).rows,
            customer: (_parent, args, request) =>
              sql.queryOne<{ id: number }>(
                'main',
                {
                  text: `${marker} SELECT id FROM ${schema}.customers WHERE tenant = :tenant AND id = :id`,
                  bindings: { tenant: request.auth!.tenantId, id: args.id as number },
                },
                { signal: request.signal },
              ),
          },
        },
        loaders: {
          Customer: {
            orders: {
              maxBatchSize: 100,
              load: async (requests, request) => {
                const ids = requests.map((item) => (item.parent as { id: number }).id);
                const rows = await sql.query<{ customer_id: number; description: string }>(
                  'main',
                  {
                    text: `${marker} SELECT customer_id, description FROM ${schema}.orders WHERE tenant = :tenant AND customer_id IN (SELECT value::integer FROM jsonb_array_elements_text(CAST(:ids AS jsonb))) ORDER BY customer_id`,
                    bindings: { tenant: request.auth!.tenantId, ids: JSON.stringify(ids) },
                  },
                  { signal: request.signal },
                );
                const grouped = new Map(rows.rows.map((row) => [row.customer_id, [row]]));
                return ids.map((id) => grouped.get(id) ?? []);
              },
            },
          },
        },
        security: { authorizeField: ({ context }) => !!context.auth },
      },
      {
        plugins: [postgresPlugin()],
        databases: {
          main: { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_POSTGRES_URL', poolMax: 2 },
        },
      },
    );
    const sql: Application['sql'] = f.app.sql;
    try {
      await sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
      await sql.execute('main', {
        text: `CREATE TABLE ${schema}.customers (id integer NOT NULL, tenant text NOT NULL, PRIMARY KEY (tenant, id))`,
      });
      await sql.execute('main', {
        text: `CREATE TABLE ${schema}.orders (customer_id integer NOT NULL, tenant text NOT NULL, description text NOT NULL)`,
      });
      for (const tenant of ['tenant-a', 'tenant-b']) {
        await sql.execute('main', {
          text: `INSERT INTO ${schema}.customers SELECT id, :tenant FROM generate_series(1, 100) AS id`,
          bindings: { tenant },
        });
        await sql.execute('main', {
          text: `INSERT INTO ${schema}.orders SELECT id, :tenant, :tenant || '-order-' || id FROM generate_series(1, 100) AS id`,
          bindings: { tenant },
        });
      }
      await sql.execute('main', {
        text: `INSERT INTO ${schema}.customers VALUES (9999, :tenant)`,
        bindings: { tenant: 'tenant-b' },
      });
      for (const [index, tenant] of ['tenant-a', 'tenant-b'].entries()) {
        const response = await send(
          f.origin,
          { query: '{ customers(first: 100) { id orders(first: 1) { description } } }' },
          {
            headers: {
              authorization: await f.token(tenant),
              'x-tenant-id': 'untrusted-foreign-tenant',
            },
          },
        );
        assert.equal(response.status, 200, response.body);
        const result = response.json() as {
          data: { customers: { id: number; orders: { description: string }[] }[] };
        };
        assert.equal(result.data.customers.length, 100);
        assert.deepEqual(
          result.data.customers,
          Array.from({ length: 100 }, (_, i) => ({
            id: i + 1,
            orders: [{ description: `${tenant}-order-${i + 1}` }],
          })),
        );
        assert.equal(
          statements,
          (index + 1) * 2,
          'The real native driver must dispatch exactly two business statements per request',
        );
      }
      assert.equal(f.service.stats().loaderBatches, 2);
      const foreign = await send(
        f.origin,
        { query: '{ customer(id: 9999) { id } }' },
        { headers: { authorization: await f.token() } },
      );
      assert.deepEqual(foreign.json(), { data: { customer: null } });
      assert.equal(statements, 5);
      assert.doesNotMatch(f.logs(), /tenant-a-order-|tenant-b-order-/);
    } finally {
      try {
        await sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
      } finally {
        await f.close();
      }
    }
  },
);
