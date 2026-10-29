// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { fixture } from '../fixture.js';

if (!process.env.ARKENIVA_POSTGRES_URL || process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
  throw new Error('The customer guide requires an explicitly disposable PostgreSQL endpoint');

test(
  'Public HTTPS customer guide batches 1 and 100 real PostgreSQL parents while isolating verified tenants',
  { timeout: 30000 },
  async (context) => {
    const schema = 'gql_' + randomBytes(12).toString('hex'),
      native = pg.Client.prototype.query;
    let statements = 0;
    // Count native business dispatch without substituting results or bypassing the server.
    context.mock.method(
      pg.Client.prototype,
      'query',
      function (this: pg.Client, ...args: unknown[]) {
        const query = args[0],
          text =
            typeof query === 'string'
              ? query
              : query && typeof query === 'object' && 'text' in query
                ? query.text
                : undefined;
        if (
          typeof text === 'string' &&
          /^(SELECT|WITH)\b/u.test(text) &&
          text.includes(schema + '.')
        )
          statements++;
        return Reflect.apply(native, this, args);
      },
    );
    const f = await fixture(schema);
    let created = false;
    try {
      const sql = f.app.sql;
      await sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
      created = true;
      await sql.execute('main', {
        text: `CREATE TABLE ${schema}.customers (id text NOT NULL, tenant_id text NOT NULL, name text NOT NULL, PRIMARY KEY (tenant_id,id))`,
      });
      await sql.execute('main', {
        text: `CREATE TABLE ${schema}.orders (id text NOT NULL, tenant_id text NOT NULL, customer_id text NOT NULL, total numeric(18,2) NOT NULL, PRIMARY KEY (tenant_id,id))`,
      });
      await sql.execute('main', {
        text: `CREATE INDEX ON ${schema}.orders (tenant_id,customer_id,id)`,
      });
      for (const tenant of ['tenant-a', 'tenant-b']) {
        await sql.execute('main', {
          text: `INSERT INTO ${schema}.customers SELECT lpad(id::text,3,'0'), :tenant, :tenant || '-customer-' || id FROM generate_series(1,100) AS id`,
          bindings: { tenant },
        });
        await sql.execute('main', {
          text: `INSERT INTO ${schema}.orders SELECT lpad(customer::text,3,'0') || '-' || item, :tenant, lpad(customer::text,3,'0'), CAST('9007199254740991.23' AS numeric) FROM generate_series(1,99) AS customer CROSS JOIN generate_series(1,3) AS item`,
          bindings: { tenant },
        });
      }
      await sql.execute('main', {
        text: `INSERT INTO ${schema}.customers VALUES ('foreign-only','tenant-b','foreign-private-name')`,
      });
      const query =
        'query Page($first: Int!) { customers(first:$first) { id tenantId name orders(first:2) { id tenantId total } } }';
      for (const tenant of ['tenant-a', 'tenant-b'])
        for (const first of [1, 100]) {
          const before = statements,
            response = await f.send(
              { query, variables: { first } },
              await f.token(tenant),
              '/graphql',
              'POST',
              true,
              { 'x-tenant-id': tenant === 'tenant-a' ? 'tenant-b' : 'tenant-a' },
            );
          assert.equal(response.status, 200, response.body);
          const result = JSON.parse(response.body) as {
            data: { customers: unknown[] };
            errors?: unknown;
          };
          assert.equal(result.errors, undefined, response.body);
          assert.deepEqual(
            result.data.customers,
            Array.from({ length: first }, (_, index) => {
              const id = String(index + 1).padStart(3, '0');
              return {
                id,
                tenantId: tenant,
                name: tenant + '-customer-' + (index + 1),
                orders:
                  index === 99
                    ? []
                    : [1, 2].map((item) => ({
                        id: id + '-' + item,
                        tenantId: tenant,
                        total: '9007199254740991.23',
                      })),
              };
            }),
          );
          assert.equal(
            statements - before,
            2,
            'Parent count must not create per-customer SQL dispatch',
          );
        }
      assert.equal(f.service().stats().loaderBatches, 4);
      const beforeForeign = statements,
        foreign = await f.send(
          { query: '{ customer(id:"foreign-only") { id name } }' },
          await f.token(),
        );
      assert.deepEqual(JSON.parse(foreign.body), { data: { customer: null } });
      assert.equal(statements - beforeForeign, 1);
      const beforeAliases = statements,
        aliases = await f.send(
          {
            query:
              '{ customer(id:"001") { small: orders(first:1) { id } large: orders(first:3) { id } } }',
          },
          await f.token(),
        );
      assert.deepEqual(JSON.parse(aliases.body), {
        data: {
          customer: {
            small: [{ id: '001-1' }],
            large: [{ id: '001-1' }, { id: '001-2' }, { id: '001-3' }],
          },
        },
      });
      assert.equal(statements - beforeAliases, 2);
      for (const [body, authorization] of [
        [{ query }, undefined],
        [{ query }, await f.token('tenant-a', 'other:read')],
        [{ query: 'query { customers(first:101) { id } }' }, await f.token()],
        [{ query: '{ __schema { queryType { name } } }' }, await f.token()],
      ] as const) {
        const before = statements,
          response = await f.send(body, authorization);
        assert.ok(response.status >= 400 || JSON.parse(response.body).errors, response.body);
        assert.equal(statements, before, 'Denied requests must not reach SQL');
      }
      await assert.rejects(() =>
        f.send({ query: '{ customer(id:"001") { id } }' }, undefined, '/graphql', 'POST', false),
      );
      assert.doesNotMatch(
        f.logs(),
        /foreign-private-name|tenant-a-customer-|tenant-b-customer-|9007199254740991\.23|Bearer /u,
      );
    } finally {
      try {
        if (created) await f.app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
      } finally {
        await f.close();
      }
    }
  },
);
