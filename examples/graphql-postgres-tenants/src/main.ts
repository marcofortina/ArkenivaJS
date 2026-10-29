// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import type { Application, ApplicationOptions } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { graphqlPlugin, GRAPHQL_CAPABILITY } from '@arkenivajs/graphql';
import type { GraphqlRequestContext, GraphqlService } from '@arkenivajs/graphql';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import type { Writable } from 'node:stream';

interface Customer {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
}
interface Order {
  readonly id: string;
  readonly tenantId: string;
  readonly customerId: string;
  readonly total: string;
}
function page(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 100)
    throw new Error('The requested page size must be an integer between 1 and 100');
  return value;
}
function tenant(context: GraphqlRequestContext): string {
  if (!context.auth) throw new Error('A verified tenant is required');
  return context.auth.tenantId;
}

/** Compose public services over administrator-selected tables; requests cannot select SQL identifiers. */
export async function createCustomerExample(options: {
  readonly service: ApplicationOptions['service'];
  readonly http: NonNullable<ApplicationOptions['http']>;
  readonly issuer: string;
  readonly audience: string;
  readonly schema: string;
  readonly connectionStringEnv?: string;
  readonly allowInsecureLoopback?: boolean;
  readonly destination?: Writable;
}) {
  if (
    typeof options.schema !== 'string' ||
    !/^[a-z][a-z0-9_]{0,62}(?![\s\S])/u.test(options.schema)
  )
    throw new Error('The configured SQL schema identifier is invalid');
  const schema = options.schema;
  const app: Application = await createApplication({
    service: options.service,
    http: options.http,
    security: { issuer: options.issuer, audience: options.audience, algorithms: ['ES256'] },
    databases: {
      main: {
        driver: 'postgresql',
        connectionStringEnv: options.connectionStringEnv ?? 'ARKENIVA_POSTGRES_URL',
        poolMax: 2,
      },
    },
    plugins: [
      loggingPlugin(options.destination ? { destination: options.destination } : {}),
      securityPlugin({ allowInsecureLoopback: options.allowInsecureLoopback ?? false }),
      postgresPlugin(),
      apiPlugin({ dependencies: ['security', 'database-postgres'] }),
      graphqlPlugin({
        schema: `
          type Customer { id: ID! tenantId: String! name: String! orders(first: Int!): [Order!]! }
          type Order { id: ID! tenantId: String! total: String! }
          type Query { customer(id: ID!): Customer customers(first: Int!): [Customer!]! }
        `,
        resolvers: {
          Query: {
            customer: (_parent, args, context) =>
              app.sql.queryOne<Customer>(
                'main',
                {
                  text: `SELECT id, tenant_id AS "tenantId", name FROM ${schema}.customers WHERE tenant_id = :tenant AND id = :id`,
                  bindings: { tenant: tenant(context), id: String(args.id) },
                },
                { signal: context.signal },
              ),
            customers: async (_parent, args, context) =>
              (
                await app.sql.query<Customer>(
                  'main',
                  {
                    text: `SELECT id, tenant_id AS "tenantId", name FROM ${schema}.customers WHERE tenant_id = :tenant ORDER BY id LIMIT :limit`,
                    bindings: { tenant: tenant(context), limit: page(args.first) },
                  },
                  { signal: context.signal },
                )
              ).rows,
          },
        },
        loaders: {
          Customer: {
            orders: {
              maxBatchSize: 100,
              load: async (requests, context) => {
                if (requests.length === 0) return [];
                const ids = requests.map((request) => (request.parent as Customer).id),
                  sizes = requests.map((request) => page(request.args.first)),
                  bindings = Object.fromEntries(ids.map((id, index) => ['id' + index, id])),
                  placeholders = ids.map((_id, index) => ':id' + index),
                  rows = await app.sql.query<Order>(
                    'main',
                    {
                      text: `WITH ranked AS (
                        SELECT id, tenant_id AS "tenantId", customer_id AS "customerId", total::text AS total,
                          ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY id) AS position
                        FROM ${schema}.orders WHERE tenant_id = :tenant AND customer_id IN (${placeholders.join(',')})
                      ) SELECT id, "tenantId", "customerId", total FROM ranked WHERE position <= :limit ORDER BY "customerId", id`,
                      bindings: { ...bindings, tenant: tenant(context), limit: Math.max(...sizes) },
                    },
                    { signal: context.signal },
                  ),
                  grouped = new Map<string, Order[]>();
                for (const row of rows.rows) {
                  const group = grouped.get(row.customerId) ?? [];
                  group.push(row);
                  grouped.set(row.customerId, group);
                }
                return ids.map((id, index) => (grouped.get(id) ?? []).slice(0, sizes[index]));
              },
            },
          },
        },
        security: {
          auth: { required: true, scopes: ['customers.read'] },
          authorizeField: ({ context, field, parent }) => {
            if (!context.auth || !context.identity?.scopes.includes('customers.read')) return false;
            if (field.parentType === 'Query')
              return field.fieldName === 'customer' || field.fieldName === 'customers';
            return (parent as Customer | Order | null)?.tenantId === context.auth.tenantId;
          },
          limits: { maxCollectionItems: 100, maxComplexity: 5000 },
        },
      }),
    ],
  });
  return { app, service: () => app.resolve<GraphqlService>(GRAPHQL_CAPABILITY) };
}
