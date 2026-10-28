// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import type { ApplicationOptions } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { graphqlPlugin, GRAPHQL_CAPABILITY } from '@arkenivajs/graphql';
import type { GraphqlService } from '@arkenivajs/graphql';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import type { Writable } from 'node:stream';

/** Small application-owned demonstration store; deploy an independently authorized shared data layer. */
export async function createGraphqlExample(options: {
  readonly service: ApplicationOptions['service'];
  readonly http: NonNullable<ApplicationOptions['http']>;
  readonly issuer: string;
  readonly audience: string;
  readonly allowInsecureLoopback?: boolean;
  readonly destination?: Writable;
}) {
  const counters = new Map([
    ['tenant-a', 0],
    ['tenant-b', 0],
  ]);
  const records = [
    { id: '1', tenant: 'tenant-a', label: 'First customer' },
    { id: '2', tenant: 'tenant-b', label: 'Second customer' },
  ];
  let privateReads = 0;
  const app = await createApplication({
    service: options.service,
    http: options.http,
    security: { issuer: options.issuer, audience: options.audience, algorithms: ['ES256'] },
    plugins: [
      loggingPlugin(options.destination ? { destination: options.destination } : {}),
      securityPlugin({ allowInsecureLoopback: options.allowInsecureLoopback ?? false }),
      apiPlugin({ dependencies: ['security'] }),
      graphqlPlugin({
        schema: `
          type Customer { id: ID! label: String! privateNote: String }
          type Query { tenant: String! counter: Int! customer(id: ID!): Customer }
          type Mutation { increment: Int! }
        `,
        resolvers: {
          Query: {
            tenant: (_parent, _args, context) => context.auth!.tenantId,
            counter: (_parent, _args, context) => counters.get(context.auth!.tenantId),
            customer: (_parent, args, context) => {
              const row = records.find(
                (candidate) =>
                  candidate.id === args.id && candidate.tenant === context.auth!.tenantId,
              );
              return row
                ? {
                    id: row.id,
                    label: row.label,
                    get privateNote() {
                      privateReads++;
                      return 'private demonstration field';
                    },
                  }
                : null;
            },
          },
          Mutation: {
            increment: (_parent, _args, context) => {
              const tenant = context.auth!.tenantId,
                next = counters.get(tenant)! + 1;
              counters.set(tenant, next);
              return next;
            },
          },
        },
        security: {
          auth: { required: true, scopes: ['example:read'] },
          authorizeField: ({ context, field }) =>
            !!context.auth &&
            counters.has(context.auth.tenantId) &&
            field.fieldName !== 'privateNote' &&
            !!context.identity?.scopes.includes(
              field.operation === 'mutation' ? 'example:write' : 'example:read',
            ),
        },
      }),
    ],
  });
  app.api.get('/status', {
    auth: { required: false },
    schema: {
      response: {
        type: 'object',
        properties: { ready: { type: 'boolean' } },
        required: ['ready'],
        additionalProperties: false,
      },
    },
    handler: () => ({ ready: true }),
  });
  return {
    app,
    service: () => app.resolve<GraphqlService>(GRAPHQL_CAPABILITY),
    privateReads: () => privateReads,
  };
}
