// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  GraphqlPluginSettings,
  GraphqlAuthenticationPolicy,
  GraphqlFieldInfo,
  GraphqlService,
} from '../../dist/index.js';
import { GRAPHQL_CAPABILITY } from '../../dist/index.js';

const settings: GraphqlPluginSettings = {
  schema: 'type Query { ping: String! }',
  resolvers: { Query: { ping: () => 'pong' } },
  security: {
    auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public health probe' },
    authorizeField: ({ field }) => field.parentType === 'Query' && field.fieldName === 'ping',
    allowBatchedHttpRequests: false,
  },
  loaders: {
    Query: { ping: { load: async (requests) => requests.map(() => 'pong'), maxBatchSize: 100 } },
  },
};
// @ts-expect-error Anonymous operations cannot omit their explicit root-field policy.
const anonymous: GraphqlAuthenticationPolicy = { required: false };
const batched: GraphqlPluginSettings = {
  ...settings,
  // @ts-expect-error R8 permits one GraphQL operation per HTTP request.
  security: { ...settings.security, allowBatchedHttpRequests: true },
};
// @ts-expect-error Field authorization is required at every startup.
const unguarded: GraphqlPluginSettings = { ...settings, security: {} };
const field: GraphqlFieldInfo = {
  parentType: 'Query',
  fieldName: 'ping',
  operation: 'query',
  path: ['renamed', 0],
};
// @ts-expect-error Clients cannot mutate the trusted response path.
field.path.push('unsafe');
const capability: symbol = GRAPHQL_CAPABILITY;
declare const service: GraphqlService;
const schema: string = service.schemaSdl();
void settings;
void anonymous;
void batched;
void unguarded;
void capability;
void schema;
