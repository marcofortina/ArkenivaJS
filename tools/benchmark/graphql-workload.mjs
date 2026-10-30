// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import Fastify from 'fastify';
import mercurius from 'mercurius';
import { GraphQLError } from 'graphql';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export const GRAPHQL_COMPARISON = Symbol('graphql.comparison');

export function graphqlCoordinates(fixture) {
  const issuer = new URL(fixture.issuer);
  assert.equal(issuer.protocol, 'http:');
  assert.equal(issuer.hostname, '127.0.0.1');
  assert.ok(issuer.port && !issuer.username && !issuer.password && !issuer.search && !issuer.hash);
  assert.equal(issuer.pathname, '/');
  for (const path of [fixture.privateKeyFile, fixture.certificateFile])
    assert.ok(typeof path === 'string' && path.startsWith('/') && !/[\0\r\n]/.test(path));
  assert.ok(typeof fixture.ca === 'string' && fixture.ca.length > 0);
}

/** Fixed application memory and idempotency are shared only within one owned server instance. */
export function graphqlCorpus(fixture) {
  graphqlCoordinates(fixture);
  const counters = new Map([
      [fixture.tenant, 0],
      [fixture.otherTenant, 0],
    ]),
    receipts = new Map();
  let mutations = 0,
    privateReads = 0;
  const denied = () =>
    new GraphQLError('The field is forbidden', {
      extensions: { code: 'EK_GQL_FORBIDDEN' },
    });
  const authorized = (context, mutation = false) =>
    !!context.auth &&
    counters.has(context.auth.tenantId) &&
    context.identity.scopes.includes(mutation ? 'orders:write' : 'orders:read');
  const resolvers = {
    Query: {
      counter(_parent, _args, context) {
        if (!authorized(context)) throw denied();
        return counters.get(context.auth.tenantId);
      },
      customer(_parent, args, context) {
        if (!authorized(context)) throw denied();
        const id = context.auth.tenantId === fixture.tenant ? '1' : '2';
        return args.id !== id
          ? null
          : {
              id,
              label: fixture.marker,
              get privateNote() {
                privateReads++;
                return fixture.privateMarker;
              },
            };
      },
    },
    Mutation: {
      increment(_parent, args, context) {
        if (!authorized(context, true)) throw denied();
        const key = JSON.stringify([context.auth.tenantId, args.key]);
        if (receipts.has(key)) return receipts.get(key);
        if (receipts.size >= 4) throw new GraphQLError('The receipt capacity is exhausted');
        const value = counters.get(context.auth.tenantId) + 1;
        counters.set(context.auth.tenantId, value);
        receipts.set(key, value);
        mutations++;
        return value;
      },
    },
  };
  return {
    schema:
      'type Customer { id: ID! label: String! privateNote: String } type Query { counter: Int! customer(id: ID!, tenantHint: String): Customer } type Mutation { increment(key: ID!): Int! }',
    resolvers,
    authorized,
    denied,
    stats: () => ({ mutations, privateReads, receipts: receipts.size }),
  };
}

/** Direct Mercurius retains verified JWT admission and explicit field/row authorization. */
export async function nativeGraphql(fixture) {
  const corpus = graphqlCorpus(fixture),
    keys = createRemoteJWKSet(new URL('/keys', fixture.issuer)),
    server = Fastify({
      logger: false,
      https: {
        key: await readFile(fixture.privateKeyFile),
        cert: await readFile(fixture.certificateFile),
      },
    });
  server.decorateRequest('comparisonContext', null);
  server.addHook('preValidation', async (incoming, reply) => {
    try {
      const header = incoming.headers.authorization;
      assert.ok(typeof header === 'string' && /^Bearer [^\s]+$/.test(header));
      const { payload } = await jwtVerify(header.slice(7), keys, {
        issuer: fixture.issuer,
        audience: fixture.audience,
        algorithms: ['RS256'],
        requiredClaims: ['sub', 'exp', 'tenant_id'],
      });
      assert.ok([fixture.tenant, fixture.otherTenant].includes(payload.tenant_id));
      const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
      assert.ok(scopes.includes('orders:read'));
      incoming.comparisonContext = { identity: { scopes }, auth: { tenantId: payload.tenant_id } };
    } catch {
      return reply.code(401).send({ errors: [{ message: 'Authentication required' }] });
    }
  });
  try {
    await server.register(mercurius, {
      schema: corpus.schema,
      resolvers: {
        ...corpus.resolvers,
        Customer: {
          privateNote() {
            throw corpus.denied();
          },
        },
      },
      context: (incoming) => incoming.comparisonContext,
      graphiql: false,
      jit: 0,
    });
    const address = await server.listen({ host: '127.0.0.1', port: 0 });
    return { api: { address: () => address }, stats: corpus.stats, close: () => server.close() };
  } catch (error) {
    await server.close();
    throw error;
  }
}

/** Native HTTPS client verifies the fixture certificate for every public operation. */
export function graphqlRequest(service, fixture, body, token) {
  const target = new URL(service.api.address() + '/graphql');
  assert.equal(target.protocol, 'https:');
  assert.equal(target.hostname, '127.0.0.1');
  return new Promise((resolve, reject) => {
    const outgoing = request(
      target,
      {
        method: 'POST',
        ca: Buffer.from(fixture.ca, 'base64'),
        headers: {
          'content-type': 'application/json',
          'x-tenant-id': fixture.otherTenant,
          ...(token ? { authorization: 'Bearer ' + token } : {}),
        },
        signal: AbortSignal.timeout(3000),
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 65536) response.destroy(new Error('The GraphQL response exceeded its bound'));
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          try {
            resolve({
              status: response.statusCode,
              body: JSON.parse(Buffer.concat(chunks).toString()),
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    outgoing.once('error', reject);
    outgoing.end(JSON.stringify(body));
  });
}

export async function verifyGraphql(service, fixture) {
  const send = (body, token = fixture.token) => graphqlRequest(service, fixture, body, token),
    mutation = { query: 'mutation { increment(key:"same-owned-action") }' };
  for (const token of ['', fixture.invalidToken, fixture.foreignTenantToken])
    assert.equal((await send(mutation, token)).status, 401);
  assert.deepEqual(service.stats(), { mutations: 0, privateReads: 0, receipts: 0 });
  const query = await send({
    query:
      'query Detail($id:ID!,$hint:String){ own:customer(id:$id,tenantHint:$hint){...Row privateNote} counter } fragment Row on Customer { id label }',
    variables: { id: '1', hint: fixture.otherTenant },
    operationName: 'Detail',
  });
  assert.equal(query.status, 200);
  assert.deepEqual(query.body.data, {
    own: { id: '1', label: fixture.marker, privateNote: null },
    counter: 0,
  });
  assert.equal(query.body.errors.length, 1);
  assert.equal(query.body.errors[0].extensions.code, 'EK_GQL_FORBIDDEN');
  assert.equal((await send({ query: '{ customer(id:"2"){ id } }' })).body.data.customer, null);
  const forbidden = await send(mutation, fixture.readOnlyToken);
  assert.equal(forbidden.body.data, null);
  assert.equal(forbidden.body.errors[0].extensions.code, 'EK_GQL_FORBIDDEN');
  for (const token of [fixture.token, fixture.token, fixture.otherTenantToken])
    assert.deepEqual((await send(mutation, token)).body, { data: { increment: 1 } });
  for (const token of [fixture.token, fixture.otherTenantToken])
    assert.deepEqual((await send({ query: '{ counter }' }, token)).body, { data: { counter: 1 } });
  assert.equal((await send({ query: '{' })).status, 400);
  assert.deepEqual(service.stats(), { mutations: 2, privateReads: 0, receipts: 2 });
  return {
    authenticatedRequests: 9,
    rejectedCredentials: 3,
    physicalMutations: 2,
    idempotencyReceipts: 2,
    deniedPrivateGetterReads: 0,
    isolatedTenants: 2,
  };
}
