// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { URLSearchParams } from 'node:url';
import { KitError } from '@arkenivajs/core';
import SCIMMY from 'scimmy';
import { nativeAuth, authConnection } from './auth-workload.mjs';

let appOwner;
export const rememberScimOwner = (app) => {
  appOwner = app;
};
export function scimConnection(fixture) {
  const url = new URL(fixture.bridgeUrl);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && fixture.bridgeUrl === url.origin);
  authConnection(fixture);
  return url;
}
export async function grantScim(fixture) {
  scimConnection(fixture);
  const response = await globalThis.fetch(fixture.bridgeUrl + '/grant', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + fixture.bridgeKey },
    signal: AbortSignal.timeout(3000),
    redirect: 'error',
  });
  assert.equal(response.status, 200);
  fixture.grant = await response.json();
  assert.match(fixture.grant.tenant, /^scim-[a-f0-9]{24}$/);
}

function remoteProvider(fixture, kind) {
  const arities = { list: 1, get: 1, create: 1, replace: 3, patch: 3, delete: 2 };
  return {
    usage: 'test-only',
    ...Object.fromEntries(
      Object.entries(arities).map(([operation, arity]) => [
        operation,
        async (...args) => {
          const response = await globalThis.fetch(fixture.bridgeUrl + '/provider', {
            method: 'POST',
            headers: {
              authorization: 'Bearer ' + fixture.grant.token,
              'content-type': 'application/json',
            },
            body: JSON.stringify({ operation, kind, args: args.slice(0, arity) }),
            signal: AbortSignal.timeout(4000),
            redirect: 'error',
          });
          if (response.status === 503)
            throw new KitError({
              code: 'EK_BACKEND_UNAVAILABLE',
              message: 'The owned SCIM provider is unavailable',
            });
          assert.ok([200, 409].includes(response.status));
          const value = await response.json();
          if (value.code)
            throw new KitError({
              code: value.code,
              message: 'The owned SCIM provider rejected the operation',
            });
          return value.value;
        },
      ]),
    ),
  };
}

export function scimSettings(fixture) {
  scimConnection(fixture);
  return {
    users: remoteProvider(fixture, 'Users'),
    groups: remoteProvider(fixture, 'Groups'),
    authority: {
      usage: 'test-only',
      async require(action, subject, context) {
        assert.ok(/^scim\.(?:users|groups)\.(?:read|write)$|^scim\.discovery$/.test(action));
        const tenant = context?.tenant;
        assert.equal(appOwner.auth.tenantFrom(tenant.identity), tenant);
        assert.equal(tenant.tenantId, fixture.grant.tenant);
        assert.equal(subject.issuer, fixture.issuer);
        assert.equal(subject.subject, 'synthetic-user');
        return { ...subject, tenant };
      },
    },
    capabilities: { patch: true, bulk: false, filter: true, sort: true, etag: true },
    maxPageSize: 100,
    maxFilterDepth: 8,
    maxRequestBytes: 262144,
    maxConcurrent: 8,
  };
}

const user = (value, direction = 'out') =>
  JSON.parse(JSON.stringify(new SCIMMY.Schemas.User(value, direction)));
const patchSchema = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const userSchema = 'urn:ietf:params:scim:schemas:core:2.0:User';

/** A valid-request reference shares the application SQL provider while native SCIMMY owns schema/PATCH grammar. */
export async function nativeScim(fixture) {
  await grantScim(fixture);
  const auth = nativeAuth({ ...fixture, tenant: fixture.grant.tenant }),
    provider = remoteProvider(fixture, 'Users');
  return {
    auth: () => auth,
    async handle(request) {
      try {
        const identity = await auth.verifyBearer(request.headers.authorization);
        const tenant = auth.tenantFrom(identity),
          method = request.method;
        auth.requireScope(identity, 'scim:users:' + (method === 'GET' ? 'read' : 'write'));
        const url = new URL(request.path, 'https://scim.invalid');
        assert.equal(url.origin, 'https://scim.invalid');
        const parts = url.pathname.split('/').filter(Boolean);
        assert.equal(parts[0], 'Users');
        assert.ok(parts.length <= 2);
        const id = parts[1],
          version = request.headers['if-match'];
        const response = (status, body) => ({
          status,
          body,
          headers: body?.meta?.version ? { etag: body.meta.version } : {},
        });
        if (method === 'POST' && !id)
          return response(
            201,
            user(await provider.create({ ...user(request.body, 'in'), id: randomUUID() }, tenant)),
          );
        if (method === 'GET' && !id) {
          const expression = url.searchParams.get('filter');
          new SCIMMY.Types.Filter(expression);
          const page = await provider.list(
            {
              expression,
              startIndex: Number(url.searchParams.get('startIndex') ?? '1'),
              count: Number(url.searchParams.get('count') ?? '100'),
            },
            tenant,
          );
          return response(200, {
            schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            ...page,
          });
        }
        assert.ok(id);
        const stored = await provider.get(id, tenant);
        if (stored === null) return response(404, null);
        const before = user(stored);
        if (method === 'GET') return response(200, before);
        if (version !== undefined && version !== '*' && version !== before.meta.version)
          return response(412, null);
        if (method === 'DELETE') {
          await provider.delete(id, version, tenant);
          return response(204, null);
        }
        assert.equal(method, 'PATCH');
        new SCIMMY.Messages.PatchOp(request.body);
        return response(200, user(await provider.patch(id, request.body, version, tenant)));
      } catch (cause) {
        const statuses = {
          EK_SCIM_PRECONDITION: 412,
          EK_SCIM_CONFLICT: 409,
          EK_SCIM_UNAUTHORIZED: 403,
          EK_HTTP_NOT_FOUND: 404,
        };
        return { status: statuses[cause.code] ?? 503, body: null, headers: {} };
      }
    },
  };
}

export async function verifyScim(service, fixture) {
  const auth = service.auth ? service.auth() : appOwner.auth;
  const identity = await auth.verifyBearer('Bearer ' + fixture.grant.token),
    tenant = auth.tenantFrom(identity);
  const request = (method, path, body, etag) =>
    service.handle({
      method,
      path,
      body,
      auth: tenant,
      headers: {
        authorization: 'Bearer ' + fixture.grant.token,
        'content-type': 'application/scim+json',
        ...(etag ? { 'if-match': etag } : {}),
      },
    });
  const body = {
    schemas: [userSchema],
    userName: fixture.marker,
    externalId: fixture.grant.externalId,
    active: true,
  };
  const created = await request('POST', '/Users', body);
  assert.equal(created.status, 201);
  const id = created.body.id;
  assert.match(id, /^[a-f0-9-]{36}$/);
  assert.equal(created.headers.etag, '"1"');
  const retries = await Promise.all([
    request('POST', '/Users', body),
    request('POST', '/Users', body),
  ]);
  for (const result of retries) {
    assert.equal(result.status, 201);
    assert.equal(result.body.id, id);
    assert.equal(result.headers.etag, '"1"');
  }
  const read = await request('GET', '/Users/' + id);
  assert.equal(read.status, 200);
  assert.equal(read.body.active, true);
  const query = new URLSearchParams({
    filter: 'userName eq ' + JSON.stringify(fixture.marker),
    startIndex: '1',
    count: '1',
  });
  const page = await request('GET', '/Users?' + query);
  assert.equal(page.status, 200);
  assert.equal(page.body.startIndex, 1);
  assert.equal(page.body.itemsPerPage, 1);
  assert.equal(page.body.totalResults, 1);
  assert.equal(page.body.Resources[0].id, id);
  const operations = (value) => ({
    schemas: [patchSchema],
    Operations: [{ op: 'replace', path: 'displayName', value }],
  });
  const updated = await request(
    'PATCH',
    '/Users/' + id,
    operations('Unicode π 😀'),
    created.headers.etag,
  );
  assert.equal(updated.status, 200);
  assert.equal(updated.body.displayName, 'Unicode π 😀');
  assert.equal(updated.headers.etag, '"2"');
  const race = await Promise.all(
    ['first', 'second'].map((value) =>
      request('PATCH', '/Users/' + id, operations(value), updated.headers.etag),
    ),
  );
  assert.deepEqual(race.map((result) => result.status).toSorted(), [200, 412]);
  const winner = race.find((result) => result.status === 200);
  assert.equal(winner.headers.etag, '"3"');
  const persisted = await request('GET', '/Users/' + id);
  assert.equal(persisted.status, 200);
  assert.equal(persisted.body.displayName, winner.body.displayName);
  assert.equal(persisted.headers.etag, winner.headers.etag);
  assert.equal(
    (await request('DELETE', '/Users/' + id, undefined, winner.headers.etag)).status,
    204,
  );
  assert.equal((await request('GET', '/Users/' + id)).status, 404);
  const empty = await request('GET', '/Users?' + query);
  assert.equal(empty.status, 200);
  assert.equal(empty.body.totalResults, 0);
  assert.deepEqual(empty.body.Resources, []);
  return {
    actualDurableCrudVerified: true,
    idempotentCreateRetries: 2,
    atomicEtagWinners: 1,
    exactNativePatchAndPagination: true,
    deletedResourceNotReturned: true,
  };
}
