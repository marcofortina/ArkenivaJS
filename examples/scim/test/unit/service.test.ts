// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createScimService } from '@arkenivajs/security-scim';
import type { ScimRecord } from '@arkenivajs/security-scim';
import { fixture } from '../fixture.js';

const user = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName: 'fixture-user',
  externalId: 'external-fixture',
  active: true,
};
const changes = (value: boolean) => ({
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations: [{ op: 'replace', path: 'active', value }],
});
test('Actual signed bearer authorization gates discovery and complete User CRUD with native schema validation', async () => {
  const f = await fixture();
  try {
    for (const path of [
      '/Schemas',
      '/Schemas/' + encodeURIComponent(user.schemas[0]!),
      '/ResourceTypes',
      '/ResourceTypes/User',
      '/ServiceProviderConfig',
    ])
      assert.equal((await f.service.handle(await f.request('GET', path))).status, 200, path);
    const created = await f.service.handle(await f.request('POST', '/Users', user));
    assert.equal(created.status, 201);
    const value = created.body as ScimRecord;
    assert.ok(value.id);
    assert.ok(created.headers.etag);
    const duplicate = await f.service.handle(await f.request('POST', '/Users', user));
    assert.equal((duplicate.body as ScimRecord).id, value.id);
    const read = await f.service.handle(await f.request('GET', '/Users/' + value.id));
    assert.equal(read.status, 200);
    const replaced = await f.service.handle(
      await f.request('PUT', '/Users/' + value.id, { ...user, displayName: 'Updated fixture' }),
    );
    assert.equal(replaced.status, 200);
    const request = await f.request('PATCH', '/Users/' + value.id, changes(false));
    const patched = await f.service.handle({
      ...request,
      headers: { ...request.headers, 'if-match': replaced.headers.etag },
    });
    assert.equal(patched.status, 200);
    assert.equal((patched.body as ScimRecord).active, false);
    const conflict = await f.service.handle({
      ...request,
      headers: { ...request.headers, 'if-match': replaced.headers.etag },
    });
    assert.equal(conflict.status, 412);
    const listed = await f.service.handle(
      await f.request(
        'GET',
        '/Users?filter=active%20eq%20false&startIndex=1&count=1&sortBy=userName&sortOrder=descending',
      ),
    );
    assert.equal(listed.status, 200);
    assert.equal((listed.body as { totalResults: number }).totalResults, 1);
    assert.equal((await f.service.handle(await f.request('GET', '/Users?count=0'))).status, 200);
    assert.equal(
      (await f.service.handle(await f.request('DELETE', '/Users/' + value.id))).status,
      204,
    );
    assert.equal(
      (await f.service.handle(await f.request('GET', '/Users/' + value.id))).status,
      404,
    );
  } finally {
    await f.close();
  }
});

test('Manual tenant objects, foreign bearer bindings, missing scopes and failed independent authority never reach storage', async () => {
  const f = await fixture();
  try {
    const request = await f.request('GET', '/Users'),
      before = f.calls();
    for (const input of [
      { ...request, auth: { ...request.auth } },
      { ...request, headers: { 'content-type': 'application/scim+json' } },
      { ...request, headers: { ...request.headers, authorization: 'Bearer invalid' } },
    ])
      assert.ok([401, 403].includes((await f.service.handle(input)).status));
    const foreign = await f.request('GET', '/Users', undefined, 'tenant-b');
    assert.equal((await f.service.handle({ ...request, headers: foreign.headers })).status, 403);
    assert.equal(
      (
        await f.service.handle(
          await f.request('POST', '/Users', user, 'tenant-a', 'scim:users:read'),
        )
      ).status,
      403,
    );
    f.authorized(false);
    assert.equal((await f.service.handle(request)).status, 403);
    assert.equal(f.calls(), before);
    const missing = createScimService({ environment: 'test' });
    missing.registerUsers(f.provider('Users'));
    assert.equal((await missing.handle(request)).status, 403);
  } finally {
    await f.close();
  }
});

test('Foreign tenant IDs, privileged writes, immutable external mappings and storage errors fail closed', async () => {
  const f = await fixture();
  try {
    const created = await f.service.handle(await f.request('POST', '/Users', user)),
      id = (created.body as ScimRecord).id;
    assert.equal(
      (await f.service.handle(await f.request('GET', '/Users/' + id, undefined, 'tenant-b')))
        .status,
      403,
    );
    assert.equal(
      (await f.service.handle(await f.request('PATCH', '/Users/' + id, changes(false), 'tenant-b')))
        .status,
      403,
    );
    assert.equal(
      (
        await f.service.handle(
          await f.request('POST', '/Users', {
            ...user,
            externalId: 'privileged',
            roles: [{ value: 'admin' }],
          }),
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await f.service.handle(
          await f.request('PUT', '/Users/' + id, { ...user, externalId: 'replacement' }),
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await f.service.handle(
          await f.request('POST', '/Users', { ...user, externalId: 'different' }),
        )
      ).status,
      409,
    );
    f.storageAvailable(false);
    const result = await f.service.handle(await f.request('GET', '/Users/' + id));
    assert.equal(result.status, 503);
    assert.ok(!JSON.stringify(result).includes('private-storage-credential'));
  } finally {
    await f.close();
  }
});

test('Invalid filters, headers, paging, bodies and deadlines reject before provider dispatch', async () => {
  const f = await fixture();
  try {
    for (const path of [
      '/Users?count=0.5',
      '/Users?count=101',
      '/Users?startIndex=0',
      '/Users?filter=active%20eq',
      '/Users?count=1&count=2',
      '/Users?unknown=x',
      '/Users?sortOrder=descending',
      '/Users?filter=password%20pr',
      '/Users?sortBy=password',
      '/Users?filter=userName%20eq%20%22fixture%22%20and',
    ])
      assert.equal((await f.service.handle(await f.request('GET', path))).status, 400, path);
    const request = await f.request('GET', '/Users');
    assert.equal(
      (
        await f.service.handle({
          ...request,
          headers: { ...request.headers, Authorization: request.headers.authorization },
        })
      ).status,
      400,
    );
    for (const timeoutMs of [0, -1, 0.5, Infinity, NaN, 30001])
      await assert.rejects(f.service.handle(request, { timeoutMs }), { code: 'EK_CONFIG_INVALID' });
    await assert.rejects(f.service.handle(request, { signal: AbortSignal.abort() }), {
      code: 'EK_ABORTED',
    });
    assert.equal(
      (
        await f.service.handle(
          await f.request('POST', '/Users', { ...user, extra: 'x'.repeat(262145) }),
        )
      ).status,
      400,
    );
    assert.equal(f.calls(), 0);
    assert.throws(() => f.service.registerGroups(f.provider('Groups')), {
      code: 'EK_LIFECYCLE_STATE',
    });
  } finally {
    await f.close();
  }
});
