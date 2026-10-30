// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createScimService } from '../../dist/index.js';
import { capture, provider, testOnly } from '../../dist/settings.js';
import type { ScimProvider, ScimRecord } from '../../dist/index.js';
import { fixture } from '../fixture.js';

const user = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName: 'bounded-user',
  externalId: 'bounded-external',
  active: true,
};
const patch = {
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations: [{ op: 'replace', path: 'active', value: false }],
};

test('SCIM rejects incoherent provider IDs, ETags, external mappings and pages without returning partial resources', async () => {
  const f = await fixture();
  try {
    const created = await f.service.handle(await f.request('POST', '/Users', user)),
      record = created.body as ScimRecord,
      original = f.provider('Users');
    assert.equal(created.status, 201);
    const build = (overrides: Partial<ScimProvider>) => {
      const service = createScimService(f.settings);
      service.registerUsers({ ...original, ...overrides });
      service.registerGroups(f.provider('Groups'));
      return service;
    };
    for (const transform of [
      (value: ScimRecord) => ({ ...value, id: randomUUID() }),
      (value: ScimRecord) => {
        const { meta, ...rest } = value;
        void meta;
        return rest;
      },
      (value: ScimRecord) => ({ ...value, meta: { ...value.meta, version: 'unquoted' } }),
    ]) {
      const service = build({
        async get(...args) {
          const result = await original.get(...args);
          assert.ok(result);
          return transform(result);
        },
      });
      const methods =
        transform(record).id !== record.id
          ? (['GET', 'PUT', 'PATCH', 'DELETE'] as const)
          : (['GET'] as const);
      for (const method of methods) {
        const response = await service.handle(
          await f.request(
            method,
            '/Users/' + record.id,
            method === 'PUT' ? user : method === 'PATCH' ? patch : undefined,
          ),
        );
        assert.equal(response.status, 503);
      }
    }
    const restore = await f.service.handle(await f.request('POST', '/Users', user));
    assert.equal(restore.status, 201);
    const target = restore.body as ScimRecord;
    for (const method of ['PUT', 'PATCH'] as const) {
      const service = build({
        async replace(...args) {
          const result = await original.replace(...args);
          return { ...result, externalId: 'foreign-external' };
        },
        async patch(...args) {
          const result = await original.patch(...args);
          return { ...result, id: randomUUID() };
        },
      });
      const response = await service.handle(
        await f.request(method, '/Users/' + target.id, method === 'PUT' ? user : patch),
      );
      assert.equal(response.status, 503);
      assert.equal(JSON.stringify(response.body).includes('foreign-external'), false);
    }
    for (const change of [
      { startIndex: 2 },
      { itemsPerPage: 2 },
      { totalResults: -1 },
      { Resources: [record, record], itemsPerPage: 2 },
    ]) {
      const service = build({
        async list(...args) {
          return { ...(await original.list(...args)), ...change } as never;
        },
      });
      const response = await service.handle(await f.request('GET', '/Users?count=1'));
      assert.ok(response.status >= 400);
      assert.equal('Resources' in (response.body as object), false);
    }
  } finally {
    await f.close();
  }
});

test('SCIM create receipts cannot replace an external mapping and missing providers fail closed', async () => {
  const f = await fixture();
  try {
    const missing = createScimService(f.settings);
    assert.equal((await missing.handle(await f.request('GET', '/Users'))).status, 503);
    const original = f.provider('Users'),
      service = createScimService(f.settings);
    service.registerUsers({
      ...original,
      async create(...args) {
        const result = await original.create(...args);
        return { ...result, externalId: 'replacement-external' };
      },
    });
    const response = await service.handle(await f.request('POST', '/Users', user));
    assert.equal(response.status, 503);
    assert.equal(JSON.stringify(response.body).includes('replacement-external'), false);
  } finally {
    await f.close();
  }
});

test('SCIM runtime authorization cannot be replaced by another verified subject, tenant or structural hint', async () => {
  const f = await fixture();
  try {
    const request = await f.request('GET', '/Users'),
      foreign = await f.request('GET', '/Users', undefined, 'tenant-b');
    for (const decision of [
      null,
      { issuer: 'foreign', subject: request.auth.identity.subject, tenant: request.auth },
      { issuer: request.auth.identity.issuer, subject: 'foreign', tenant: request.auth },
      {
        issuer: request.auth.identity.issuer,
        subject: request.auth.identity.subject,
        tenant: foreign.auth,
      },
      {
        issuer: request.auth.identity.issuer,
        subject: request.auth.identity.subject,
        tenant: { ...request.auth },
      },
      {
        issuer: request.auth.identity.issuer,
        subject: request.auth.identity.subject,
        tenant: { identity: {} },
      },
    ]) {
      const service = createScimService({
        ...f.settings,
        authority: {
          async require() {
            return decision as never;
          },
        },
      });
      service.registerUsers(f.provider('Users'));
      assert.equal((await service.handle(request)).status, decision === null ? 400 : 403);
    }
    assert.equal(f.calls(), 0);
    const noRead = await f.request(
      'GET',
      '/ServiceProviderConfig',
      undefined,
      'tenant-a',
      'scim:users:write',
    );
    assert.equal((await f.service.handle(noRead)).status, 403);
  } finally {
    await f.close();
  }
});

test('SCIM mutation preconditions, immutable patch previews and absent content types reject without changing stored resources', async () => {
  const f = await fixture();
  try {
    const created = await f.service.handle(await f.request('POST', '/Users', user)),
      id = (created.body as ScimRecord).id;
    const request = await f.request('POST', '/Users', { ...user, externalId: 'other' });
    assert.equal(
      (
        await f.service.handle({
          ...request,
          headers: { authorization: request.headers.authorization },
        })
      ).status,
      400,
    );
    assert.equal(
      (await f.service.handle(await f.request('POST', '/Users/' + id, user))).status,
      400,
    );
    const update = await f.request('PUT', '/Users/' + id, user);
    assert.equal(
      (
        await f.service.handle({
          ...update,
          headers: { ...update.headers, 'if-match': 'unquoted' },
        })
      ).status,
      412,
    );
    assert.equal(
      (
        await f.service.handle(
          await f.request('PATCH', '/Users/' + id, {
            ...patch,
            Operations: [{ op: 'replace', path: 'externalId', value: 'foreign-external' }],
          }),
        )
      ).status,
      400,
    );
    assert.equal(
      (await f.service.handle(await f.request('DELETE', '/Users/' + randomUUID()))).status,
      404,
    );
    const read = await f.request('GET', '/Users/' + id);
    const retained = await f.service.handle({
      ...read,
      headers: { ...read.headers, optional: undefined },
    });
    assert.equal(retained.status, 200);
    assert.equal((retained.body as ScimRecord).externalId, user.externalId);
    assert.equal(retained.headers.etag, created.headers.etag);
  } finally {
    await f.close();
  }
});

test('SCIM actual closed logger errors cannot alter fixed diagnostic outcomes', async () => {
  const { createLogger } = await import('@arkenivajs/logging'),
    { Writable } = await import('node:stream'),
    { recorder } = await import('../../dist/observation.js');
  const logger = createLogger({
    service: { name: 'scim-closed-observer', version: '1.0.0', environment: 'test' },
    level: 'debug',
    destination: new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
  });
  await logger.close();
  const observer = recorder({ logger }),
    label = { operation: 'get' as const, resource: 'Users' as const };
  assert.doesNotThrow(() => observer.active(1));
  assert.doesNotThrow(() => observer.payload(label, 'response', 1));
  assert.doesNotThrow(() => observer.complete(label, 1, 'EK_BACKEND_UNAVAILABLE', 503, false));
});

test('SCIM request headers enforce descriptor, case, byte and path boundaries before storage', async () => {
  const f = await fixture();
  let effects = 0;
  try {
    const request = await f.request('GET', '/Users');
    for (const headers of [
      null,
      { ...request.headers, [Symbol()]: 'value' },
      { ...request.headers, 'invalid header': 'value' },
      Object.defineProperty({ ...request.headers }, 'private', {
        get() {
          effects++;
          return 'value';
        },
      }),
      { ...request.headers, a: 'x'.repeat(16384), b: 'y'.repeat(16384) },
    ])
      assert.equal((await f.service.handle({ ...request, headers } as never)).status, 400);
    for (const path of [
      '//foreign.invalid/Users',
      '/Users#fragment',
      '/Users\\extra',
      '/Users/absent?count=1',
      '/Users?sortOrder=invalid&sortBy=userName',
      '/Users?startIndex=01',
    ])
      assert.ok((await f.service.handle({ ...request, path })).status >= 400);
    const discovery = await f.service.handle(await f.request('GET', '/Schemas/unknown'));
    assert.equal(discovery.status, 404);
    assert.equal(
      (await f.service.handle(await f.request('GET', '/ResourceTypes/unknown'))).status,
      404,
    );
    assert.equal(f.calls(), 0);
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});

test('SCIM provider classification remains bounded and descriptor-only outside test', async () => {
  const f = await fixture();
  let effects = 0;
  try {
    const source = f.provider('Users');
    assert.throws(() => provider(source, 'production'), { code: 'EK_CONFIG_INVALID' });
    for (const name of ['usage', 'securityLevel']) {
      const value = Object.defineProperty({}, name, {
        get() {
          effects++;
          return 'production';
        },
      });
      assert.throws(() => testOnly(value), { code: 'EK_CONFIG_INVALID' });
    }
    let chain: object = {};
    for (let i = 0; i < 33; i++) chain = Object.create(chain) as object;
    assert.throws(() => testOnly(chain), { code: 'EK_CONFIG_INVALID' });
    assert.equal(testOnly(null), false);
    assert.equal(capture({}).environment, 'production');
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
