// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthService } from '@arkenivajs/security';
import { createScimService } from '@arkenivajs/security-scim';
import type {
  ScimRecord,
  ScimHttpRequest,
  ScimProvider,
  TrustedSecurityAuthority,
} from '@arkenivajs/security-scim';
import { createPostgresScimProvider, createPostgresScimTables } from '../../dist/scim-provider.js';
import { securityStateFixture } from './security-state-fixture.js';
import { startMfaIssuer } from './mfa-issuer.js';

test(
  'Real PostgreSQL SCIM providers enforce atomic ETags, create idempotency, group membership and integration ownership',
  { timeout: 20000 },
  async () => {
    const backend = await securityStateFixture(),
      issuer = await startMfaIssuer();
    const auth = await createAuthService({
      issuer: issuer.authority,
      audience: 'api://mfa-fixture',
      environment: 'test',
      allowInsecureLoopback: true,
      algorithms: ['RS256'],
      authorizeTenant: (_identity, tenant) => ['tenant-a', 'tenant-b'].includes(tenant),
    });
    const authority: TrustedSecurityAuthority = {
      async require(_action, hint, context) {
        const tenant = context.tenant;
        if (
          !hint ||
          !tenant ||
          auth.tenantFrom(tenant.identity) !== tenant ||
          hint.issuer !== tenant.identity.issuer ||
          hint.subject !== tenant.identity.subject
        )
          throw new Error('The actual SCIM authority rejected the provisioning session');
        return { ...hint, tenant };
      },
    };
    const request = async (
      method: ScimHttpRequest['method'],
      path: string,
      body: unknown = undefined,
      tenant = 'tenant-a',
      subject = 'provisioning-client',
    ): Promise<ScimHttpRequest> => {
      const bearer = await issuer.bearer({
          tenant_id: tenant,
          sub: subject,
          scope: 'scim:users:read scim:users:write scim:groups:read scim:groups:write',
        }),
        identity = await auth.verifyBearer(bearer);
      return {
        method,
        path,
        body,
        headers: { authorization: bearer, 'content-type': 'application/scim+json' },
        auth: auth.tenantFrom(identity),
      };
    };
    try {
      await createPostgresScimTables(backend.app.sql, 'main', backend.schema);
      const service = () => {
        const value = createScimService({ auth, authority, environment: 'test' });
        value.registerUsers(
          createPostgresScimProvider(backend.app.sql, auth, 'main', backend.schema, 'Users'),
        );
        value.registerGroups(
          createPostgresScimProvider(backend.app.sql, auth, 'main', backend.schema, 'Groups'),
        );
        return value;
      };
      const first = service(),
        second = service(),
        body = {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'owned-user',
          externalId: 'stable-external',
          active: true,
        };
      const creates = await Promise.all([
        first.handle(await request('POST', '/Users', body)),
        second.handle(await request('POST', '/Users', body)),
      ]);
      assert.deepEqual(
        creates.map((item) => item.status),
        [201, 201],
        JSON.stringify(creates),
      );
      const created = creates[0]!.body as ScimRecord,
        id = created.id;
      assert.equal((creates[1]!.body as ScimRecord).id, id);
      const stored = await backend.app.sql.queryOne<{ body: string; version: string }>('main', {
        text: `SELECT body,version::text AS version FROM ${backend.schema}.scim_resources WHERE id=:id`,
        bindings: { id },
      });
      assert.ok(stored);
      try {
        await backend.app.sql.execute('main', {
          text: `UPDATE ${backend.schema}.scim_resources SET body=:body WHERE id=:id`,
          bindings: { id, body: '{invalid-private-resource' },
        });
        for (const path of ['/Users/' + id, '/Users']) {
          const denied = await second.handle(await request('GET', path));
          assert.equal(denied.status, 503);
          assert.equal(JSON.stringify(denied.body).includes('invalid-private-resource'), false);
        }
      } finally {
        await backend.app.sql.execute('main', {
          text: `UPDATE ${backend.schema}.scim_resources SET body=:body WHERE id=:id`,
          bindings: { id, body: stored.body },
        });
      }
      const retained = await backend.app.sql.queryOne<{ version: string }>('main', {
        text: `SELECT version::text AS version FROM ${backend.schema}.scim_resources WHERE id=:id`,
        bindings: { id },
      });
      assert.equal(retained?.version, stored.version);
      assert.equal(
        (await second.handle(await request('GET', '/Users/' + id))).headers.etag,
        creates[0]!.headers.etag,
      );
      const changes = {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        },
        base = await request('PATCH', '/Users/' + id, changes),
        version = creates[0]!.headers.etag!;
      const outcomes = await Promise.all([
        first.handle({ ...base, headers: { ...base.headers, 'if-match': version } }),
        second.handle({ ...base, headers: { ...base.headers, 'if-match': version } }),
      ]);
      assert.deepEqual(
        outcomes.map((item) => item.status).sort(),
        [200, 412],
        JSON.stringify(outcomes),
      );
      assert.equal(
        (await first.handle(await request('GET', '/Users/' + id, undefined, 'tenant-b'))).status,
        403,
      );
      assert.equal(
        (
          await first.handle(
            await request('GET', '/Users/' + id, undefined, 'tenant-a', 'other-integration'),
          )
        ).status,
        403,
      );
      const groups = {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          displayName: 'Owned group',
          externalId: 'stable-group',
          members: [{ value: id, type: 'User' }],
        },
        groupResponse = await first.handle(await request('POST', '/Groups', groups));
      assert.equal(groupResponse.status, 201, JSON.stringify(groupResponse));
      const groupId = (groupResponse.body as ScimRecord).id;
      assert.equal((await first.handle(await request('DELETE', '/Users/' + id))).status, 409);
      const clear = await first.handle(
        await request('PATCH', '/Groups/' + groupId, {
          schemas: changes.schemas,
          Operations: [{ op: 'replace', value: { members: [] } }],
        }),
      );
      assert.equal(clear.status, 200, JSON.stringify(clear));
      assert.deepEqual((clear.body as ScimRecord).members ?? [], []);
      assert.equal(
        (
          await first.handle(
            await request('POST', '/Groups', {
              ...groups,
              externalId: 'foreign-group',
              members: [{ value: '00000000-0000-0000-0000-000000000000', type: 'User' }],
            }),
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await first.handle(
            await request('POST', '/Users', {
              ...body,
              userName: 'privileged',
              externalId: 'privileged',
              roles: [{ value: 'admin' }],
            }),
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await first.handle(
            await request('PUT', '/Users/' + id, { ...body, displayName: 'Updated fixture' }),
          )
        ).status,
        200,
      );
      const listed = await first.handle(
        await request('GET', '/Users?filter=userName%20eq%20%22OWNED-USER%22&startIndex=1&count=1'),
      );
      assert.equal(listed.status, 200);
      assert.equal((listed.body as { totalResults: number }).totalResults, 1);
      assert.equal((await first.handle(await request('DELETE', '/Users/' + id))).status, 204);
      assert.equal((await first.handle(await request('GET', '/Users/' + id))).status, 404);
      assert.equal((await first.handle(await request('POST', '/Users', body))).status, 409);
      const tombstones = await backend.app.sql.queryOne<{ deleted: boolean; body: string }>(
        'main',
        {
          text: `SELECT deleted,body FROM ${backend.schema}.scim_resources WHERE id=:id`,
          bindings: { id },
        },
      );
      assert.equal(tombstones!.deleted, true);
      assert.equal((JSON.parse(tombstones!.body) as ScimRecord).active, false);
      const provider = createPostgresScimProvider(
          backend.app.sql,
          auth,
          'main',
          backend.schema,
          'Users',
        ),
        valid = await request('GET', '/Users');
      await assert.rejects(provider.get(id, { ...valid.auth }), { code: 'EK_SCIM_UNAUTHORIZED' });
      const broken = createScimService({ auth, authority, environment: 'test' });
      broken.registerUsers({
        ...provider,
        async patch(...args) {
          await provider.patch(...args);
          throw new Error('private-persistence-acknowledgement');
        },
      } satisfies ScimProvider);
      const retryUser = await first.handle(
          await request('POST', '/Users', {
            ...body,
            externalId: 'late-write',
            userName: 'late-write',
          }),
        ),
        retryId = (retryUser.body as ScimRecord).id;
      const failed = await broken.handle(await request('PATCH', '/Users/' + retryId, changes));
      assert.equal(failed.status, 503);
      assert.match(JSON.stringify(failed.body), /outcome is unknown/);
      assert.ok(!JSON.stringify(failed).includes('private-persistence'));
    } finally {
      await auth.close();
      await issuer.close();
      await backend.close();
    }
  },
);
