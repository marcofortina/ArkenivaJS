// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { createAuthService } from '@arkenivajs/security';
import { securityStateFixture } from '../../examples/postgres/dist-test/integration/security-state-fixture.js';
import {
  createPostgresScimProvider,
  createPostgresScimTables,
} from '../../examples/postgres/dist/scim-provider.js';
import { createIssuer } from './http-issuer.mjs';

/** Actual signed identities and the existing transactional provider remain independently parent-owned. */
export async function startScimFixture(sampleReads = false) {
  assert.equal(typeof sampleReads, 'boolean');
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  const backend = await securityStateFixture();
  let issuer, bridge, auth;
  const tasks = new Set(),
    grants = [],
    privacyValues = ['127.0.0.1'],
    readSeeds = new Map();
  const bridgeKey = randomBytes(32).toString('base64url'),
    marker = 'owned-scim-private-user';
  let handedOut = 0,
    providerCalls = 0,
    unavailable = false;
  const remember = (value) => {
    if (typeof value === 'string' && value && !privacyValues.includes(value))
      privacyValues.push(value);
  };
  remember(backend.schema);
  const close = async () => {
    try {
      if (bridge?.listening) {
        bridge.closeAllConnections();
        await new Promise((done) => bridge.close(done));
      }
      await Promise.allSettled([...tasks]);
      try {
        await auth?.close();
      } finally {
        await issuer?.close();
      }
    } finally {
      await backend.close();
    }
  };
  try {
    issuer = await createIssuer();
    const scope = 'scim:users:read scim:users:write scim:groups:read scim:groups:write';
    for (let index = 0; index < 4; index++) {
      const tenant = 'scim-' + randomBytes(12).toString('hex');
      const token = await issuer.token({ claims: { tenant_id: tenant, scope } });
      grants.push({ tenant, token, externalId: 'external-' + randomBytes(12).toString('hex') });
      for (const value of Object.values(grants.at(-1))) remember(value);
    }
    auth = await createAuthService({
      issuer: issuer.origin,
      audience: issuer.audience,
      environment: 'test',
      allowInsecureLoopback: true,
      algorithms: ['RS256'],
      authorizeTenant: (_identity, tenant) => grants.some((grant) => grant.tenant === tenant),
    });
    await createPostgresScimTables(backend.app.sql, 'main', backend.schema);
    const providers = Object.fromEntries(
      ['Users', 'Groups'].map((kind) => [
        kind,
        createPostgresScimProvider(backend.app.sql, auth, 'main', backend.schema, kind),
      ]),
    );
    bridge = createServer((request, response) => {
      if (tasks.size >= 8) {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
      const task = (async () => {
        assert.equal(request.method, 'POST');
        const supplied = request.headers.authorization ?? '';
        if (request.url === '/grant') {
          const actual = Buffer.from(supplied),
            expected = Buffer.from('Bearer ' + bridgeKey);
          assert.equal(actual.length, expected.length);
          assert.ok(timingSafeEqual(actual, expected));
          assert.ok(handedOut < grants.length);
          response
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify(grants[handedOut++]));
          return;
        }
        assert.equal(request.url, '/provider');
        const identity = await auth.verifyBearer(supplied),
          tenant = auth.tenantFrom(identity);
        const grant = grants.find(
          (value) => value.tenant === tenant.tenantId && supplied === 'Bearer ' + value.token,
        );
        assert.ok(grant);
        assert.ok(grants.indexOf(grant) < handedOut);
        const chunks = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          assert.ok(size <= 262144);
          chunks.push(chunk);
        }
        const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const arity = { list: 1, get: 1, create: 1, replace: 3, patch: 3, delete: 2 };
        assert.ok(['Users', 'Groups'].includes(input.kind));
        assert.ok(Object.hasOwn(arity, input.operation));
        assert.ok(Array.isArray(input.args));
        assert.equal(input.args.length, arity[input.operation]);
        auth.requireScope(
          identity,
          'scim:' +
            input.kind.toLowerCase() +
            ':' +
            (['list', 'get'].includes(input.operation) ? 'read' : 'write'),
        );
        if (unavailable) {
          response.writeHead(503).end();
          return;
        }
        providerCalls++;
        try {
          const value = await providers[input.kind][input.operation](...input.args, tenant, {
            timeoutMs: 3000,
          });
          if (sampleReads && input.kind === 'Users') {
            if (input.operation === 'create' && input.args[0].userName === marker + '-read') {
              assert.equal(input.args[0].externalId, grant.externalId + '-read');
              assert.equal(readSeeds.has(tenant.tenantId), false);
              assert.ok(readSeeds.size < 4);
              const stored = await backend.app.sql.query('main', {
                text: `SELECT body FROM ${backend.schema}.scim_resources WHERE id = :id LIMIT 1`,
                bindings: { id: value.id },
              });
              assert.equal(stored.rows.length, 1);
              const storedBody = stored.rows[0].body,
                contents = JSON.parse(storedBody);
              assert.equal(contents.userName, marker + '-read');
              assert.equal(contents.externalId, grant.externalId + '-read');
              assert.equal(contents.active, true);
              assert.deepEqual(contents.schemas, ['urn:ietf:params:scim:schemas:core:2.0:User']);
              readSeeds.set(tenant.tenantId, {
                id: value.id,
                resource: JSON.parse(JSON.stringify(value)),
                storedBody,
                ownerKey: createHash('sha256')
                  .update(
                    JSON.stringify([
                      tenant.identity.issuer,
                      tenant.identity.subject,
                      tenant.tenantId,
                    ]),
                  )
                  .digest('hex'),
                reads: 0,
              });
            }
            const seed = readSeeds.get(tenant.tenantId);
            if (input.operation === 'get' && seed?.id === input.args[0]) {
              assert.ok(seed.reads < 120);
              seed.reads++;
            }
          }
          for (const record of [...(value?.Resources ?? []), ...(value?.id ? [value] : [])])
            remember(record.id);
          response
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ value }));
        } catch (cause) {
          const allowed = [
            'EK_SCIM_PRECONDITION',
            'EK_SCIM_CONFLICT',
            'EK_SCIM_UNAUTHORIZED',
            'EK_SCIM_BAD_REQUEST',
            'EK_HTTP_NOT_FOUND',
          ];
          response.writeHead(409, { 'content-type': 'application/json' }).end(
            JSON.stringify({
              code: allowed.includes(cause?.code) ? cause.code : 'EK_BACKEND_UNAVAILABLE',
            }),
          );
        }
      })()
        .catch(() => response.writeHead(400).end())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    });
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    const fixture = {
      bridgeUrl: 'http://127.0.0.1:' + bridge.address().port,
      bridgeKey,
      issuer: issuer.origin,
      audience: issuer.audience,
      marker,
      scope,
      sampleReads,
    };
    Object.values(fixture).forEach(remember);
    return {
      fixture,
      privacyValues,
      close,
      unavailable: (value) => {
        unavailable = value;
      },
      observations: () => ({ handedOut, providerCalls }),
      async verify(profiles, expectedReads = 0) {
        assert.equal(handedOut, profiles);
        assert.equal(profiles, 4);
        assert.equal(expectedReads, sampleReads ? 480 : 0);
        const { rows } = await backend.app.sql.query('main', {
          text: `SELECT id::text,kind,body,deleted,version::text AS version,owner_key FROM ${backend.schema}.scim_resources LIMIT 9`,
        });
        assert.equal(rows.length, sampleReads ? 2 * profiles : profiles);
        assert.equal(new Set(rows.map((row) => row.owner_key)).size, profiles);
        const deleted = rows.filter((row) => row.deleted === true);
        assert.equal(deleted.length, profiles);
        assert.ok(deleted.every((row) => row.version === '4'));
        let observedReads = 0;
        if (sampleReads) {
          assert.equal(readSeeds.size, profiles);
          for (const seed of readSeeds.values()) {
            const row = rows.find((value) => value.id === seed.id);
            assert.ok(row);
            assert.equal(row.deleted, false);
            assert.equal(row.kind, 'Users');
            assert.equal(row.version, '1');
            assert.equal(row.owner_key, seed.ownerKey);
            assert.equal(seed.resource.meta.version, '"1"');
            const { id, meta } = seed.resource;
            assert.equal(id, row.id);
            assert.equal(meta.resourceType, 'User');
            assert.equal(row.body, seed.storedBody);
            assert.equal(seed.reads, expectedReads / profiles);
            observedReads += seed.reads;
          }
          assert.equal(observedReads, expectedReads);
        }
        return {
          actualDeletedResources: deleted.length,
          independentTenantOwners: profiles,
          durableVersionPerResource: 4,
          ...(sampleReads
            ? {
                actualLiveReadResources: readSeeds.size,
                unchangedReadResourceVersion: 1,
                independentlyObservedSampleReads: observedReads,
                unchangedReadBodyAndOwnership: true,
                parentProviderResources: null,
                postgresServerResources: null,
              }
            : {}),
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
