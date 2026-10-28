// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import SCIMMY from 'scimmy';
import { createAuthService } from '@arkenivajs/security';
import { KitError } from '@arkenivajs/core';
import type { VerifiedTenantContext } from '@arkenivajs/core';
import { createScimService } from '../dist/index.js';
import type {
  ScimProvider,
  ScimRecord,
  ScimHttpRequest,
  ScimServiceSettings,
} from '../dist/index.js';
import { apply } from '../dist/codec.js';

/** A real signed OIDC authority and explicitly process-local unit state; shared acceptance uses PostgreSQL. */
export async function fixture(change: Partial<ScimServiceSettings> = {}) {
  const pair = await generateKeyPair('ES256'),
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'scim-fixture', alg: 'ES256' };
  let issuer = '',
    available = true,
    decisions = true,
    calls = 0;
  const server = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys' ? { keys: [jwk] } : { issuer, jwks_uri: issuer + '/keys' },
      ),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string')
    throw new Error('The owned SCIM issuer is unavailable');
  issuer = 'http://127.0.0.1:' + address.port;
  const auth = await createAuthService({
    issuer,
    audience: 'api://scim-fixture',
    algorithms: ['ES256'],
    environment: 'test',
    allowInsecureLoopback: true,
    authorizeTenant: (_identity, tenant) => ['tenant-a', 'tenant-b'].includes(tenant),
  });
  const records = new Map<string, ScimRecord>(),
    owners = new Map<string, string>();
  const ownerKey = (tenant: VerifiedTenantContext) =>
    JSON.stringify([tenant.identity.issuer, tenant.tenantId]);
  const key = (kind: string, id: string, tenant: VerifiedTenantContext) =>
    JSON.stringify([ownerKey(tenant), kind, id]);
  const failure = (code: 'EK_SCIM_UNAUTHORIZED' | 'EK_SCIM_CONFLICT' | 'EK_SCIM_PRECONDITION') =>
    new KitError({ code, message: 'The owned fixture rejected the operation' });
  const check = () => {
    calls++;
    if (!available) throw new Error('private-storage-credential');
  };
  function provider(kind: 'Users' | 'Groups'): ScimProvider & { usage: 'test-only' } {
    const get = async (id: string, tenant: VerifiedTenantContext) => {
      check();
      if (owners.has(id) && owners.get(id) !== ownerKey(tenant))
        throw failure('EK_SCIM_UNAUTHORIZED');
      return records.get(key(kind, id, tenant)) ?? null;
    };
    const versioned = (record: ScimRecord): ScimRecord => ({
      ...record,
      meta: {
        resourceType: kind === 'Users' ? 'User' : 'Group',
        version: '"' + randomUUID() + '"',
      },
    });
    const expected = (record: ScimRecord | null, ifMatch: string | undefined): ScimRecord => {
      if (!record || (ifMatch !== undefined && ifMatch !== '*' && record.meta?.version !== ifMatch))
        throw failure('EK_SCIM_PRECONDITION');
      return record;
    };
    const policy = (record: ScimRecord) => {
      if (
        record.roles !== undefined ||
        record.entitlements !== undefined ||
        (record.members as { value: string }[] | undefined)?.some(
          (member) => member.value === 'privileged-account',
        )
      )
        throw failure('EK_SCIM_UNAUTHORIZED');
    };
    return {
      usage: 'test-only',
      get,
      async list(filter, tenant) {
        check();
        let values = [...records.entries()]
          .filter(
            ([name]) => JSON.parse(name)[0] === ownerKey(tenant) && JSON.parse(name)[1] === kind,
          )
          .map(([, value]) => value);
        values = new SCIMMY.Types.Filter(filter.expression).match(
          values,
          (kind === 'Users' ? SCIMMY.Schemas.User : SCIMMY.Schemas.Group).definition,
        ) as ScimRecord[];
        const totalResults = values.length,
          startIndex = filter.startIndex ?? 1;
        if (filter.sortBy)
          values.sort(
            (a, b) =>
              String(a[filter.sortBy!]).localeCompare(String(b[filter.sortBy!])) *
              (filter.sortOrder === 'descending' ? -1 : 1),
          );
        const Resources = values.slice(startIndex - 1, startIndex - 1 + (filter.count ?? 100));
        return { startIndex, itemsPerPage: Resources.length, totalResults, Resources };
      },
      async create(record, tenant) {
        check();
        policy(record);
        const owned = [...records.entries()]
          .filter(
            ([name]) => JSON.parse(name)[0] === ownerKey(tenant) && JSON.parse(name)[1] === kind,
          )
          .map(([, value]) => value);
        const existing = owned.find(
          (item) => record.externalId !== undefined && item.externalId === record.externalId,
        );
        if (existing) return existing;
        if (owned.some((item) => kind === 'Users' && item.userName === record.userName))
          throw failure('EK_SCIM_CONFLICT');
        const value = versioned(record);
        owners.set(value.id, ownerKey(tenant));
        records.set(key(kind, value.id, tenant), value);
        return value;
      },
      async replace(id, record, ifMatch, tenant) {
        const before = expected(await get(id, tenant), ifMatch);
        policy(record);
        if (before.externalId !== record.externalId) throw failure('EK_SCIM_CONFLICT');
        const value = versioned({ ...record, id });
        records.set(key(kind, id, tenant), value);
        return value;
      },
      async patch(id, patch, ifMatch, tenant) {
        const before = expected(await get(id, tenant), ifMatch);
        const next = await apply(kind, before, patch);
        policy(next);
        if (records.get(key(kind, id, tenant))?.meta?.version !== before.meta?.version)
          throw failure('EK_SCIM_PRECONDITION');
        const value = versioned(next);
        records.set(key(kind, id, tenant), value);
        return value;
      },
      async delete(id, ifMatch, tenant) {
        expected(await get(id, tenant), ifMatch);
        records.delete(key(kind, id, tenant));
      },
    };
  }
  const authority = {
    async require(
      _action: string,
      subject: { issuer: string; subject: string } | undefined,
      context: { tenant?: VerifiedTenantContext },
    ) {
      if (
        !decisions ||
        !subject ||
        !context.tenant ||
        auth.tenantFrom(context.tenant.identity) !== context.tenant ||
        subject.issuer !== context.tenant.identity.issuer ||
        subject.subject !== context.tenant.identity.subject
      )
        throw failure('EK_SCIM_UNAUTHORIZED');
      return { ...subject, tenant: context.tenant };
    },
  };
  const settings = { auth, authority, environment: 'test' as const, ...change },
    service = createScimService(settings);
  service.registerUsers(provider('Users'));
  service.registerGroups(provider('Groups'));
  return {
    issuer,
    auth,
    authority,
    settings,
    service,
    provider,
    calls: () => calls,
    storageAvailable: (value: boolean) => {
      available = value;
    },
    authorized: (value: boolean) => {
      decisions = value;
    },
    async request(
      method: ScimHttpRequest['method'],
      path: string,
      body: unknown = undefined,
      tenant = 'tenant-a',
      scopes = 'scim:users:read scim:users:write scim:groups:read scim:groups:write',
    ): Promise<ScimHttpRequest> {
      const bearer =
        'Bearer ' +
        (await new SignJWT({ tenant_id: tenant, scope: scopes })
          .setProtectedHeader({ alg: 'ES256', kid: 'scim-fixture', typ: 'JWT' })
          .setIssuer(issuer)
          .setSubject('provisioning-integration')
          .setAudience('api://scim-fixture')
          .setExpirationTime('2m')
          .sign(pair.privateKey));
      const identity = await auth.verifyBearer(bearer);
      return {
        method,
        path,
        body,
        headers: { authorization: bearer, 'content-type': 'application/scim+json' },
        auth: auth.tenantFrom(identity),
      };
    },
    async close() {
      await auth.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
