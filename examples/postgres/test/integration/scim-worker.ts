// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication, KitError } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createAuthService } from '@arkenivajs/security';
import type { ManagedAuthService } from '@arkenivajs/security';
import { createScimService } from '@arkenivajs/security-scim';
import type { ScimService, TrustedSecurityAuthority } from '@arkenivajs/security-scim';
import { createPostgresScimProvider } from '../../dist/scim-provider.js';

interface Start {
  type: 'start';
  schema: string;
  issuer: string;
  bearer: string;
}
let database: Awaited<ReturnType<typeof createApplication>> | undefined,
  auth: ManagedAuthService | undefined,
  service: ScimService | undefined,
  bearer: string | undefined;
let busy = false;
async function close() {
  await auth?.close();
  await database?.stop();
  if (process.connected) process.disconnect();
}
process.on(
  'message',
  (input: Start | { type: 'patch'; id: string; version: string } | { type: 'close' }) => {
    void (async () => {
      if (input.type === 'start') {
        if (database) throw new Error('The owned SCIM worker was already started');
        database = await createApplication({
          service: { name: 'scim-process-database', version: '1.0.0', environment: 'test' },
          plugins: [postgresPlugin()],
          databases: {
            main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 1 },
          },
        });
        await database.start();
        auth = await createAuthService({
          issuer: input.issuer,
          audience: 'api://mfa-fixture',
          environment: 'test',
          allowInsecureLoopback: true,
          algorithms: ['RS256'],
          authorizeTenant: (_identity, tenant) => tenant === 'tenant-a',
        });
        const authority: TrustedSecurityAuthority = {
          async require(_action, hint, context) {
            const tenant = context.tenant;
            if (
              !hint ||
              !tenant ||
              auth!.tenantFrom(tenant.identity) !== tenant ||
              hint.issuer !== tenant.identity.issuer ||
              hint.subject !== tenant.identity.subject
            )
              throw new Error('The owned SCIM worker denied authorization');
            return { ...hint, tenant };
          },
        };
        service = createScimService({ auth, authority, environment: 'test' });
        service.registerUsers(
          createPostgresScimProvider(database.sql, auth, 'main', input.schema, 'Users'),
        );
        bearer = input.bearer;
        await auth.verifyBearer(bearer);
        process.send?.({ type: 'ready' });
        return;
      }
      if (input.type === 'close') {
        await close();
        return;
      }
      if (!service || !auth || !bearer || busy)
        throw new Error('The owned SCIM worker is unavailable');
      busy = true;
      const identity = await auth.verifyBearer(bearer),
        result = await service.handle({
          method: 'PATCH',
          path: '/Users/' + input.id,
          auth: auth.tenantFrom(identity),
          headers: {
            authorization: bearer,
            'content-type': 'application/scim+json',
            'if-match': input.version,
          },
          body: {
            schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            Operations: [{ op: 'replace', path: 'active', value: false }],
          },
        });
      process.send?.({ type: 'result', status: result.status });
    })().catch(async (error: unknown) => {
      process.send?.({
        type: 'failed',
        code: error instanceof KitError ? error.code : 'unexpected-error',
      });
      process.exitCode = 1;
      await close();
    });
  },
);
process.once('disconnect', () => {
  void close().catch(() => {
    process.exitCode = 1;
  });
});
