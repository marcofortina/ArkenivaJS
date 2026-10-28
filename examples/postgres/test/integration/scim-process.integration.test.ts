// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { createAuthService } from '@arkenivajs/security';
import { createPostgresScimProvider, createPostgresScimTables } from '../../dist/scim-provider.js';
import { securityStateFixture } from './security-state-fixture.js';
import { startMfaIssuer } from './mfa-issuer.js';

test(
  'Separate SCIM processes with independent verified PostgreSQL pools allow one conditional update',
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
      authorizeTenant: (_identity, tenant) => tenant === 'tenant-a',
    });
    const children: ReturnType<typeof fork>[] = [],
      exits: Promise<unknown>[] = [];
    try {
      await createPostgresScimTables(backend.app.sql, 'main', backend.schema);
      const bearer = await issuer.bearer({
          sub: 'provisioning-client',
          scope: 'scim:users:read scim:users:write',
        }),
        identity = await auth.verifyBearer(bearer),
        tenant = auth.tenantFrom(identity),
        provider = createPostgresScimProvider(
          backend.app.sql,
          auth,
          'main',
          backend.schema,
          'Users',
        );
      const { randomUUID } = await import('node:crypto');
      const record = await provider.create(
        {
          id: randomUUID(),
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'process-fixture',
          active: true,
          externalId: 'process-fixture',
        },
        tenant,
      );
      const workers = Array.from({ length: 2 }, () => {
        const child = fork(new URL('./scim-worker.js', import.meta.url), [], {
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          env: {
            NODE_ENV: 'test',
            DATABASE_URL: process.env.DATABASE_URL!,
            ARKENIVA_POSTGRES_DISPOSABLE: process.env.ARKENIVA_POSTGRES_DISPOSABLE!,
          },
        });
        children.push(child);
        exits.push(
          once(child, 'exit').then(([code]) => {
            assert.equal(code, 0, 'The owned SCIM process must exit cleanly');
          }),
        );
        let ready!: () => void,
          result!: (status: number) => void,
          failReady!: (error: Error) => void,
          failResult!: (error: Error) => void;
        const started = new Promise<void>((resolve, reject) => {
            ready = resolve;
            failReady = reject;
          }),
          completed = new Promise<number>((resolve, reject) => {
            result = resolve;
            failResult = reject;
          });
        void completed.catch(() => undefined);
        const failed = (error: Error) => {
          failReady(error);
          failResult(error);
        };
        child.on('message', (input) => {
          const value = input as { type: string; status?: number; code?: string };
          if (value.type === 'ready') ready();
          else if (value.type === 'result' && value.status) result(value.status);
          else if (value.type === 'failed')
            failed(
              new Error('The owned SCIM process failed: ' + (value.code ?? 'unexpected-error')),
            );
        });
        child.once('error', failed);
        child.once('exit', (code) => {
          if (code !== 0) failed(new Error('The owned SCIM process exited'));
        });
        // The owned IPC channel carries the synthetic short-lived bearer, never command arguments or output.
        child.send({ type: 'start', schema: backend.schema, issuer: issuer.authority, bearer });
        return { child, started, completed };
      });
      await Promise.all(workers.map((worker) => worker.started));
      for (const worker of workers)
        worker.child.send({ type: 'patch', id: record.id, version: record.meta!.version! });
      assert.deepEqual(
        (await Promise.all(workers.map((worker) => worker.completed))).sort(),
        [200, 412],
      );
      const updated = await provider.get(record.id, tenant);
      assert.equal(updated!.active, false);
      assert.notEqual(updated!.meta?.version, record.meta?.version);
      const repeated = await provider.patch(
        record.id,
        {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        },
        undefined,
        tenant,
      );
      assert.equal(repeated.meta?.version, updated!.meta?.version);
    } finally {
      for (const child of children) if (child.connected) child.send({ type: 'close' });
      const timer = setTimeout(() => {
        for (const child of children) if (child.exitCode === null) child.kill('SIGTERM');
      }, 5000);
      timer.unref();
      try {
        await Promise.all(exits);
      } finally {
        clearTimeout(timer);
        await auth.close();
        await issuer.close();
        await backend.close();
      }
    }
  },
);
