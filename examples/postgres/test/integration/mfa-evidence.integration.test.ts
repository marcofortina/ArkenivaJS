// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import type { MfaEvidenceRecord, MfaEvidenceStore } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import {
  createPostgresMfaEvidenceStore,
  createPostgresMfaEvidenceTable,
} from '../../dist/mfa-evidence-store.js';
import { startMfaWorker } from './mfa-worker.js';

const evidence = (id: string): MfaEvidenceRecord => ({
  evidenceId: id,
  method: 'totp',
  assurance: 'mfa',
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  tenantId: 'tenant-a',
  primarySessionId: 'session-a',
  verifiedAt: '2026-10-25T00:00:00.000Z',
  expiresAt: '2026-10-25T00:01:00.000Z',
});
const claim = (record: MfaEvidenceRecord): Parameters<MfaEvidenceStore['consume']>[0] => ({
  evidenceId: record.evidenceId,
  issuer: record.issuer,
  subject: record.subject,
  ...(record.tenantId ? { tenantId: record.tenantId } : {}),
  primarySessionId: record.primarySessionId,
  now: '2026-10-25T00:00:30.000Z',
});
async function fixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const app = await createApplication({
    service: { name: 'mfa-evidence-example', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 } },
  });
  const schema = 'mfa_' + randomBytes(12).toString('hex');
  let created = false;
  try {
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresMfaEvidenceTable(app.sql, 'main', schema);
    return {
      schema,
      sql: app.sql,
      store: createPostgresMfaEvidenceStore(app.sql, 'main', schema),
      close: async () => {
        try {
          await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
        } finally {
          await app.stop();
        }
      },
    };
  } catch (error) {
    try {
      if (created) await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
    } finally {
      await app.stop();
    }
    throw error;
  }
}

test(
  'MFA evidence binds issuer, account, tenant, session and validity and cannot be re-recorded after use',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    try {
      const record = evidence('owner');
      await value.store.recordOnce(record);
      await assert.rejects(
        value.store.recordOnce(record),
        (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
      );
      for (const change of [
        { issuer: 'https://foreign.example.test' },
        { subject: 'foreign-account' },
        { tenantId: 'tenant-b' },
        { primarySessionId: 'session-b' },
        { now: record.expiresAt },
        { now: '2026-10-24T23:59:59.000Z' },
      ])
        assert.equal(await value.store.consume({ ...claim(record), ...change }), null);
      const { tenantId: _tenant, ...missingTenant } = claim(record);
      void _tenant;
      assert.equal(await value.store.consume(missingTenant), null);
      await assert.rejects(
        value.store.consume(claim(record), { signal: AbortSignal.abort() }),
        (error) => error instanceof KitError && error.code === 'EK_ABORTED',
      );
      assert.deepEqual(await value.store.consume(claim(record)), record);
      assert.equal(await value.store.consume(claim(record)), null);
      await assert.rejects(
        value.store.recordOnce(record),
        (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
      );
    } finally {
      await value.close();
    }
  },
);

test(
  'Corrupt evidence body cannot substitute an owner or elevate TOTP to phishing resistance',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    try {
      for (const [index, change] of [
        { subject: 'foreign-account' },
        { primarySessionId: 'foreign-session' },
        { tenantId: 'tenant-b' },
        { assurance: 'phishing-resistant' },
        { method: 'webauthn', assurance: 'phishing-resistant' },
        { verifiedAt: '2026-10-25T00:00:20.000Z' },
        { expiresAt: '2026-10-25T00:05:00.000Z' },
      ].entries()) {
        const record = evidence('corrupt-' + index);
        await value.store.recordOnce(record);
        await value.sql.execute('main', {
          text: `UPDATE ${value.schema}.mfa_evidence SET body=:body::jsonb WHERE id=:id`,
          bindings: { id: record.evidenceId, body: JSON.stringify({ ...record, ...change }) },
        });
        await assert.rejects(
          value.store.consume(claim(record)),
          (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
        );
        assert.equal(await value.store.consume(claim(record)), null);
      }
    } finally {
      await value.close();
    }
  },
);

test(
  'Two independent session-authority processes can consume MFA evidence only once',
  { timeout: 20000 },
  async (t) => {
    const value = await fixture();
    try {
      const record = evidence('cross-process');
      await value.store.recordOnce(record);
      const script = `
      import {createApplication,KitError} from '@arkenivajs/core';
      import {postgresPlugin} from '@arkenivajs/database-postgres';
      import {createPostgresMfaEvidenceStore} from './dist/mfa-evidence-store.js';
      const {schema,input}=JSON.parse(process.argv[1]);
      const app=await createApplication({service:{name:'mfa-evidence-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
      try{await app.start();const go=new Promise(resolve=>process.stdin.once('data',resolve));console.log(JSON.stringify({ready:true}));await go;
        const result=await createPostgresMfaEvidenceStore(app.sql,'main',schema).consume(input);console.log(JSON.stringify({result:result!==null}));
      }catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}
      finally{await app.stop();process.stdin.destroy();}
    `;
      const workers = [
        startMfaWorker(t, script, { schema: value.schema, input: claim(record) }),
        startMfaWorker(t, script, { schema: value.schema, input: claim(record) }),
      ];
      await Promise.all(workers.map((worker) => worker.ready));
      for (const worker of workers) worker.go();
      assert.deepEqual((await Promise.all(workers.map((worker) => worker.result))).sort(), [
        false,
        true,
      ]);
      assert.equal(await value.store.consume(claim(record)), null);
    } finally {
      await value.close();
    }
  },
);
