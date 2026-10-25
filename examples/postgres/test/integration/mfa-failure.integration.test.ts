// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import type {
  Application,
  MfaChallengeRecord,
  MfaEvidenceRecord,
  SqlProvider,
} from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import {
  createPostgresMfaStateStore,
  createPostgresMfaStateTable,
} from '../../dist/mfa-state-store.js';
import {
  createPostgresMfaRateLimitStore,
  createPostgresMfaRateLimitTable,
} from '../../dist/mfa-rate-limit-store.js';
import {
  createPostgresMfaEvidenceStore,
  createPostgresMfaEvidenceTable,
} from '../../dist/mfa-evidence-store.js';
import { startMfaWorker } from './mfa-worker.js';

const record = (id: string): MfaEvidenceRecord => ({
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
const claim = (value: MfaEvidenceRecord) => ({
  evidenceId: value.evidenceId,
  issuer: value.issuer,
  subject: value.subject,
  tenantId: value.tenantId!,
  primarySessionId: value.primarySessionId,
  now: '2026-10-25T00:00:30.000Z',
});
const stores = (sql: SqlProvider, schema: string) => ({
  state: createPostgresMfaStateStore(sql, 'main', schema),
  limiter: createPostgresMfaRateLimitStore(sql, 'main', schema),
  evidence: createPostgresMfaEvidenceStore(sql, 'main', schema),
});
async function application() {
  const app = await createApplication({
    service: { name: 'mfa-failure-fixture', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 } },
  });
  try {
    await app.start();
    return app;
  } catch (error) {
    await app.stop();
    throw error;
  }
}
async function fixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const app = await application(),
    schema = 'mfa_' + randomBytes(12).toString('hex');
  let created = false;
  try {
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresMfaStateTable(app.sql, 'main', schema);
    await createPostgresMfaRateLimitTable(app.sql, 'main', schema);
    await createPostgresMfaEvidenceTable(app.sql, 'main', schema);
    return {
      schema,
      stores: stores(app.sql, schema),
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

const crashScript = `
  import {createApplication,KitError} from '@arkenivajs/core';
  import {postgresPlugin} from '@arkenivajs/database-postgres';
  import {createPostgresMfaEvidenceStore} from './dist/mfa-evidence-store.js';
  const {schema,phase,record,input}=JSON.parse(process.argv[1]);
  const app=await createApplication({service:{name:'mfa-crash-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
  try{await app.start();const go=new Promise(resolve=>process.stdin.once('data',resolve));console.log(JSON.stringify({ready:true}));await go;
    const store=createPostgresMfaEvidenceStore(app.sql,'main',schema);
    if(phase==='record')await store.recordOnce(record);else{const value=await store.consume(input);if(value===null)throw new Error('Expected pending synthetic evidence');}
    process.kill(process.pid,'SIGKILL');
  }catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}
  finally{await app.stop();process.stdin.destroy();}
`;

test(
  'Evidence survives producer death; authority death after consume cannot resurrect a proof',
  { timeout: 20000 },
  async (t) => {
    const value = await fixture();
    try {
      const produced = record('producer-crash');
      const producer = startMfaWorker(t, crashScript, {
        schema: value.schema,
        phase: 'record',
        record: produced,
      });
      await producer.ready;
      producer.go();
      await assert.rejects(producer.result);
      assert.deepEqual(await producer.exit, { code: null, signal: 'SIGKILL' });
      assert.deepEqual(await value.stores.evidence.consume(claim(produced)), produced);
      const consumed = record('consumer-crash');
      await value.stores.evidence.recordOnce(consumed);
      const consumer = startMfaWorker(t, crashScript, {
        schema: value.schema,
        phase: 'consume',
        input: claim(consumed),
      });
      await consumer.ready;
      consumer.go();
      await assert.rejects(consumer.result);
      assert.deepEqual(await consumer.exit, { code: null, signal: 'SIGKILL' });
      assert.equal(await value.stores.evidence.consume(claim(consumed)), null);
      await assert.rejects(
        value.stores.evidence.recordOnce(consumed),
        (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
      );
    } finally {
      await value.close();
    }
  },
);

test(
  'Unavailable real SQL providers fail closed without consuming state or granting quota',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    let secondary: Application | undefined;
    try {
      secondary = await application();
      const unavailable = stores(secondary.sql, value.schema),
        proof = record('provider-outage');
      const challenge: MfaChallengeRecord = {
        id: 'provider-challenge',
        purpose: 'totp-enroll',
        issuer: proof.issuer,
        subject: proof.subject,
        tenantId: 'tenant-a',
        primarySessionId: proof.primarySessionId,
        challengeDigest: 'a'.repeat(64),
        createdAt: proof.verifiedAt,
        expiresAt: proof.expiresAt,
      };
      const challengeClaim = {
        id: challenge.id,
        purpose: challenge.purpose,
        issuer: challenge.issuer,
        subject: challenge.subject!,
        tenantId: 'tenant-a',
        primarySessionId: proof.primarySessionId,
        now: '2026-10-25T00:00:30.000Z',
      };
      const limit = {
        scopeKey: 'provider-scope',
        operation: 'verify',
        maxAttempts: 2,
        windowMs: 1000,
        nowMs: 1000,
      };
      await unavailable.state.createChallenge(challenge);
      await unavailable.evidence.recordOnce(proof);
      assert.deepEqual(await unavailable.limiter.checkAndRecord(limit), { allowed: true });
      await secondary.stop();
      for (const operation of [
        () => unavailable.state.claimChallenge(challengeClaim),
        () => unavailable.evidence.consume(claim(proof)),
        () => unavailable.limiter.checkAndRecord(limit),
      ])
        await assert.rejects(
          operation(),
          (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
        );
      assert.deepEqual(await value.stores.state.claimChallenge(challengeClaim), challenge);
      assert.deepEqual(await value.stores.evidence.consume(claim(proof)), proof);
      assert.deepEqual(await value.stores.limiter.checkAndRecord(limit), { allowed: true });
      assert.deepEqual(await value.stores.limiter.checkAndRecord(limit), {
        allowed: false,
        retryAfterMs: 1000,
      });
    } finally {
      try {
        await secondary?.stop();
      } finally {
        await value.close();
      }
    }
  },
);
