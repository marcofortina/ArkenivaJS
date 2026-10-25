// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import type { MfaChallengeRecord, MfaStateStore } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import {
  createPostgresMfaStateStore,
  createPostgresMfaStateTable,
} from '../../dist/mfa-state-store.js';

const challenge = (id: string): MfaChallengeRecord => ({
  id,
  purpose: 'webauthn-authenticate',
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  tenantId: 'tenant-a',
  primarySessionId: 'session-a',
  rpId: 'example.test',
  challengeDigest: 'a'.repeat(64),
  createdAt: '2026-10-25T00:00:00.000Z',
  expiresAt: '2026-10-25T00:05:00.000Z',
});
const claim = (value: MfaChallengeRecord): Parameters<MfaStateStore['claimChallenge']>[0] => ({
  id: value.id,
  purpose: value.purpose,
  issuer: value.issuer,
  ...(value.subject ? { subject: value.subject } : {}),
  ...(value.tenantId ? { tenantId: value.tenantId } : {}),
  ...(value.primarySessionId ? { primarySessionId: value.primarySessionId } : {}),
  ...(value.rpId ? { rpId: value.rpId } : {}),
  now: '2026-10-25T00:01:00.000Z',
});

async function fixture() {
  assert.equal(
    process.env.ARKENIVA_POSTGRES_DISPOSABLE,
    '1',
    'A disposable PostgreSQL fixture is required',
  );
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const app = await createApplication({
    service: { name: 'mfa-shared-store-example', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 } },
  });
  const schema = 'mfa_' + randomBytes(12).toString('hex');
  let created = false;
  try {
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresMfaStateTable(app.sql, 'main', schema);
    return {
      store: createPostgresMfaStateStore(app.sql, 'main', schema),
      sql: app.sql,
      schema,
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

function worker(
  t: TestContext,
  schema: string,
  input: Parameters<MfaStateStore['claimChallenge']>[0],
) {
  const script = `
    import {createApplication,KitError} from '@arkenivajs/core';
    import {postgresPlugin} from '@arkenivajs/database-postgres';
    import {createPostgresMfaStateStore} from './dist/mfa-state-store.js';
    const {schema,input}=JSON.parse(process.argv[1]);
    const app=await createApplication({service:{name:'mfa-claim-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
    try {
      await app.start();
      const ready=new Promise(resolve=>process.stdin.once('data',resolve));
      console.log(JSON.stringify({ready:true}));
      await ready;
      const value=await createPostgresMfaStateStore(app.sql,'main',schema).claimChallenge(input);
      console.log(JSON.stringify({accepted:value!==null}));
    } catch(error) {
      console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));
      process.exitCode=1;
    } finally { await app.stop(); process.stdin.destroy(); }
  `;
  const child = spawn(
    process.execPath,
    ['--input-type=module', '-e', script, JSON.stringify({ schema, input })],
    {
      cwd: fileURLToPath(new URL('../../', import.meta.url)),
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  t.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });
  let resolveReady: () => void, rejectReady: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  let accepted: boolean | undefined;
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const result = JSON.parse(line) as { ready?: boolean; accepted?: boolean };
    if (result.ready === true) resolveReady();
    if (typeof result.accepted === 'boolean') accepted = result.accepted;
  });
  // Child errors are already sanitized; cap diagnostic retention in the test harness.
  let diagnostic = '';
  child.stderr.on('data', (chunk) => {
    diagnostic = (diagnostic + String(chunk)).slice(-4096);
  });
  const result = new Promise<boolean>((resolve, reject) => {
    child.once('error', (error) => {
      rejectReady(error);
      reject(error);
    });
    child.once('close', (code) => {
      lines.close();
      if (code !== 0 || accepted === undefined) {
        const error = new Error('MFA worker failed: ' + diagnostic);
        rejectReady(error);
        reject(error);
      } else resolve(accepted);
    });
  });
  // Keep a failed child observed even while its peer is still reaching the barrier.
  void result.catch(() => undefined);
  return { ready, result, go: () => child.stdin.end('claim\n') };
}

test(
  'Corrupt persisted MFA metadata cannot yield another owner or a successful challenge',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    try {
      for (const [index, mutation] of [
        { tenantId: 'tenant-b' },
        { subject: 'foreign-account' },
        { primarySessionId: 'foreign-session' },
        { expiresAt: '2026-10-25T00:00:30.000Z' },
      ].entries()) {
        const record = challenge('corrupt-' + index);
        await value.store.createChallenge(record);
        await value.sql.execute('main', {
          text: `UPDATE ${value.schema}.mfa_challenges SET body=:body::jsonb WHERE id=:id`,
          bindings: { id: record.id, body: JSON.stringify({ ...record, ...mutation }) },
        });
        await assert.rejects(
          value.store.claimChallenge(claim(record)),
          (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
        );
        assert.equal(await value.store.claimChallenge(claim(record)), null);
      }
    } finally {
      await value.close();
    }
  },
);

test(
  'PostgreSQL MFA challenges retain exact ownership and fail closed on expiry, duplicate creation and reuse',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    try {
      const record = challenge('ownership');
      await value.store.createChallenge(record);
      await assert.rejects(
        value.store.claimChallenge(claim(record), { signal: AbortSignal.abort() }),
        (error) => error instanceof KitError && error.code === 'EK_ABORTED',
      );
      await assert.rejects(
        value.store.createChallenge(record),
        (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
      );
      for (const override of [
        { issuer: 'https://foreign.example.test' },
        { subject: 'other-account' },
        { tenantId: 'tenant-b' },
        { primarySessionId: 'session-b' },
        { rpId: 'foreign.example.test' },
        { purpose: 'webauthn-register' as const },
        { now: record.expiresAt },
      ])
        assert.equal(await value.store.claimChallenge({ ...claim(record), ...override }), null);
      const { tenantId: _tenant, ...withoutTenant } = claim(record);
      void _tenant;
      assert.equal(await value.store.claimChallenge(withoutTenant), null);
      assert.deepEqual(await value.store.claimChallenge(claim(record)), record);
      assert.equal(await value.store.claimChallenge(claim(record)), null);
      const discarded = challenge('discarded');
      await value.store.createChallenge(discarded);
      await value.store.discardChallenge(discarded.id);
      assert.equal(await value.store.claimChallenge(claim(discarded)), null);
    } finally {
      await value.close();
    }
  },
);

test(
  'Two independent Node processes can consume a durable MFA challenge at most once',
  { timeout: 20000 },
  async (t) => {
    const value = await fixture();
    try {
      const record = challenge('cross-process');
      await value.store.createChallenge(record);
      const workers = [
        worker(t, value.schema, claim(record)),
        worker(t, value.schema, claim(record)),
      ];
      await Promise.all(workers.map((item) => item.ready));
      for (const item of workers) item.go();
      const results = await Promise.all(workers.map((item) => item.result));
      assert.deepEqual(results.sort(), [false, true]);
      assert.equal(await value.store.claimChallenge(claim(record)), null);
    } finally {
      await value.close();
    }
  },
);
