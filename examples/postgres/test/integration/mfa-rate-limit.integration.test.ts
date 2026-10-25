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
import { postgresPlugin } from '@arkenivajs/database-postgres';
import {
  createPostgresMfaRateLimitStore,
  createPostgresMfaRateLimitTable,
} from '../../dist/mfa-rate-limit-store.js';

const input = {
  scopeKey: 'synthetic-scope',
  operation: 'verify',
  maxAttempts: 2,
  windowMs: 1000,
  nowMs: 1000,
};
async function fixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const app = await createApplication({
    service: { name: 'mfa-limiter-example', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 } },
  });
  const schema = 'mfa_' + randomBytes(12).toString('hex');
  let created = false;
  try {
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresMfaRateLimitTable(app.sql, 'main', schema);
    return {
      schema,
      store: createPostgresMfaRateLimitStore(app.sql, 'main', schema),
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

function worker(t: TestContext, schema: string) {
  const script = `
    import {createApplication,KitError} from '@arkenivajs/core';
    import {postgresPlugin} from '@arkenivajs/database-postgres';
    import {createPostgresMfaRateLimitStore} from './dist/mfa-rate-limit-store.js';
    const schema=process.argv[1];
    const app=await createApplication({service:{name:'mfa-limit-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
    try {
      await app.start();
      const go=new Promise(resolve=>process.stdin.once('data',resolve));
      console.log(JSON.stringify({ready:true})); await go;
      const store=createPostgresMfaRateLimitStore(app.sql,'main',schema);
      let count=0;
      for(let attempt=0;attempt<5;attempt++) {
        const value=await store.checkAndRecord({scopeKey:'shared-worker-scope',operation:'verify',maxAttempts:3,windowMs:1000,nowMs:1000});
        if(value.allowed)count++;
      }
      console.log(JSON.stringify({count}));
    } catch(error) {console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}
    finally {await app.stop();process.stdin.destroy();}
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, schema], {
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });
  let resolveReady: () => void, rejectReady: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  let count: number | undefined,
    diagnostic = '';
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const message = JSON.parse(line) as { ready?: boolean; count?: number };
    if (message.ready === true) resolveReady();
    if (
      typeof message.count === 'number' &&
      Number.isInteger(message.count) &&
      message.count >= 0 &&
      message.count <= 5
    )
      count = message.count;
  });
  child.stderr.on('data', (chunk) => {
    diagnostic = (diagnostic + String(chunk)).slice(-4096);
  });
  const result = new Promise<number>((resolve, reject) => {
    child.once('error', (error) => {
      rejectReady(error);
      reject(error);
    });
    child.once('close', (code) => {
      lines.close();
      if (code !== 0 || count === undefined) {
        const error = new Error('MFA limiter worker failed: ' + diagnostic);
        rejectReady(error);
        reject(error);
      } else resolve(count);
    });
  });
  void result.catch(() => undefined);
  return { ready, result, go: () => child.stdin.end('limit\n') };
}

test(
  'Shared MFA rate windows preserve quotas, isolate scopes and fail closed on clock rollback',
  { timeout: 20000 },
  async () => {
    const value = await fixture();
    try {
      assert.deepEqual(await value.store.checkAndRecord(input), { allowed: true });
      assert.deepEqual(await value.store.checkAndRecord(input), { allowed: true });
      assert.deepEqual(await value.store.checkAndRecord(input), {
        allowed: false,
        retryAfterMs: 1000,
      });
      assert.deepEqual(await value.store.checkAndRecord({ ...input, nowMs: 1500 }), {
        allowed: false,
        retryAfterMs: 500,
      });
      await assert.rejects(
        value.store.checkAndRecord({ ...input, maxAttempts: 3, nowMs: 1500 }),
        (error) => error instanceof KitError && error.code === 'EK_MFA_POLICY',
      );
      assert.deepEqual(
        await value.store.checkAndRecord({ ...input, scopeKey: 'different-scope' }),
        { allowed: true },
      );
      assert.deepEqual(await value.store.checkAndRecord({ ...input, operation: 'enroll' }), {
        allowed: true,
      });
      const unicode = { ...input, scopeKey: '界'.repeat(1024), operation: '行'.repeat(1024) };
      assert.deepEqual(await value.store.checkAndRecord(unicode), { allowed: true });
      assert.deepEqual(
        await value.store.checkAndRecord({ ...unicode, scopeKey: 'different-unicode-scope' }),
        { allowed: true },
      );
      assert.deepEqual(await value.store.checkAndRecord({ ...input, nowMs: 2000 }), {
        allowed: true,
      });
      assert.deepEqual(await value.store.checkAndRecord({ ...input, nowMs: 1999 }), {
        allowed: false,
        retryAfterMs: 1001,
      });
      assert.deepEqual(await value.store.checkAndRecord({ ...input, nowMs: 2000 }), {
        allowed: false,
        retryAfterMs: 1000,
      });
      assert.deepEqual(
        await value.store.checkAndRecord({ ...input, nowMs: 3000, maxAttempts: 3 }),
        { allowed: true },
      );
      const wide = {
        ...input,
        scopeKey: 'wide-clock',
        maxAttempts: 1,
        windowMs: 2 ** 33,
        nowMs: 2 ** 42,
      };
      assert.deepEqual(await value.store.checkAndRecord(wide), { allowed: true });
      assert.deepEqual(await value.store.checkAndRecord(wide), {
        allowed: false,
        retryAfterMs: 2 ** 33,
      });
      assert.deepEqual(
        await value.store.checkAndRecord({ ...wide, nowMs: wide.nowMs + wide.windowMs - 1 }),
        { allowed: false, retryAfterMs: 1 },
      );
      assert.deepEqual(
        await value.store.checkAndRecord({ ...wide, nowMs: wide.nowMs + wide.windowMs }),
        { allowed: true },
      );
    } finally {
      await value.close();
    }
  },
);

test(
  'Two Node processes share one MFA attempt budget under contention',
  { timeout: 20000 },
  async (t) => {
    const value = await fixture();
    try {
      const workers = [worker(t, value.schema), worker(t, value.schema)];
      await Promise.all(workers.map((item) => item.ready));
      for (const item of workers) item.go();
      const counts = await Promise.all(workers.map((item) => item.result));
      assert.equal(
        counts.reduce((sum, count) => sum + count, 0),
        3,
      );
      assert.deepEqual(
        await value.store.checkAndRecord({
          ...input,
          scopeKey: 'shared-worker-scope',
          maxAttempts: 3,
        }),
        { allowed: false, retryAfterMs: 1000 },
      );
    } finally {
      await value.close();
    }
  },
);
