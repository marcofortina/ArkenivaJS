// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext } from '@arkenivajs/core';
import type { TotpPendingEnrollment } from '@arkenivajs/security-totp';
import { totpFixture } from './totp-fixture.js';
import { startMfaWorker } from './mfa-worker.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
async function enrollment(
  value: Awaited<ReturnType<typeof totpFixture>>,
  subject: MfaSubjectContext,
  id: string,
): Promise<TotpPendingEnrollment> {
  return {
    id,
    issuer: subject.issuer,
    subject: subject.subject,
    tenantId: subject.tenant!.tenantId,
    primarySessionId: subject.primarySessionId,
    secret: await value.protector.seal(new Uint8Array([1, 2, 3, 4]), {
      issuer: subject.issuer,
      subject: subject.subject,
      tenantId: subject.tenant!.tenantId,
    }),
    expiresAt: new Date(value.clock() + 300000).toISOString(),
  };
}

test(
  'Pending TOTP enrollment binds real primary ownership/session, expires and activates atomically once',
  { timeout: 20000 },
  async () => {
    const f = await totpFixture();
    try {
      const owner = await f.subject(),
        pending = await enrollment(f, owner, 'first-enrollment');
      await f.state.putPending(pending);
      await assert.rejects(f.state.putPending(pending), hasCode('EK_MFA_STORAGE'));
      assert.deepEqual(await f.state.getPending(owner, pending.id), pending);
      for (const claims of [
        { sub: 'other-account' },
        { tenant_id: 'tenant-b' },
        { sid: 'session-b' },
      ]) {
        const foreign = await f.subject(claims);
        assert.equal(await f.state.getPending(foreign, pending.id), null);
        assert.equal(
          await f.state.activatePending(
            foreign,
            pending.id,
            100,
            new Date(f.clock()).toISOString(),
          ),
          false,
        );
      }
      assert.equal(await f.state.getFactor(owner), null);
      await assert.rejects(
        f.state.activatePending(owner, pending.id, 100, new Date(f.clock()).toISOString(), {
          signal: AbortSignal.abort(),
        }),
        hasCode('EK_ABORTED'),
      );
      assert.equal(
        await f.state.activatePending(owner, pending.id, 100, new Date(f.clock()).toISOString()),
        true,
      );
      assert.equal(
        await f.state.activatePending(owner, pending.id, 100, new Date(f.clock()).toISOString()),
        false,
      );
      assert.equal(await f.state.getPending(owner, pending.id), null);
      const factor = await f.state.getFactor(owner);
      assert.ok(factor);
      assert.equal(factor.generation, 1);
      assert.equal(factor.lastAcceptedStep, 100);
      assert.equal(await f.state.acceptStepIfGreater(owner, factor.id, 1, 100), false);
      assert.equal(await f.state.acceptStepIfGreater(owner, factor.id, 2, 101), false);
      assert.equal(await f.state.acceptStepIfGreater(owner, factor.id, 1, 101), true);
      assert.equal((await f.state.getFactor(owner))!.lastAcceptedStep, 101);
      const expired = await enrollment(f, owner, 'expired-enrollment');
      await f.state.putPending(expired);
      f.setTime(Date.parse(expired.expiresAt));
      assert.equal(await f.state.getPending(owner, expired.id), null);
      assert.equal(await f.state.activatePending(owner, expired.id, 200, expired.expiresAt), false);
      assert.equal((await f.state.getFactor(owner))!.lastAcceptedStep, 101);
    } finally {
      await f.close();
    }
  },
);

test(
  'Replacement preserves the active factor until commit; revocation invalidates pending and recovery state',
  { timeout: 20000 },
  async () => {
    const f = await totpFixture();
    try {
      const owner = await f.subject(),
        first = await enrollment(f, owner, 'original');
      await f.state.putPending(first);
      await f.state.activatePending(owner, first.id, 100, new Date(f.clock()).toISOString());
      const replacement = await enrollment(f, owner, 'replacement'),
        competing = await enrollment(f, owner, 'competing');
      await f.state.putPending(replacement);
      await f.state.putPending(competing);
      assert.equal((await f.state.getFactor(owner))!.id, first.id);
      const hashes = ['first:' + 'a'.repeat(64), 'first:' + 'b'.repeat(64)];
      await f.state.replaceRecoveryHashes(owner, hashes);
      assert.equal(
        await f.state.activatePending(
          owner,
          replacement.id,
          101,
          new Date(f.clock()).toISOString(),
        ),
        true,
      );
      assert.equal(
        await f.state.activatePending(owner, competing.id, 102, new Date(f.clock()).toISOString()),
        false,
      );
      const factor = await f.state.getFactor(owner);
      assert.equal(factor!.id, replacement.id);
      assert.equal(factor!.generation, 2);
      assert.equal(await f.state.consumeRecoveryHash(owner, hashes[0]!), false);
      assert.equal(await f.state.acceptStepIfGreater(owner, first.id, 1, 102), false);
      await f.state.replaceRecoveryHashes(owner, hashes);
      const pending = await enrollment(f, owner, 'pending-before-revoke');
      await f.state.putPending(pending);
      assert.equal(await f.state.revokeFactor(owner, first.id), false);
      assert.equal(await f.state.revokeFactor(owner, factor!.id), true);
      assert.equal(await f.state.getFactor(owner), null);
      assert.equal(await f.state.getPending(owner, pending.id), null);
      assert.equal(await f.state.consumeRecoveryHash(owner, hashes[0]!), false);
      assert.equal(await f.state.acceptStepIfGreater(owner, factor!.id, 2, 103), false);
      await assert.rejects(f.state.putPending(first), hasCode('EK_MFA_STORAGE'));
    } finally {
      await f.close();
    }
  },
);

test(
  'Recovery sets replace atomically, preserve owner isolation and fail closed on corrupt factor metadata',
  { timeout: 20000 },
  async () => {
    const f = await totpFixture();
    try {
      const owner = await f.subject(),
        pending = await enrollment(f, owner, 'recovery-owner');
      await f.state.putPending(pending);
      await f.state.activatePending(owner, pending.id, 100, new Date(f.clock()).toISOString());
      const first = 'first:' + 'c'.repeat(64),
        second = 'second:' + 'd'.repeat(64);
      await f.state.replaceRecoveryHashes(owner, [first]);
      const foreign = await f.subject({ tenant_id: 'tenant-b' });
      assert.equal(await f.state.consumeRecoveryHash(foreign, first), false);
      await f.state.replaceRecoveryHashes(owner, [second]);
      assert.equal(await f.state.consumeRecoveryHash(owner, first), false);
      assert.equal(await f.state.consumeRecoveryHash(owner, second), true);
      assert.equal(await f.state.consumeRecoveryHash(owner, second), false);
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.mfa_totp_accounts SET body=jsonb_set(body,'{subject}','"foreign-account"') WHERE factor_id=:id`,
        bindings: { id: pending.id },
      });
      await assert.rejects(f.state.getFactor(owner), hasCode('EK_MFA_STORAGE'));
    } finally {
      await f.close();
    }
  },
);

test(
  'Two independent processes have one enrollment, OTP-step and recovery-code winner',
  { timeout: 20000 },
  async (t) => {
    const f = await totpFixture();
    try {
      const owner = await f.subject(),
        pending = await enrollment(f, owner, 'cross-process-factor');
      await f.state.putPending(pending);
      const keyedHash = 'first:' + 'e'.repeat(64);
      const script = `
      import {createApplication,KitError} from '@arkenivajs/core';import {postgresPlugin} from '@arkenivajs/database-postgres';import {createPostgresTotpStateStore} from './dist/totp-state-store.js';
      const {schema,owner,factorId,keyedHash,phase,now}=JSON.parse(process.argv[1]);const app=await createApplication({service:{name:'totp-cas-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
      try{await app.start();const go=new Promise(resolve=>process.stdin.once('data',resolve));console.log(JSON.stringify({ready:true}));await go;const store=createPostgresTotpStateStore(app.sql,'main',schema);if(phase==='activate'){console.log(JSON.stringify({result:await store.activatePending(owner,factorId,100,now)}));}else{const step=await store.acceptStepIfGreater(owner,factorId,1,101);const recovery=await store.consumeRecoveryHash(owner,keyedHash);console.log(JSON.stringify({result:{step,recovery}}));}}
      catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}finally{await app.stop();process.stdin.destroy();}
    `;
      const activation = [0, 1].map(() =>
        startMfaWorker(t, script, {
          schema: f.schema,
          owner,
          factorId: pending.id,
          phase: 'activate',
          now: new Date(f.clock()).toISOString(),
        }),
      );
      await Promise.all(activation.map((worker) => worker.ready));
      for (const worker of activation) worker.go();
      assert.deepEqual((await Promise.all(activation.map((worker) => worker.result))).sort(), [
        false,
        true,
      ]);
      await f.state.replaceRecoveryHashes(owner, [keyedHash]);
      const workers = [
        startMfaWorker(t, script, { schema: f.schema, owner, factorId: pending.id, keyedHash }),
        startMfaWorker(t, script, { schema: f.schema, owner, factorId: pending.id, keyedHash }),
      ];
      await Promise.all(workers.map((w) => w.ready));
      for (const worker of workers) worker.go();
      const results = await Promise.all(workers.map((w) => w.result));
      for (const field of ['step', 'recovery'])
        assert.equal(
          results.filter(
            (row) =>
              row !== null &&
              typeof row === 'object' &&
              (row as Record<string, unknown>)[field] === true,
          ).length,
          1,
        );
      assert.equal((await f.state.getFactor(owner))!.lastAcceptedStep, 101);
      assert.equal(await f.state.consumeRecoveryHash(owner, keyedHash), false);
    } finally {
      await f.close();
    }
  },
);

test(
  'A real SQL error after recovery deletion rolls back the entire replacement',
  { timeout: 20000 },
  async () => {
    const f = await totpFixture();
    try {
      const owner = await f.subject(),
        pending = await enrollment(f, owner, 'rollback-factor');
      await f.state.putPending(pending);
      await f.state.activatePending(owner, pending.id, 100, new Date(f.clock()).toISOString());
      const original = 'first:' + 'f'.repeat(64);
      await f.state.replaceRecoveryHashes(owner, [original]);
      await f.app.sql.execute('main', {
        text: `CREATE FUNCTION ${f.schema}.reject_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic recovery persistence failure'; END $$`,
      });
      await f.app.sql.execute('main', {
        text: `CREATE TRIGGER reject_recovery BEFORE INSERT ON ${f.schema}.mfa_totp_recovery FOR EACH ROW EXECUTE FUNCTION ${f.schema}.reject_recovery()`,
      });
      await assert.rejects(
        f.state.replaceRecoveryHashes(owner, ['second:' + 'a'.repeat(64)]),
        hasCode('EK_MFA_STORAGE'),
      );
      assert.equal(await f.state.consumeRecoveryHash(owner, original), true);
      assert.equal(await f.state.consumeRecoveryHash(owner, 'second:' + 'a'.repeat(64)), false);
    } finally {
      await f.close();
    }
  },
);
