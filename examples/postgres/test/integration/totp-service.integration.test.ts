// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate } from 'otplib';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext } from '@arkenivajs/core';
import { createTotpService } from '@arkenivajs/security-totp';
import { totpServiceFixture } from './totp-service-fixture.js';
import { startMfaWorker } from './mfa-worker.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
type Fixture = Awaited<ReturnType<typeof totpServiceFixture>>;
async function enrolled(f: Fixture) {
  const owner = await f.subject({ acr: 'urn:fixture:reauthenticated' });
  f.approveReauthentication(owner, 'enroll');
  const pending = await f.service.beginEnrollment(owner),
    seed = new URL(pending.otpauthUri).searchParams.get('secret')!;
  const code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) });
  await f.service.confirmEnrollment(owner, pending.enrollmentId, code);
  return { owner, pending, seed, code };
}
const next = (f: Fixture) => f.setTime((Math.floor(f.clock() / 30000) + 1) * 30000);

test(
  'An intervening activation cannot turn approved enrollment into unauthorized replacement',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const owner = await f.subject({ acr: 'urn:fixture:reauthenticated' });
      f.approveReauthentication(owner, 'enroll');
      const first = await f.service.beginEnrollment(owner),
        second = await f.service.beginEnrollment(owner),
        seed = new URL(first.otpauthUri).searchParams.get('secret')!;
      await f.service.confirmEnrollment(
        owner,
        first.enrollmentId,
        await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
      );
      await assert.rejects(
        f.service.confirmEnrollment(owner, second.enrollmentId, '123456'),
        hasCode('EK_MFA_POLICY'),
      );
      assert.equal((await f.state.getFactor(owner))!.id, first.enrollmentId);
      f.approveReauthentication(owner, 'replace');
      const replacement = await f.service.beginEnrollment(owner),
        changed = new URL(replacement.otpauthUri).searchParams.get('secret')!;
      assert.equal((await f.state.getFactor(owner))!.id, first.enrollmentId);
      await f.service.confirmEnrollment(
        owner,
        replacement.enrollmentId,
        await generate({ secret: changed, epoch: Math.floor(f.clock() / 1000) }),
      );
      assert.equal((await f.state.getFactor(owner))!.id, replacement.enrollmentId);
      assert.equal((await f.state.getFactor(owner))!.generation, 2);
    } finally {
      await f.close();
    }
  },
);

test(
  'A verified nontenant identity works without fabricating or stripping a tenant binding',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const owner = await f.subject({ tenant_id: undefined, acr: 'urn:fixture:reauthenticated' });
      assert.equal(owner.tenant, undefined);
      f.approveReauthentication(owner, 'enroll');
      const pending = await f.service.beginEnrollment(owner),
        seed = new URL(pending.otpauthUri).searchParams.get('secret')!;
      await f.service.confirmEnrollment(
        owner,
        pending.enrollmentId,
        await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
      );
      next(f);
      const proof = await f.service.verify(
        owner,
        await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
      );
      assert.equal(
        (await f.management(owner, 'recovery-codes', proof.evidenceId)).subject,
        owner.subject,
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'The service keeps the prescribed drift window and exact pending expiration',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const { owner, seed } = await enrolled(f);
      f.setTime((Math.floor(f.clock() / 30000) + 2) * 30000);
      const at = Math.floor(f.clock() / 1000),
        previous = await generate({ secret: seed, epoch: at - 30 });
      assert.equal((await f.service.verify(owner, previous)).method, 'totp');
      await assert.rejects(
        f.service.verify(owner, await generate({ secret: seed, epoch: at + 60 })),
        hasCode('EK_MFA_INVALID'),
      );
      const strict = createTotpService({ ...f.settings, driftSteps: 0 }),
        future = await generate({ secret: seed, epoch: at + 30 });
      await assert.rejects(strict.verify(owner, future), hasCode('EK_MFA_INVALID'));
      assert.equal(
        (await strict.verify(owner, await generate({ secret: seed, epoch: at }))).assurance,
        'mfa',
      );
      assert.equal((await f.service.verify(owner, future)).assurance, 'mfa');
    } finally {
      await f.close();
    }
    const g = await totpServiceFixture();
    try {
      const owner = await g.subject({ acr: 'urn:fixture:reauthenticated' });
      g.approveReauthentication(owner, 'enroll');
      const service = createTotpService({ ...g.settings, enrollmentTtlMs: 1 }),
        pending = await service.beginEnrollment(owner);
      g.setTime(Date.parse(pending.expiresAt));
      await assert.rejects(
        service.getQrCodeImage(owner, pending.enrollmentId),
        hasCode('EK_MFA_ENROLLMENT_EXPIRED'),
      );
      await assert.rejects(
        service.confirmEnrollment(owner, pending.enrollmentId, '123456'),
        hasCode('EK_MFA_ENROLLMENT_EXPIRED'),
      );
      assert.equal(await service.isEnabled(owner), false);
      const { clock: _clock, ...production } = g.settings;
      void _clock;
      assert.throws(
        () => createTotpService({ ...production, environment: 'production' }),
        hasCode('EK_MFA_POLICY'),
      );
    } finally {
      await g.close();
    }
  },
);

test(
  'Two full factor-service processes accept one OTP and one recovery proof through shared SQL',
  { timeout: 20000 },
  async (t) => {
    const f = await totpServiceFixture();
    try {
      const { owner, seed } = await enrolled(f);
      next(f);
      const script = `
      import {createApplication,KitError} from '@arkenivajs/core';import {postgresPlugin} from '@arkenivajs/database-postgres';import {createTotpService} from '@arkenivajs/security-totp';
      import {createPostgresTotpStateStore} from './dist/totp-state-store.js';import {createPostgresMfaRateLimitStore} from './dist/mfa-rate-limit-store.js';import {createPostgresMfaEvidenceStore} from './dist/mfa-evidence-store.js';import {createDisposableMfaSecretProtector} from './dist/mfa-secret-protector.js';
      const {schema,owner,clock,phase}=JSON.parse(process.argv[1]);const freeze=value=>{if(value&&typeof value==='object'){for(const field of Object.values(value))freeze(field);Object.freeze(value);}return value;};freeze(owner);
      const app=await createApplication({service:{name:'totp-service-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:2}}});let encryptionKey,recoveryKey;
      try{await app.start();const input=new Promise(resolve=>{let text='';process.stdin.on('data',chunk=>{text+=String(chunk);if(text.length>4096)throw new Error('Worker input exceeds its bound');});process.stdin.once('end',()=>resolve(JSON.parse(text)));});console.log(JSON.stringify({ready:true}));const payload=await input;encryptionKey=Buffer.from(payload.encryptionKey,'base64');recoveryKey=Buffer.from(payload.recoveryKey,'base64');
        // The closed parent authority channel supplies this preauthenticated fixture context; clones remain unowned.
        const approved=new WeakSet([owner]), state=createPostgresTotpStateStore(app.sql,'main',schema,()=>clock), limiter=createPostgresMfaRateLimitStore(app.sql,'main',schema), evidence=createPostgresMfaEvidenceStore(app.sql,'main',schema), protector=createDisposableMfaSecretProtector('encryption-first',async()=>encryptionKey);
        const service=createTotpService({issuer:'Synthetic Company',environment:'test',clock:()=>clock,stateStore:state,rateLimitStore:{...limiter,usage:'test-only'},evidenceStore:{...evidence,usage:'test-only'},secretProtector:{...protector,usage:'test-only'},trustPolicy:{usage:'test-only',async resolveSubject(subject){return approved.has(subject)?subject:null;},async authorize(){return false;}},recoveryCodeHmac:{algorithm:'HMAC-SHA256',keyProvider:{usage:'test-only',async currentKeyId(){return payload.version;},async resolveKey(version){if(version!==payload.version)throw new Error('Unknown worker key');return recoveryKey;}}}});
        try{if(phase==='otp')await service.verify(owner,payload.code);else await service.verifyRecoveryCode(owner,payload.code);console.log(JSON.stringify({result:true}));}catch(error){if(error instanceof KitError&&['EK_MFA_REPLAY','EK_MFA_INVALID'].includes(error.code))console.log(JSON.stringify({result:false}));else throw error;}
      }catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}finally{encryptionKey?.fill(0);recoveryKey?.fill(0);await app.stop();process.stdin.destroy();}
    `;
      const compete = async (phase: string, code: string) => {
        const workers = [0, 1].map(() =>
          startMfaWorker(t, script, { schema: f.schema, owner, clock: f.clock(), phase }),
        );
        await Promise.all(workers.map((w) => w.ready));
        const encryption = f.workerEncryptionKey(),
          recovery = f.workerRecoveryKey('first');
        try {
          for (const worker of workers)
            worker.go({
              code,
              version: 'first',
              encryptionKey: Buffer.from(encryption).toString('base64'),
              recoveryKey: Buffer.from(recovery).toString('base64'),
            });
        } finally {
          encryption.fill(0);
          recovery.fill(0);
        }
        assert.deepEqual((await Promise.all(workers.map((w) => w.result))).sort(), [false, true]);
      };
      await compete('otp', await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }));
      next(f);
      const proof = await f.service.verify(
          owner,
          await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
        ),
        grant = await f.management(owner, 'recovery-codes', proof.evidenceId),
        codes = await f.service.generateRecoveryCodes(owner, grant);
      await compete('recovery', codes[0]!);
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, codes[0]!),
        hasCode('EK_MFA_INVALID'),
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Public TOTP enrollment requires real primary authority and fresh independent reauthentication',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const owner = await f.subject({ acr: 'urn:fixture:reauthenticated' }),
        plain = await f.subject();
      await assert.rejects(f.service.beginEnrollment(owner), hasCode('EK_MFA_POLICY'));
      assert.throws(() => f.approveReauthentication(plain, 'enroll'), hasCode('EK_MFA_POLICY'));
      for (const subject of [
        undefined,
        Object.freeze({ ...owner }),
        Object.freeze({ ...owner, subject: 'other-account' }),
        await f.subject({ scope: '' }),
      ])
        await assert.rejects(
          f.service.beginEnrollment(subject as MfaSubjectContext),
          (error) =>
            error instanceof KitError &&
            ['EK_MFA_POLICY', 'EK_AUTH_FORBIDDEN'].includes(error.code),
        );
      f.approveReauthentication(owner, 'enroll');
      const pending = await f.service.beginEnrollment(owner),
        seed = new URL(pending.otpauthUri).searchParams.get('secret')!;
      assert.equal(Date.parse(pending.expiresAt) - f.clock(), 300000);
      assert.equal(await f.service.isEnabled(owner), false);
      const png = await f.service.getQrCodeImage(owner, pending.enrollmentId);
      assert.equal(
        Buffer.from(png.split(',')[1]!, 'base64').subarray(0, 8).toString('hex'),
        '89504e470d0a1a0a',
      );
      const foreign = await f.subject({
        tenant_id: 'tenant-b',
        acr: 'urn:fixture:reauthenticated',
      });
      f.approveReauthentication(foreign, 'enroll');
      await assert.rejects(
        f.service.getQrCodeImage(foreign, pending.enrollmentId),
        hasCode('EK_MFA_ENROLLMENT_EXPIRED'),
      );
      await assert.rejects(
        f.service.confirmEnrollment(foreign, pending.enrollmentId, '123456'),
        hasCode('EK_MFA_ENROLLMENT_EXPIRED'),
      );
      const wrongSession = await f.subject({
        sid: 'session-b',
        acr: 'urn:fixture:reauthenticated',
      });
      f.approveReauthentication(wrongSession, 'enroll');
      await assert.rejects(
        f.service.getQrCodeImage(wrongSession, pending.enrollmentId),
        hasCode('EK_MFA_ENROLLMENT_EXPIRED'),
      );
      await assert.rejects(
        f.service.confirmEnrollment(owner, pending.enrollmentId, '123456\n'),
        hasCode('EK_MFA_INVALID'),
      );
      const code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) });
      assert.equal(
        (await f.service.confirmEnrollment(owner, pending.enrollmentId, code)).enabled,
        true,
      );
      assert.equal(await f.service.isEnabled(owner), true);
      await assert.rejects(f.service.verify(owner, code), hasCode('EK_MFA_REPLAY'));
      await assert.rejects(f.service.beginEnrollment(owner), hasCode('EK_MFA_POLICY'));
      f.approveReauthentication(owner, 'replace');
      const replacement = await f.service.beginEnrollment(owner);
      assert.equal((await f.state.getFactor(owner))!.id, pending.enrollmentId);
      f.setTime(Date.parse(replacement.expiresAt));
      await assert.rejects(
        f.service.getQrCodeImage(owner, replacement.enrollmentId),
        hasCode('EK_MFA_POLICY'),
      );
      const stored = await f.app.sql.query<{ body: string }>('main', {
        text: `SELECT body::text FROM ${f.schema}.mfa_totp_pending`,
      });
      assert.equal(
        stored.rows.some((row) => row.body.includes(seed) || row.body.includes(pending.otpauthUri)),
        false,
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'OTP proof is accepted once across service instances and persists one session-bound evidence record',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const { owner, seed } = await enrolled(f);
      next(f);
      const code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
        other = createTotpService(f.settings);
      const results = await Promise.allSettled([
        f.service.verify(owner, code),
        other.verify(owner, code),
      ]);
      const successes = results.filter((r) => r.status === 'fulfilled');
      assert.equal(successes.length, 1);
      const success = successes[0]!;
      assert.equal(success.status, 'fulfilled');
      if (success.status !== 'fulfilled') throw new Error('Expected successful proof');
      const proof = success.value;
      assert.equal(proof.assurance, 'mfa');
      assert.equal(proof.method, 'totp');
      assert.equal('issuer' in proof, false);
      assert.equal('primarySessionId' in proof, false);
      assert.equal(
        JSON.stringify(proof).includes(code) || JSON.stringify(proof).includes(seed),
        false,
      );
      await assert.rejects(f.service.verify(owner, code), hasCode('EK_MFA_REPLAY'));
      assert.throws(
        () => f.auth.requireAssurance(owner.tenant!.identity, 'mfa'),
        hasCode('EK_MFA_ASSURANCE_REQUIRED'),
      );
      const grant = await f.management(owner, 'recovery-codes', proof.evidenceId);
      assert.equal(grant.subject, owner.subject);
      await assert.rejects(f.management(owner, 'recovery-codes', proof.evidenceId));
    } finally {
      await f.close();
    }
  },
);

test(
  'Recovery codes use external rotated HMAC keys, replace prior sets and consume atomically once',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const { owner, seed } = await enrolled(f);
      next(f);
      const proof = await f.service.verify(
          owner,
          await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
        ),
        grant = await f.management(owner, 'recovery-codes', proof.evidenceId);
      await assert.rejects(
        f.service.generateRecoveryCodes(owner, { ...grant }),
        hasCode('EK_MFA_POLICY'),
      );
      const codes = await f.service.generateRecoveryCodes(owner, grant);
      assert.equal(codes.length, 10);
      assert.equal(new Set(codes).size, 10);
      assert.equal(Object.isFrozen(codes), true);
      const rows = await f.app.sql.query<{ keyed_hash: string }>('main', {
        text: `SELECT keyed_hash FROM ${f.schema}.mfa_totp_recovery`,
      });
      assert.equal(rows.rows.length, 10);
      assert.equal(
        rows.rows.some((row) => codes.includes(row.keyed_hash)),
        false,
      );
      const key = f.workerRecoveryKey('first');
      try {
        const stored = JSON.stringify(rows.rows);
        assert.equal(
          stored.includes(Buffer.from(key).toString('base64')) ||
            stored.includes(Buffer.from(key).toString('hex')) ||
            stored.includes(seed) ||
            codes.some((code) => stored.includes(code)),
          false,
        );
      } finally {
        key.fill(0);
      }
      const foreign = await f.subject({ tenant_id: 'tenant-b' });
      await assert.rejects(
        f.service.verifyRecoveryCode(foreign, codes[0]!),
        hasCode('EK_MFA_INVALID'),
      );
      const other = createTotpService(f.settings),
        results = await Promise.allSettled([
          f.service.verifyRecoveryCode(owner, codes[0]!),
          other.verifyRecoveryCode(owner, codes[0]!),
        ]);
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, codes[0]!),
        hasCode('EK_MFA_INVALID'),
      );
      f.rotateRecoveryKey();
      assert.equal((await f.service.verifyRecoveryCode(owner, codes[1]!)).method, 'recovery-code');
      const replacement = await f.service.generateRecoveryCodes(owner, grant);
      assert.equal(
        replacement.every((code) => code.startsWith('second.')),
        true,
      );
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, codes[2]!),
        hasCode('EK_MFA_INVALID'),
      );
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, replacement[0]!),
        hasCode('EK_MFA_RATE_LIMIT'),
      );
      f.setTime(f.clock() + 60000);
      const recovered = await f.service.verifyRecoveryCode(owner, replacement[0]!);
      assert.equal(recovered.assurance, 'mfa');
      const disabling = await f.management(owner, 'disable', recovered.evidenceId);
      await assert.rejects(
        f.service.disable(owner, Object.freeze({ ...disabling })),
        hasCode('EK_MFA_POLICY'),
      );
      await f.service.disable(owner, disabling);
      assert.equal(await f.service.isEnabled(owner), false);
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, replacement[1]!),
        hasCode('EK_MFA_INVALID'),
      );
      await assert.rejects(
        f.service.verify(
          owner,
          await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) }),
        ),
        hasCode('EK_MFA_INVALID'),
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Unknown persistence outcomes burn OTP/recovery proof and never return MFA evidence',
  { timeout: 20000 },
  async () => {
    const f = await totpServiceFixture();
    try {
      const { owner, seed } = await enrolled(f);
      next(f);
      let code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) });
      const lostStep = createTotpService({
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          async acceptStepIfGreater(...args) {
            await f.state.acceptStepIfGreater(...args);
            throw new Error('Synthetic lost write acknowledgment');
          },
        },
      });
      await assert.rejects(lostStep.verify(owner, code), hasCode('EK_MFA_STORAGE'));
      await assert.rejects(f.service.verify(owner, code), hasCode('EK_MFA_REPLAY'));
      next(f);
      code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) });
      const unavailableEvidence = createTotpService({
        ...f.settings,
        evidenceStore: {
          ...f.settings.evidenceStore,
          async recordOnce() {
            throw new Error('Synthetic evidence provider unavailable');
          },
        },
      });
      await assert.rejects(unavailableEvidence.verify(owner, code), hasCode('EK_MFA_STORAGE'));
      await assert.rejects(f.service.verify(owner, code), hasCode('EK_MFA_REPLAY'));
      f.setTime(f.clock() + 60000);
      code = await generate({ secret: seed, epoch: Math.floor(f.clock() / 1000) });
      const proof = await f.service.verify(owner, code),
        grant = await f.management(owner, 'recovery-codes', proof.evidenceId),
        codes = await f.service.generateRecoveryCodes(owner, grant);
      const lostRecovery = createTotpService({
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          async consumeRecoveryHash(...args) {
            await f.state.consumeRecoveryHash(...args);
            throw new Error('Synthetic lost recovery acknowledgment');
          },
        },
      });
      await assert.rejects(
        lostRecovery.verifyRecoveryCode(owner, codes[0]!),
        hasCode('EK_MFA_STORAGE'),
      );
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, codes[0]!),
        hasCode('EK_MFA_INVALID'),
      );
      const unavailableLimiter = createTotpService({
        ...f.settings,
        rateLimitStore: {
          ...f.settings.rateLimitStore,
          async checkAndRecord() {
            throw new Error('Synthetic limiter outage');
          },
        },
      });
      await assert.rejects(unavailableLimiter.verify(owner, code), hasCode('EK_MFA_STORAGE'));
      f.removeRecoveryKey('first');
      await assert.rejects(
        f.service.verifyRecoveryCode(owner, codes[1]!),
        hasCode('EK_MFA_STORAGE'),
      );
      const untrustedSecret = createTotpService({
        ...f.settings,
        secretProtector: {
          ...f.settings.secretProtector,
          async open() {
            return new Uint8Array(32).fill(193);
          },
        },
      });
      await assert.rejects(untrustedSecret.verify(owner, code), hasCode('EK_MFA_STORAGE'));
    } finally {
      await f.close();
    }
  },
);
