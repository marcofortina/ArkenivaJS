// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { MfaChallengeRecord, MfaSubjectContext } from '@arkenivajs/core';
import type {
  WebAuthnCredentialRecord,
  WebAuthnStateMutationResult,
} from '@arkenivajs/security-webauthn';
import {
  createPostgresWebAuthnTables,
  createPostgresWebAuthnStateStore,
} from '../../dist/webauthn-state-store.js';
import { totpFixture } from './totp-fixture.js';
import { startMfaWorker } from './mfa-worker.js';

const rp = 'example.test';
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
async function fixture() {
  const f = await totpFixture();
  try {
    await createPostgresWebAuthnTables(f.app.sql, 'main', f.schema);
    return { ...f, store: createPostgresWebAuthnStateStore(f.app.sql, 'main', f.schema, f.clock) };
  } catch (error) {
    await f.close();
    throw error;
  }
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function record(f: Fixture, subject: MfaSubjectContext): Promise<WebAuthnCredentialRecord> {
  return {
    credentialId: randomBytes(32).toString('base64url'),
    rpId: rp,
    issuer: subject.issuer,
    subject: subject.subject,
    ...(subject.tenant === undefined ? {} : { tenantId: subject.tenant.tenantId }),
    userHandle: await f.store.getOrCreateUserHandle(subject, rp),
    stateVersion: 'untrusted-candidate-marker',
    publicKey: randomBytes(80),
    counter: 0,
    backupEligible: true,
    backedUp: false,
    transports: ['internal'],
    registeredAt: new Date(f.clock()).toISOString(),
  };
}
const advance = (value: WebAuthnCredentialRecord, next = value.counter) => ({
  credentialId: value.credentialId,
  rpId: value.rpId,
  issuer: value.issuer,
  subject: value.subject,
  ...(value.tenantId === undefined ? {} : { tenantId: value.tenantId }),
  userHandle: value.userHandle,
  expectedVersion: value.stateVersion,
  previousCounter: value.counter,
  newCounter: next,
  backedUp: value.backedUp,
});

// Each worker owns an independent framework application, pool and operating-system process.
const workerScript = `
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createPostgresWebAuthnStateStore } from './dist/webauthn-state-store.js';
import { createInterface } from 'node:readline';
const context = JSON.parse(process.argv[1]);
const app = await createApplication({
  service: {name:'webauthn-store-worker',version:'1.0.0',environment:'test'},
  plugins:[postgresPlugin()],
  databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}},
});
await app.start();
try {
  const store = createPostgresWebAuthnStateStore(app.sql,'main',context.schema,()=>context.now);
  const lines = createInterface({input:process.stdin});
  const request = new Promise(resolve=>lines.once('line',line=>resolve(JSON.parse(line))));
  console.log(JSON.stringify({ready:true}));
  const input = await request;
  let result;
  if(input.action==='handle') result=await store.getOrCreateUserHandle(input.subject,input.rp);
  else if(input.action==='advance') result=await store.advanceCounter(input.value);
  else if(input.action==='revoke') result=await store.revokeCredential(input.subject,input.rp,input.id,input.version);
  else if(input.action==='insert') result=await store.insertCredentialIfAbsent({...input.value,publicKey:Buffer.from(input.value.publicKey,'base64url')});
  else throw new Error('Unknown WebAuthn worker action');
  console.log(JSON.stringify({result}));
  lines.close();
} finally {await app.stop();}
`;
async function race(t: TestContext, f: Fixture, requests: readonly unknown[]) {
  const workers = requests.map(() =>
    startMfaWorker(t, workerScript, { schema: f.schema, now: f.clock() }),
  );
  await Promise.all(workers.map((worker) => worker.ready));
  workers.forEach((worker, index) => worker.go(requests[index]));
  return Promise.all(workers.map((worker) => worker.result));
}

test(
  'PostgreSQL allocates one stable random account handle across independent processes and tenant scopes',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture();
    try {
      const owner = await f.subject({ tenant_id: undefined });
      const handles = await race(
        t,
        f,
        [0, 1].map(() => ({ action: 'handle', subject: owner, rp })),
      );
      assert.equal(handles[0], handles[1]);
      assert.equal(Buffer.from(String(handles[0]), 'base64url').length, 32);
      assert.equal(await f.store.getOrCreateUserHandle(owner, rp), handles[0]);
      const tenant = await f.subject({ tenant_id: 'tenant-a' });
      const other = await f.subject({ tenant_id: 'tenant-b' });
      const scoped = await Promise.all([
        f.store.getOrCreateUserHandle(tenant, rp),
        f.store.getOrCreateUserHandle(other, rp),
        f.store.getOrCreateUserHandle(owner, 'other.example.test'),
      ]);
      assert.equal(new Set([...handles, ...scoped]).size, 4);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL inserts a credential once globally per RP and independently checks account-handle association',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      const results = await race(
        t,
        f,
        [0, 1].map(() => ({
          action: 'insert',
          value: { ...value, publicKey: Buffer.from(value.publicKey).toString('base64url') },
        })),
      );
      assert.deepEqual(results.sort(), [false, true]);
      const saved = await f.store.getCredential(value.credentialId, rp);
      assert.ok(saved);
      assert.notEqual(saved.stateVersion, value.stateVersion);
      assert.deepEqual(saved.publicKey, Uint8Array.from(value.publicKey));
      assert.equal(saved.counter, 0);
      for (const userHandle of [undefined, null, value.userHandle])
        assert.equal(
          await f.store.verifyUserHandleBinding({
            credentialId: value.credentialId,
            rpId: rp,
            ...(userHandle === undefined ? {} : { userHandle }),
          }),
          true,
        );
      assert.equal(
        await f.store.verifyUserHandleBinding({
          credentialId: value.credentialId,
          rpId: rp,
          userHandle: randomBytes(32).toString('base64url'),
        }),
        false,
      );
      const foreign = await f.subject({ tenant_id: 'foreign' }),
        foreignRecord = await record(f, foreign);
      assert.equal(
        await f.store.insertCredentialIfAbsent({
          ...foreignRecord,
          credentialId: value.credentialId,
        }),
        false,
      );
      assert.equal(
        await f.store.insertCredentialIfAbsent({ ...foreignRecord, userHandle: value.userHandle }),
        false,
      );
      assert.deepEqual(await f.store.listCredentials(foreign, rp), []);
      assert.equal((await f.store.listCredentials(owner, rp)).length, 1);
      assert.equal(await f.store.getCredential(value.credentialId, 'other.example.test'), null);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL zero and increasing counters compare one durable version across processes without retries',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      assert.equal(await f.store.insertCredentialIfAbsent(value), true);
      for (const next of [0, 2]) {
        const saved = (await f.store.getCredential(value.credentialId, rp))!;
        const results = (await race(
          t,
          f,
          [0, 1].map(() => ({ action: 'advance', value: advance(saved, next) })),
        )) as WebAuthnStateMutationResult[];
        assert.deepEqual(results.map((result) => result.status).sort(), ['conflict', 'updated']);
        const current = (await f.store.getCredential(value.credentialId, rp))!;
        assert.equal(current.counter, next);
        assert.notEqual(current.stateVersion, saved.stateVersion);
        assert.equal(
          results.find((result) => result.status === 'updated')!.newVersion,
          current.stateVersion,
        );
        const stale = await f.store.advanceCounter(advance(saved, next));
        assert.equal(stale.status, 'conflict');
      }
      const saved = (await f.store.getCredential(value.credentialId, rp))!;
      await assert.rejects(f.store.advanceCounter(advance(saved, 2)), hasCode('EK_MFA_POLICY'));
      await assert.rejects(f.store.advanceCounter(advance(saved, 1)), hasCode('EK_MFA_POLICY'));
      const changed = await f.store.advanceCounter({ ...advance(saved, 3), backedUp: true });
      assert.equal(changed.status, 'updated');
      assert.equal((await f.store.getCredential(value.credentialId, rp))!.backedUp, true);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL revocation and zero-counter acceptance contend on the same row and invalidate account ceremonies',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      await f.store.insertCredentialIfAbsent(value);
      const saved = (await f.store.getCredential(value.credentialId, rp))!;
      const results = (await race(t, f, [
        { action: 'advance', value: advance(saved) },
        {
          action: 'revoke',
          subject: owner,
          rp,
          id: saved.credentialId,
          version: saved.stateVersion,
        },
      ])) as WebAuthnStateMutationResult[];
      assert.equal(results.filter((result) => result.status === 'updated').length, 1);
      assert.ok(
        ['conflict', 'revoked'].includes(
          results.find((result) => result.status !== 'updated')!.status,
        ),
      );
      let current = (await f.store.getCredential(value.credentialId, rp))!;
      if (current.revokedAt === undefined) {
        const revoked = await f.store.revokeCredential(
          owner,
          rp,
          current.credentialId,
          current.stateVersion,
        );
        assert.equal(revoked.status, 'updated');
      }
      current = (await f.store.getCredential(value.credentialId, rp))!;
      assert.ok(current.revokedAt);
      assert.equal((await f.store.advanceCounter(advance(current))).status, 'revoked');
      assert.equal(await f.store.getOrCreateUserHandle(owner, rp), value.userHandle);
      assert.equal(
        await f.store.verifyUserHandleBinding({ credentialId: value.credentialId, rpId: rp }),
        false,
      );

      const active = await record(f, owner);
      await f.store.insertCredentialIfAbsent(active);
      const challenge: MfaChallengeRecord = {
        id: randomBytes(32).toString('base64url'),
        purpose: 'webauthn-authenticate',
        issuer: owner.issuer,
        subject: owner.subject,
        primarySessionId: owner.primarySessionId,
        rpId: rp,
        ...(owner.tenant === undefined ? {} : { tenantId: owner.tenant.tenantId }),
        challengeDigest: 'b'.repeat(64),
        createdAt: new Date(f.clock()).toISOString(),
        expiresAt: new Date(f.clock() + 300000).toISOString(),
      };
      await f.store.createChallenge(challenge);
      const binding = {
        id: challenge.id,
        purpose: challenge.purpose,
        issuer: owner.issuer,
        subject: owner.subject,
        primarySessionId: owner.primarySessionId,
        rpId: rp,
        ...(owner.tenant === undefined ? {} : { tenantId: owner.tenant.tenantId }),
        now: new Date(f.clock()).toISOString(),
      };
      assert.ok(await f.store.claimChallenge(binding));
      const pending = { ...challenge, id: randomBytes(32).toString('base64url') };
      await f.store.createChallenge(pending);
      await f.store.revokeCredential(
        owner,
        rp,
        active.credentialId,
        (await f.store.getCredential(active.credentialId, rp))!.stateVersion,
      );
      assert.equal(await f.store.claimChallenge({ ...binding, id: pending.id }), null);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL bounds active credential reads without truncation or counting revoked tombstones',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      for (let index = 0; index < 101; index++) {
        assert.equal(
          await f.store.insertCredentialIfAbsent({
            ...value,
            credentialId: randomBytes(32).toString('base64url'),
          }),
          true,
        );
        if (index === 99) assert.equal((await f.store.listCredentials(owner, rp)).length, 100);
      }
      await assert.rejects(f.store.listCredentials(owner, rp), hasCode('EK_MFA_STORAGE'));
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.mfa_webauthn_credentials SET revoked_at=:now,state_version=gen_random_uuid()`,
        bindings: { now: new Date(f.clock()).toISOString() },
      });
      assert.deepEqual(await f.store.listCredentials(owner, rp), []);
      assert.equal(await f.store.getOrCreateUserHandle(owner, rp), value.userHandle);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL already-aborted credential operations neither return state nor commit mutations',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      await f.store.insertCredentialIfAbsent(value);
      const saved = (await f.store.getCredential(value.credentialId, rp))!;
      const options = { signal: AbortSignal.abort() };
      for (const work of [
        () => f.store.getOrCreateUserHandle(owner, rp, options),
        () => f.store.listCredentials(owner, rp, options),
        () => f.store.getCredential(value.credentialId, rp, options),
        () =>
          f.store.verifyUserHandleBinding({ credentialId: value.credentialId, rpId: rp }, options),
        () =>
          f.store.insertCredentialIfAbsent(
            { ...value, credentialId: randomBytes(32).toString('base64url') },
            options,
          ),
        () => f.store.advanceCounter(advance(saved), options),
        () => f.store.revokeCredential(owner, rp, saved.credentialId, saved.stateVersion, options),
      ])
        await assert.rejects(work(), hasCode('EK_ABORTED'));
      assert.equal(
        (await f.store.getCredential(value.credentialId, rp))!.stateVersion,
        saved.stateVersion,
      );
      assert.equal((await f.store.listCredentials(owner, rp)).length, 1);
    } finally {
      await f.close();
    }
  },
);

test(
  'PostgreSQL rejects foreign ownership, corrupt metadata, unsafe input and unavailable state without success',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const owner = await f.subject(),
        value = await record(f, owner);
      await f.store.insertCredentialIfAbsent(value);
      const saved = (await f.store.getCredential(value.credentialId, rp))!;
      assert.equal(
        (await f.store.advanceCounter({ ...advance(saved), tenantId: 'foreign' })).status,
        'conflict',
      );
      assert.equal(
        (
          await f.store.advanceCounter({
            ...advance(saved),
            userHandle: randomBytes(32).toString('base64url'),
          })
        ).status,
        'conflict',
      );
      const foreign = await f.subject({ tenant_id: 'foreign' });
      assert.equal(
        (await f.store.revokeCredential(foreign, rp, saved.credentialId, saved.stateVersion))
          .status,
        'not-found',
      );
      assert.equal(
        (
          await f.store.advanceCounter({
            ...advance(saved),
            credentialId: randomBytes(32).toString('base64url'),
          })
        ).status,
        'not-found',
      );
      let getter = 0;
      await assert.rejects(
        f.store.insertCredentialIfAbsent({
          ...value,
          get publicKey() {
            getter++;
            return value.publicKey;
          },
        }),
        hasCode('EK_MFA_POLICY'),
      );
      assert.equal(getter, 0);
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.mfa_webauthn_credentials SET body=jsonb_set(body,'{issuer}','"https://foreign.example.test"'::jsonb) WHERE credential_id=:id`,
        bindings: { id: value.credentialId },
      });
      await assert.rejects(
        f.store.getCredential(value.credentialId, rp),
        hasCode('EK_MFA_STORAGE'),
      );
      await f.app.sql.execute('main', { text: `DROP TABLE ${f.schema}.mfa_webauthn_credentials` });
      await assert.rejects(
        f.store.getCredential(value.credentialId, rp),
        hasCode('EK_MFA_STORAGE'),
      );
    } finally {
      await f.close();
    }
  },
);
