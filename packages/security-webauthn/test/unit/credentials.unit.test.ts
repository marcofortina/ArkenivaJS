// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, OperationOptions } from '@arkenivajs/core';
import type {
  WebAuthnCredentialRecord,
  WebAuthnStateMutationResult,
} from '../../dist/contracts.js';
import { createWebAuthnRuntime } from '../../dist/runtime.js';
import {
  credentialRecord,
  loadCredential,
  requireOwner,
  advanceCredential,
  revokeCredential,
  verifyHandleBinding,
} from '../../dist/credentials.js';
import { runtimeFixture } from '../support/runtime-fixture.js';
import { authenticator } from '../support/authenticator.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

/** Atomic row simulator only; database durability and cross-process integration require separate tests. */
function fixture() {
  const f = runtimeFixture(),
    device = authenticator();
  let version = 1,
    updates = 0,
    revocations = 0;
  let current: WebAuthnCredentialRecord | null = {
    credentialId: device.id,
    rpId: f.options.rpId,
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    userHandle: randomBytes(32).toString('base64url'),
    stateVersion: 'backend-1',
    publicKey: device.publicKey,
    counter: 0,
    backupEligible: true,
    backedUp: false,
    transports: ['internal'],
    registeredAt: f.subject.authenticatedAt,
  };
  const requests: OperationOptions[] = [];
  const stateStore = {
    ...f.options.stateStore,
    async getCredential() {
      return current;
    },
    async verifyUserHandleBinding(
      input: Parameters<typeof f.options.stateStore.verifyUserHandleBinding>[0],
    ) {
      return (
        current !== null &&
        input.rpId === current.rpId &&
        input.credentialId === current.credentialId &&
        (input.userHandle == null || input.userHandle === current.userHandle)
      );
    },
    async advanceCounter(
      input: Parameters<typeof f.options.stateStore.advanceCounter>[0],
      operation?: OperationOptions,
    ): Promise<WebAuthnStateMutationResult> {
      updates++;
      requests.push(operation!);
      if (!current) return { status: 'not-found' };
      if (current.revokedAt !== undefined) return { status: 'revoked' };
      if (
        input.expectedVersion !== current.stateVersion ||
        input.previousCounter !== current.counter ||
        input.credentialId !== current.credentialId ||
        input.rpId !== current.rpId ||
        input.issuer !== current.issuer ||
        input.subject !== current.subject ||
        input.tenantId !== current.tenantId ||
        input.userHandle !== current.userHandle
      )
        return { status: 'conflict' };
      const newVersion = 'backend-' + ++version;
      current = {
        ...current,
        counter: input.newCounter,
        backedUp: input.backedUp,
        stateVersion: newVersion,
      };
      return { status: 'updated', newVersion };
    },
    async revokeCredential(
      owner: MfaSubjectContext,
      rpId: string,
      id: string,
      expectedVersion: string,
      operation?: OperationOptions,
    ): Promise<WebAuthnStateMutationResult> {
      revocations++;
      requests.push(operation!);
      if (!current) return { status: 'not-found' };
      if (current.revokedAt !== undefined) return { status: 'revoked' };
      if (
        expectedVersion !== current.stateVersion ||
        rpId !== current.rpId ||
        id !== current.credentialId ||
        owner.issuer !== current.issuer ||
        owner.subject !== current.subject ||
        owner.tenant?.tenantId !== current.tenantId
      )
        return { status: 'conflict' };
      const newVersion = 'backend-' + ++version;
      current = {
        ...current,
        stateVersion: newVersion,
        revokedAt: new Date(f.now()).toISOString(),
      };
      return { status: 'updated', newVersion };
    },
  };
  const options = { ...f.options, stateStore };
  return {
    ...f,
    options,
    device,
    requests,
    runtime: createWebAuthnRuntime(options),
    get: () => current!,
    replace(value: WebAuthnCredentialRecord | null) {
      current = value;
    },
    updates: () => updates,
    revocations: () => revocations,
  };
}

test('Credential snapshots preserve exact bytes without invoking mutable view or iterator hooks', () => {
  const f = fixture(),
    original = f.get();
  let calls = 0;
  Object.defineProperty(original.publicKey, Symbol.iterator, {
    get() {
      calls++;
      throw new Error('Untrusted iterator');
    },
  });
  Object.defineProperty(original.publicKey, 'byteLength', {
    get() {
      calls++;
      throw new Error('Untrusted byte length');
    },
  });
  const record = credentialRecord(original, f.options.rpId, f.now());
  assert.ok(Object.isFrozen(record));
  assert.ok(Object.isFrozen(record.transports));
  assert.notEqual(record.publicKey, original.publicKey);
  assert.equal(calls, 0);
  const expected = Uint8Array.from(record.publicKey);
  original.publicKey.fill(0);
  assert.deepEqual(record.publicKey, expected);
});

test('Corrupt credential shape, ownership metadata, counters and key bounds fail as storage errors', () => {
  const f = fixture(),
    original = f.get();
  for (const changes of [
    { credentialId: '' },
    { credentialId: 'A'.repeat(42) + 'B' },
    { rpId: 'foreign' },
    { userHandle: randomBytes(16).toString('base64url') },
    { issuer: '' },
    { subject: null },
    { tenantId: null },
    { stateVersion: '' },
    { stateVersion: '\u0000' },
    { publicKey: 'not bytes' },
    { publicKey: new Uint8Array() },
    { publicKey: new Uint8Array(16385) },
    { counter: -1 },
    { counter: 0.1 },
    { counter: 4294967296 },
    { backupEligible: 'yes' },
    { backedUp: 'yes' },
    { backupEligible: false, backedUp: true },
    { unexpected: 1 },
    { registeredAt: 'invalid' },
    { registeredAt: new Date(f.now() + 1).toISOString() },
    { revokedAt: new Date(f.now() - 1).toISOString() },
    { revokedAt: new Date(f.now() + 1).toISOString() },
    { transports: null },
    { transports: ['internal', 'internal'] },
    { transports: new Array(17).fill('usb') },
    { transports: [null] },
    { transports: new Array(1) },
  ])
    assert.throws(
      () => credentialRecord({ ...original, ...changes }, f.options.rpId, f.now()),
      hasCode('EK_MFA_STORAGE'),
    );
  let reads = 0;
  const key = {
    ...original,
    get publicKey() {
      reads++;
      throw new Error('Sensitive storage getter');
    },
  };
  const transports: string[] = [];
  Object.defineProperty(transports, '0', {
    get() {
      reads++;
      return 'internal';
    },
  });
  for (const record of [null, key, { ...original, transports }])
    assert.throws(
      () => credentialRecord(record, f.options.rpId, f.now()),
      hasCode('EK_MFA_STORAGE'),
    );
  assert.equal(reads, 0);
  assert.equal(
    credentialRecord(
      { ...original, transports: undefined, revokedAt: original.registeredAt },
      f.options.rpId,
      f.now(),
    ).revokedAt,
    original.registeredAt,
  );
});

test('Unknown, revoked and foreign-account credentials cannot become an owned active record', async () => {
  const f = fixture(),
    initial = f.get();
  await f.runtime.run(undefined, async (call) => {
    assert.equal(
      (await loadCredential(f.runtime, f.device.id, call, f.subject)).stateVersion,
      initial.stateVersion,
    );
    for (const changes of [
      { issuer: 'foreign' },
      { subject: 'foreign' },
      { tenant: { tenantId: 'foreign' } },
    ])
      await assert.rejects(
        loadCredential(f.runtime, f.device.id, call, {
          ...f.subject,
          ...changes,
        } as MfaSubjectContext),
        hasCode('EK_MFA_INVALID'),
      );
    f.replace({ ...initial, credentialId: randomBytes(32).toString('base64url') });
    await assert.rejects(loadCredential(f.runtime, f.device.id, call), hasCode('EK_MFA_STORAGE'));
    f.replace({ ...initial, revokedAt: initial.registeredAt });
    await assert.rejects(loadCredential(f.runtime, f.device.id, call), hasCode('EK_MFA_INVALID'));
    f.replace(null);
    await assert.rejects(loadCredential(f.runtime, f.device.id, call), hasCode('EK_MFA_INVALID'));
    await assert.rejects(loadCredential(f.runtime, 'invalid=', call), hasCode('EK_MFA_INVALID'));
  });
  assert.throws(
    () => requireOwner({ ...initial, tenantId: 'foreign' }, f.subject),
    hasCode('EK_MFA_INVALID'),
  );
});

test('Optional assertion user handles are matched locally and checked against the durable binding', async () => {
  const f = fixture(),
    record = f.get();
  await f.runtime.run(undefined, async (call) => {
    for (const handle of [undefined, null, record.userHandle])
      await verifyHandleBinding(f.runtime, record, handle, call);
    for (const handle of ['', randomBytes(32).toString('base64url')])
      await assert.rejects(
        verifyHandleBinding(f.runtime, record, handle, call),
        hasCode('EK_MFA_INVALID'),
      );
    f.replace(null);
    await assert.rejects(
      verifyHandleBinding(f.runtime, record, undefined, call),
      hasCode('EK_MFA_INVALID'),
    );
  });
  const refused = createWebAuthnRuntime({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async verifyUserHandleBinding() {
        return 'true' as never;
      },
    },
  });
  await assert.rejects(
    refused.run(undefined, (call) => verifyHandleBinding(refused, record, undefined, call)),
    hasCode('EK_MFA_INVALID'),
  );
});

test('Two zero-counter assertions require a version CAS and exactly one stale-snapshot update succeeds', async () => {
  const f = fixture(),
    other = createWebAuthnRuntime(f.options);
  const records = await Promise.all(
    [f.runtime, other].map((runtime) =>
      runtime.run(undefined, (call) => loadCredential(runtime, f.device.id, call)),
    ),
  );
  const verified = { newCounter: 0, backupEligible: true, backedUp: true };
  const results = await Promise.allSettled(
    [f.runtime, other].map((runtime, index) =>
      runtime.run(undefined, (call) => advanceCredential(runtime, records[index]!, verified, call)),
    ),
  );
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const denied = results.find((result) => result.status === 'rejected');
  assert.ok(denied?.status === 'rejected' && hasCode('EK_MFA_CREDENTIAL_CONFLICT')(denied.reason));
  assert.equal(f.get().counter, 0);
  assert.equal(f.get().backedUp, true);
  assert.equal(f.get().stateVersion, 'backend-2');
  assert.equal(f.updates(), 2);
  await f.runtime.run(undefined, async (call) => {
    const fresh = await loadCredential(f.runtime, f.device.id, call);
    assert.equal(
      await advanceCredential(f.runtime, fresh, { ...verified, backedUp: false }, call),
      'backend-3',
    );
    assert.equal(f.requests[2], call.options);
  });
  assert.equal(f.get().backedUp, false);
});

test('Nonzero counters must advance and invalid assertion metadata never reaches the backend', async () => {
  const f = fixture(),
    record = { ...f.get(), counter: 5 };
  f.replace(record);
  for (const newCounter of [0, 4, 5])
    await assert.rejects(
      f.runtime.run(undefined, (call) =>
        advanceCredential(
          f.runtime,
          record,
          { newCounter, backupEligible: true, backedUp: false },
          call,
        ),
      ),
      hasCode('EK_MFA_COUNTER_REGRESSION'),
    );
  for (const change of [
    { newCounter: -1 },
    { newCounter: 0.5 },
    { newCounter: 4294967296 },
    { newCounter: NaN },
    { backupEligible: false },
    { backedUp: 'yes' },
  ])
    await assert.rejects(
      f.runtime.run(undefined, (call) =>
        advanceCredential(
          f.runtime,
          record,
          { newCounter: 6, backupEligible: true, backedUp: false, ...change } as never,
          call,
        ),
      ),
      hasCode('EK_MFA_INVALID'),
    );
  await assert.rejects(
    f.runtime.run(undefined, (call) =>
      advanceCredential(
        f.runtime,
        { ...record, backupEligible: false },
        { newCounter: 6, backupEligible: false, backedUp: true },
        call,
      ),
    ),
    hasCode('EK_MFA_INVALID'),
  );
  assert.equal(f.updates(), 0);
  await f.runtime.run(undefined, async (call) =>
    assert.equal(
      await advanceCredential(
        f.runtime,
        record,
        { newCounter: 6, backupEligible: true, backedUp: true },
        call,
      ),
      'backend-2',
    ),
  );
  assert.equal(f.get().counter, 6);
});

test('CAS compares the stored tenant and user handle when ownership changes after lookup', async () => {
  const f = fixture();
  f.replace({ ...f.get(), tenantId: 'tenant-a' });
  const verified = { newCounter: 0, backupEligible: true, backedUp: false };
  await f.runtime.run(undefined, async (call) => {
    const original = await loadCredential(f.runtime, f.device.id, call);
    assert.equal(await advanceCredential(f.runtime, original, verified, call), 'backend-2');
    const fresh = await loadCredential(f.runtime, f.device.id, call);
    f.replace({ ...f.get(), tenantId: 'tenant-b' });
    await assert.rejects(
      advanceCredential(f.runtime, fresh, verified, call),
      hasCode('EK_MFA_CREDENTIAL_CONFLICT'),
    );
    f.replace({
      ...f.get(),
      tenantId: 'tenant-a',
      userHandle: randomBytes(32).toString('base64url'),
    });
    await assert.rejects(
      advanceCredential(f.runtime, fresh, verified, call),
      hasCode('EK_MFA_CREDENTIAL_CONFLICT'),
    );
  });
  assert.equal(f.get().stateVersion, 'backend-2');
  assert.equal(f.updates(), 3);
});

test('Revocation and authentication contend on one row revision without automatic retry', async () => {
  for (const revokeFirst of [true, false]) {
    const f = fixture(),
      other = createWebAuthnRuntime(f.options),
      record = f.get();
    const revoke = () =>
      other.run(undefined, (call) => revokeCredential(other, record, f.subject, call));
    const authenticate = () =>
      f.runtime.run(undefined, (call) =>
        advanceCredential(
          f.runtime,
          record,
          { newCounter: 0, backupEligible: true, backedUp: false },
          call,
        ),
      );
    const ordered = revokeFirst ? [revoke, authenticate] : [authenticate, revoke];
    const result = await Promise.allSettled(ordered.map((work) => work()));
    assert.equal(result[0]!.status, 'fulfilled');
    assert.equal(result[1]!.status, 'rejected');
    assert.equal(f.updates(), 1);
    assert.equal(f.revocations(), 1);
    if (revokeFirst) {
      assert.ok(f.get().revokedAt);
      await assert.rejects(
        f.runtime.run(undefined, (call) =>
          advanceCredential(
            f.runtime,
            f.get(),
            { newCounter: 0, backupEligible: true, backedUp: false },
            call,
          ),
        ),
        hasCode('EK_MFA_INVALID'),
      );
    } else {
      await f.runtime.run(undefined, (call) =>
        revokeCredential(f.runtime, f.get(), f.subject, call),
      );
      assert.ok(f.get().revokedAt);
    }
    await assert.rejects(
      f.runtime.run(undefined, (call) => revokeCredential(f.runtime, f.get(), f.subject, call)),
      hasCode('EK_MFA_INVALID'),
    );
  }
});

test('Persistence ambiguity, invalid mutation receipts and provider diagnostics cannot produce success', async () => {
  const f = fixture(),
    record = f.get();
  for (const receipt of [
    null,
    false,
    { status: 'unknown' },
    { status: 'updated' },
    { status: 'updated', newVersion: '' },
    { status: 'updated', newVersion: record.stateVersion },
    { status: 'updated', newVersion: 'v2', extra: true },
    { status: 'conflict', newVersion: 'v2' },
  ]) {
    const runtime = createWebAuthnRuntime({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async advanceCounter() {
          return receipt as WebAuthnStateMutationResult;
        },
      },
    });
    await assert.rejects(
      runtime.run(undefined, (call) =>
        advanceCredential(
          runtime,
          record,
          { newCounter: 0, backupEligible: true, backedUp: false },
          call,
        ),
      ),
      hasCode('EK_MFA_STORAGE'),
    );
  }
  for (const status of ['not-found', 'revoked'] as const) {
    const runtime = createWebAuthnRuntime({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async advanceCounter() {
          return { status };
        },
      },
    });
    await assert.rejects(
      runtime.run(undefined, (call) =>
        advanceCredential(
          runtime,
          record,
          { newCounter: 0, backupEligible: true, backedUp: false },
          call,
        ),
      ),
      hasCode('EK_MFA_INVALID'),
    );
  }
  const failed = createWebAuthnRuntime({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async advanceCounter() {
        throw new Error('Sensitive persistence diagnostic');
      },
      async revokeCredential() {
        throw new Error('Sensitive revocation diagnostic');
      },
    },
  });
  for (const operation of [
    () =>
      failed.run(undefined, (call) =>
        advanceCredential(
          failed,
          record,
          { newCounter: 0, backupEligible: true, backedUp: false },
          call,
        ),
      ),
    () => failed.run(undefined, (call) => revokeCredential(failed, record, f.subject, call)),
  ])
    await assert.rejects(operation(), (error) => {
      assert.ok(hasCode('EK_MFA_STORAGE')(error));
      assert.equal(inspect(error).includes('Sensitive'), false);
      return true;
    });
});
