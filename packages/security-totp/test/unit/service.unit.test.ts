// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type {
  MfaSubjectContext,
  OperationOptions,
  MfaManagementAuthorization,
} from '@arkenivajs/core';
import { createTotpService } from '../../dist/index.js';
import { runtimeFixture } from '../support/runtime-fixture.js';
import { generate } from 'otplib';
import { inspect } from 'node:util';
import type { TotpFactorRecord, TotpPendingEnrollment } from '../../dist/index.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
test('Every public factor operation rejects unowned objects and cancellation before storage access', async () => {
  const f = runtimeFixture();
  let calls = 0;
  const unavailable = async (): Promise<never> => {
    calls++;
    throw new Error('Synthetic provider unavailable');
  };
  const state = { ...f.options.stateStore };
  for (const key of Object.keys(state))
    if (key !== 'usage') (state as unknown as Record<string, unknown>)[key] = unavailable;
  const service = createTotpService({
    ...f.options,
    stateStore: state,
    rateLimitStore: { usage: 'test-only', checkAndRecord: unavailable },
  });
  const grant = (action: 'disable' | 'recovery-codes'): MfaManagementAuthorization => {
    const value = Object.freeze({
      action,
      subject: f.subject.subject,
      trustedSessionId: f.subject.primarySessionId,
      verifiedAt: f.subject.authenticatedAt,
    });
    f.grants.add(value);
    return value;
  };
  const disable = grant('disable'),
    recovery = grant('recovery-codes');
  const operations: Array<
    (subject: MfaSubjectContext, options?: OperationOptions) => Promise<unknown>
  > = [
    (s, o) => service.beginEnrollment(s, o),
    (s, o) => service.getQrCodeImage(s, 'enrollment', o),
    (s, o) => service.confirmEnrollment(s, 'enrollment', '123456', o),
    (s, o) => service.verify(s, '123456', o),
    (s, o) => service.isEnabled(s, o),
    (s, o) => service.disable(s, disable, o),
    (s, o) => service.generateRecoveryCodes(s, recovery, o),
    (s, o) => service.verifyRecoveryCode(s, 'first.invalid', o),
  ];
  for (const operation of operations) {
    await assert.rejects(operation(Object.freeze({ ...f.subject })), hasCode('EK_AUTH_FORBIDDEN'));
    await assert.rejects(
      operation(undefined as unknown as MfaSubjectContext),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      operation(f.subject, { signal: AbortSignal.abort() }),
      hasCode('EK_ABORTED'),
    );
  }
  assert.equal(calls, 0);
  f.strong.add(f.subject);
  for (const operation of operations)
    await assert.rejects(operation(f.subject), hasCode('EK_MFA_STORAGE'));
  assert.equal(calls, 8);
});

test('Missing, malformed or request-like factory settings cannot activate a TOTP service', () => {
  const f = runtimeFixture();
  for (const value of [
    undefined,
    null,
    {},
    { ...f.options, environment: undefined },
    { ...f.options, subjectAuthority: null },
    { ...f.options, now: Date.now() },
  ])
    assert.throws(() => createTotpService(value as never), hasCode('EK_MFA_POLICY'));
});

test('All eight actions require their own authorization before factor or limiter access', async () => {
  const f = runtimeFixture();
  const actions = [
    'begin-enrollment',
    'read-enrollment-qr',
    'confirm-enrollment',
    'verify',
    'is-enabled',
    'disable',
    'generate-recovery-codes',
    'verify-recovery-code',
  ];
  const service = createTotpService(f.options);
  const grant = {
    action: 'disable',
    subject: f.subject.subject,
    trustedSessionId: f.subject.primarySessionId,
    verifiedAt: f.subject.authenticatedAt,
  } as const;
  const work = [
    () => service.beginEnrollment(f.subject),
    () => service.getQrCodeImage(f.subject, 'handle'),
    () => service.confirmEnrollment(f.subject, 'handle', '123456'),
    () => service.verify(f.subject, '123456'),
    () => service.isEnabled(f.subject),
    () => service.disable(f.subject, grant),
    () => service.generateRecoveryCodes(f.subject, { ...grant, action: 'recovery-codes' }),
    () => service.verifyRecoveryCode(f.subject, 'A'.repeat(43)),
  ];
  for (let index = 0; index < actions.length; index++) {
    f.denied.add(actions[index]!);
    await assert.rejects(work[index]!(), hasCode('EK_AUTH_FORBIDDEN'));
    f.denied.clear();
  }
});

/** Fault injection only: these providers are neither encryption nor durable storage implementations. */
function faultyProviderFixture() {
  const f = runtimeFixture(),
    seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  f.strong.add(f.subject);
  const envelope = {
    keyId: 'synthetic',
    ciphertext: 'synthetic',
    nonce: 'synthetic',
    tag: 'synthetic',
  };
  const factor = {
    id: 'factor',
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    secret: envelope,
    generation: 1,
    lastAcceptedStep: 0,
    enabledAt: f.subject.authenticatedAt,
  };
  const pending = {
    id: 'enrollment',
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    primarySessionId: f.subject.primarySessionId,
    secret: envelope,
    expiresAt: new Date(f.options.clock!.nowEpochMs() + 300000).toISOString(),
  };
  const state = {
    factor: factor as unknown,
    pending: pending as unknown,
    decision: { allowed: true } as unknown,
    plaintext: () => new Uint8Array([...seed].map((c) => c.charCodeAt(0))) as unknown,
  };
  const service = createTotpService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async getFactor() {
        return state.factor as TotpFactorRecord | null;
      },
      async getPending() {
        return state.pending as TotpPendingEnrollment | null;
      },
      async putPending() {},
      async activatePending() {
        return false;
      },
      async revokeFactor() {
        return false;
      },
      async acceptStepIfGreater() {
        return false;
      },
    },
    rateLimitStore: {
      usage: 'test-only',
      async checkAndRecord() {
        return state.decision as { allowed: boolean };
      },
    },
    secretProtector: {
      usage: 'test-only',
      async seal() {
        return envelope;
      },
      async open() {
        return state.plaintext() as Uint8Array;
      },
    },
  });
  const grant = (action: 'disable' | 'recovery-codes') => {
    const result = Object.freeze({
      action,
      subject: f.subject.subject,
      trustedSessionId: f.subject.primarySessionId,
      verifiedAt: f.subject.authenticatedAt,
    });
    f.grants.add(result);
    return result;
  };
  return {
    f,
    service,
    state,
    factor,
    pending,
    grant,
    code: () => generate({ secret: seed, epoch: Math.floor(f.options.clock!.nowEpochMs() / 1000) }),
  };
}

test('Malformed persisted ownership, generation and step metadata never becomes enabled factor state', async () => {
  const x = faultyProviderFixture();
  for (const change of [
    { issuer: 'foreign' },
    { subject: 'foreign' },
    { tenantId: 'foreign' },
    { id: 'bad/id' },
    { generation: 0 },
    { generation: 1.5 },
    { lastAcceptedStep: -1 },
    { lastAcceptedStep: '1' },
    { enabledAt: 'invalid' },
    { secret: { ...x.factor.secret, extra: 'forbidden' } },
  ]) {
    x.state.factor = { ...x.factor, ...change };
    await assert.rejects(x.service.isEnabled(x.f.subject), hasCode('EK_MFA_STORAGE'));
  }
  x.state.factor = { ...x.factor, lastAcceptedStep: null };
  assert.equal(await x.service.isEnabled(x.f.subject), true);
  await assert.rejects(x.service.verify(x.f.subject, await x.code()), hasCode('EK_MFA_REPLAY'));
});

test('Pending metadata, invalid proof and refused atomic transitions fail without activation', async () => {
  const x = faultyProviderFixture();
  for (const [change, code] of [
    [{ primarySessionId: 'other' }, 'EK_MFA_STORAGE'],
    [{ id: 'other' }, 'EK_MFA_STORAGE'],
    [{ expiresAt: x.f.subject.authenticatedAt }, 'EK_MFA_ENROLLMENT_EXPIRED'],
  ] as const) {
    x.state.pending = { ...x.pending, ...change };
    await assert.rejects(x.service.getQrCodeImage(x.f.subject, 'enrollment'), hasCode(code));
  }
  x.state.pending = x.pending;
  await assert.rejects(
    x.service.getQrCodeImage(x.f.subject, 'invalid/handle'),
    hasCode('EK_MFA_POLICY'),
  );
  await assert.rejects(
    x.service.confirmEnrollment(x.f.subject, 'enrollment', await x.code()),
    hasCode('EK_MFA_REPLAY'),
  );
  const valid = await x.code();
  let invalid = '000000';
  const adjacent = new Set(
    await Promise.all(
      [-30, 0, 30].map((delta) =>
        generate({
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          epoch: Math.floor(x.f.options.clock!.nowEpochMs() / 1000) + delta,
        }),
      ),
    ),
  );
  while (adjacent.has(invalid)) invalid = String(Number(invalid) + 1).padStart(6, '0');
  assert.notEqual(invalid, valid);
  await assert.rejects(
    x.service.confirmEnrollment(x.f.subject, 'enrollment', invalid),
    hasCode('EK_MFA_INVALID'),
  );
  await assert.rejects(
    x.service.disable(x.f.subject, x.grant('disable')),
    hasCode('EK_MFA_STORAGE'),
  );
  x.state.factor = null;
  await assert.rejects(
    x.service.disable(x.f.subject, x.grant('disable')),
    hasCode('EK_MFA_INVALID'),
  );
  await assert.rejects(
    x.service.generateRecoveryCodes(x.f.subject, x.grant('recovery-codes')),
    hasCode('EK_MFA_INVALID'),
  );
});

test('Limiter/secret corruption and malformed recovery proofs cannot bypass service guards', async () => {
  const x = faultyProviderFixture();
  for (const decision of [null, { allowed: 'yes' }]) {
    x.state.decision = decision;
    await assert.rejects(x.service.verify(x.f.subject, '123456'), hasCode('EK_MFA_STORAGE'));
  }
  x.state.decision = { allowed: false };
  await assert.rejects(x.service.verify(x.f.subject, '123456'), hasCode('EK_MFA_RATE_LIMIT'));
  x.state.decision = { allowed: true };
  for (const value of [null, new Uint8Array(31), new Uint8Array(32).fill(193)]) {
    x.state.plaintext = () => value;
    await assert.rejects(x.service.verify(x.f.subject, '123456'), hasCode('EK_MFA_STORAGE'));
  }
  for (const code of [
    123456,
    'x'.repeat(109),
    'missing-separator',
    'bad/version.' + 'A'.repeat(43),
    'first.short',
    'first.' + 'A'.repeat(42) + '+',
    'first.' + 'A'.repeat(42) + 'B',
  ])
    await assert.rejects(
      x.service.verifyRecoveryCode(x.f.subject, code as string),
      hasCode('EK_MFA_INVALID'),
    );
});

test('A trusted clock near the representable date boundary cannot create overflowing enrollment', async () => {
  const x = faultyProviderFixture(),
    at = 253402300799999;
  x.state.factor = null;
  x.f.setTime(at);
  const owner = Object.freeze({ ...x.f.subject, authenticatedAt: new Date(at).toISOString() });
  x.f.owners.add(owner);
  x.f.strong.add(owner);
  await assert.rejects(x.service.beginEnrollment(owner), hasCode('EK_MFA_POLICY'));
});

test('Provider diagnostics and caller abort reasons cannot escape through MFA error inspection', async () => {
  const f = runtimeFixture(),
    marker = 'synthetic-sensitive-provider-value';
  const service = createTotpService({
    ...f.options,
    rateLimitStore: {
      usage: 'test-only',
      async checkAndRecord() {
        throw new Error(marker);
      },
    },
  });
  for (const work of [
    () => service.verify(f.subject, '123456'),
    () => service.verify(f.subject, '123456', { signal: AbortSignal.abort(new Error(marker)) }),
  ])
    await assert.rejects(work(), (error) => {
      assert.equal(error instanceof KitError, true);
      assert.equal(
        inspect(error).includes(marker) || JSON.stringify(error).includes(marker),
        false,
      );
      return true;
    });
});
