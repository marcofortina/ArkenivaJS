// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type {
  MfaSubjectContext,
  MfaSealedSecret,
  MfaEvidence,
  MfaEvidenceRecord,
  MfaManagementAuthorization,
} from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';
import type {
  TotpServiceOptions,
  TotpService,
  TotpFactorRecord,
  TotpPendingEnrollment,
  TotpPolicyAction,
} from './contracts.js';
import {
  createTotpRuntime,
  data,
  text,
  instant,
  policyError,
  invalidProof,
  storageError,
} from './runtime.js';
import type { TotpCall } from './runtime.js';
import { newTotpSecret, totpProvisioningUri, verifyTotpStep } from './totp-driver.js';

function randomToken(): string {
  try {
    return randomBytes(32).toString('base64url');
  } catch {
    throw storageError();
  }
}

function handle(value: unknown): asserts value is string {
  text(value, 128);
  if (/[^A-Za-z0-9._:-]/.test(value)) throw policyError();
}
function expires(now: number, ttl: number): string {
  if (now + ttl > 253402300799999) throw policyError();
  return new Date(now + ttl).toISOString();
}
function binding(subject: MfaSubjectContext) {
  return {
    issuer: subject.issuer,
    subject: subject.subject,
    ...(subject.tenant ? { tenantId: subject.tenant.tenantId } : {}),
  };
}
function secret(value: unknown): MfaSealedSecret {
  const record = data(value, ['keyId', 'ciphertext', 'nonce', 'tag']);
  for (const field of ['keyId', 'ciphertext', 'nonce', 'tag']) text(record[field], 8192);
  return Object.freeze(record) as unknown as MfaSealedSecret;
}
function owned(value: unknown, subject: MfaSubjectContext, kind: 'factor' | 'pending') {
  const fields =
    kind === 'factor'
      ? [
          'id',
          'issuer',
          'subject',
          'tenantId',
          'secret',
          'generation',
          'lastAcceptedStep',
          'enabledAt',
        ]
      : ['id', 'issuer', 'subject', 'tenantId', 'primarySessionId', 'secret', 'expiresAt'];
  const record = data(copyData(value), fields);
  handle(record.id);
  if (
    record.issuer !== subject.issuer ||
    record.subject !== subject.subject ||
    (record.tenantId ?? null) !== (subject.tenant?.tenantId ?? null)
  )
    throw storageError();
  record.secret = secret(record.secret);
  if (kind === 'factor') {
    if (
      !Number.isSafeInteger(record.generation) ||
      (record.generation as number) < 1 ||
      (record.lastAcceptedStep !== null &&
        (!Number.isSafeInteger(record.lastAcceptedStep) || (record.lastAcceptedStep as number) < 0))
    )
      throw storageError();
    instant(record.enabledAt);
  } else {
    if (record.primarySessionId !== subject.primarySessionId) throw storageError();
    instant(record.expiresAt);
  }
  return Object.freeze(record);
}

/** Create a factor service with explicit external authority and durable providers; no session is issued. */
export function createTotpService(options: TotpServiceOptions): TotpService {
  const runtime = createTotpRuntime(options);
  const limit = async (subject: MfaSubjectContext, operation: TotpPolicyAction, call: TotpCall) => {
    const scopeKey = createHash('sha256')
      .update(
        JSON.stringify([
          'arkenivajs-totp-limit-v1',
          subject.issuer,
          subject.subject,
          subject.tenant?.tenantId ?? null,
        ]),
      )
      .digest('hex');
    const decision = await call.call(() =>
      runtime.limiter.checkAndRecord(
        { scopeKey, operation, maxAttempts: 5, windowMs: 60000, nowMs: call.now() },
        call.options,
      ),
    );
    if (!decision || typeof decision.allowed !== 'boolean') throw storageError();
    if (!decision.allowed)
      throw new KitError({ code: 'EK_MFA_RATE_LIMIT', message: 'MFA attempt limit reached' });
  };
  const factor = async (
    subject: MfaSubjectContext,
    call: TotpCall,
  ): Promise<TotpFactorRecord | null> => {
    const result = await call.call(() => runtime.state.getFactor(subject, call.options));
    if (result === null) return null;
    return call.call(async () => owned(result, subject, 'factor') as unknown as TotpFactorRecord);
  };
  const enrollment = async (
    subject: MfaSubjectContext,
    enrollmentId: string,
    call: TotpCall,
  ): Promise<TotpPendingEnrollment> => {
    handle(enrollmentId);
    const result = await call.call(() =>
      runtime.state.getPending(subject, enrollmentId, call.options),
    );
    if (result === null)
      throw new KitError({
        code: 'EK_MFA_ENROLLMENT_EXPIRED',
        message: 'Enrollment is unavailable',
      });
    const record = await call.call(
      async () => owned(result, subject, 'pending') as unknown as TotpPendingEnrollment,
    );
    if (record.id !== enrollmentId) throw storageError();
    if (instant(record.expiresAt) <= call.now())
      throw new KitError({
        code: 'EK_MFA_ENROLLMENT_EXPIRED',
        message: 'Enrollment is unavailable',
      });
    return record;
  };
  const open = async (
    subject: MfaSubjectContext,
    envelope: MfaSealedSecret,
    call: TotpCall,
  ): Promise<string> => {
    const bytes = await call.call(() =>
      runtime.protector.open(envelope, binding(subject), call.options),
    );
    if (!(bytes instanceof Uint8Array)) throw storageError();
    try {
      if (bytes.byteLength !== 32) throw storageError();
      const value = String.fromCharCode(...bytes);
      if (!/^[A-Z2-7]{32}$/.test(value)) throw storageError();
      return value;
    } finally {
      bytes.fill(0);
    }
  };
  const evidence = async (
    subject: MfaSubjectContext,
    method: 'totp' | 'recovery-code',
    call: TotpCall,
  ): Promise<MfaEvidence> => {
    const at = call.now(),
      result: MfaEvidence = Object.freeze({
        evidenceId: randomToken(),
        method,
        assurance: 'mfa',
        subject: subject.subject,
        verifiedAt: new Date(at).toISOString(),
        expiresAt: expires(at, 60000),
      });
    const record: MfaEvidenceRecord = Object.freeze({
      ...result,
      ...binding(subject),
      primarySessionId: subject.primarySessionId,
    });
    await call.call(() => runtime.evidence.recordOnce(record, call.options));
    return result;
  };

  const ownerFor = async (
    subject: MfaSubjectContext,
    action: TotpPolicyAction,
    call: TotpCall,
    authorization?: MfaManagementAuthorization,
  ) => {
    const owner = await runtime.resolve(subject, call);
    await runtime.authorize(owner, action, authorization, call);
    return owner;
  };

  return Object.freeze<TotpService>({
    beginEnrollment(subject, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'begin-enrollment', call);
        await limit(owner, 'begin-enrollment', call);
        const at = call.now(),
          expiresAt = expires(at, runtime.enrollmentTtlMs),
          value = newTotpSecret(),
          bytes = Buffer.from(value, 'ascii');
        let sealed: MfaSealedSecret;
        try {
          sealed = await call.call(async () =>
            secret(await runtime.protector.seal(bytes, binding(owner), call.options)),
          );
        } finally {
          bytes.fill(0);
        }
        const enrollmentId = randomToken(),
          otpauthUri = totpProvisioningUri(runtime.issuer, owner.subject, value);
        await call.call(() =>
          runtime.state.putPending(
            Object.freeze({
              id: enrollmentId,
              ...binding(owner),
              primarySessionId: owner.primarySessionId,
              secret: sealed,
              expiresAt,
            }),
            call.options,
          ),
        );
        return Object.freeze({ enrollmentId, expiresAt, otpauthUri });
      });
    },
    getQrCodeImage(subject, enrollmentId, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'read-enrollment-qr', call);
        await limit(owner, 'read-enrollment-qr', call);
        const pending = await enrollment(owner, enrollmentId, call),
          value = await open(owner, pending.secret, call),
          uri = totpProvisioningUri(runtime.issuer, owner.subject, value);
        if (uri.length > 4096) throw invalidProof();
        const png = await call.call(async () => {
          const qr = await import('qrcode');
          call.check();
          return qr.toDataURL(uri, { type: 'image/png', errorCorrectionLevel: 'M' });
        });
        if (
          typeof png !== 'string' ||
          !png.startsWith('data:image/png;base64,') ||
          png.length > 65536
        )
          throw storageError();
        return png;
      });
    },
    confirmEnrollment(subject, enrollmentId, code, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'confirm-enrollment', call);
        await limit(owner, 'confirm-enrollment', call);
        const pending = await enrollment(owner, enrollmentId, call),
          value = await open(owner, pending.secret, call);
        call.check();
        const step = await verifyTotpStep(value, code, call.now(), runtime.driftSteps);
        call.check();
        if (step === null) throw invalidProof();
        if (
          (await call.call(() =>
            runtime.state.activatePending(
              owner,
              enrollmentId,
              step,
              new Date(call.now()).toISOString(),
              call.options,
            ),
          )) !== true
        )
          throw new KitError({
            code: 'EK_MFA_REPLAY',
            message: 'Factor transition was not accepted',
          });
        return Object.freeze({ enabled: true });
      });
    },
    verify(subject, code, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'verify', call);
        await limit(owner, 'verify', call);
        const current = await factor(owner, call);
        if (!current) throw invalidProof();
        const value = await open(owner, current.secret, call);
        call.check();
        const step = await verifyTotpStep(value, code, call.now(), runtime.driftSteps);
        call.check();
        if (step === null) throw invalidProof();
        if (
          (current.lastAcceptedStep !== null && step <= current.lastAcceptedStep) ||
          (await call.call(() =>
            runtime.state.acceptStepIfGreater(
              owner,
              current.id,
              current.generation,
              step,
              call.options,
            ),
          )) !== true
        )
          throw new KitError({
            code: 'EK_MFA_REPLAY',
            message: 'Factor proof was already used or superseded',
          });
        return evidence(owner, 'totp', call);
      });
    },
    isEnabled(subject, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'is-enabled', call);
        await limit(owner, 'is-enabled', call);
        return (await factor(owner, call)) !== null;
      });
    },
    disable(subject, authorization, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'disable', call, authorization);
        await limit(owner, 'disable', call);
        const current = await factor(owner, call);
        if (!current) throw invalidProof();
        if (
          (await call.call(() => runtime.state.revokeFactor(owner, current.id, call.options))) !==
          true
        )
          throw storageError();
      });
    },
    generateRecoveryCodes(subject, authorization, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'generate-recovery-codes', call, authorization);
        await limit(owner, 'generate-recovery-codes', call);
        const current = await factor(owner, call);
        if (!current) throw invalidProof();
        const codes: string[] = [],
          hashes: string[] = [];
        for (let index = 0; index < runtime.recoveryCodeCount; index++) {
          const code = randomToken();
          codes.push(code);
          hashes.push(
            await runtime.recoveryVerifier({ ...binding(owner), factorId: current.id, code }, call),
          );
        }
        if (new Set(codes).size !== codes.length || new Set(hashes).size !== hashes.length)
          throw storageError();
        await call.call(() =>
          runtime.state.replaceRecoveryHashes(owner, Object.freeze(hashes), call.options),
        );
        return Object.freeze(codes);
      });
    },
    verifyRecoveryCode(subject, code, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await ownerFor(subject, 'verify-recovery-code', call);
        await limit(owner, 'verify-recovery-code', call);
        if (
          typeof code !== 'string' ||
          code.length !== 43 ||
          /[^A-Za-z0-9_-]/.test(code) ||
          Buffer.from(code, 'base64url').toString('base64url') !== code
        )
          throw invalidProof();
        const current = await factor(owner, call);
        if (!current) throw invalidProof();
        const hashes = await runtime.recoveryCandidates(
          { ...binding(owner), factorId: current.id, code },
          call,
        );
        let accepted = false;
        for (const hash of hashes) {
          const consumed = await call.call(() =>
            runtime.state.consumeRecoveryHash(owner, hash, call.options),
          );
          if (typeof consumed !== 'boolean') throw storageError();
          accepted = consumed || accepted;
        }
        if (!accepted) throw invalidProof();
        return evidence(owner, 'recovery-code', call);
      });
    },
  });
}
