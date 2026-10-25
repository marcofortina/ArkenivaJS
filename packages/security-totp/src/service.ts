// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type {
  MfaSubjectContext,
  MfaSealedSecret,
  MfaEvidence,
  MfaEvidenceRecord,
} from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';
import type {
  TotpServiceOptions,
  TotpService,
  TotpFactorRecord,
  TotpPendingEnrollment,
  TotpOperation,
} from './contracts.js';
import {
  createTotpRuntime,
  data,
  text,
  instant,
  keyId,
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
  const limit = async (subject: MfaSubjectContext, operation: TotpOperation, call: TotpCall) => {
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

  return Object.freeze<TotpService>({
    beginEnrollment(subject, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await runtime.resolve(subject, 'begin-enrollment', call),
          current = await factor(owner, call);
        await runtime.authorize(owner, current ? 'replace' : 'enroll', undefined, call);
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
        const owner = await runtime.resolve(subject, 'qr-code', call),
          current = await factor(owner, call);
        await runtime.authorize(owner, current ? 'replace' : 'enroll', undefined, call);
        await limit(owner, 'qr-code', call);
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
        const owner = await runtime.resolve(subject, 'confirm-enrollment', call),
          current = await factor(owner, call);
        // Reauthorize the current transition: an intervening activation can turn enrollment into replacement.
        await runtime.authorize(owner, current ? 'replace' : 'enroll', undefined, call);
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
        const owner = await runtime.resolve(subject, 'verify', call);
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
        const owner = await runtime.resolve(subject, 'status', call);
        return (await factor(owner, call)) !== null;
      });
    },
    disable(subject, authorization, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await runtime.resolve(subject, 'disable', call);
        await runtime.authorize(owner, 'disable', authorization, call);
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
        const owner = await runtime.resolve(subject, 'recovery-codes', call);
        await runtime.authorize(owner, 'recovery-codes', authorization, call);
        await limit(owner, 'recovery-codes', call);
        if (!(await factor(owner, call))) throw invalidProof();
        const version = await runtime.activeRecoveryKey(call),
          codes: string[] = [],
          hashes: string[] = [];
        for (let index = 0; index < 10; index++) {
          const code = version + '.' + randomToken();
          codes.push(code);
          hashes.push(await runtime.recoveryHash(owner, version, code, call));
        }
        await call.call(() =>
          runtime.state.replaceRecoveryHashes(owner, Object.freeze(hashes), call.options),
        );
        return Object.freeze(codes);
      });
    },
    verifyRecoveryCode(subject, code, operation) {
      return runtime.run(operation, async (call) => {
        const owner = await runtime.resolve(subject, 'verify-recovery-code', call);
        await limit(owner, 'verify-recovery-code', call);
        if (typeof code !== 'string' || code.length > 108) throw invalidProof();
        const parts = code.split('.');
        if (parts.length !== 2) throw invalidProof();
        const version = parts[0]!,
          body = parts[1]!;
        try {
          keyId(version);
        } catch {
          throw invalidProof();
        }
        if (
          body.length !== 43 ||
          /[^A-Za-z0-9_-]/.test(body) ||
          Buffer.from(body, 'base64url').toString('base64url') !== body
        )
          throw invalidProof();
        const hash = await runtime.recoveryHash(owner, version, code, call);
        if (
          (await call.call(() => runtime.state.consumeRecoveryHash(owner, hash, call.options))) !==
          true
        )
          throw invalidProof();
        return evidence(owner, 'recovery-code', call);
      });
    },
  });
}
