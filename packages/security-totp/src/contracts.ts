// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  OperationOptions,
  MfaSubjectContext,
  MfaEvidence,
  MfaEvidenceStore,
  MfaStateStore,
  MfaRateLimitStore,
  MfaSealedSecret,
  MfaSecretProtector,
  MfaManagementAuthorization,
  Environment,
} from '@arkenivajs/core';

/** Deployment declaration backed by the adapter's independent conformance tests. */
export interface TotpComponentPolicy {
  readonly usage: 'production' | 'test-only';
}

/** Explicitly classified provider; a declaration cannot establish storage atomicity by itself. */
export type TotpComponent<T> = T & TotpComponentPolicy;

/** Operation presented to the application's trusted primary authentication authority. */
export type TotpOperation =
  | 'begin-enrollment'
  | 'qr-code'
  | 'confirm-enrollment'
  | 'verify'
  | 'status'
  | 'disable'
  | 'recovery-codes'
  | 'verify-recovery-code';

/** Runtime trust boundary; structural identity/session/authorization objects are never sufficient. */
export interface TotpTrustPolicy extends TotpComponentPolicy {
  /** Revalidate actual authority provenance, current session and exact tenant ownership or return null. */
  resolveSubject(
    subject: MfaSubjectContext,
    operation: TotpOperation,
    options?: OperationOptions,
  ): Promise<MfaSubjectContext | null>;
  /**
   * Independently validate recent, sufficiently strong authentication and action permission.
   * Enrollment/replacement have no caller grant: the authority must obtain its own trusted proof.
   * A supplied management grant must be verified by the authority, never accepted by its fields alone.
   */
  authorize(
    subject: MfaSubjectContext,
    input: {
      readonly action: 'enroll' | 'replace' | 'disable' | 'recovery-codes';
      readonly authorization?: MfaManagementAuthorization;
    },
    options?: OperationOptions,
  ): Promise<boolean>;
}

/** Secure external secret provider; key material must never be persisted with application factors. */
export interface TotpRecoveryKeyProvider extends TotpComponentPolicy {
  /** Select the active immutable version for a newly issued recovery set. */
  currentKeyId(options?: OperationOptions): Promise<string>;
  /** Resolve a retained version; use independent random 256–512-bit keys and authorized secret access. */
  resolveKey(keyId: string, options?: OperationOptions): Promise<Uint8Array>;
}

/** The framework computes standard HMAC-SHA256; the provider supplies versioned external keys only. */
export interface TotpRecoveryCodeHmacProvider {
  readonly algorithm: 'HMAC-SHA256';
  readonly keyProvider: TotpRecoveryKeyProvider;
}

/** Encrypted, expiring enrollment tied to an authenticated primary session. */
export interface TotpPendingEnrollment {
  readonly id: string;
  readonly subject: string;
  readonly issuer: string;
  readonly tenantId?: string;
  readonly primarySessionId: string;
  readonly secret: MfaSealedSecret;
  readonly expiresAt: string;
}

/** One active factor generation; key rotation must preserve its accepted step. */
export interface TotpFactorRecord {
  readonly id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId?: string;
  readonly secret: MfaSealedSecret;
  readonly generation: number;
  readonly lastAcceptedStep: number | null;
  readonly enabledAt: string;
}

/** Durable shared storage; every transition must retain exact issuer/account/tenant ownership. */
export interface TotpStateStore extends MfaStateStore {
  /** Create pending state once; keep any active factor unchanged until atomic activation. */
  putPending(pending: TotpPendingEnrollment, options?: OperationOptions): Promise<void>;
  /** Return only the exact owner's unexpired, primary-session-bound pending state. */
  getPending(
    subject: MfaSubjectContext,
    enrollmentId: string,
    options?: OperationOptions,
  ): Promise<TotpPendingEnrollment | null>;
  /** Atomically consume valid pending state and install an active factor with this accepted step. */
  activatePending(
    subject: MfaSubjectContext,
    enrollmentId: string,
    acceptedStep: number,
    now: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  /** Return the active generation for one authenticated owner. */
  getFactor(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<TotpFactorRecord | null>;
  /** CAS for the exact ACTIVE factor/generation and step greater than the persisted step. */
  acceptStepIfGreater(
    subject: MfaSubjectContext,
    factorId: string,
    generation: number,
    step: number,
    options?: OperationOptions,
  ): Promise<boolean>;
  /** Atomically revoke the factor, pending enrollments and recovery set. */
  revokeFactor(
    subject: MfaSubjectContext,
    factorId: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  /** Replace the complete recovery set atomically; persist keyed hashes only. */
  replaceRecoveryHashes(
    subject: MfaSubjectContext,
    hashes: readonly string[],
    options?: OperationOptions,
  ): Promise<void>;
  /** Consume one matching keyed hash at most once across independent instances. */
  consumeRecoveryHash(
    subject: MfaSubjectContext,
    keyedHash: string,
    options?: OperationOptions,
  ): Promise<boolean>;
}

/** Startup-only TOTP policy; capture trusted providers once, never from request data. */
export interface TotpServiceOptions {
  readonly issuer: string;
  readonly environment: Environment;
  readonly trustPolicy: TotpTrustPolicy;
  readonly recoveryCodeHmac: TotpRecoveryCodeHmacProvider;
  readonly stateStore: TotpComponent<TotpStateStore>;
  readonly rateLimitStore: TotpComponent<MfaRateLimitStore>;
  readonly secretProtector: TotpComponent<MfaSecretProtector>;
  readonly evidenceStore: TotpComponent<MfaEvidenceStore>;
  /** Trusted construction-time test/development clock in integer epoch milliseconds; forbidden in production. */
  readonly clock?: () => number;
  readonly periodSeconds?: 30;
  readonly digits?: 6;
  readonly driftSteps?: 0 | 1;
  readonly enrollmentTtlMs?: number;
}

/** Secret-bearing provisioning result; deliver only through an authenticated no-store response. */
export interface TotpEnrollment {
  readonly enrollmentId: string;
  readonly expiresAt: string;
  readonly otpauthUri: string;
}

/** Acknowledged durable activation; no authentication session is issued. */
export interface TotpConfirmation {
  readonly enabled: true;
}

/** Factor lifecycle contract; successful verification is server-side evidence, never a bearer token. */
export interface TotpService {
  beginEnrollment(subject: MfaSubjectContext, options?: OperationOptions): Promise<TotpEnrollment>;
  getQrCodeImage(
    subject: MfaSubjectContext,
    enrollmentId: string,
    options?: OperationOptions,
  ): Promise<string>;
  confirmEnrollment(
    subject: MfaSubjectContext,
    enrollmentId: string,
    code: string,
    options?: OperationOptions,
  ): Promise<TotpConfirmation>;
  verify(
    subject: MfaSubjectContext,
    code: string,
    options?: OperationOptions,
  ): Promise<MfaEvidence>;
  isEnabled(subject: MfaSubjectContext, options?: OperationOptions): Promise<boolean>;
  disable(
    subject: MfaSubjectContext,
    authorization: MfaManagementAuthorization,
    options?: OperationOptions,
  ): Promise<void>;
  generateRecoveryCodes(
    subject: MfaSubjectContext,
    authorization: MfaManagementAuthorization,
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  verifyRecoveryCode(
    subject: MfaSubjectContext,
    code: string,
    options?: OperationOptions,
  ): Promise<MfaEvidence>;
}
