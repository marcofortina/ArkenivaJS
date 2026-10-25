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
export type TotpPolicyAction =
  | 'begin-enrollment'
  | 'read-enrollment-qr'
  | 'confirm-enrollment'
  | 'verify'
  | 'is-enabled'
  | 'disable'
  | 'generate-recovery-codes'
  | 'verify-recovery-code';

/** Runtime trust boundary; structural identity/session/authorization objects are never sufficient. */
export interface TotpPolicyRequest {
  readonly action: TotpPolicyAction;
  readonly subject: MfaSubjectContext;
  readonly authorization?: MfaManagementAuthorization;
}

/** Independently verify actual authority provenance, session validity and operation permission. */
export interface TotpTrustedSubjectAuthority {
  /** Revalidate authority provenance, current session and exact tenant ownership; reject failures. */
  resolveSubject(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<MfaSubjectContext>;
  /**
   * Independently validate recent, sufficiently strong authentication and action permission.
   * Enrollment/replacement have no caller grant: the authority must obtain its own trusted proof.
   * A supplied management grant must be verified by the authority, never accepted by its fields alone.
   */
  authorize(request: TotpPolicyRequest, options?: OperationOptions): Promise<void>;
}

/** Only server-retrieved factor state may supply the factor binding. Never log this input. */
export interface TotpRecoveryProofInput {
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId?: string;
  readonly factorId: string;
  readonly code: string;
}

/** Externally keyed MAC backend; the framework never obtains raw HMAC keys. */
export interface TotpRecoveryHmacProvider {
  readonly algorithm: 'HMAC-SHA256';
  readonly securityLevel: 'production' | 'test-only';
  createVerifier(input: TotpRecoveryProofInput, options?: OperationOptions): Promise<string>;
  /** Return one to eight distinct versioned verifiers for approved current/retained keys. */
  candidateVerifiers(
    input: TotpRecoveryProofInput,
    options?: OperationOptions,
  ): Promise<readonly string[]>;
}

/** Deterministic wall clock permitted only in the test environment. */
export interface TotpClock {
  nowEpochMs(): number;
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
  readonly environment?: Environment;
  readonly subjectAuthority: TotpTrustedSubjectAuthority & Partial<TotpComponentPolicy>;
  readonly recoveryHmac: TotpRecoveryHmacProvider;
  readonly stateStore: TotpStateStore & Partial<TotpComponentPolicy>;
  readonly rateLimitStore: MfaRateLimitStore & Partial<TotpComponentPolicy>;
  readonly secretProtector: MfaSecretProtector & Partial<TotpComponentPolicy>;
  readonly evidenceStore: MfaEvidenceStore & Partial<TotpComponentPolicy>;
  readonly clock?: TotpClock;
  readonly periodSeconds?: 30;
  readonly digits?: 6;
  readonly driftSteps?: 0 | 1;
  readonly enrollmentTtlMs?: number;
  /** Default ten; integer range ten through twenty. */
  readonly recoveryCodeCount?: number;
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
