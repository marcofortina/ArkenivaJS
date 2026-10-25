// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from './contracts.js';
import type { MfaAssurance, VerifiedTenantContext } from './ports.js';

/**
 * Subject resolved by a trusted primary session authority on the server.
 * The structural type is not runtime proof: factor services must validate the
 * issuer, subject, session, authentication freshness and verified tenant binding.
 */
export interface MfaSubjectContext {
  readonly issuer: string;
  readonly subject: string;
  readonly tenant?: VerifiedTenantContext;
  readonly primarySessionId: string;
  readonly authenticatedAt: string;
}

/** Verified factor class; recovery codes and TOTP cannot establish phishing resistance. */
export type MfaMethod = 'totp' | 'recovery-code' | 'webauthn';

/**
 * Short-lived server-side verification result, never a browser bearer credential.
 * The session authority must consume its persisted record for the same owner
 * and primary session before granting assurance. No session or token is issued here.
 */
export interface MfaEvidence {
  readonly evidenceId: string;
  readonly method: MfaMethod;
  readonly assurance: MfaAssurance;
  readonly subject: string;
  readonly verifiedAt: string;
  readonly expiresAt: string;
}

/** Recent management decision verified by the session authority, never a client-supplied flag. */
export interface MfaManagementAuthorization {
  readonly action: 'enroll' | 'replace' | 'disable' | 'recovery-codes' | 'revoke';
  readonly subject: string;
  readonly trustedSessionId: string;
  readonly verifiedAt: string;
}

/** Durable challenge metadata; challengeDigest must not contain raw proof or provisioning material. */
export interface MfaChallengeRecord {
  readonly id: string;
  readonly purpose:
    'totp-enroll' | 'webauthn-register' | 'webauthn-authenticate' | 'webauthn-passwordless';
  readonly issuer: string;
  readonly subject?: string;
  readonly tenantId?: string;
  readonly primarySessionId?: string;
  readonly rpId?: string;
  readonly challengeDigest: string;
  readonly expiresAt: string;
  readonly createdAt: string;
}

/**
 * Durable shared challenge SPI. Implementations must enforce atomic ownership,
 * expiration and consumption across processes; read-then-delete is insufficient.
 * Backend outage or unknown persistence outcome must fail closed.
 */
export interface MfaStateStore {
  /** Create once; an existing ID must reject without replacing its owner's record. */
  createChallenge(record: MfaChallengeRecord, options?: OperationOptions): Promise<void>;
  /** Atomically consume the exact owner/purpose/session/RP match; absent, expired or used returns null. */
  claimChallenge(
    input: {
      id: string;
      purpose: MfaChallengeRecord['purpose'];
      issuer: string;
      subject?: string;
      tenantId?: string;
      primarySessionId?: string;
      rpId?: string;
      now: string;
    },
    options?: OperationOptions,
  ): Promise<MfaChallengeRecord | null>;
  /** Remove one opaque challenge ID without disclosing whether an account or factor exists. */
  discardChallenge(id: string, options?: OperationOptions): Promise<void>;
}

/** Shared atomic check-and-record limiter; a store outage cannot grant an attempt. */
export interface MfaRateLimitStore {
  /** Bound the operation class, capacity and integer-millisecond window in one shared transition. */
  checkAndRecord(
    input: {
      scopeKey: string;
      operation: string;
      maxAttempts: number;
      windowMs: number;
      nowMs: number;
    },
    options?: OperationOptions,
  ): Promise<{ allowed: boolean; retryAfterMs?: number }>;
}

/** Persistent evidence binds the verification result to its issuer, tenant and primary session. */
export interface MfaEvidenceRecord extends MfaEvidence {
  readonly issuer: string;
  readonly tenantId?: string;
  readonly primarySessionId: string;
}

/** Durable single-use handoff to the application's independent session authority. */
export interface MfaEvidenceStore {
  /** Insert once; duplicate evidence IDs and uncertain writes must not produce a success proof. */
  recordOnce(evidence: MfaEvidenceRecord, options?: OperationOptions): Promise<void>;
  /** Atomically consume for the exact owner/session; missing, expired or mismatched records return null. */
  consume(
    input: {
      evidenceId: string;
      issuer: string;
      subject: string;
      tenantId?: string;
      primarySessionId: string;
      now: string;
    },
    options?: OperationOptions,
  ): Promise<MfaEvidenceRecord | null>;
}

/** Versioned authenticated-encryption envelope; raw keys and factor secrets remain private. */
export interface MfaSealedSecret {
  readonly keyId: string;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly tag: string;
}

/** Trusted AEAD/KMS provider with issuer/subject/tenant associated-data binding. */
export interface MfaSecretProtector {
  /** Seal bytes with a fresh nonce and versioned key; honor caller cancellation and deadlines. */
  seal(
    plain: Uint8Array,
    binding: { issuer: string; subject: string; tenantId?: string },
    options?: OperationOptions,
  ): Promise<MfaSealedSecret>;
  /** Authenticate the envelope and identical binding before returning secret bytes; never log them. */
  open(
    secret: MfaSealedSecret,
    binding: { issuer: string; subject: string; tenantId?: string },
    options?: OperationOptions,
  ): Promise<Uint8Array>;
}
