// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  Environment,
  MfaEvidence,
  MfaEvidenceStore,
  MfaManagementAuthorization,
  MfaRateLimitStore,
  MfaStateStore,
  MfaSubjectContext,
  OperationOptions,
} from '@arkenivajs/core';
import type { WebAuthnCeremony } from './index.js';

/** Durable RP credential metadata; neither an identity grant nor a session. */
export interface WebAuthnCredentialRecord {
  readonly credentialId: string;
  readonly rpId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId?: string;
  /** EK-R12-MFA-001: stable account mapping of exactly 32 random bytes as unpadded base64url. */
  readonly userHandle: string;
  /** EK-R12-MFA-002: opaque backend revision; every successful state write must replace it. */
  readonly stateVersion: string;
  readonly publicKey: Uint8Array;
  readonly counter: number;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly transports?: readonly string[];
  readonly registeredAt: string;
  readonly revokedAt?: string;
}

/** Only an updated result may carry a newly committed backend revision. */
export interface WebAuthnStateMutationResult {
  readonly status: 'updated' | 'conflict' | 'revoked' | 'not-found';
  readonly newVersion?: string;
}

/** Independent authorization decisions for each bound operation and anonymous ceremony policy. */
export type WebAuthnPolicyAction =
  | 'begin-registration'
  | 'finish-registration'
  | 'begin-authentication'
  | 'finish-authentication'
  | 'begin-passwordless'
  | 'finish-passwordless'
  | 'list-credentials'
  | 'revoke-credential';

/** Independently consult application-owned authentication and authorization state. */
export interface WebAuthnTrustedSubjectAuthority {
  /** Resolve live application identity/session/tenant state; structural TypeScript objects confer no trust. */
  resolveSubject(
    candidate: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<MfaSubjectContext>;
  /** Authorize once per public operation; a management grant may be consumed here. Denial must throw. */
  authorize(
    input: {
      action: WebAuthnPolicyAction;
      subject: MfaSubjectContext;
      authorization?: MfaManagementAuthorization;
    },
    options?: OperationOptions,
  ): Promise<void>;
  /** Map only the cryptographically verified durable owner; an existing primary session is unnecessary. */
  resolvePasswordlessSubject(
    input: {
      rpId: string;
      credentialId: string;
      userHandle?: string | null;
      issuer: string;
      subject: string;
      tenantId?: string;
    },
    options?: OperationOptions,
  ): Promise<{ issuer: string; subject: string; tenantId?: string }>;
}

/** Trusted test time source, rejected when injected in production or development. */
export interface WebAuthnClock {
  /** Return a finite nonnegative integer Unix epoch in milliseconds, independent of request data. */
  nowEpochMs(): number;
}

/** All ownership and version transitions must be atomic across service instances. */
export interface WebAuthnStateStore extends MfaStateStore {
  /** Return a bounded account collection; exceeding the provider budget must reject without truncation. */
  listCredentials(
    subject: MfaSubjectContext,
    rpId: string,
    options?: OperationOptions,
  ): Promise<readonly WebAuthnCredentialRecord[]>;
  /** Look up one globally unique RP/credential binding; absence returns null and grants no identity. */
  getCredential(
    credentialId: string,
    rpId: string,
    options?: OperationOptions,
  ): Promise<WebAuthnCredentialRecord | null>;
  /** EK-R12-MFA-001: atomically allocate or reuse one immutable random handle for this RP/account. */
  getOrCreateUserHandle(
    subject: MfaSubjectContext,
    rpId: string,
    options?: OperationOptions,
  ): Promise<string>;
  /** Check the durable credential/account association, also when the browser omits its user handle. */
  verifyUserHandleBinding(
    input: { credentialId: string; rpId: string; userHandle?: string | null },
    options?: OperationOptions,
  ): Promise<boolean>;
  /** Insert globally once with a backend-owned initial revision; false means no credential was inserted. */
  insertCredentialIfAbsent(
    record: WebAuthnCredentialRecord,
    options?: OperationOptions,
  ): Promise<boolean>;
  /**
   * EK-R12-MFA-002: atomically compare the complete active owner/handle/version/counter tuple.
   * Every successful write replaces the revision, including 0 -> 0. Never retry a stale assertion.
   */
  advanceCounter(
    input: {
      credentialId: string;
      rpId: string;
      issuer: string;
      subject: string;
      tenantId?: string;
      userHandle: string;
      expectedVersion: string;
      previousCounter: number;
      newCounter: number;
      backedUp: boolean;
    },
    options?: OperationOptions,
  ): Promise<WebAuthnStateMutationResult>;
  /** Revoke the same versioned row and invalidate affected account ceremonies in one durable transaction. */
  revokeCredential(
    subject: MfaSubjectContext,
    rpId: string,
    credentialId: string,
    expectedVersion: string,
    options?: OperationOptions,
  ): Promise<WebAuthnStateMutationResult>;
}

/** Captured application trust policy; required providers are caller-owned and fail closed when unavailable. */
export interface WebAuthnServiceOptions {
  /** Stable deployment RP, selected by trusted configuration rather than request headers. */
  readonly rpId: string;
  /** Human-readable application name supplied to the authenticator. */
  readonly rpName: string;
  /** Exact HTTPS origins, with the browser's explicit localhost HTTP exception in test/development. */
  readonly expectedOrigins: readonly string[];
  readonly stateStore: WebAuthnStateStore;
  readonly rateLimitStore: MfaRateLimitStore;
  readonly evidenceStore: MfaEvidenceStore;
  readonly subjectAuthority: WebAuthnTrustedSubjectAuthority;
  /** Defaults to production, which rejects explicitly test-only providers. */
  readonly environment?: Environment;
  /** Injectable only in the test environment; never chosen by an application request. */
  readonly clock?: WebAuthnClock;
  /** User verification is always mandatory, with no weaker fallback. */
  readonly userVerification?: 'required';
  /** Defaults to none; direct delegates statement verification without asserting enterprise provenance. */
  readonly attestation?: 'none' | 'direct';
  /** Positive integer milliseconds, at most 300,000; defaults to five minutes. */
  readonly challengeTtlMs?: number;
  /** Defaults to false; explicit opt-in enables the separate pre-session identity mapping path. */
  readonly passwordlessEnabled?: boolean;
}

/** Authorized account-management projection without public-key or internal ownership material. */
export interface WebAuthnCredentialSummary {
  readonly credentialId: string;
  readonly registeredAt: string;
  readonly backedUp: boolean;
}

/** Verified pre-session owner and one-use evidence, bound to the consumed ceremony as its transaction. */
export interface PasswordlessVerifiedSubject {
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId?: string;
  readonly evidence: MfaEvidence;
}

/** The eight factor operations never mint application sessions. */
export interface WebAuthnService {
  /** Begin an expiring owner/session-bound enrollment after recent primary authentication and authorization. */
  beginRegistration(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<WebAuthnCeremony>;
  /** Consume once, verify upstream attestation/RP/origin/UP/UV and persist a unique owned credential. */
  finishRegistration(
    subject: MfaSubjectContext,
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<WebAuthnCredentialSummary>;
  /** Begin a bound assertion with only the authorized account's active credential allowlist. */
  beginAuthentication(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<WebAuthnCeremony>;
  /**
   * Verify a consumed bound ceremony, commit the credential CAS, then persist one-use evidence.
   * A conflict requires a fresh ceremony; uncertain persistence never returns a successful proof.
   */
  finishAuthentication(
    subject: MfaSubjectContext,
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<MfaEvidence>;
  /** Begin an explicitly enabled anonymous ceremony under shared RP attempt limits. */
  beginPasswordless(options?: OperationOptions): Promise<WebAuthnCeremony>;
  /** Verify first, map the durable owner, and persist evidence for this pre-session transaction. */
  finishPasswordless(
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<PasswordlessVerifiedSubject>;
  /** List authorized active credential summaries; neither discovery nor a request-controlled clock override. */
  listCredentials(subject: MfaSubjectContext): Promise<readonly WebAuthnCredentialSummary[]>;
  /** Require recent primary authentication plus a trusted management grant and atomically revoke once. */
  revokeCredential(
    subject: MfaSubjectContext,
    credentialId: string,
    authorization: MfaManagementAuthorization,
    options?: OperationOptions,
  ): Promise<void>;
}
