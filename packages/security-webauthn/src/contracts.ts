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
  readonly userHandle: string;
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
  resolveSubject(
    candidate: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<MfaSubjectContext>;
  authorize(
    input: {
      action: WebAuthnPolicyAction;
      subject: MfaSubjectContext;
      authorization?: MfaManagementAuthorization;
    },
    options?: OperationOptions,
  ): Promise<void>;
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

export interface WebAuthnClock {
  nowEpochMs(): number;
}

/** All ownership and version transitions must be atomic across service instances. */
export interface WebAuthnStateStore extends MfaStateStore {
  listCredentials(
    subject: MfaSubjectContext,
    rpId: string,
    options?: OperationOptions,
  ): Promise<readonly WebAuthnCredentialRecord[]>;
  getCredential(
    credentialId: string,
    rpId: string,
    options?: OperationOptions,
  ): Promise<WebAuthnCredentialRecord | null>;
  getOrCreateUserHandle(
    subject: MfaSubjectContext,
    rpId: string,
    options?: OperationOptions,
  ): Promise<string>;
  verifyUserHandleBinding(
    input: { credentialId: string; rpId: string; userHandle?: string | null },
    options?: OperationOptions,
  ): Promise<boolean>;
  insertCredentialIfAbsent(
    record: WebAuthnCredentialRecord,
    options?: OperationOptions,
  ): Promise<boolean>;
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
  revokeCredential(
    subject: MfaSubjectContext,
    rpId: string,
    credentialId: string,
    expectedVersion: string,
    options?: OperationOptions,
  ): Promise<WebAuthnStateMutationResult>;
}

export interface WebAuthnServiceOptions {
  readonly rpId: string;
  readonly rpName: string;
  readonly expectedOrigins: readonly string[];
  readonly stateStore: WebAuthnStateStore;
  readonly rateLimitStore: MfaRateLimitStore;
  readonly evidenceStore: MfaEvidenceStore;
  readonly subjectAuthority: WebAuthnTrustedSubjectAuthority;
  readonly environment?: Environment;
  readonly clock?: WebAuthnClock;
  readonly userVerification?: 'required';
  readonly attestation?: 'none' | 'direct';
  readonly challengeTtlMs?: number;
  readonly passwordlessEnabled?: boolean;
}

export interface WebAuthnCredentialSummary {
  readonly credentialId: string;
  readonly registeredAt: string;
  readonly backedUp: boolean;
}

export interface PasswordlessVerifiedSubject {
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId?: string;
  readonly evidence: MfaEvidence;
}

/** The eight factor operations never mint application sessions. */
export interface WebAuthnService {
  beginRegistration(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<WebAuthnCeremony>;
  finishRegistration(
    subject: MfaSubjectContext,
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<WebAuthnCredentialSummary>;
  beginAuthentication(
    subject: MfaSubjectContext,
    options?: OperationOptions,
  ): Promise<WebAuthnCeremony>;
  finishAuthentication(
    subject: MfaSubjectContext,
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<MfaEvidence>;
  beginPasswordless(options?: OperationOptions): Promise<WebAuthnCeremony>;
  finishPasswordless(
    ceremonyId: string,
    responseJSON: unknown,
    options?: OperationOptions,
  ): Promise<PasswordlessVerifiedSubject>;
  listCredentials(subject: MfaSubjectContext): Promise<readonly WebAuthnCredentialSummary[]>;
  revokeCredential(
    subject: MfaSubjectContext,
    credentialId: string,
    authorization: MfaManagementAuthorization,
    options?: OperationOptions,
  ): Promise<void>;
}
