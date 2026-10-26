// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { MfaAssurance, OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';

/** A hint until the configured authority verifies account and tenant membership at runtime. */
export type IdentitySubject = Readonly<{
  issuer: string;
  subject: string;
  tenant?: VerifiedTenantContext;
}>;
/** A durable acknowledgement, never an assumption about an interrupted write. */
export type DurableMutationReceipt = Readonly<{ committed: boolean; version?: string }>;
/** Indexed ownership is independent of the application record. */
export interface SecurityIndexedRecord {
  readonly id: string;
  readonly ownerKey: string;
  readonly version: string;
  readonly expiresAt?: string;
  readonly fields: Readonly<Record<string, unknown>>;
}
/** Every predicate must hold at one shared transactional boundary. */
export interface SecurityAtomicMutation {
  readonly namespace: string;
  readonly id: string;
  readonly expectedVersion: string | null;
  readonly next: Readonly<Record<string, unknown>> | null;
  readonly ownerKey: string;
}
/** Durable, cross-process one-use claims and backend-issued record versions. */
export interface SecurityStateStore {
  claimOnce(
    namespace: string,
    digest: string,
    expiresAt: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  compareAndSet(
    namespace: string,
    id: string,
    expectedVersion: string | null,
    next: Readonly<Record<string, unknown>> | null,
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt>;
  read(
    namespace: string,
    id: string,
    options?: OperationOptions,
  ): Promise<Readonly<Record<string, unknown>> | null>;
}
/** Complete required storage port; no partial or in-memory production fallback. */
export interface SecurityTransactionalStore extends SecurityStateStore {
  atomicBatch(
    mutations: readonly SecurityAtomicMutation[],
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt>;
  listByOwner(
    namespace: string,
    ownerKey: string,
    limit: number,
    options?: OperationOptions,
  ): Promise<readonly SecurityIndexedRecord[]>;
  bumpOwnerEpoch(namespace: string, ownerKey: string, options?: OperationOptions): Promise<number>;
  currentOwnerEpoch(
    namespace: string,
    ownerKey: string,
    options?: OperationOptions,
  ): Promise<number>;
}
/** Independently verified runtime account/session/tenant policy. */
export interface TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: Readonly<{
      tenant?: VerifiedTenantContext;
      assurance?: MfaAssurance;
      sessionId?: string;
      resetId?: string;
      authorization?: IdentitySubject;
    }>,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** External secret material is never persisted in application records. */
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
/** Complete distributed state with an explicitly bounded operation deadline. */
export interface SecurityStoreSettings {
  readonly store: SecurityTransactionalStore;
  readonly securityLevel: 'production' | 'test-only';
  readonly operationTimeoutMs: number;
}
/** Application-approved Argon2id policy; target hardware calibration remains required. */
export interface PasswordPolicy {
  readonly minLength?: number;
  readonly memoryCostKiB?: number;
  readonly timeCost?: number;
  readonly parallelism?: number;
  readonly blockBreachedPasswords?: boolean;
}
export interface PasswordHash {
  readonly phc: string;
  readonly scheme: 'argon2id';
}
export interface PasswordVerification {
  readonly valid: boolean;
  readonly rehashRecommended: boolean;
}
export type OneTimeSecret = Readonly<{ value: string; expiresAt: string }>;
export interface ResetIssue extends OneTimeSecret {
  readonly requestId: string;
}
/** K-anonymity provider receives only a five-character SHA1 prefix, never a password or complete digest. */
export interface PasswordBreachProvider {
  lookup(
    prefix: string,
    options?: OperationOptions,
  ): Promise<readonly Readonly<{ suffix: string; count: number }>[]>;
}
/** One native durable boundary must consume the reset, replace the password and apply session invalidation policy. */
export interface PasswordResetCommitter {
  commitReset(
    input: Readonly<{
      subject: IdentitySubject;
      reset: Readonly<{ namespace: string; id: string; version: string; ownerKey: string }>;
      replacement: PasswordHash;
    }>,
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt>;
}
/** Required application persistence and breach ports complete the normative runtime behavior. */
export interface PasswordPluginSettings {
  readonly resetStore: SecurityStoreSettings;
  readonly secretProvider: SecretProvider;
  readonly resetHmacKeyRef: string;
  readonly authority: TrustedSecurityAuthority;
  readonly policy: PasswordPolicy;
  readonly resetTtlMs: number;
  readonly maxResetAttemptsPerHour: number;
  readonly resetCommitter: PasswordResetCommitter;
  readonly breaches?: PasswordBreachProvider;
}
export interface PasswordService {
  hash(plain: string, policy?: PasswordPolicy, options?: OperationOptions): Promise<PasswordHash>;
  verify(
    plain: string,
    stored: PasswordHash,
    options?: OperationOptions,
  ): Promise<PasswordVerification>;
  needsRehash(stored: PasswordHash): boolean;
  createReset(
    subject: IdentitySubject,
    authorization: IdentitySubject,
    options?: OperationOptions,
  ): Promise<ResetIssue>;
  consumeReset(token: string, newPassword: string, options?: OperationOptions): Promise<void>;
}
