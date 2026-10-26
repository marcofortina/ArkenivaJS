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
/** Version-aware, domain-separated HMAC. The application independently verifies this provider. */
export interface KeyedDigestProvider {
  readonly algorithm: 'HMAC-SHA256';
  digest(
    domain: string,
    parts: readonly string[],
    keyRef: string,
    options?: OperationOptions,
  ): Promise<string>;
  verify(
    domain: string,
    parts: readonly string[],
    expected: string,
    keyRef: string,
    options?: OperationOptions,
  ): Promise<boolean>;
}
/** A successful decision authorizes the entire supplied policy, including scope and network grants. */
export interface TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: Readonly<{
      tenant?: VerifiedTenantContext;
      assurance?: MfaAssurance;
      sessionId?: string;
      apiKeyId?: string;
      apiKeyPolicy?: ApiKeyPolicy;
    }>,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** The security label is configuration, not independent evidence of provider safety. */
export interface SecurityStoreSettings {
  readonly store: SecurityTransactionalStore;
  readonly securityLevel: 'production' | 'test-only';
  readonly operationTimeoutMs: number;
}
/** Explicit optional-package configuration; all providers are captured before startup. */
export interface ApiKeyPluginSettings {
  readonly store: SecurityStoreSettings;
  readonly hmac: KeyedDigestProvider;
  readonly hmacKeyRef: string;
  readonly authority: TrustedSecurityAuthority;
  readonly maxActiveKeysPerSubject: number;
  readonly maxVerifyAttemptsPerMinute: number;
}
/** Secret material is returned once; applications must deliver it through authenticated TLS. */
export type OneTimeSecret = Readonly<{ value: string; expiresAt: string }>;
/** Exact grants approved by the trusted authority before issuing or rotating a credential. */
export interface ApiKeyPolicy {
  readonly scopes: readonly string[];
  readonly expiresAt: string;
  readonly allowedIpRanges?: readonly string[];
}
/** Public lookup metadata is not proof of possession. */
export interface ApiKeyIssue extends OneTimeSecret {
  readonly id: string;
  readonly keyPrefix: string;
}
/** Metadata never contains the raw secret or its verifier. */
export interface ApiKeyMetadata {
  readonly id: string;
  readonly keyPrefix: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly revokedAt?: string;
  readonly scopes: readonly string[];
}
/** Account/tenant state has been freshly authorized after cryptographic verification. */
export interface ApiKeyIdentity {
  readonly subject: IdentitySubject;
  readonly scopes: readonly string[];
  readonly keyId: string;
}
/** Stateful bearer credentials; they convey no MFA assurance. */
export interface ApiKeyService {
  issue(
    subject: IdentitySubject,
    policy: ApiKeyPolicy,
    options?: OperationOptions,
  ): Promise<ApiKeyIssue>;
  verify(
    rawKey: string,
    context: Readonly<{ clientIp?: string }>,
    options?: OperationOptions,
  ): Promise<ApiKeyIdentity>;
  rotate(
    keyId: string,
    authorization: IdentitySubject,
    options?: OperationOptions,
  ): Promise<ApiKeyIssue>;
  revoke(keyId: string, authorization: IdentitySubject, options?: OperationOptions): Promise<void>;
  list(subject: IdentitySubject, options?: OperationOptions): Promise<readonly ApiKeyMetadata[]>;
}
