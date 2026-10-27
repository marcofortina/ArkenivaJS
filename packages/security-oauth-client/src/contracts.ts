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
/** Only the current application's independently verified authority can approve grant ownership and policy. */
export interface TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: Readonly<{
      tenant?: VerifiedTenantContext;
      assurance?: MfaAssurance;
      sessionId?: string;
      oauth?: Readonly<{
        clientId: string;
        audience: string;
        scopes: readonly string[];
        returnPath?: string;
      }>;
    }>,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** External client secrets never enter state storage or diagnostics. */
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
export interface SecurityStoreSettings {
  readonly store: SecurityTransactionalStore;
  readonly securityLevel: 'production' | 'test-only';
  readonly operationTimeoutMs: number;
}
/** Explicit issuer registration; endpoint origins never come from a request. */
export interface OAuthClientRegistration {
  readonly id: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecretRef?: string;
  readonly redirectUri: string;
  readonly allowedAudiences: readonly string[];
  readonly allowedScopes: readonly string[];
  readonly allowedEndpointOrigins?: readonly string[];
  readonly idTokenAlgorithm?: 'RS256' | 'PS256' | 'ES256' | 'EdDSA';
}
/** Explicit protected shared state uses the separately installed native cryptography capability. */
export interface OAuthClientPluginSettings {
  readonly clients: readonly OAuthClientRegistration[];
  readonly secretProvider: SecretProvider;
  readonly stateStore: SecurityStoreSettings;
  readonly authority: TrustedSecurityAuthority;
  readonly maxStateTtlMs: number;
  readonly stateEncryptionKeyRefs: readonly string[];
  readonly stateMacKeyRefs: readonly string[];
  readonly refreshTtlMs?: number;
  readonly allowInsecureLoopback?: boolean;
}
export interface OAuthAuthorizationStart {
  readonly authorizationUrl: string;
  readonly stateRef: string;
  readonly expiresAt: string;
}
export interface OAuthAuthorizationCallback {
  readonly stateRef: string;
  readonly code: string;
  readonly issuer: string;
  readonly redirectUri: string;
}
export interface OAuthGrant {
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresAt: string;
  readonly scopes: readonly string[];
  readonly audience: string;
  readonly refreshRef?: string;
}
export interface OAuthClientService {
  beginAuthorization(
    context: Readonly<{
      subject?: IdentitySubject;
      audience: string;
      scopes: readonly string[];
      returnPath: string;
    }>,
    options?: OperationOptions,
  ): Promise<OAuthAuthorizationStart>;
  exchangeCode(
    callback: OAuthAuthorizationCallback,
    options?: OperationOptions,
  ): Promise<OAuthGrant>;
  clientCredentials(
    audience: string,
    scopes: readonly string[],
    options?: OperationOptions,
  ): Promise<OAuthGrant>;
  refresh(refreshRef: string, options?: OperationOptions): Promise<OAuthGrant>;
  revoke(refreshRef: string, options?: OperationOptions): Promise<void>;
}
