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

import type { Identity } from '@arkenivajs/core';

/** Runtime authority for every sensitive session operation. */
export interface TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: Readonly<{
      tenant?: VerifiedTenantContext;
      assurance?: MfaAssurance;
      sessionId?: string;
      sessionPolicy?: SessionPolicy;
    }>,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** Canonical authentication event, resolved from server-owned state rather than input object shape. */
export interface SessionAuthentication {
  readonly identity: Identity;
  readonly subject: IdentitySubject;
  readonly authenticatedAt: string;
  readonly assuredAt?: string;
}
/** Creation authenticates a primary session; validation/renewal resolve current account policy after token proof. */
export interface SessionIdentityAuthority extends TrustedSecurityAuthority {
  resolveIdentity(
    identity: Identity,
    context: Readonly<{
      operation: 'create' | 'validate' | 'renew';
      sessionId: string;
      previousSessionId?: string;
    }>,
    options?: OperationOptions,
  ): Promise<SessionAuthentication>;
}
/** Durable provider classification is independently reviewed; no in-memory production fallback. */
export interface SecurityStoreSettings {
  readonly store: SecurityTransactionalStore;
  readonly securityLevel: 'production' | 'test-only';
  readonly operationTimeoutMs: number;
}
/** Explicit session limits and cookie policy; HTTP integration always sets Secure and HttpOnly. */
export interface SessionPolicy {
  readonly absoluteTtlMs: number;
  readonly idleTtlMs: number;
  readonly maxConcurrentSessions?: number;
  readonly cookieSameSite?: 'strict' | 'lax' | 'none';
}
/** Separate per-application session service, backed by externally keyed shared state. */
export interface SessionsPluginSettings {
  readonly store: SecurityStoreSettings;
  readonly hmac: KeyedDigestProvider;
  readonly hmacKeyRef: string;
  readonly authority: SessionIdentityAuthority;
  readonly defaultPolicy: SessionPolicy;
  readonly maxSessionsPerSubject: number;
}
/** Return a secret only after acknowledged commit; never place it in URLs or logs. */
export type OneTimeSecret = Readonly<{ value: string; expiresAt: string }>;
/** Applications transmit this value using the required host-only secure cookie attributes. */
export interface SessionIssue extends OneTimeSecret {
  readonly sessionId: string;
  readonly cookieName: '__Host-session';
}
/** Identity is freshly resolved; authentication timestamps never advance during ordinary validation. */
export interface SessionIdentity extends Identity {
  readonly sessionId: string;
  readonly authenticatedAt: string;
  readonly expiresAt: string;
  readonly assuredAt?: string;
}
/** Stateful sessions with atomic renewal and cross-pod revocation. */
export interface SessionService {
  create(
    identity: Identity,
    policy: SessionPolicy,
    options?: OperationOptions,
  ): Promise<SessionIssue>;
  validate(sessionToken: string, options?: OperationOptions): Promise<SessionIdentity>;
  renew(sessionToken: string, options?: OperationOptions): Promise<SessionIssue>;
  revoke(sessionId: string, options?: OperationOptions): Promise<void>;
  /** Returns the newly committed monotonic owner epoch, not an estimated session count. */
  revokeAll(subject: IdentitySubject, options?: OperationOptions): Promise<number>;
}
