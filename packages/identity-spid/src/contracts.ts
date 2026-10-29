// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Identity, OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';
import type { BoundedRuntimePolicy, SecretProvider } from '@arkenivajs/security-crypto';
import type { SecurityStoreSettings, TrustedSecurityAuthority } from '@arkenivajs/security-apikey';
export type { BoundedRuntimePolicy, SecretProvider } from '@arkenivajs/security-crypto';
export type { SecurityStoreSettings, TrustedSecurityAuthority } from '@arkenivajs/security-apikey';

export type ItalianIdentitySystem = 'spid' | 'cie';
export type FederationProtocol = 'saml2' | 'oidc-federation';
export type FederationAssurance =
  'spid-l1' | 'spid-l2' | 'spid-l3' | 'cie-l1' | 'cie-l2' | 'cie-l3';
export interface FederationTrustAnchor {
  readonly kid: string;
  readonly issuer: string;
  readonly publicKeyPem: string;
  readonly validFrom: string;
  readonly expiresAt: string;
}
export interface FederationMetadataPolicy {
  readonly trustAnchors: readonly FederationTrustAnchor[];
  readonly approvedMetadataEndpoints: readonly string[];
  readonly maxBytes: number;
  readonly refreshIntervalSeconds: number;
  readonly maxChainDepth: number;
  readonly revocation: 'mandatory';
  readonly stalePolicy: 'reject';
}
/** Immutable registration and trust policy, never populated from a login callback. */
export interface FederationProfileV1 {
  readonly schemaVersion: '1.0.0';
  readonly profileId: string;
  readonly system: ItalianIdentitySystem;
  readonly protocol: FederationProtocol;
  readonly entityId: string;
  readonly clientId?: string;
  readonly redirectUri: string;
  readonly signingKeyRef: string;
  readonly expectedIssuers: readonly string[];
  readonly allowedAssurance: readonly FederationAssurance[];
  readonly metadata: FederationMetadataPolicy;
  readonly subjectClaim: string;
  readonly tenantMappingId: string;
  readonly identityMappingVersion: string;
  readonly sessionTtlSeconds: number;
}
/** Approved mapping consumes only cryptographically verified upstream claims. */
export interface FederationIdentityMapper {
  map(
    input: {
      profileId: string;
      system: ItalianIdentitySystem;
      issuer: string;
      subject: string;
      assurance: FederationAssurance;
      attributes: Readonly<Record<string, readonly string[]>>;
    },
    options?: OperationOptions,
  ): Promise<{
    issuer: string;
    subject: string;
    tenant: VerifiedTenantContext;
    assurance: FederationAssurance;
  }>;
}
export interface FederatedLogin {
  readonly transactionId: string;
  readonly redirectUrl: string;
  readonly expiresAt: string;
}
export interface FederatedIdentity extends Identity {
  readonly system: ItalianIdentitySystem;
  readonly federationAssurance: FederationAssurance;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
  readonly profileId: string;
  readonly profileVersion: '1.0.0';
}
export interface TrustResult {
  readonly trusted: boolean;
  readonly source: string;
  readonly evaluatedAt: string;
  readonly reasons: readonly string[];
}
export interface ItalianFederationService {
  beginAuthentication(
    context: Readonly<{ returnPath: string; tenantId?: string }>,
    assurance: FederationAssurance,
    options?: OperationOptions,
  ): Promise<FederatedLogin>;
  consumeAuthentication(response: unknown, options?: OperationOptions): Promise<FederatedIdentity>;
  verifyFederationTrust(entityStatement: string, options?: OperationOptions): Promise<TrustResult>;
  metadata(): Promise<string>;
}
export type SpidService = ItalianFederationService;
export interface ItalianEidPluginSettings {
  readonly profiles: readonly FederationProfileV1[];
  readonly identityMappers: Readonly<Record<string, FederationIdentityMapper>>;
  readonly stateStore: SecurityStoreSettings;
  readonly secretProvider: SecretProvider;
  readonly authority: TrustedSecurityAuthority;
  readonly policy: BoundedRuntimePolicy;
}
