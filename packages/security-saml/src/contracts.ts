// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Identity, OperationOptions } from '@arkenivajs/core';
import type { SecretProvider } from '@arkenivajs/security-crypto';
import type { SecurityStateStore, TrustedSecurityAuthority } from '@arkenivajs/security-apikey';
export type { SecretProvider, SecretValue } from '@arkenivajs/security-crypto';
export type { SecurityStateStore, TrustedSecurityAuthority } from '@arkenivajs/security-apikey';

/** Application-owned request and acceptance policy; class ordering is never inferred from URI text. */
export interface SamlAuthenticationContext {
  readonly classReferences: readonly string[];
  readonly comparison: 'exact' | 'minimum' | 'maximum' | 'better';
  readonly acceptedClassReferences: readonly string[];
}
export interface SamlSettings {
  readonly entityId: string;
  readonly acsUrl: string;
  readonly expectedAudience: string;
  /** Pinned offline IdP metadata XML; no untrusted URL fetching. */
  readonly trustedIdpMetadata: string;
  readonly signingKeyRef?: string;
  /** Required when a signing key is configured, for matching SP metadata and POST signatures. */
  readonly signingCertificateRef?: string;
  readonly secretProvider: SecretProvider;
  readonly replayStore: SecurityStateStore;
  readonly clockSkewSeconds?: number;
  readonly binding?: 'redirect' | 'post';
  readonly requestedAuthnContext?: SamlAuthenticationContext;
  /** Login proves only an upstream identity; sensitive logout needs independent local session authorization. */
  readonly authority?: TrustedSecurityAuthority;
  readonly environment?: 'development' | 'test' | 'production';
}
export interface SamlRedirectRequest {
  readonly binding: 'redirect';
  readonly requestId: string;
  readonly redirectUrl: string;
  readonly expiresAt: string;
}
export interface SamlPostRequest {
  readonly binding: 'post';
  readonly requestId: string;
  readonly actionUrl: string;
  readonly fields: Readonly<{ SAMLRequest: string; RelayState?: string }>;
  readonly expiresAt: string;
}
export type SamlLoginRequest = SamlRedirectRequest | SamlPostRequest;
export type SamlLogoutRequest = SamlRedirectRequest | SamlPostRequest;
export interface SamlVerifiedIdentity extends Identity {
  readonly sessionIndex?: string;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
}
export interface SamlService {
  beginLogin(
    context: Readonly<{ returnPath: string }>,
    options?: OperationOptions,
  ): Promise<SamlLoginRequest>;
  consumeResponse(
    context: Readonly<{ inResponseTo: string; relayState?: string }>,
    samlResponse: string,
    options?: OperationOptions,
  ): Promise<SamlVerifiedIdentity>;
  createMetadata(): Promise<string>;
  beginLogout(
    identity: SamlVerifiedIdentity,
    options?: OperationOptions,
  ): Promise<SamlLogoutRequest>;
  consumeLogoutResponse(response: string, options?: OperationOptions): Promise<void>;
}
