// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export interface NativeConfiguration {
  readonly entityId: string;
  readonly acsUrl: string;
  readonly audience: string;
  readonly issuer: string;
  readonly certificates: readonly string[];
  readonly loginUrl: string;
  readonly logoutUrl?: string;
  readonly clockSkewSeconds: number;
  readonly binding: 'redirect' | 'post';
  readonly privateKey?: string;
  readonly publicCert?: string;
}
export interface LogoutProfile {
  readonly nameID: string;
  readonly nameIDFormat: string;
  readonly sessionIndex?: string;
  readonly nameQualifier?: string;
  readonly spNameQualifier?: string;
}
export interface NativeRequest {
  readonly action: 'login' | 'logout' | 'verify-login' | 'verify-logout' | 'metadata';
  readonly configuration: NativeConfiguration;
  readonly requestId: string;
  readonly instant: string;
  readonly relayState: string;
  readonly response?: string;
  readonly profile?: LogoutProfile;
}
export interface VerifiedAssertion {
  readonly issuer: string;
  readonly subject: string;
  readonly responseId: string;
  readonly assertionId: string;
  readonly authnContext?: string;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
  readonly nameIDFormat: string;
  readonly nameQualifier?: string;
  readonly spNameQualifier?: string;
  readonly sessionIndex?: string;
  readonly sessionExpiresAt: string;
}
export type NativeResult =
  | Readonly<{ kind: 'redirect'; url: string; createdAt: string }>
  | Readonly<{
      kind: 'post';
      fields: Readonly<{ SAMLRequest: string; RelayState?: string }>;
      createdAt: string;
    }>
  | Readonly<{ kind: 'identity'; identity: VerifiedAssertion }>
  | Readonly<{ kind: 'logout'; responseId: string }>
  | Readonly<{ kind: 'metadata'; xml: string }>;
