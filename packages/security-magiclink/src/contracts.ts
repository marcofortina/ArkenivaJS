// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type {
  IdentitySubject,
  OneTimeSecret,
  TrustedSecurityAuthority,
  KeyedDigestProvider,
  SecurityStoreSettings,
} from '@arkenivajs/security-apikey';
export type {
  IdentitySubject,
  OneTimeSecret,
  TrustedSecurityAuthority,
  KeyedDigestProvider,
  SecurityStoreSettings,
  SecurityTransactionalStore,
  SecurityAtomicMutation,
} from '@arkenivajs/security-apikey';

export type MagicLinkIntent = 'login' | 'email-verify' | 'account-recover';
/** Stored binding selectors are hints; the authority must independently resolve current account membership. */
export type MagicLinkAuthorizationContext = Parameters<TrustedSecurityAuthority['require']>[2] &
  Readonly<{
    magicLink?: Readonly<{ issueId?: string; intent?: MagicLinkIntent; tenantId?: string }>;
  }>;
export interface MagicLinkAuthority extends TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: MagicLinkAuthorizationContext,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** Deliver the URL and token once over an authorized channel; neither is diagnostic data. */
export interface MagicLinkIssue extends OneTimeSecret {
  readonly issueId: string;
  readonly redemptionUrl: string;
}
/** Email possession does not establish MFA or phishing-resistant assurance. */
export interface MagicLinkIdentity {
  readonly subject: IdentitySubject;
  readonly intent: MagicLinkIntent;
  readonly verifiedAt: string;
}
export interface MagicLinkService {
  issue(
    subject: IdentitySubject,
    intent: MagicLinkIntent,
    options?: OperationOptions,
  ): Promise<MagicLinkIssue>;
  /** A GET/prefetch cannot consume state; the HTTP application must request explicit POST confirmation. */
  consume(
    token: string,
    context: Readonly<{ method: 'POST'; purpose: MagicLinkIntent }>,
    options?: OperationOptions,
  ): Promise<MagicLinkIdentity>;
  revoke(issueId: string, options?: OperationOptions): Promise<void>;
}
export interface MagicLinksPluginSettings {
  readonly stateStore: SecurityStoreSettings;
  readonly hmac: KeyedDigestProvider;
  readonly signingKeyRef: string;
  readonly authority: MagicLinkAuthority;
  readonly trustedBaseUrl: string;
  readonly ttlMs: number;
  readonly maxClaimsPerHour: number;
}
