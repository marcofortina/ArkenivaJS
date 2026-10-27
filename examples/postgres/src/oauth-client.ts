// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  OAuthClientPluginSettings,
  OAuthClientRegistration,
  SecretProvider,
  SecurityStoreSettings,
  TrustedSecurityAuthority,
} from '@arkenivajs/security-oauth-client';

export interface OutgoingOAuthDependencies {
  readonly clients: readonly OAuthClientRegistration[];
  readonly secretProvider: SecretProvider;
  readonly stateStore: SecurityStoreSettings;
  readonly authority: TrustedSecurityAuthority;
  readonly encryptionKeyRefs: readonly string[];
  readonly macKeyRefs: readonly string[];
  readonly allowInsecureLoopback?: boolean;
}
/** Keep shared durable state and independent application authorization explicit in the composition. */
export function outgoingOAuthSettings(
  dependencies: OutgoingOAuthDependencies,
): OAuthClientPluginSettings {
  return {
    clients: dependencies.clients,
    secretProvider: dependencies.secretProvider,
    stateStore: dependencies.stateStore,
    authority: dependencies.authority,
    maxStateTtlMs: 300000,
    refreshTtlMs: 86400000,
    stateEncryptionKeyRefs: dependencies.encryptionKeyRefs,
    stateMacKeyRefs: dependencies.macKeyRefs,
    ...(dependencies.allowInsecureLoopback === undefined
      ? {}
      : { allowInsecureLoopback: dependencies.allowInsecureLoopback }),
  };
}
