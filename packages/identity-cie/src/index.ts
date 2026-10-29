// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin } from '@arkenivajs/core';
import { createItalianFederationPlugin } from '@arkenivajs/identity-spid/support';
import type { ItalianEidPluginSettings, ItalianFederationService } from '@arkenivajs/identity-spid';

export type {
  ItalianIdentitySystem,
  FederationProtocol,
  FederationAssurance,
  FederationSignatureAlgorithm,
  FederationEncryptionPolicy,
  FederationOidcRegistration,
  FederationTrustAnchor,
  FederationMetadataPolicy,
  FederationProfileV1,
  FederationIdentityMapper,
  FederatedLogin,
  FederatedIdentity,
  TrustResult,
  ItalianFederationService,
  ItalianEidPluginSettings,
  BoundedRuntimePolicy,
  SecretProvider,
  SecurityStoreSettings,
  TrustedSecurityAuthority,
  OperationOptions,
} from '@arkenivajs/identity-spid';
export type CieService = ItalianFederationService;
export const CIE_CAPABILITY: unique symbol = Symbol('arkenivajs.identity.cie');

/** Install explicit CIE profiles without registering another identity system or application listener. */
export function ciePlugin(settings: ItalianEidPluginSettings): Plugin {
  return createItalianFederationPlugin('cie', CIE_CAPABILITY, settings);
}
