// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { ciePlugin, CIE_CAPABILITY } from '../../dist/index.js';
import type {
  CieService,
  ItalianEidPluginSettings,
  FederatedLogin,
  FederatedIdentity,
  TrustResult,
} from '../../dist/index.js';
import { SPID_CAPABILITY } from '@arkenivajs/identity-spid';
import type { Plugin } from '@arkenivajs/core';

declare const settings: ItalianEidPluginSettings;
declare const service: CieService;
const plugin: Plugin = ciePlugin(settings);
const login: Promise<FederatedLogin> = service
  .forProfile('configured-cie')
  .beginAuthentication({ returnPath: '/private' }, 'cie-l2');
const identity: Promise<FederatedIdentity> = service.consumeAuthentication(
  'https://service.example.test/callback?code=opaque',
);
const trust: Promise<TrustResult> = service.verifyFederationTrust('signed-statement');
// @ts-expect-error The optional module capability is unique to CIE.
const foreign: typeof CIE_CAPABILITY = SPID_CAPABILITY;
// @ts-expect-error CIE retains the closed typed registration contract.
ciePlugin({ ...settings, arbitraryIssuer: 'https://foreign.example.test' });
// @ts-expect-error Caller metadata cannot create another assurance label.
service.beginAuthentication({ returnPath: '/private' }, 'cie-admin');
void [plugin, login, identity, trust, foreign];
