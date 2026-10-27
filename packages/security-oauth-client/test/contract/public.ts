// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { oauthClientPlugin, OAUTH_CLIENT_CAPABILITY } from '../../dist/index.js';
import type {
  OAuthClientPluginSettings,
  OAuthClientService,
  OAuthAuthorizationCallback,
  OAuthAuthorizationStart,
  OAuthGrant,
  OperationOptions,
} from '../../dist/index.js';
import type { Plugin } from '@arkenivajs/core';
export function contract(
  settings: OAuthClientPluginSettings,
  service: OAuthClientService,
  callback: OAuthAuthorizationCallback,
  options: OperationOptions,
) {
  const plugin: Plugin = oauthClientPlugin(settings),
    capability: symbol = OAUTH_CLIENT_CAPABILITY;
  const start: Promise<OAuthAuthorizationStart> = service.beginAuthorization(
      {
        audience: 'https://resource.fixture.invalid/orders',
        scopes: ['orders.read'],
        returnPath: '/orders',
      },
      options,
    ),
    grant: Promise<OAuthGrant> = service.exchangeCode(callback, options),
    machine: Promise<OAuthGrant> = service.clientCredentials(
      'https://resource.fixture.invalid/orders',
      ['orders.read'],
      options,
    ),
    refresh: Promise<OAuthGrant> = service.refresh('opaque-reference', options),
    revoked: Promise<void> = service.revoke('opaque-reference', options);
  return { plugin, capability, start, grant, machine, refresh, revoked };
}
