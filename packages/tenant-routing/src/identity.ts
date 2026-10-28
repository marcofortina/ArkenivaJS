// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import type { AuthService, Identity, VerifiedTenantContext } from '@arkenivajs/core';
import type { TenantOperationDefinition } from './contracts.js';
import type { Settings } from './settings.js';
import { routingFailure } from './errors.js';
import type { RoutingOperation } from './operation.js';

/** Structural objects and clones cannot inherit the authentication authority's live provenance. */
export function verifiedTenant(auth: AuthService, value: unknown): VerifiedTenantContext {
  try {
    if (!value || typeof value !== 'object' || types.isProxy(value))
      throw routingFailure('EK_AUTH_REQUIRED');
    const identity = Object.getOwnPropertyDescriptor(value, 'identity');
    if (
      !identity ||
      !('value' in identity) ||
      auth.tenantFrom(identity.value as Identity) !== value
    )
      throw routingFailure('EK_AUTH_REQUIRED');
    return value as VerifiedTenantContext;
  } catch {
    throw routingFailure('EK_AUTH_REQUIRED');
  }
}
export async function authorized(
  auth: AuthService,
  settings: Settings,
  tenant: VerifiedTenantContext,
  operation: TenantOperationDefinition,
  scope: RoutingOperation,
): Promise<boolean> {
  scope.check();
  verifiedTenant(auth, tenant);
  try {
    for (const required of operation.policy.requiredScopes)
      auth.requireScope(tenant.identity, required);
    if (operation.policy.assurance !== undefined)
      auth.requireAssurance(tenant.identity, operation.policy.assurance);
    const allowed = await scope.run(() =>
      settings.authorize(
        Object.freeze({ tenant, operationId: operation.id, policy: operation.policy }),
      ),
    );
    scope.check();
    return allowed === true;
  } catch {
    scope.check();
    return false;
  }
}
