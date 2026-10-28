// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError, type ErrorCode } from '@arkenivajs/core';

const messages: Partial<Record<ErrorCode, string>> = {
  EK_TROUTE_CONFIG: 'Invalid tenant routing configuration',
  EK_TROUTE_REGISTRY: 'Invalid tenant routing registry',
  EK_TROUTE_COLLISION: 'Conflicting tenant routing operation',
  EK_TROUTE_UNMAPPED: 'Operation not available',
  EK_TROUTE_FORBIDDEN: 'Operation not authorized',
  EK_TROUTE_CONTRACT: 'Operation contract validation failed',
  EK_TROUTE_UPSTREAM: 'Operation implementation unavailable',
  EK_TROUTE_TIMEOUT: 'Operation deadline exceeded',
  EK_TROUTE_CAPACITY: 'Operation capacity reached',
  EK_TCAP_UNAVAILABLE: 'Capabilities unavailable',
  EK_TCAP_LIMIT_EXCEEDED: 'Capability response limit exceeded',
  EK_AUTH_REQUIRED: 'Authentication required',
  EK_RESOURCE_CLOSED: 'Tenant routing service is closed',
  EK_LIFECYCLE_STATE: 'Tenant routing service is not ready',
};

/** Runtime errors contain only fixed messages and the internal request/response distinction. */
export function routingFailure(code: ErrorCode = 'EK_TROUTE_CONFIG', response = false): KitError {
  return new KitError({
    code,
    message: messages[code] ?? 'Tenant routing operation failed',
    ...(response ? { details: { response: true } } : {}),
  });
}

/** Configuration failures never carry filesystem paths, registry bodies or provider exceptions. */
export const registryFailure = () =>
  new KitError({ code: 'EK_TROUTE_REGISTRY', message: 'Invalid tenant routing registry' });
