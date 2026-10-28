// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
export { tenantRegistryFileProvider } from './file-provider.js';

export const TENANT_ROUTING_REGISTRY_SCHEMA_VERSION = '1.1.0' as const;
export const TENANT_ROUTING_EVENT_SCHEMA_VERSION = '1.0.0' as const;
export const DEFAULT_TENANT_ROUTING_MAX_REGISTRY_BYTES = 8388608 as const;
export const DEFAULT_TENANT_CAPABILITIES_LIMIT = 1000 as const;
/** Application-local administrative capability identity; never a client-supplied key. */
export const TENANT_ROUTING_CAPABILITY: unique symbol = Symbol('arkenivajs.tenant-routing');
