// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

test('Tenant routing adds no HTTP, SQL or registry validation engine to the initialized core', async () => {
  await import('@arkenivajs/core');
  const require = createRequire(import.meta.url),
    before = Object.keys(require.cache);
  const api = await import('../../dist/index.js');
  assert.deepEqual(Object.keys(require.cache), before);
  assert.deepEqual(Object.keys(api), [
    'DEFAULT_TENANT_CAPABILITIES_LIMIT',
    'DEFAULT_TENANT_ROUTING_MAX_REGISTRY_BYTES',
    'TENANT_ROUTING_CAPABILITY',
    'TENANT_ROUTING_EVENT_SCHEMA_VERSION',
    'TENANT_ROUTING_REGISTRY_SCHEMA_VERSION',
    'tenantRegistryFileProvider',
    'tenantRegistrySqlProvider',
    'tenantRoutingPlugin',
  ]);
});
