// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { SqlProvider, VerifiedTenantContext, RouteContext } from '@arkenivajs/core';
import type {
  TenantRegistrySnapshotV1_1,
  TenantRegistrySnapshotV1,
  TenantRegistrySqlOptions,
  TenantRegistryFileOptions,
  TenantRoutingPluginSettings,
  TenantHttpImplementation,
  TenantRoutingService,
  TenantRoutingEventV1,
  TenantCapabilitiesResponse,
  ApprovedUpstream,
} from '../../dist/index.js';

/** Compile through public declarations without treating constructed objects as runtime identity proof. */
function contract(
  sql: SqlProvider,
  tenant: VerifiedTenantContext,
  context: RouteContext,
  service: TenantRoutingService,
) {
  const snapshot: TenantRegistrySnapshotV1_1 = {
    schemaVersion: '1.1.0',
    revision: 'content-a',
    activationGeneration: 1,
    activatedAt: '2026-10-28T00:00:00.000Z',
    contentChecksum: 'sha256:' + '0'.repeat(64),
    operations: [
      {
        id: 'orders.list',
        method: 'GET',
        path: '/api/orders',
        label: 'List orders',
        schemas: { response: { type: 'object' } },
        policy: { requiredScopes: ['orders:read'], assurance: 'mfa' },
        maxConcurrency: 4,
        maxBodyBytes: 1024,
        maxResponseBytes: 4096,
        timeoutMs: 1000,
      },
    ],
    implementations: [{ id: 'orders-local', kind: 'handler', handlerKey: 'orders.list' }],
    bindings: [
      {
        tenantId: 'tenant-a',
        operationId: 'orders.list',
        implementationId: 'orders-local',
        enabled: true,
        discoverable: false,
      },
    ],
  };
  const historicalName: TenantRegistrySnapshotV1 = snapshot;
  const settings: TenantRoutingPluginSettings = {
    registry: { loadSnapshot: async () => historicalName },
    handlers: { 'orders.list': (ctx) => ctx.body },
    requestTransformers: { request: (payload, ctx) => ({ payload, request: ctx.requestId }) },
    responseTransformers: { response: (payload) => payload },
    credentialProvider: {
      get: async (input) => ({
        authorizationHeader: '',
        expiresAt: '',
        audience: input.audience,
        scopes: input.scopes,
      }),
    },
    maxCapabilities: 1000,
    activation: 'startup',
    authorize: ({ tenant: current }) => current === tenant,
  };
  const database: TenantRegistrySqlOptions = {
    connectionName: 'control',
    storageKey: 'owned_registry',
    sql,
    activationCheckpoint: {
      accept: async (input, options) => {
        void input.activationGeneration;
        void options?.signal;
      },
    },
  };
  const file: TenantRegistryFileOptions = {
    absolutePath: '/run/private/registry.json',
    maxBytes: 8388608,
    environment: 'production',
    publicRoots: ['/srv/public'],
  };
  // @ts-expect-error The production filesystem policy cannot be replaced with an unknown environment.
  const unsafeFile: TenantRegistryFileOptions = { ...file, environment: 'staging' };
  const http: TenantHttpImplementation = {
    id: 'partner',
    kind: 'http',
    method: 'POST',
    upstreamKey: 'partner',
    upstreamPath: '/quotes',
    requestTransformerKey: 'request',
    responseTransformerKey: 'response',
  };
  const legacy: TenantHttpImplementation = {
    id: 'legacy',
    kind: 'http',
    method: 'POST',
    upstreamKey: 'partner',
    upstreamPath: '/quotes',
    transformerKey: 'response',
  };
  const upstream: ApprovedUpstream = {
    key: 'partner',
    origin: 'https://partner.invalid',
    allowedHostnames: ['partner.invalid'],
    allowedCidrs: ['192.0.2.0/24'],
    allowRedirects: false,
    forwardClientAuthorization: false,
    connectionTimeoutMs: 1000,
    serviceAuth: { audience: 'api://partner', scopes: ['quotes:write'] },
  };
  const capabilities: Promise<TenantCapabilitiesResponse> = service.capabilities.list(tenant, {
    signal: context.signal,
    timeoutMs: 1000,
  });
  const event: TenantRoutingEventV1 = {
    schemaVersion: '1.0.0',
    eventId: 'event-a',
    requestId: context.requestId,
    tenantId: tenant.tenantId,
    operationId: 'orders.list',
    registryRevision: snapshot.revision,
    registryActivationGeneration: snapshot.activationGeneration,
    durationMs: 0,
    status: 'unknown',
    quality: { complete: false, missing: ['unfinished'] },
  };
  // @ts-expect-error SQL registry configuration cannot omit its existing provider.
  const missingSql: TenantRegistrySqlOptions = {
    connectionName: 'control',
    storageKey: 'owned_registry',
  };
  // @ts-expect-error Startup activation cannot be replaced with live reload.
  const hot: TenantRoutingPluginSettings = { ...settings, activation: 'hot' };
  // @ts-expect-error Undefined cannot silently replace the optional numeric limit.
  const undefinedLimit: TenantRoutingPluginSettings = { ...settings, maxCapabilities: undefined };
  // @ts-expect-error Browser credential forwarding cannot be enabled by this contract.
  const forwarding: ApprovedUpstream = { ...upstream, forwardClientAuthorization: true };
  // @ts-expect-error Redirect following is not an approved upstream policy.
  const redirects: ApprovedUpstream = { ...upstream, allowRedirects: true };
  // @ts-expect-error The generation of an immutable snapshot cannot be mutated.
  snapshot.activationGeneration = 2;
  // @ts-expect-error A schema-1.0 snapshot is not the active historical-name alias.
  const old: TenantRegistrySnapshotV1 = { ...snapshot, schemaVersion: '1.0.0' };
  void [
    database,
    file,
    unsafeFile,
    http,
    legacy,
    capabilities,
    event,
    missingSql,
    hot,
    undefinedLimit,
    forwarding,
    redirects,
    old,
  ];
}
void contract;

test('Tenant routing public constants preserve exact version and resource literal contracts', async () => {
  const api = await import('../../dist/index.js');
  const registry: '1.1.0' = api.TENANT_ROUTING_REGISTRY_SCHEMA_VERSION;
  const event: '1.0.0' = api.TENANT_ROUTING_EVENT_SCHEMA_VERSION;
  const bytes: 8388608 = api.DEFAULT_TENANT_ROUTING_MAX_REGISTRY_BYTES;
  const capabilities: 1000 = api.DEFAULT_TENANT_CAPABILITIES_LIMIT;
  assert.deepEqual([registry, event, bytes, capabilities], ['1.1.0', '1.0.0', 8388608, 1000]);
  assert.equal(typeof api.TENANT_ROUTING_CAPABILITY, 'symbol');
  assert.equal(Symbol.keyFor(api.TENANT_ROUTING_CAPABILITY), undefined);
});
