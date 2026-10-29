// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import type {
  TenantRegistrySnapshotV1_1,
  TenantOperationDefinition,
} from '@arkenivajs/tenant-routing';

/** Author deployment data using the same pinned upstream JCS algorithm as production. */
export function activate(
  content: Pick<TenantRegistrySnapshotV1_1, 'operations' | 'implementations' | 'bindings'>,
  revision: string,
  generation: number,
): TenantRegistrySnapshotV1_1 {
  const body = {
      schemaVersion: '1.1.0' as const,
      operations: content.operations,
      implementations: content.implementations,
      bindings: content.bindings,
    },
    encoded = canonicalize(body);
  if (typeof encoded !== 'string') throw new Error('Registry content is not JSON');
  return {
    ...body,
    revision,
    activationGeneration: generation,
    activatedAt: '2026-01-01T00:00:0' + generation + '.000Z',
    contentChecksum: 'sha256:' + createHash('sha256').update(encoded).digest('hex'),
  };
}
export function initialRegistry() {
  const operation: TenantOperationDefinition = {
    id: 'quotes.calculate',
    method: 'POST',
    path: '/api/quotes/calculate',
    label: 'Calculate a quote',
    schemas: {
      body: {
        type: 'object',
        properties: { amount: { type: 'number', minimum: 0, maximum: 1000000 } },
        required: ['amount'],
        additionalProperties: false,
      },
      response: {
        type: 'object',
        properties: { quoteId: { type: 'string' }, total: { type: 'number' } },
        required: ['quoteId', 'total'],
        additionalProperties: false,
      },
    },
    policy: { requiredScopes: ['quotes:write'] },
    maxConcurrency: 4,
    maxBodyBytes: 4096,
    maxResponseBytes: 4096,
    timeoutMs: 3000,
  };
  return activate(
    {
      operations: [operation],
      implementations: [
        { id: 'quote-standard', kind: 'handler', handlerKey: 'quotes.standard' },
        ...['one', 'two'].map((key) => ({
          id: 'quote-partner-' + key,
          kind: 'http' as const,
          upstreamKey: 'partner-' + key,
          upstreamPath: '/quote',
          method: 'POST' as const,
          requestTransformerKey: 'quotes.partner.request',
          responseTransformerKey: 'quotes.partner.response',
        })),
      ],
      bindings: [
        {
          tenantId: 'tenant-a',
          operationId: operation.id,
          implementationId: 'quote-standard',
          enabled: true,
        },
        {
          tenantId: 'tenant-b',
          operationId: operation.id,
          implementationId: 'quote-partner-one',
          enabled: true,
        },
      ],
    },
    'content-blue',
    1,
  );
}
export function expandedRegistry(original: TenantRegistrySnapshotV1_1): TenantRegistrySnapshotV1_1 {
  const status: TenantOperationDefinition = {
    ...original.operations[0]!,
    id: 'orders.status',
    method: 'GET',
    path: '/api/orders/:orderId/status',
    label: 'Read order status',
    policy: { requiredScopes: ['orders:read'] },
    schemas: {
      params: {
        type: 'object',
        properties: { orderId: { type: 'string' } },
        required: ['orderId'],
        additionalProperties: false,
      },
      response: {
        type: 'object',
        properties: { orderId: { type: 'string' }, status: { type: 'string' } },
        required: ['orderId', 'status'],
        additionalProperties: false,
      },
    },
  };
  return activate(
    {
      operations: [...original.operations, status],
      implementations: [
        ...original.implementations,
        { id: 'order-status', kind: 'handler', handlerKey: 'orders.status' },
      ],
      bindings: [
        ...original.bindings.map((binding) =>
          binding.tenantId === 'tenant-b'
            ? { ...binding, implementationId: 'quote-partner-two' }
            : binding,
        ),
        {
          tenantId: 'tenant-c',
          operationId: 'quotes.calculate',
          implementationId: 'quote-standard',
          enabled: true,
        },
        ...['tenant-a', 'tenant-b', 'tenant-c'].map((tenantId) => ({
          tenantId,
          operationId: 'orders.status',
          implementationId: 'order-status',
          enabled: true,
        })),
      ],
    },
    'content-green',
    2,
  );
}
