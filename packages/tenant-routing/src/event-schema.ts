// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Supplementary routing event 1.0.0; independent from technical metering v1. */
export const TENANT_ROUTING_EVENT_SCHEMA_V1 = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://schemas.arkenivajs.example/tenant-routing/event-v1.0.0.json',
  type: 'object',
  additionalProperties: false,
  required: Object.freeze([
    'schemaVersion',
    'eventId',
    'requestId',
    'tenantId',
    'operationId',
    'registryRevision',
    'durationMs',
    'status',
    'quality',
  ]),
  properties: Object.freeze({
    schemaVersion: Object.freeze({ const: '1.0.0' }),
    ...Object.fromEntries(
      [
        'eventId',
        'requestId',
        'tenantId',
        'operationId',
        'registryRevision',
        'implementationId',
      ].map((key) => [key, Object.freeze({ type: 'string', minLength: 1 })]),
    ),
    traceId: Object.freeze({ type: 'string', pattern: '^[0-9a-f]{32}$' }),
    implementationKind: Object.freeze({ enum: Object.freeze(['handler', 'http']) }),
    registryActivationGeneration: Object.freeze({
      type: 'integer',
      minimum: 1,
      maximum: Number.MAX_SAFE_INTEGER,
    }),
    durationMs: Object.freeze({ type: 'number', minimum: 0 }),
    status: Object.freeze({ enum: Object.freeze(['ok', 'error', 'aborted', 'unknown']) }),
    quality: Object.freeze({
      type: 'object',
      additionalProperties: false,
      required: Object.freeze(['complete', 'missing']),
      properties: Object.freeze({
        complete: Object.freeze({ type: 'boolean' }),
        missing: Object.freeze({
          type: 'array',
          uniqueItems: true,
          items: Object.freeze({ type: 'string' }),
        }),
      }),
    }),
  }),
});
