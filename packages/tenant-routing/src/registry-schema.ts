// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

const text = (maxLength = 128) => ({ type: 'string', minLength: 1, maxLength });
const identifier = { ...text(), pattern: '^[a-z][a-z0-9._-]*$' };
const integer = (maximum: number) => ({ type: 'integer', minimum: 1, maximum });
const object = (properties: Record<string, unknown>, required = Object.keys(properties)) => ({
  type: 'object',
  additionalProperties: false,
  properties,
  required,
});
const method = { enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] };
const array = (items: unknown, maxItems: number) => ({ type: 'array', maxItems, items });
const schemas = object(
  {
    params: { type: 'object' },
    query: { type: 'object' },
    body: { type: 'object' },
    response: { type: 'object' },
  },
  ['response'],
);
const policy = object(
  {
    requiredScopes: { ...array(text(), 20), uniqueItems: true },
    assurance: { enum: ['single-factor', 'mfa', 'phishing-resistant'] },
  },
  ['requiredScopes'],
);
const operation = object({
  id: identifier,
  method,
  path: { ...text(512), minLength: 2, pattern: '^/api/(?:[A-Za-z0-9._:-]+/?)+$' },
  schemas,
  policy,
  label: text(),
  maxConcurrency: integer(10000),
  maxBodyBytes: integer(10485760),
  maxResponseBytes: integer(10485760),
  timeoutMs: integer(120000),
});
const local = object({ id: identifier, kind: { const: 'handler' }, handlerKey: identifier });
const http = {
  ...object(
    {
      id: identifier,
      kind: { const: 'http' },
      upstreamKey: identifier,
      upstreamPath: { ...text(512), pattern: '^/(?:[A-Za-z0-9._/-]*)$' },
      method,
      requestTransformerKey: identifier,
      responseTransformerKey: identifier,
      transformerKey: identifier,
    },
    ['id', 'kind', 'upstreamKey', 'upstreamPath', 'method'],
  ),
  allOf: [
    {
      not: {
        type: 'object',
        properties: { transformerKey: {}, responseTransformerKey: {} },
        required: ['transformerKey', 'responseTransformerKey'],
      },
    },
  ],
};
const binding = object(
  {
    tenantId: identifier,
    operationId: identifier,
    implementationId: identifier,
    enabled: { type: 'boolean' },
    discoverable: { type: 'boolean' },
  },
  ['tenantId', 'operationId', 'implementationId', 'enabled'],
);

/** Product-owned offline Draft 2020-12 schema; configuration cannot supply validators or references. */
export const registrySchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  ...object({
    schemaVersion: { const: '1.1.0' },
    revision: { ...text(), pattern: '^[A-Za-z0-9._-]+$' },
    activationGeneration: integer(Number.MAX_SAFE_INTEGER),
    contentChecksum: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' },
    activatedAt: { type: 'string', format: 'date-time' },
    operations: array(operation, 10000),
    implementations: array({ oneOf: [local, http] }, 20000),
    bindings: array(binding, 200000),
  }),
};
