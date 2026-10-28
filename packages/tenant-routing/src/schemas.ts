// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import canonicalize from 'canonicalize';
import type { TenantOperationDefinition } from './contracts.js';

const single = [
  'additionalProperties',
  'unevaluatedProperties',
  'propertyNames',
  'items',
  'unevaluatedItems',
  'contains',
  'not',
  'if',
  'then',
  'else',
  'contentSchema',
];
const lists = ['allOf', 'anyOf', 'oneOf', 'prefixItems'];
const maps = ['properties', 'patternProperties', 'dependentSchemas', '$defs', 'definitions'];

/** Inspect schema positions only: a literal property's value is never executable schema syntax. */
function offline(input: unknown): void {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return;
  const value = input as Record<string, unknown>;
  if (Object.hasOwn(value, '$async')) throw new Error('Asynchronous schemas are not supported');
  for (const name of ['$ref', '$dynamicRef', '$recursiveRef']) {
    if (Object.hasOwn(value, name)) {
      const reference = value[name];
      if (typeof reference !== 'string' || !reference.startsWith('#'))
        throw new Error('Only local schema references are supported');
    }
  }
  for (const name of single) if (Object.hasOwn(value, name)) offline(value[name]);
  for (const name of lists)
    if (Array.isArray(value[name])) for (const item of value[name]) offline(item);
  for (const name of maps) {
    const entries = value[name];
    if (entries && typeof entries === 'object' && !Array.isArray(entries))
      for (const item of Object.values(entries)) offline(item);
  }
  const dependencies = value.dependencies;
  if (dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies))
    for (const item of Object.values(dependencies)) if (!Array.isArray(item)) offline(item);
}

/** A startup-scoped native compiler rejects invalid schemas without fetching external resources. */
export function validateOperationSchemas(operations: readonly TenantOperationDefinition[]): void {
  const compiler = new Ajv2020({
    strictSchema: true,
    strictNumbers: true,
    strictTypes: false,
    strictRequired: false,
    strictTuples: false,
    ownProperties: true,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    allErrors: false,
    messages: false,
    logger: false,
    inlineRefs: false,
    loopEnum: 128,
    loopRequired: 128,
  });
  addFormats.default(compiler);
  const checked = new Set<string>();
  for (const operation of operations) {
    for (const source of Object.values(operation.schemas)) {
      const key = canonicalize(source);
      if (typeof key !== 'string') throw new Error('Invalid operation schema');
      if (checked.has(key)) continue;
      offline(source);
      // Native equality handles ordinary JSON objects; the registry itself remains deeply frozen.
      const schema = JSON.parse(JSON.stringify(source)) as Record<string, unknown>;
      const validate = compiler.compile(schema);
      if ('$async' in validate && validate.$async)
        throw new Error('Invalid asynchronous validator');
      checked.add(key);
      // Schemas are independent and cannot share remote IDs or retain unbounded global caches.
      compiler.removeSchema(schema);
    }
  }
}
