// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Ajv2020 } from 'ajv/dist/2020.js';
const string = (maxLength: number, minLength = 0) => ({ type: 'string', maxLength, minLength });
const integer = (maximum: number) => ({ type: 'integer', minimum: 1, maximum });
const object = (properties: Record<string, object>, required = Object.keys(properties)) => ({
  type: 'object',
  properties,
  required,
  additionalProperties: false,
});
const expression = { $ref: '#/$defs/expression' };
const pointer = { ...string(1024), pattern: '^(?:|/(?:[^~/]|~[01])*(?:/(?:[^~/]|~[01])*)*)$' };
const args = { type: 'array', items: expression, minItems: 1, maxItems: 32 };
const operator = (
  name: string,
  properties: Record<string, object>,
  optional: readonly string[] = [],
) =>
  object({ op: { const: name }, ...properties }, [
    'op',
    ...Object.keys(properties).filter((key) => !optional.includes(key)),
  ]);

/** A fixed native schema checks the entire closed mapping language, including every nested operator. */
export const mappingGrammar = new Ajv2020({
  strict: true,
  allErrors: false,
  messages: false,
  logger: false,
}).compile({
  ...object({
    schemaVersion: { const: '1.0.0' },
    id: { ...string(128, 1), pattern: '^[a-z][a-z0-9._-]*$' },
    inputSchemaId: string(128, 1),
    outputSchemaId: string(128, 1),
    fields: {
      type: 'object',
      minProperties: 1,
      maxProperties: 256,
      propertyNames: {
        pattern: '^(?!__proto__$|constructor$|prototype$)[A-Za-z_][A-Za-z0-9_]{0,127}$',
      },
      additionalProperties: expression,
    },
    limits: object({
      maxDepth: integer(16),
      maxNodes: integer(2048),
      maxArrayItems: integer(100000),
      maxOutputBytes: integer(8388608),
    }),
  }),
  $defs: {
    expression: {
      oneOf: [
        operator('copy', { path: pointer, required: { type: 'boolean' } }, ['required']),
        operator('literal', { value: {} }),
        operator('coalesce', { args }),
        operator('concat', { args, separator: string(128) }, ['separator']),
        ...['to-string', 'to-number', 'to-boolean'].map((name) =>
          operator(name, { value: expression }),
        ),
        operator('array-map', { path: pointer, item: expression, maxItems: integer(100000) }),
      ],
    },
  },
});
