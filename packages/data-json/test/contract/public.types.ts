// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  DataJsonPluginSettings,
  JsonMappingRegistry,
  JsonMappingV1,
  JsonService,
  JsonValidation,
} from '../../dist/index.js';
declare const mapping: JsonMappingV1;
const registry: JsonMappingRegistry = {
  ids: Object.freeze([mapping.id]),
  get(id) {
    return id === mapping.id ? mapping : null;
  },
};
// @ts-expect-error A get-only registry cannot prove complete startup approval.
const dynamic: JsonMappingRegistry = { get: () => mapping };
const executable: JsonMappingV1 = {
  ...mapping,
  // @ts-expect-error The mapping grammar cannot execute arbitrary JavaScript.
  fields: { x: { op: 'eval', source: 'process.env' } },
};
const settings: DataJsonPluginSettings = {
  defaults: {},
  schemas: {},
  mappings: registry,
  policy: { maxConcurrent: 1, timeoutMs: 1000 },
};
function synchronous(json: JsonService) {
  const text: string = json.stringify(json.parse('null'));
  const result: JsonValidation = json.validate(text, 'input.v1');
  const transformed: unknown = json.transform(text, 'mapping.v1');
  // @ts-expect-error JSON options never relax schema or prototype safety.
  json.parse('{}', { allowPrototype: true });
  return { result, transformed };
}
void [dynamic, executable, settings, synchronous];
