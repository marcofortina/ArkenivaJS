// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Ajv2020 } from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { snapshot } from './codec.js';
import { failure, record } from './validation.js';
import type { JsonValidation } from './contracts.js';
const dialect = 'https://json-schema.org/draft/2020-12/schema';
const idPattern = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const one = [
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
const many = ['allOf', 'anyOf', 'oneOf', 'prefixItems'];
const keyed = ['properties', 'patternProperties', 'dependentSchemas', '$defs', 'definitions'];
const escape = (value: string) => value.replaceAll('~', '~0').replaceAll('/', '~1');

/** Ajv remains the schema authority; this audit only closes remote and recursive reference paths. */
function references(catalog: Readonly<Record<string, object>>): void {
  const nodes = new Map<string, { schema: Record<string, unknown> | boolean; edges: string[] }>();
  function visit(id: string, value: unknown, path: string, parent?: string) {
    const schema = typeof value === 'boolean' ? value : record(value),
      key = id + '#' + path;
    nodes.set(key, { schema, edges: [] });
    if (parent) nodes.get(parent)!.edges.push(key);
    if (typeof schema === 'boolean') return;
    if (
      Object.hasOwn(schema, '$async') ||
      Object.hasOwn(schema, '$dynamicRef') ||
      Object.hasOwn(schema, '$dynamicAnchor') ||
      Object.hasOwn(schema, '$anchor') ||
      (Object.hasOwn(schema, '$id') && (path !== '' || schema.$id !== id)) ||
      (Object.hasOwn(schema, '$schema') && schema.$schema !== dialect)
    )
      throw failure('EK_JSON_SCHEMA');
    for (const name of one)
      if (Object.hasOwn(schema, name)) visit(id, schema[name], path + '/' + name, key);
    for (const name of many)
      if (Array.isArray(schema[name]))
        (schema[name] as unknown[]).forEach((item, index) =>
          visit(id, item, path + '/' + name + '/' + index, key),
        );
    for (const name of keyed)
      if (Object.hasOwn(schema, name))
        for (const [entry, item] of Object.entries(record(schema[name])))
          visit(id, item, path + '/' + name + '/' + escape(entry), key);
  }
  for (const [id, schema] of Object.entries(catalog)) visit(id, schema, '');
  for (const [key, node] of nodes) {
    if (typeof node.schema === 'boolean') continue;
    if (!Object.hasOwn(node.schema, '$ref')) continue;
    const ref = node.schema.$ref;
    if (typeof ref !== 'string' || ref.length > 1024) throw failure('EK_JSON_SCHEMA');
    const marker = ref.indexOf('#'),
      targetId = marker < 0 ? ref : ref.slice(0, marker),
      fragment = marker < 0 ? '' : ref.slice(marker + 1);
    let path: string;
    try {
      path = decodeURIComponent(fragment);
    } catch {
      throw failure('EK_JSON_SCHEMA');
    }
    if ((path !== '' && !path.startsWith('/')) || /~(?![01])/u.test(path))
      throw failure('EK_JSON_SCHEMA');
    const resolved = (targetId || key.slice(0, key.indexOf('#'))) + '#' + path;
    if (!nodes.has(resolved)) throw failure('EK_JSON_SCHEMA');
    node.edges.push(resolved);
  }
  const done = new Set<string>(),
    active = new Set<string>();
  function acyclic(key: string) {
    if (active.has(key)) throw failure('EK_JSON_SCHEMA');
    if (done.has(key)) return;
    active.add(key);
    for (const next of nodes.get(key)!.edges) acyclic(next);
    active.delete(key);
    done.add(key);
  }
  for (const key of nodes.keys()) acyclic(key);
}
export class Schemas {
  readonly validators = new Map<string, ValidateFunction>();
  readonly catalog: Readonly<Record<string, object>>;
  constructor(source: Readonly<Record<string, object>>) {
    try {
      const clean = record(snapshot(source, { maxBytes: 1048576, maxDepth: 64, indentSpaces: 0 }));
      if (Object.keys(clean).length > 128 || Object.keys(clean).some((id) => !idPattern.test(id)))
        throw failure('EK_JSON_SCHEMA');
      for (const value of Object.values(clean)) record(value);
      this.catalog = clean as Readonly<Record<string, object>>;
      references(this.catalog);
      const ajv = new Ajv2020({
        strictSchema: true,
        strictNumbers: true,
        strictTypes: false,
        strictTuples: false,
        strictRequired: false,
        allErrors: false,
        ownProperties: true,
        coerceTypes: false,
        useDefaults: false,
        removeAdditional: false,
        messages: false,
        logger: false,
        inlineRefs: false,
        loopEnum: 128,
        loopRequired: 128,
      });
      addFormats.default(ajv);
      const equality = ajv.compile({ const: { valueOf: 'data', toString: 'data' } });
      if (
        !equality({ valueOf: 'data', toString: 'data' }) ||
        equality({ valueOf: 'changed', toString: 'data' })
      )
        throw failure('EK_JSON_SCHEMA');
      // The native equality backend requires ordinary JSON prototypes on both sides.
      for (const [id, schema] of Object.entries(this.catalog))
        ajv.addSchema(JSON.parse(JSON.stringify(schema)), id);
      for (const id of Object.keys(this.catalog)) {
        const validate = ajv.getSchema(id);
        if (!validate || ('$async' in validate && validate.$async)) throw failure('EK_JSON_SCHEMA');
        this.validators.set(id, validate);
      }
    } catch {
      throw failure('EK_JSON_SCHEMA');
    }
  }
  validate(value: unknown, id: string): JsonValidation {
    if (typeof id !== 'string' || !this.validators.has(id)) throw failure('EK_JSON_SCHEMA');
    const validate = this.validators.get(id)!;
    const clean = snapshot(value, { maxBytes: 8388608, maxDepth: 128, indentSpaces: 0 });
    if (validate(JSON.parse(JSON.stringify(clean))))
      return Object.freeze({ valid: true, value: clean, errors: Object.freeze([]) as readonly [] });
    return Object.freeze({
      valid: false,
      errors: Object.freeze(
        (validate.errors ?? []).slice(0, 1).map((error) =>
          Object.freeze({
            path: error.instancePath,
            code: 'EK_JSON_SCHEMA',
            message: 'The value does not satisfy the registered JSON schema',
          }),
        ),
      ),
    });
  }
}
