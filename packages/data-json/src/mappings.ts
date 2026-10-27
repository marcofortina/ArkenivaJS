// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { snapshot } from './codec.js';
import { failure, record } from './validation.js';
import { mappingGrammar } from './mapping-grammar.js';
import { Schemas } from './schemas.js';
import type { JsonMappingExpr, JsonMappingRegistry, JsonMappingV1 } from './contracts.js';

const missing = Symbol('missing-json-path');
const idPattern = /^[a-z][a-z0-9._-]{0,127}$/;
const inputLimits = { maxBytes: 8388608, maxDepth: 128, indentSpaces: 0 };
const metadataLimits = { maxBytes: 8388608, maxDepth: 64, indentSpaces: 0 };
function mappingError(error: unknown): never {
  if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
  throw failure('EK_JSON_TRANSFORM');
}

/** Consult the trusted deployment provider once per manifest entry, never from a request. */
export function captureMappings(provider: JsonMappingRegistry): readonly JsonMappingV1[] {
  try {
    if (!provider || typeof provider !== 'object' || types.isProxy(provider)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(provider, 'ids');
    if (!descriptor || !('value' in descriptor)) throw failure();
    const ids = snapshot(descriptor.value, { maxBytes: 32768, maxDepth: 1, indentSpaces: 0 });
    if (
      !Array.isArray(ids) ||
      ids.length > 128 ||
      !ids.every((id) => typeof id === 'string' && idPattern.test(id)) ||
      new Set(ids).size !== ids.length
    )
      throw failure();
    let owner: object | null = provider,
      method: unknown;
    for (let depth = 0; owner && depth < 8; depth++, owner = Object.getPrototypeOf(owner)) {
      if (types.isProxy(owner)) throw failure();
      const entry = Object.getOwnPropertyDescriptor(owner, 'get');
      if (entry) {
        if (!('value' in entry)) throw failure();
        method = entry.value;
        break;
      }
    }
    if (typeof method !== 'function' || types.isProxy(method)) throw failure();
    const result: JsonMappingV1[] = [];
    for (const id of ids) {
      const value = snapshot(Reflect.apply(method, provider, [id]), metadataLimits);
      if (!value || typeof value !== 'object' || record(value).id !== id) throw failure();
      result.push(value as JsonMappingV1);
    }
    return snapshot(result, metadataLimits) as readonly JsonMappingV1[];
  } catch (error) {
    return mappingError(error);
  }
}
function pointer(text: string): readonly string[] {
  if (text === '') return [];
  if (!text.startsWith('/') || /~(?![01])/u.test(text)) throw failure('EK_JSON_TRANSFORM');
  const parts = text
    .slice(1)
    .split('/')
    .map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (parts.some((part) => ['__proto__', 'prototype', 'constructor'].includes(part)))
    throw failure('EK_JSON_TRANSFORM');
  return parts;
}
function lookup(input: unknown, path: readonly string[]): unknown {
  let value = input;
  for (const key of path) {
    if (
      !value ||
      typeof value !== 'object' ||
      (Array.isArray(value) && !/^(?:0|[1-9][0-9]*)$/.test(key)) ||
      !Object.hasOwn(value, key)
    )
      return missing;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}
interface Budget {
  nodes: number;
  items: number;
  check(): void;
}
function dataSize(
  value: unknown,
  check: () => void = () => undefined,
): { nodes: number; items: number } {
  check();
  let nodes = 1,
    items = Array.isArray(value) ? value.length : 0;
  if (value && typeof value === 'object')
    for (const child of Object.values(value)) {
      const size = dataSize(child, check);
      nodes += size.nodes;
      items += size.items;
    }
  return { nodes, items };
}
type Evaluate = (value: unknown, budget: Budget) => unknown;
interface Compiled {
  readonly source: JsonMappingV1;
  readonly fields: readonly (readonly [string, Evaluate])[];
}

function compile(source: JsonMappingV1, schemas: Schemas): Compiled {
  if (
    !mappingGrammar(source) ||
    !schemas.validators.has(source.inputSchemaId) ||
    !schemas.validators.has(source.outputSchemaId)
  )
    throw failure('EK_JSON_TRANSFORM');
  const outputSchema = schemas.catalog[source.outputSchemaId]! as Record<string, unknown>;
  const outputType = outputSchema.type;
  if (
    outputType !== undefined &&
    outputType !== 'object' &&
    !(Array.isArray(outputType) && outputType.includes('object'))
  )
    throw failure('EK_JSON_TRANSFORM');
  const names = Object.keys(source.fields);
  for (const [name, expr] of Object.entries(source.fields)) {
    const kind =
      expr.op === 'concat' || expr.op === 'to-string'
        ? 'string'
        : expr.op === 'to-number'
          ? 'number'
          : expr.op === 'to-boolean'
            ? 'boolean'
            : expr.op === 'array-map'
              ? 'array'
              : undefined;
    if (
      !schemas.acceptsProperty(
        source.outputSchemaId,
        name,
        kind,
        expr.op === 'literal' ? { value: expr.value } : undefined,
      )
    )
      throw failure('EK_JSON_TRANSFORM');
  }
  if (
    Array.isArray(outputSchema.required) &&
    outputSchema.required.some((name) => typeof name === 'string' && !names.includes(name))
  )
    throw failure('EK_JSON_TRANSFORM');
  if (
    outputSchema.additionalProperties === false &&
    !Object.hasOwn(outputSchema, 'patternProperties')
  ) {
    const allowed = Object.keys(record(outputSchema.properties ?? {}));
    if (names.some((name) => !allowed.includes(name))) throw failure('EK_JSON_TRANSFORM');
  }
  let nodes = 0,
    literalItems = 0;
  function expression(expr: JsonMappingExpr, depth: number): Evaluate {
    if (++nodes > source.limits.maxNodes || depth > source.limits.maxDepth)
      throw failure('EK_JSON_TRANSFORM');
    let evaluate: Evaluate;
    switch (expr.op) {
      case 'copy': {
        const parts = pointer(expr.path);
        evaluate = (value) => {
          const result = lookup(value, parts);
          if (result === missing && expr.required) throw failure('EK_JSON_TRANSFORM');
          return result;
        };
        break;
      }
      case 'literal': {
        const literal = snapshot(expr.value, {
          maxBytes: source.limits.maxOutputBytes,
          maxDepth: source.limits.maxDepth - depth,
          indentSpaces: 0,
        });
        const size = dataSize(literal);
        nodes += size.nodes - 1;
        literalItems += size.items;
        if (nodes > source.limits.maxNodes || literalItems > source.limits.maxArrayItems)
          throw failure('EK_JSON_TRANSFORM');
        evaluate = () => literal;
        break;
      }
      case 'coalesce': {
        const args = expr.args.map((arg) => expression(arg, depth + 1));
        evaluate = (value, budget) => {
          for (const arg of args) {
            const result = arg(value, budget);
            if (result !== missing && result !== null) return result;
          }
          return missing;
        };
        break;
      }
      case 'concat': {
        const args = expr.args.map((arg) => expression(arg, depth + 1)),
          separator = expr.separator ?? '';
        evaluate = (value, budget) => {
          const parts: string[] = [];
          let bytes = 0;
          for (const arg of args) {
            const result = arg(value, budget);
            if (typeof result !== 'string') throw failure('EK_JSON_TRANSFORM');
            bytes += Buffer.byteLength(result) + (parts.length ? Buffer.byteLength(separator) : 0);
            if (bytes > source.limits.maxOutputBytes) throw failure('EK_JSON_TRANSFORM');
            parts.push(result);
          }
          return parts.join(separator);
        };
        break;
      }
      case 'to-string': {
        const inner = expression(expr.value, depth + 1);
        evaluate = (value, budget) => {
          const result = inner(value, budget);
          if (typeof result === 'string') return result;
          if (
            typeof result === 'boolean' ||
            (typeof result === 'number' && Number.isFinite(result))
          )
            return JSON.stringify(result);
          throw failure('EK_JSON_TRANSFORM');
        };
        break;
      }
      case 'to-number': {
        const inner = expression(expr.value, depth + 1);
        evaluate = (value, budget) => {
          const result = inner(value, budget);
          if (typeof result === 'number') return result;
          if (
            typeof result !== 'string' ||
            !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(result)
          )
            throw failure('EK_JSON_TRANSFORM');
          const number = Number(result);
          if (
            !Number.isFinite(number) ||
            (Number.isInteger(number) && !Number.isSafeInteger(number)) ||
            (number === 0 && /[1-9]/.test(result.split(/[eE]/, 1)[0]!))
          )
            throw failure('EK_JSON_TRANSFORM');
          return number;
        };
        break;
      }
      case 'to-boolean': {
        const inner = expression(expr.value, depth + 1);
        evaluate = (value, budget) => {
          const result = inner(value, budget);
          if (typeof result === 'boolean') return result;
          if (result === 'true') return true;
          if (result === 'false') return false;
          throw failure('EK_JSON_TRANSFORM');
        };
        break;
      }
      case 'array-map': {
        const parts = pointer(expr.path),
          item = expression(expr.item, depth + 1);
        evaluate = (value, budget) => {
          const array = lookup(value, parts);
          if (
            !Array.isArray(array) ||
            array.length > expr.maxItems ||
            (budget.items += array.length) > source.limits.maxArrayItems
          )
            throw failure('EK_JSON_TRANSFORM');
          return array.map((value) => {
            const result = item(value, budget);
            if (result === missing) throw failure('EK_JSON_TRANSFORM');
            return result;
          });
        };
        break;
      }
    }
    return (value, budget) => {
      budget.check();
      if (++budget.nodes > source.limits.maxNodes) throw failure('EK_JSON_TRANSFORM');
      return evaluate(value, budget);
    };
  }
  return {
    source,
    fields: Object.entries(source.fields).map(
      ([name, expr]) => [name, expression(expr, 1)] as const,
    ),
  };
}
/** Compile only a finite owned deployment catalog; evaluation cannot load mappings or execute code. */
export class Mappings {
  readonly compiled = new Map<string, Compiled>();
  constructor(
    source: readonly JsonMappingV1[],
    readonly schemas: Schemas,
  ) {
    try {
      const captured = snapshot(source, metadataLimits);
      if (!Array.isArray(captured) || captured.length > 128) throw failure();
      for (const item of captured) {
        const mapping = item as JsonMappingV1;
        if (!mappingGrammar(mapping) || this.compiled.has(mapping.id)) throw failure();
        this.compiled.set(mapping.id, compile(mapping, schemas));
      }
    } catch (error) {
      mappingError(error);
    }
  }
  transform(value: unknown, id: string, check: () => void = () => undefined): unknown {
    try {
      check();
      if (typeof id !== 'string' || !this.compiled.has(id)) throw failure();
      const mapping = this.compiled.get(id)!,
        source = mapping.source;
      const input = snapshot(value, inputLimits, check),
        validated = this.schemas.validate(input, source.inputSchemaId);
      if (!validated.valid) throw failure();
      const budget: Budget = { nodes: 0, items: 0, check },
        output = Object.create(null) as Record<string, unknown>;
      for (const [name, evaluate] of mapping.fields) {
        const result = evaluate(validated.value, budget);
        if (result !== missing) output[name] = result;
      }
      const owned = snapshot(
        output,
        {
          maxBytes: source.limits.maxOutputBytes,
          maxDepth: source.limits.maxDepth,
          indentSpaces: 0,
        },
        check,
      );
      const result = this.schemas.validate(owned, source.outputSchemaId);
      const expanded = dataSize(owned, check);
      if (
        expanded.nodes - 1 > source.limits.maxNodes ||
        expanded.items > source.limits.maxArrayItems
      )
        throw failure('EK_JSON_TRANSFORM');
      check();
      if (!result.valid) throw failure();
      return result.value;
    } catch (error) {
      return mappingError(error);
    }
  }
}
