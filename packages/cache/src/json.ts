// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { compileSchema, copyData } from '@arkenivajs/core/support';

const MAX_BYTES = 1_048_576;
const schema = {
  type: 'object',
  additionalProperties: false,
  required: ['schemaVersion', 'value'],
  properties: { schemaVersion: { const: 1 }, value: { $ref: '#/$defs/value' } },
  $defs: {
    value: {
      anyOf: [
        { type: 'null' },
        { type: 'boolean' },
        { type: 'number' },
        { type: 'string' },
        { type: 'array', maxItems: 10000, items: { $ref: '#/$defs/value' } },
        { type: 'object', maxProperties: 10000, additionalProperties: { $ref: '#/$defs/value' } },
      ],
    },
  },
};

/** Bound traversal before cloning/schema evaluation; custom accessors and serializers never execute. */
function bounded(value: unknown): void {
  const seen = new Set<object>();
  let nodes = 0,
    bytes = 0;
  const charge = (size: number) => {
    bytes += size;
    if (bytes > MAX_BYTES) throw new Error('Cache JSON exceeds its pre-serialization byte bound');
  };
  const visit = (entry: unknown, depth: number) => {
    charge(1);
    if (
      ++nodes > 50000 ||
      depth > 64 ||
      entry === undefined ||
      ['function', 'symbol', 'bigint'].includes(typeof entry) ||
      (typeof entry === 'number' && !Number.isFinite(entry))
    )
      throw new Error('Cache JSON exceeds its structural bound');
    if (typeof entry === 'string') charge(Buffer.byteLength(entry));
    if (!entry || typeof entry !== 'object') return;
    if (
      seen.has(entry) ||
      Object.getOwnPropertySymbols(entry).length ||
      (Array.isArray(entry) && entry.length > 10000)
    )
      throw new Error('Cache JSON requires bounded acyclic plain data');
    if (Array.isArray(entry))
      for (let index = 0; index < entry.length; index++)
        if (!Object.hasOwn(entry, index)) throw new Error('Cache JSON arrays must be dense');
    const keys = Object.getOwnPropertyNames(entry);
    if (keys.length > 10001) throw new Error('Cache JSON has too many fields');
    seen.add(entry);
    try {
      for (const key of keys) {
        if (Array.isArray(entry) && key === 'length') continue;
        if (!Array.isArray(entry)) charge(Buffer.byteLength(key));
        if (Array.isArray(entry) && !/^(0|[1-9]\d*)(?![\s\S])/.test(key))
          throw new Error('Cache JSON arrays cannot contain named properties');
        const descriptor = Object.getOwnPropertyDescriptor(entry, key);
        if (!descriptor || !('value' in descriptor))
          throw new Error('Cache JSON cannot execute an accessor');
        visit(descriptor.value, depth + 1);
      }
    } finally {
      seen.delete(entry);
    }
  };
  visit(value, 0);
}

/** Every stored value uses the same checked, versioned JSON envelope; decode never instantiates a class. */
export function cacheSerializer() {
  const validate = compileSchema(schema);
  return {
    encode(value: unknown): string {
      try {
        const envelope = { schemaVersion: 1, value };
        bounded(envelope);
        const captured = copyData(envelope);
        if (!validate(captured)) throw new Error('Cache value does not satisfy its JSON schema');
        const text = JSON.stringify(captured);
        if (Buffer.byteLength(text) > MAX_BYTES)
          throw new Error('Cache JSON exceeds its byte bound');
        return text;
      } catch (cause) {
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Cache value requires bounded schema-checked JSON data',
          cause,
        });
      }
    },
    decode(text: string): unknown {
      try {
        if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES)
          throw new Error('Stored cache JSON exceeds its byte bound');
        const envelope: unknown = JSON.parse(text);
        bounded(envelope);
        const captured = copyData(envelope);
        if (!validate(captured)) throw new Error('Stored cache JSON does not satisfy its schema');
        return (captured as { value: unknown }).value;
      } catch (cause) {
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Stored cache value is invalid',
          cause,
        });
      }
    },
  };
}
