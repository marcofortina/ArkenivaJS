// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString, types } from 'node:util';
import { copyData, freezeData } from '@arkenivajs/core/support';

const invalid = () => new Error('The value is not bounded canonical JSON data');

/** Count native JSON string encoding before allocating its escaped representation. */
function stringBytes(value: string): number {
  if (toUSVString(value) !== value) throw invalid();
  let bytes = Buffer.byteLength(value) + 2;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code === 34 || code === 92) bytes++;
    else if (code < 32) bytes += [8, 9, 10, 12, 13].includes(code) ? 1 : 5;
  }
  return bytes;
}

/** Strict data-only copy with an exact UTF-8 encoding budget, finite depth and no getter execution. */
export function jsonSnapshot<T>(input: T, maxBytes: number): T {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw invalid();
  let nodes = 0,
    bytes = 0;
  const ancestors = new Set<object>();
  const add = (count: number) => {
    bytes += count;
    if (bytes > maxBytes) throw invalid();
  };
  const walk = (value: unknown, depth = 0): void => {
    if (++nodes > 4000000) throw invalid();
    if (value === null || typeof value === 'boolean') add(value === false ? 5 : 4);
    else if (typeof value === 'string') add(stringBytes(value));
    else if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw invalid();
      add(JSON.stringify(value).length);
    } else if (value && typeof value === 'object') {
      if (types.isProxy(value) || depth >= 64 || ancestors.has(value)) throw invalid();
      const array = Array.isArray(value);
      if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
        throw invalid();
      const names = Reflect.ownKeys(value);
      if (names.length > 4000000 || (array && names.length !== value.length + 1)) throw invalid();
      const keys = names.filter((name) => !array || name !== 'length');
      add(2 + Math.max(0, keys.length - 1));
      ancestors.add(value);
      for (const key of keys) {
        if (typeof key !== 'string') throw invalid();
        const field = Object.getOwnPropertyDescriptor(value, key);
        if (!field || !('value' in field) || !field.enumerable) throw invalid();
        if (array) {
          const index = Number(key);
          if (
            !Number.isSafeInteger(index) ||
            index < 0 ||
            index >= value.length ||
            String(index) !== key
          )
            throw invalid();
        } else add(stringBytes(key) + 1);
        walk(field.value, depth + 1);
      }
      ancestors.delete(value);
    } else throw invalid();
  };
  walk(input);
  return freezeData(copyData(input));
}
