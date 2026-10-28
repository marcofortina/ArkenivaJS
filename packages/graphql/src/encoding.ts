// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { failure } from './policy.js';

/** Keep Node's JSON encoder while refusing oversized data before its output buffer grows. */
export function encodeResult(value: unknown, maximum: number): string {
  let bytes = 0,
    root = true;
  const entries = new WeakMap<object, number>();
  const add = (amount: number) => {
    bytes += amount;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
  };
  const quoted = (text: string) => {
    // Reject a large string before JSON.stringify can allocate its escaped representation.
    if (Buffer.byteLength(text) > maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
    return Buffer.byteLength(JSON.stringify(text));
  };
  try {
    const encoded = JSON.stringify(value, function (this: object, key: string, item: unknown) {
      const first = root;
      root = false;
      const array = Array.isArray(this);
      const omitted = item === undefined || typeof item === 'function' || typeof item === 'symbol';
      if (omitted && !array) return undefined;
      if (!first) {
        const count = entries.get(this) ?? 0;
        if (count) add(1);
        entries.set(this, count + 1);
        if (!array) add(quoted(key) + 1);
      }
      if (omitted || item === null) add(4);
      else if (typeof item === 'string') add(quoted(item));
      else if (typeof item === 'number' || typeof item === 'boolean')
        add(
          String(Number.isNaN(item) || item === Infinity || item === -Infinity ? null : item)
            .length,
        );
      else if (typeof item === 'object') {
        if (
          types.isProxy(item) ||
          (!Array.isArray(item) && ![null, Object.prototype].includes(Object.getPrototypeOf(item)))
        )
          throw failure('EK_GQL_EXECUTION');
        add(2);
        entries.set(item, 0);
      } else throw failure('EK_GQL_EXECUTION');
      return item;
    });
    if (encoded === undefined) throw failure('EK_GQL_EXECUTION');
    if (Buffer.byteLength(encoded) > maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
    return encoded;
  } catch (error) {
    throw failure(
      error instanceof KitError && error.code === 'EK_GQL_RESPONSE_LIMIT'
        ? 'EK_GQL_RESPONSE_LIMIT'
        : 'EK_GQL_EXECUTION',
    );
  }
}
