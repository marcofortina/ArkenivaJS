// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { failure } from './validation.js';

/** Snapshot portable application values before native serialization can access user-controlled objects. */
export function input(value: unknown, maximum: number): unknown {
  let bytes = 0,
    nodes = 0;
  const active = new Set<object>();
  function visit(value: unknown, depth: number): unknown {
    if (++nodes > 10000 || depth > 32) throw failure('EK_SOAP_SCHEMA');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))
        throw failure('EK_SOAP_SCHEMA');
      bytes += 32;
      return value;
    }
    if (typeof value === 'string') {
      if (value.length > maximum || toUSVString(value) !== value) throw failure('EK_SOAP_SCHEMA');
      bytes += Buffer.byteLength(value);
      if (bytes > maximum) throw failure('EK_SOAP_SCHEMA');
      return value;
    }
    if (!value || typeof value !== 'object' || types.isProxy(value))
      throw failure('EK_SOAP_SCHEMA');
    if (types.isDate(value)) {
      const time = Date.prototype.getTime.call(value);
      if (!Number.isFinite(time)) throw failure('EK_SOAP_SCHEMA');
      return new Date(time);
    }
    if (Buffer.isBuffer(value)) {
      throw failure('EK_UNSUPPORTED_CAPABILITY');
    }
    if (
      active.has(value) ||
      (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    )
      throw failure('EK_SOAP_SCHEMA');
    active.add(value);
    try {
      const array = Array.isArray(value),
        output: unknown[] | Record<string, unknown> = array ? [] : Object.create(null);
      const keys = Reflect.ownKeys(value);
      if (keys.length > 10000 || (array && keys.length !== value.length + 1))
        throw failure('EK_SOAP_SCHEMA');
      for (const key of keys) {
        if (array && key === 'length') continue;
        if (
          array &&
          (typeof key !== 'string' ||
            !/^(0|[1-9][0-9]*)$/.test(key) ||
            Number(key) >= (value as unknown[]).length)
        )
          throw failure('EK_SOAP_SCHEMA');
        if (
          typeof key !== 'string' ||
          ['__proto__', 'constructor', 'prototype', '$xml', '$value', 'attributes'].includes(key) ||
          (!array && !/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(key))
        )
          throw failure('EK_SOAP_SCHEMA');
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
          throw failure('EK_SOAP_SCHEMA');
        bytes += Buffer.byteLength(key) + 8;
        if (bytes > maximum) throw failure('EK_SOAP_SCHEMA');
        const owned = visit(descriptor.value, depth + 1);
        if (array) (output as unknown[]).push(owned);
        else (output as Record<string, unknown>)[key] = owned;
      }
      return output;
    } finally {
      active.delete(value);
    }
  }
  return visit(value, 0);
}
