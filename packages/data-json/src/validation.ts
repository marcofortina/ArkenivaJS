// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import { types } from 'node:util';
const messages: Partial<Record<ErrorCode, string>> = {
  EK_JSON_PARSE: 'The JSON document is invalid or exceeds its resource policy',
  EK_JSON_SCHEMA: 'The JSON schema catalog or validation request is invalid',
  EK_JSON_TRANSFORM: 'The JSON mapping or transformation is invalid',
  EK_CONFIG_INVALID: 'The JSON settings are invalid',
  EK_TIMEOUT: 'The JSON operation exceeded its deadline',
  EK_ABORTED: 'The JSON operation was canceled',
  EK_RESOURCE_CLOSED: 'The JSON service is closed',
  EK_LIFECYCLE_STATE: 'The JSON application is not ready',
  EK_BACKEND_UNAVAILABLE: 'The JSON worker is unavailable',
};
export function failure(code: ErrorCode = 'EK_CONFIG_INVALID'): KitError {
  return new KitError({ code, message: messages[code] ?? 'The JSON operation failed' });
}
export function record(value: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw failure();
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (
      typeof key !== 'string' ||
      ['__proto__', 'prototype', 'constructor'].includes(key) ||
      (allowed && !allowed.includes(key))
    )
      throw failure();
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field || !('value' in field) || !field.enumerable) throw failure();
    result[key] = field.value;
  }
  return result;
}
export function integer(value: unknown, fallback: number, maximum: number, minimum = 1): number {
  if (value === undefined) return fallback;
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    throw failure();
  return value;
}
