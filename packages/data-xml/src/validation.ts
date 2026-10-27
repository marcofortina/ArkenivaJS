// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
const messages: Partial<Record<ErrorCode, string>> = {
  EK_CONFIG_INVALID: 'The XML configuration is invalid',
  EK_XML_SECURITY: 'The XML security policy rejected the document',
  EK_XML_PARSE: 'The XML document could not be processed',
  EK_XML_SCHEMA: 'The XML schema could not be processed',
  EK_UNSUPPORTED_CAPABILITY: 'The installed XML backend does not support this operation',
  EK_ABORTED: 'The XML operation was aborted',
  EK_TIMEOUT: 'The XML operation deadline expired',
  EK_RESOURCE_CLOSED: 'The XML service is closed',
  EK_LIFECYCLE_STATE: 'The XML service is not ready',
};
export const failure = (code: ErrorCode = 'EK_CONFIG_INVALID') =>
  new KitError({
    code,
    message: messages[code] ?? 'The XML operation failed',
    retryable: false,
  });
export function fields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(input)) {
    if (
      typeof key !== 'string' ||
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      (allowed && !allowed.includes(key))
    )
      throw failure();
    const property = Object.getOwnPropertyDescriptor(input, key)!;
    if (!property.enumerable || !Object.hasOwn(property, 'value')) throw failure();
    result[key] = property.value;
  }
  return result;
}
export function integer(value: unknown, maximum: number) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > maximum)
    throw failure();
  return value;
}
