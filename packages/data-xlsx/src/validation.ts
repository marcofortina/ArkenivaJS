// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export const failure = (code: ErrorCode = 'EK_XLSX_FORMAT', unknown = false) =>
  new KitError({
    code,
    message: 'The workbook operation could not complete',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
export function fields(input: unknown, names?: readonly string[]): Record<string, unknown> {
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    )
      throw failure();
    const keys = Reflect.ownKeys(input),
      result: Record<string, unknown> = Object.create(null);
    if (keys.length > 32) throw failure();
    for (const key of keys) {
      const field = Object.getOwnPropertyDescriptor(input, key)!;
      if (
        typeof key !== 'string' ||
        (names && !names.includes(key)) ||
        ['__proto__', 'constructor', 'prototype'].includes(key) ||
        !('value' in field)
      )
        throw failure();
      result[key] = field.value;
    }
    return result;
  } catch {
    throw failure();
  }
}
export function integer(input: unknown, maximum: number, minimum = 1): number {
  if (
    typeof input !== 'number' ||
    !Number.isSafeInteger(input) ||
    input < minimum ||
    input > maximum
  )
    throw failure('EK_XLSX_LIMIT');
  return input;
}
export function text(input: unknown, maximum: number, empty = false): string {
  if (
    typeof input !== 'string' ||
    (!empty && !input.length) ||
    input.length > maximum ||
    input.includes('\0') ||
    Buffer.byteLength(input) > maximum
  )
    throw failure();
  const bytes = Buffer.from(input);
  try {
    if (bytes.toString('utf8') !== input) throw failure();
    return input;
  } finally {
    bytes.fill(0);
  }
}
export function array(input: unknown, maximum = 16384): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure('EK_XLSX_LIMIT');
  return Array.from({ length: input.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(input, String(index));
    if (!field || !('value' in field)) throw failure();
    return field.value as unknown;
  });
}
export function bytes(input: unknown, maximum: number): Buffer {
  const prototype = Object.getPrototypeOf(Uint8Array.prototype),
    size = Object.getOwnPropertyDescriptor(prototype, 'byteLength')!.get!,
    buffer = Object.getOwnPropertyDescriptor(prototype, 'buffer')!.get!;
  if (!(input instanceof Uint8Array) || buffer.call(input) instanceof SharedArrayBuffer)
    throw failure();
  const length = size.call(input) as number;
  if (length > maximum) throw failure('EK_XLSX_LIMIT');
  const copy = Buffer.alloc(length);
  Uint8Array.prototype.set.call(copy, input);
  return copy;
}
export function sheetName(input: unknown): string {
  const name = text(input, 124);
  if (
    name.length > 31 ||
    /[\\/*?:[\]]/.test(name) ||
    name.startsWith("'") ||
    name.endsWith("'") ||
    name.toLowerCase() === 'history' ||
    [...name].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  return name;
}
