// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { types } from 'node:util';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { CodeOptions, DataCodesPluginSettings } from './contracts.js';

export type FailureCode =
  | 'EK_CONFIG_INVALID'
  | 'EK_CODE_UNSUPPORTED'
  | 'EK_CODE_DECODE'
  | 'EK_CODE_LIMIT'
  | 'EK_TIMEOUT'
  | 'EK_ABORTED'
  | 'EK_RESOURCE_CLOSED';
const messages: Record<FailureCode, string> = {
  EK_CONFIG_INVALID: 'The code service configuration or operation options are invalid',
  EK_CODE_UNSUPPORTED: 'The code symbology or image format is unsupported',
  EK_CODE_DECODE: 'The code or image cannot be processed',
  EK_CODE_LIMIT: 'The code service resource policy was exceeded',
  EK_TIMEOUT: 'The code operation deadline expired',
  EK_ABORTED: 'The code operation was cancelled',
  EK_RESOURCE_CLOSED: 'The code service is unavailable or closed',
};
export const failure = (code: FailureCode) => new KitError({ code, message: messages[code] });
const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!,
  offsetGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
/** Inspect native byte storage without reading caller-owned accessors or iterators. */
export function imageSnapshot(input: unknown, maximum: number): Uint8Array {
  if (!types.isUint8Array(input)) throw failure('EK_CODE_DECODE');
  try {
    const buffer = bufferGetter.call(input) as ArrayBuffer,
      offset = offsetGetter.call(input) as number,
      length = lengthGetter.call(input) as number;
    if (types.isSharedArrayBuffer(buffer)) throw failure('EK_CODE_DECODE');
    if (length < 1 || length > maximum) throw failure('EK_CODE_LIMIT');
    return new Uint8Array(buffer, offset, length).slice();
  } catch (cause) {
    if (cause instanceof KitError) throw cause;
    throw failure('EK_CODE_DECODE');
  }
}
export function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  try {
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    )
      throw failure('EK_CONFIG_INVALID');
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || !allowed.includes(key)) throw failure('EK_CONFIG_INVALID');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export function integer(value: unknown, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
export interface Captured {
  readonly defaults: Required<CodeOptions>;
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
}
export function options(input: unknown, defaults: Required<CodeOptions>, decode = false) {
  const value = fields(input === undefined ? {} : input, [
    'format',
    'widthPixels',
    'maxPixels',
    'errorCorrection',
    ...(decode ? ['signal', 'timeoutMs'] : []),
  ]);
  const format = value.format === undefined ? defaults.format : value.format,
    errorCorrection =
      value.errorCorrection === undefined ? defaults.errorCorrection : value.errorCorrection;
  if (
    (format !== 'png' && format !== 'svg') ||
    !['L', 'M', 'Q', 'H'].includes(errorCorrection as string)
  )
    throw failure('EK_CONFIG_INVALID');
  const maxPixels =
    value.maxPixels === undefined
      ? defaults.maxPixels
      : integer(value.maxPixels, 1, defaults.maxPixels);
  return {
    format: format as 'png' | 'svg',
    errorCorrection: errorCorrection as Required<CodeOptions>['errorCorrection'],
    widthPixels:
      value.widthPixels === undefined
        ? defaults.widthPixels
        : integer(value.widthPixels, 32, defaults.widthPixels),
    maxPixels,
    timeoutMs: value.timeoutMs,
    signal: value.signal === undefined ? undefined : captureAbortSignal(value.signal),
  };
}
export function capture(input: DataCodesPluginSettings): Captured {
  const root = fields(input, ['defaults', 'policy']),
    policy = fields(root.policy, ['maxConcurrent', 'timeoutMs', 'maxInputBytes', 'maxOutputBytes']),
    defaults = options(root.defaults, {
      format: 'png',
      widthPixels: 4096,
      maxPixels: 16777216,
      errorCorrection: 'M',
    });
  // Deployment bounds may be larger than the implicit defaults, within fixed process envelopes.
  const raw = fields(root.defaults, ['format', 'widthPixels', 'maxPixels', 'errorCorrection']);
  return Object.freeze({
    defaults: Object.freeze({
      format: defaults.format,
      errorCorrection: defaults.errorCorrection,
      widthPixels: raw.widthPixels === undefined ? 512 : integer(raw.widthPixels, 32, 4096),
      maxPixels: raw.maxPixels === undefined ? 4194304 : integer(raw.maxPixels, 1, 16777216),
    }),
    maxConcurrent: integer(policy.maxConcurrent, 1, 4),
    timeoutMs: integer(policy.timeoutMs, 1, 120000),
    maxInputBytes:
      policy.maxInputBytes === undefined ? 1048576 : integer(policy.maxInputBytes, 1, 8388608),
    maxOutputBytes:
      policy.maxOutputBytes === undefined ? 8388608 : integer(policy.maxOutputBytes, 1, 16777216),
  });
}
