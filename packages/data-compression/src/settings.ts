// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { CompressionLimits, DataCompressionPluginSettings, InputBytes } from './contracts.js';

export type FailureCode =
  | 'EK_CONFIG_INVALID'
  | 'EK_ARCHIVE_CORRUPT'
  | 'EK_ARCHIVE_LIMIT'
  | 'EK_ARCHIVE_PATH'
  | 'EK_ABORTED'
  | 'EK_TIMEOUT'
  | 'EK_RESOURCE_CLOSED';
const messages: Record<FailureCode, string> = {
  EK_CONFIG_INVALID: 'The compression configuration or operation options are invalid',
  EK_ARCHIVE_CORRUPT: 'The compressed input or archive is invalid',
  EK_ARCHIVE_LIMIT: 'The compression operation exceeds its resource policy',
  EK_ARCHIVE_PATH: 'The archive entry path or type is unsafe',
  EK_ABORTED: 'The compression operation was cancelled',
  EK_TIMEOUT: 'The compression operation deadline expired',
  EK_RESOURCE_CLOSED: 'The compression service is closed',
};
export const failure = (code: FailureCode) => new KitError({ code, message: messages[code] });
export function safeFailure(cause: unknown): KitError {
  return cause instanceof KitError && Object.hasOwn(messages, cause.code)
    ? failure(cause.code as FailureCode)
    : failure('EK_ARCHIVE_CORRUPT');
}
export function fields(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    )
      throw failure('EK_CONFIG_INVALID');
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== 'string' || !allowed.includes(key)) throw failure('EK_CONFIG_INVALID');
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
const ceilings: Required<CompressionLimits> = {
  maxCompressedBytes: 67108864,
  maxUncompressedBytes: 67108864,
  maxRatio: 10000,
  maxEntries: 4096,
  maxDepth: 64,
  maxEntryBytes: 67108864,
  maxCpuTimeMs: 120000,
};
const defaults: Required<CompressionLimits> = {
  maxCompressedBytes: 16777216,
  maxUncompressedBytes: 67108864,
  maxRatio: 100,
  maxEntries: 1000,
  maxDepth: 16,
  maxEntryBytes: 8388608,
  maxCpuTimeMs: 5000,
};
const keys = Object.keys(defaults) as (keyof CompressionLimits)[];
export interface Captured {
  readonly defaults: Required<CompressionLimits>;
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
}
function limits(
  input: Record<string, unknown>,
  base: Required<CompressionLimits>,
  maximum: Required<CompressionLimits>,
): Required<CompressionLimits> {
  return Object.freeze(
    Object.fromEntries(
      keys.map((key) => {
        const value = input[key] === undefined ? base[key] : input[key];
        if (key === 'maxRatio') {
          if (
            typeof value !== 'number' ||
            !Number.isFinite(value) ||
            value <= 0 ||
            value > maximum[key]
          )
            throw failure('EK_CONFIG_INVALID');
          return [key, value];
        }
        return [key, integer(value, maximum[key])];
      }),
    ) as Required<CompressionLimits>,
  );
}
export function capture(input: DataCompressionPluginSettings): Captured {
  const root = fields(input, ['defaults', 'policy']),
    policy = fields(root.policy, ['maxConcurrent', 'timeoutMs', 'maxInputBytes', 'maxOutputBytes']);
  return Object.freeze({
    defaults: limits(fields(root.defaults, keys), defaults, ceilings),
    maxConcurrent: integer(policy.maxConcurrent, 16),
    timeoutMs: integer(policy.timeoutMs, 120000),
    maxInputBytes:
      policy.maxInputBytes === undefined ? 16777216 : integer(policy.maxInputBytes, 67108864),
    maxOutputBytes:
      policy.maxOutputBytes === undefined ? 67108864 : integer(policy.maxOutputBytes, 67108864),
  });
}
export interface Policy extends Required<CompressionLimits> {
  readonly timeoutMs: number;
  readonly signal: AbortSignal | undefined;
}
export function operation(input: unknown, captured: Captured): Policy {
  const fields_ = fields(input === undefined ? {} : input, [...keys, 'signal', 'timeoutMs']);
  return Object.freeze({
    ...limits(fields_, captured.defaults, captured.defaults),
    timeoutMs:
      fields_.timeoutMs === undefined
        ? captured.timeoutMs
        : Math.min(captured.timeoutMs, integer(fields_.timeoutMs, 120000)),
    signal: fields_.signal === undefined ? undefined : captureAbortSignal(fields_.signal),
  });
}
const prototype = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(prototype, 'buffer')!.get!,
  offsetGetter = Object.getOwnPropertyDescriptor(prototype, 'byteOffset')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(prototype, 'byteLength')!.get!;
export function snapshot(input: unknown, maximum: number): Uint8Array {
  try {
    if (!types.isUint8Array(input)) throw failure('EK_ARCHIVE_CORRUPT');
    const buffer = bufferGetter.call(input) as ArrayBuffer,
      offset = offsetGetter.call(input) as number,
      length = lengthGetter.call(input) as number;
    if (types.isSharedArrayBuffer(buffer)) throw failure('EK_ARCHIVE_CORRUPT');
    if (length > maximum) throw failure('EK_ARCHIVE_LIMIT');
    return new Uint8Array(buffer, offset, length).slice();
  } catch (cause) {
    throw safeFailure(cause);
  }
}
export function source(input: InputBytes, maximum: number): InputBytes {
  if (types.isUint8Array(input)) return snapshot(input, maximum);
  try {
    if (!input || typeof input !== 'object' || typeof input[Symbol.asyncIterator] !== 'function')
      throw failure('EK_ARCHIVE_CORRUPT');
    return input;
  } catch {
    throw failure('EK_ARCHIVE_CORRUPT');
  }
}
/** Path policy operates on names decoded by the native ZIP parser, never ZIP bytes. */
export function path(
  input: unknown,
  depth: number,
): { name: string; key: string; directory: boolean } {
  if (
    typeof input !== 'string' ||
    !input ||
    input.length > 1024 ||
    Buffer.byteLength(input, 'utf8') > 1024 ||
    input !== toUSVString(input)
  )
    throw failure('EK_ARCHIVE_PATH');
  const name = input.normalize('NFC'),
    directory = name.endsWith('/'),
    clean = directory ? name.slice(0, -1) : name,
    parts = clean.split('/');
  if (
    parts.length > depth ||
    parts.some(
      (part) =>
        !part ||
        part === '.' ||
        part === '..' ||
        [...part].some(
          (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
        ) ||
        /[\\<>:"|?*]/u.test(part) ||
        /[. ]$/.test(part) ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part),
    )
  )
    throw failure('EK_ARCHIVE_PATH');
  return { name, directory, key: clean.normalize('NFKC').toUpperCase() };
}
export function register(names: Map<string, boolean>, entry: ReturnType<typeof path>): void {
  if (names.has(entry.key)) throw failure('EK_ARCHIVE_PATH');
  const parts = entry.key.split('/');
  for (let index = 1; index < parts.length; index++)
    if (names.get(parts.slice(0, index).join('/')) === false) throw failure('EK_ARCHIVE_PATH');
  if (!entry.directory && [...names.keys()].some((key) => key.startsWith(entry.key + '/')))
    throw failure('EK_ARCHIVE_PATH');
  names.set(entry.key, entry.directory);
}
