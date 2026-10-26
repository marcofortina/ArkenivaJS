// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString } from 'node:util';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { CsvOptions, DataCsvPluginSettings } from './types.js';

export type CsvFailure =
  | 'EK_CSV_PARSE'
  | 'EK_CSV_LIMIT'
  | 'EK_CSV_SCHEMA'
  | 'EK_CONFIG_INVALID'
  | 'EK_ABORTED'
  | 'EK_TIMEOUT'
  | 'EK_RESOURCE_CLOSED';
export const failure = (code: CsvFailure): KitError =>
  new KitError({
    code,
    message:
      code === 'EK_CSV_LIMIT'
        ? 'The CSV operation exceeds its resource limits'
        : code === 'EK_CSV_SCHEMA'
          ? 'The CSV record or header does not satisfy its schema'
          : code === 'EK_CONFIG_INVALID'
            ? 'The CSV configuration is invalid'
            : code === 'EK_ABORTED'
              ? 'The CSV operation was cancelled'
              : code === 'EK_TIMEOUT'
                ? 'The CSV operation deadline expired'
                : code === 'EK_RESOURCE_CLOSED'
                  ? 'The CSV service is closed'
                  : 'The CSV input or encoding is invalid',
  });
export function fields(
  input: unknown,
  allowed: readonly PropertyKey[],
): Record<PropertyKey, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
  )
    throw failure('EK_CONFIG_INVALID');
  const result: Record<PropertyKey, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    if (!allowed.includes(key)) throw failure('EK_CONFIG_INVALID');
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
    result[key] = descriptor.value;
  }
  return result;
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
function flag(value: unknown): boolean {
  if (typeof value !== 'boolean') throw failure('EK_CONFIG_INVALID');
  return value;
}
function scalar(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length > 2 ||
    Array.from(value).length !== 1 ||
    toUSVString(value) !== value ||
    value === '\r' ||
    value === '\n'
  )
    throw failure('EK_CONFIG_INVALID');
  return value;
}
const optionKeys = [
  'delimiter',
  'quote',
  'escape',
  'hasHeader',
  'maxColumns',
  'maxRecordBytes',
  'maxRows',
  'maxTotalBytes',
  'encoding',
  'inputBom',
  'outputBom',
  'escapeSpreadsheetFormulas',
];
const defaults = Object.freeze({
  delimiter: ',',
  quote: '"',
  escape: '"',
  hasHeader: false,
  maxColumns: 256,
  maxRecordBytes: 1048576,
  maxRows: 100000,
  maxTotalBytes: 67108864,
  encoding: 'utf-8' as const,
  inputBom: 'auto' as const,
  outputBom: false,
  escapeSpreadsheetFormulas: false,
});
export function options(
  input: unknown,
  base: Required<CsvOptions> = defaults,
): Required<CsvOptions> {
  const supplied = fields(input, optionKeys),
    pick = (key: keyof CsvOptions) => (supplied[key] === undefined ? base[key] : supplied[key]);
  const delimiter = scalar(pick('delimiter')),
    quote = scalar(pick('quote')),
    escape =
      supplied.escape === undefined && supplied.quote !== undefined
        ? quote
        : scalar(pick('escape'));
  if (
    delimiter === quote ||
    delimiter === escape ||
    pick('encoding') !== 'utf-8' ||
    !['auto', 'require', 'forbid'].includes(pick('inputBom') as string)
  )
    throw failure('EK_CONFIG_INVALID');
  return Object.freeze({
    delimiter,
    quote,
    escape,
    encoding: 'utf-8',
    inputBom: pick('inputBom') as 'auto' | 'require' | 'forbid',
    hasHeader: flag(pick('hasHeader')),
    outputBom: flag(pick('outputBom')),
    escapeSpreadsheetFormulas: flag(pick('escapeSpreadsheetFormulas')),
    maxColumns: integer(pick('maxColumns'), 10000),
    maxRecordBytes: integer(pick('maxRecordBytes'), 16777216),
    maxRows: integer(pick('maxRows'), 10000000),
    maxTotalBytes: integer(pick('maxTotalBytes'), 1073741824),
  });
}
export function capture(input: DataCsvPluginSettings) {
  try {
    const setting = fields(input, ['defaults', 'policy']),
      policy = fields(setting.policy, [
        'maxConcurrent',
        'timeoutMs',
        'maxInputBytes',
        'maxOutputBytes',
      ]);
    return Object.freeze({
      defaults: options(setting.defaults),
      maxConcurrent: integer(policy.maxConcurrent, 1024),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes: integer(
        policy.maxInputBytes === undefined ? 1073741824 : policy.maxInputBytes,
        1073741824,
      ),
      maxOutputBytes: integer(
        policy.maxOutputBytes === undefined ? 1073741824 : policy.maxOutputBytes,
        1073741824,
      ),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Captured = ReturnType<typeof capture>;
export function callOptions(input: (CsvOptions & OperationOptions) | undefined, setting: Captured) {
  try {
    const supplied = fields(input === undefined ? {} : input, [
      ...optionKeys,
      'signal',
      'timeoutMs',
    ]);
    const { signal, timeoutMs, ...codec } = supplied;
    return {
      codec: options(codec, setting.defaults),
      signal: signal === undefined ? undefined : captureAbortSignal(signal),
      timeoutMs:
        timeoutMs === undefined
          ? setting.timeoutMs
          : Math.min(integer(timeoutMs, 120000), setting.timeoutMs),
    };
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export class Scope {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly codec: Required<CsvOptions>;
  #timer: NodeJS.Timeout;
  #deadline: number;
  #expired = false;
  #ended = false;
  #settled = true;
  #input = 0;
  #output = 0;
  constructor(
    readonly setting: Captured,
    input: ReturnType<typeof callOptions>,
    readonly release: () => void,
  ) {
    this.codec = input.codec;
    try {
      this.signal =
        input.signal === undefined
          ? this.controller.signal
          : AbortSignal.any([this.controller.signal, input.signal]);
    } catch {
      throw failure('EK_CONFIG_INVALID');
    }
    if (this.signal.aborted) throw failure('EK_ABORTED');
    this.#deadline = performance.now() + input.timeoutMs;
    this.#timer = setTimeout(() => {
      this.#expired = true;
      this.stop();
    }, input.timeoutMs);
    this.signal.addEventListener(
      'abort',
      () => {
        this.#ended = true;
        clearTimeout(this.#timer);
        this.#release();
      },
      { once: true },
    );
  }
  #release() {
    if (this.#ended && this.#settled) this.release();
  }
  check() {
    if (!this.#expired && performance.now() >= this.#deadline) {
      this.#expired = true;
      this.stop();
    }
    if (this.signal.aborted) throw failure(this.#expired ? 'EK_TIMEOUT' : 'EK_ABORTED');
  }
  input(size: number) {
    this.check();
    this.#input += size;
    if (this.#input > Math.min(this.setting.maxInputBytes, this.codec.maxTotalBytes))
      throw failure('EK_CSV_LIMIT');
  }
  output(size: number) {
    this.check();
    this.#output += size;
    if (this.#output > Math.min(this.setting.maxOutputBytes, this.codec.maxTotalBytes))
      throw failure('EK_CSV_LIMIT');
  }
  watch(promise: Promise<void>) {
    this.#settled = false;
    const settle = () => {
      this.#settled = true;
      this.#release();
    };
    // A source ignoring cancellation retains admission until native pipeline cleanup settles.
    promise.then(settle, settle);
  }
  stop() {
    this.#ended = true;
    clearTimeout(this.#timer);
    this.controller.abort();
    this.#release();
  }
  error(cause: unknown): KitError {
    if (this.signal.aborted) return failure(this.#expired ? 'EK_TIMEOUT' : 'EK_ABORTED');
    try {
      const code =
        cause && typeof cause === 'object'
          ? Object.getOwnPropertyDescriptor(cause, 'code')?.value
          : undefined;
      if (code === 'EK_CSV_LIMIT' || code === 'CSV_MAX_RECORD_SIZE') return failure('EK_CSV_LIMIT');
      if (
        code === 'EK_CSV_SCHEMA' ||
        code === 'EK_CONFIG_INVALID' ||
        code === 'CSV_RECORD_INCONSISTENT_FIELDS_LENGTH'
      )
        return failure('EK_CSV_SCHEMA');
    } catch {
      /* Native and source diagnostics never enter public errors. */
    }
    return failure('EK_CSV_PARSE');
  }
}
