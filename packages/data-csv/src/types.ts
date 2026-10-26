// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** Bounded bytes or a one-shot asynchronous byte source. */
export type InputBytes = Uint8Array | AsyncIterable<Uint8Array>;
/** Backpressured output; consume fully or explicitly return/cancel the iterator. */
export type OutputBytes = AsyncIterable<Uint8Array>;
/** Safe validation metadata never contains the rejected record. */
export interface SchemaValidationError {
  readonly path: string;
  readonly code: string;
  readonly message: string;
}
/** Tagged result; rejected records have no usable value. */
export type ValidationResult<T> =
  | Readonly<{ valid: true; value: T; errors: readonly [] }>
  | Readonly<{ valid: false; errors: readonly SchemaValidationError[] }>;
/** Text-only CSV data record; rowIndex is one-based and excludes a parsed header. */
export interface CsvRecord {
  readonly fields: readonly string[];
  readonly rowIndex: number;
  readonly columns?: Readonly<Record<string, string>>;
}
/** Explicit encoding, quoting, BOM and finite document/record limits. */
export interface CsvOptions {
  readonly delimiter?: string;
  readonly quote?: string;
  readonly escape?: string;
  readonly hasHeader?: boolean;
  readonly maxColumns?: number;
  readonly maxRecordBytes?: number;
  readonly maxRows?: number;
  readonly maxTotalBytes?: number;
  readonly encoding?: 'utf-8';
  readonly inputBom?: 'auto' | 'require' | 'forbid';
  readonly outputBom?: boolean;
  readonly escapeSpreadsheetFormulas?: boolean;
}
/** Positive operation deadlines, finite admission and optional hard byte caps. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Defaults apply to each operation; runtime policy caps remain authoritative. */
export interface DataCsvPluginSettings {
  readonly defaults: CsvOptions;
  readonly policy: BoundedRuntimePolicy;
}
/** Native codecs with explicit bounds; no field type coercion or filesystem extraction. */
export interface CsvService {
  /** Stream validated UTF-8 records using the approved native parser. */
  parse(input: InputBytes, options?: CsvOptions & OperationOptions): AsyncIterable<CsvRecord>;
  /** Encode one bounded record at a time using the approved native writer. */
  stringify(
    rows: AsyncIterable<CsvRecord> | Iterable<CsvRecord>,
    options?: CsvOptions & OperationOptions,
  ): OutputBytes;
  /** Check bounded row shape and exact declared columns without coercion. */
  validate(
    row: CsvRecord,
    schema: Readonly<{ columns: readonly string[] }>,
  ): ValidationResult<CsvRecord>;
}
