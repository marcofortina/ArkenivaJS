// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { PassThrough, Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { toUSVString } from 'node:util';
import { setImmediate as immediate } from 'node:timers/promises';
import { parse as nativeParse } from 'csv-parse';
import { stringify as nativeStringify } from 'csv-stringify/sync';
import type { Plugin, OperationOptions } from '@arkenivajs/core';
import { capture, callOptions, fields, failure, Scope } from './runtime.js';
import type { Captured } from './runtime.js';
import type {
  CsvOptions,
  CsvRecord,
  CsvService,
  DataCsvPluginSettings,
  InputBytes,
  ValidationResult,
} from './types.js';
export type * from './types.js';

const order: unique symbol = Symbol('arkenivajs.csv.header-order');
const bom = Buffer.from([239, 187, 191]);
function strings(input: unknown, maximum: number, maximumBytes: number): readonly string[] {
  if (
    !Array.isArray(input) ||
    input.length < 1 ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure('EK_CSV_SCHEMA');
  if (input.length > maximum) throw failure('EK_CSV_LIMIT');
  let bytes = 0;
  const result: string[] = [];
  for (let index = 0; index < input.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string')
      throw failure('EK_CSV_SCHEMA');
    if (descriptor.value.length > maximumBytes) throw failure('EK_CSV_LIMIT');
    if (toUSVString(descriptor.value) !== descriptor.value) throw failure('EK_CSV_SCHEMA');
    bytes += Buffer.byteLength(descriptor.value);
    if (bytes > maximumBytes) throw failure('EK_CSV_LIMIT');
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}
function headers(input: unknown, codec: Required<CsvOptions>) {
  const names = strings(input, codec.maxColumns, codec.maxRecordBytes);
  if (
    new Set(names).size !== names.length ||
    names.some((name) => ['__proto__', 'constructor', 'prototype'].includes(name))
  )
    throw failure('EK_CSV_SCHEMA');
  return names;
}
function record(values: readonly string[], rowIndex: number, names?: readonly string[]): CsvRecord {
  const columns: Record<string, string> = Object.create(null);
  if (names)
    names.forEach((name, index) =>
      Object.defineProperty(columns, name, { value: values[index], enumerable: true }),
    );
  const result: CsvRecord = {
    fields: values,
    rowIndex,
    ...(names ? { columns: Object.freeze(columns) } : {}),
  };
  if (names) Object.defineProperty(result, order, { value: names });
  return Object.freeze(result);
}
function snapshot(
  input: unknown,
  codec: Required<CsvOptions>,
): { row: CsvRecord; names?: readonly string[] } {
  const supplied = fields(input, ['fields', 'rowIndex', 'columns', order]);
  if (!Number.isSafeInteger(supplied.rowIndex) || (supplied.rowIndex as number) < 1)
    throw failure('EK_CSV_SCHEMA');
  const values = strings(supplied.fields, codec.maxColumns, codec.maxRecordBytes);
  let names: readonly string[] | undefined;
  if (supplied.columns !== undefined) {
    if (
      !supplied.columns ||
      typeof supplied.columns !== 'object' ||
      Array.isArray(supplied.columns)
    )
      throw failure('EK_CSV_SCHEMA');
    names = headers(
      supplied[order] === undefined ? Reflect.ownKeys(supplied.columns) : supplied[order],
      codec,
    );
    const columns = fields(supplied.columns, names);
    if (
      Object.keys(columns).length !== names.length ||
      names.length !== values.length ||
      names.some((name, index) => columns[name] !== values[index])
    )
      throw failure('EK_CSV_SCHEMA');
  } else if (supplied[order] !== undefined) throw failure('EK_CSV_SCHEMA');
  return { row: record(values, supplied.rowIndex as number, names), ...(names ? { names } : {}) };
}
async function* chunks(input: InputBytes, scope: Scope): AsyncIterable<Buffer> {
  let segments = 0;
  if (input instanceof Uint8Array) {
    for (let start = 0; start < input.byteLength; start += 16384) {
      scope.check();
      const chunk = Buffer.from(input.subarray(start, start + 16384));
      scope.input(chunk.length);
      yield chunk;
      if (++segments % 64 === 0) await immediate(undefined, { signal: scope.signal });
    }
  } else {
    if (!input || typeof input[Symbol.asyncIterator] !== 'function') throw failure('EK_CSV_PARSE');
    for await (const part of input) {
      scope.check();
      if (!(part instanceof Uint8Array)) throw failure('EK_CSV_PARSE');
      if (!part.byteLength && ++segments % 64 === 0)
        await immediate(undefined, { signal: scope.signal });
      for (let start = 0; start < part.byteLength; start += 16384) {
        scope.check();
        const chunk = Buffer.from(part.subarray(start, start + 16384));
        scope.input(chunk.length);
        yield chunk;
        if (++segments % 64 === 0) await immediate(undefined, { signal: scope.signal });
      }
    }
  }
}
async function* inputBytes(input: InputBytes, scope: Scope): AsyncIterable<Buffer> {
  const decoder = new TextDecoder('utf-8', { fatal: true }),
    codec = scope.codec;
  let prefix = Buffer.alloc(0),
    started = false;
  const verify = () => {
    const present = prefix.subarray(0, 3).equals(bom);
    if (
      (codec.inputBom === 'require' && !present) ||
      (codec.inputBom === 'forbid' && present) ||
      (present && prefix.subarray(3, 6).equals(bom))
    )
      throw failure('EK_CSV_PARSE');
  };
  for await (let chunk of chunks(input, scope)) {
    if (!started) {
      const take = Math.min(6 - prefix.length, chunk.length);
      prefix = Buffer.concat([prefix, chunk.subarray(0, take)]);
      chunk = chunk.subarray(take);
      if (prefix.length < 6) continue;
      verify();
      decoder.decode(prefix, { stream: true });
      yield prefix;
      started = true;
    }
    if (chunk.length) {
      decoder.decode(chunk, { stream: true });
      yield chunk;
    }
  }
  if (!started) {
    verify();
    decoder.decode(prefix, { stream: true });
    if (prefix.length) yield prefix;
  }
  decoder.decode();
}
function service(setting: Captured, ready: () => void) {
  const scopes = new Set<Scope>();
  const begin = (options?: CsvOptions & OperationOptions) => {
    ready();
    const call = callOptions(options, setting);
    if (scopes.size >= setting.maxConcurrent) throw failure('EK_CSV_LIMIT');
    const scope = new Scope(setting, call, () => scopes.delete(scope));
    scopes.add(scope);
    return scope;
  };
  const api: CsvService = Object.freeze({
    async *parse(input: InputBytes, options?: CsvOptions & OperationOptions) {
      const scope = begin(options),
        codec = scope.codec;
      let names: readonly string[] | undefined,
        count = 0,
        emitted = 0,
        previousBytes = 0;
      let source: Readable | undefined, parser: ReturnType<typeof nativeParse> | undefined;
      try {
        parser = nativeParse({
          delimiter: codec.delimiter,
          quote: codec.quote,
          escape: codec.escape,
          encoding: 'utf8',
          bom: true,
          cast(value: string, context: { column: string | number; bytes: number }) {
            // Upstream field boundaries enforce caps before a delimiter-only record can grow.
            scope.check();
            if (
              (typeof context.column === 'number' && context.column >= codec.maxColumns) ||
              context.bytes - previousBytes > codec.maxRecordBytes
            )
              throw failure('EK_CSV_LIMIT');
            return value;
          },
          cast_date: false,
          max_record_size: codec.maxRecordBytes,
          relax_column_count: false,
          skip_empty_lines: false,
          record_delimiter: ['\r\n', '\n', '\r'],
          on_record(native: string[], info: { bytes: number }) {
            scope.check();
            const rawBytes = info.bytes - previousBytes;
            previousBytes = info.bytes;
            if (rawBytes > codec.maxRecordBytes) throw failure('EK_CSV_LIMIT');
            if (native.length > codec.maxColumns) throw failure('EK_CSV_LIMIT');
            if (codec.hasHeader && names === undefined) {
              names = headers(native, codec);
              return null;
            }
            if (++count > codec.maxRows) throw failure('EK_CSV_LIMIT');
            const values = strings(native, codec.maxColumns, codec.maxRecordBytes);
            scope.output(values.reduce((bytes, value) => bytes + Buffer.byteLength(value), 0));
            return native;
          },
        });
        source = Readable.from(inputBytes(input, scope), {
          objectMode: false,
          highWaterMark: 16384,
        });
        scope.watch(pipeline(source, parser, { signal: scope.signal }));
        for await (const row of parser) {
          scope.check();
          yield record(strings(row, codec.maxColumns, codec.maxRecordBytes), ++emitted, names);
        }
        scope.check();
        if (codec.hasHeader && names === undefined) throw failure('EK_CSV_SCHEMA');
      } catch (cause) {
        throw scope.error(cause);
      } finally {
        source?.destroy();
        parser?.destroy();
        scope.stop();
      }
    },
    async *stringify(
      rows: AsyncIterable<CsvRecord> | Iterable<CsvRecord>,
      options?: CsvOptions & OperationOptions,
    ) {
      const scope = begin(options),
        codec = scope.codec;
      let source: Readable | undefined, output: PassThrough | undefined;
      async function* encoded() {
        let names: readonly string[] | undefined,
          width: number | undefined,
          count = 0;
        const encode = (values: readonly string[]) => {
          const safe = codec.escapeSpreadsheetFormulas
            ? values.map((value) =>
                /^[\s\p{Cc}\p{Cf}]*[=+\-@]/u.test(value) ? "'" + value : value,
              )
            : values;
          const result = Buffer.from(
            nativeStringify([safe], {
              delimiter: codec.delimiter,
              quote: codec.quote,
              escape: codec.escape,
              record_delimiter: '\n',
              escape_formulas: codec.escapeSpreadsheetFormulas,
            }),
          );
          if (result.length > codec.maxRecordBytes) throw failure('EK_CSV_LIMIT');
          scope.output(result.length);
          return result;
        };
        if (codec.outputBom) {
          scope.output(3);
          yield Buffer.from(bom);
        }
        if (
          !rows ||
          (typeof rows[Symbol.asyncIterator as keyof typeof rows] !== 'function' &&
            typeof rows[Symbol.iterator as keyof typeof rows] !== 'function')
        )
          throw failure('EK_CSV_SCHEMA');
        for await (const input of rows) {
          scope.check();
          if (++count > codec.maxRows) throw failure('EK_CSV_LIMIT');
          const captured = snapshot(input, codec),
            row = captured.row;
          if (width !== undefined && row.fields.length !== width) throw failure('EK_CSV_SCHEMA');
          width = row.fields.length;
          scope.input(row.fields.reduce((bytes, field) => bytes + Buffer.byteLength(field), 0));
          if (codec.hasHeader) {
            if (!captured.names || !row.columns) throw failure('EK_CSV_SCHEMA');
            if (!names) {
              names = captured.names;
              yield encode(names);
            }
            if (
              captured.names.length !== names.length ||
              captured.names.some((name) => !names!.includes(name))
            )
              throw failure('EK_CSV_SCHEMA');
            yield encode(names.map((name) => row.columns![name]!));
          } else yield encode(row.fields);
          if (count % 64 === 0) await immediate(undefined, { signal: scope.signal });
        }
        if (codec.hasHeader && !names) throw failure('EK_CSV_SCHEMA');
      }
      try {
        source = Readable.from(encoded(), { objectMode: false, highWaterMark: 16384 });
        output = new PassThrough({ highWaterMark: 16384 });
        scope.watch(pipeline(source, output, { signal: scope.signal }));
        for await (const chunk of output) {
          scope.check();
          yield chunk as Buffer;
        }
        scope.check();
      } catch (cause) {
        throw scope.error(cause);
      } finally {
        source?.destroy();
        output?.destroy();
        scope.stop();
      }
    },
    validate(
      input: CsvRecord,
      schema: Readonly<{ columns: readonly string[] }>,
    ): ValidationResult<CsvRecord> {
      ready();
      try {
        const codec = {
          ...setting.defaults,
          maxRecordBytes: Math.min(
            setting.defaults.maxRecordBytes,
            setting.maxInputBytes,
            setting.maxOutputBytes,
          ),
        };
        const names = headers(fields(schema, ['columns']).columns, codec),
          captured = snapshot(input, codec);
        if (
          names.length !== captured.row.fields.length ||
          (captured.names && names.some((name, index) => name !== captured.names![index]))
        )
          throw failure('EK_CSV_SCHEMA');
        return Object.freeze({
          valid: true,
          value: captured.row,
          errors: Object.freeze([]) as readonly [],
        });
      } catch {
        return Object.freeze({
          valid: false,
          errors: Object.freeze([
            Object.freeze({
              path: '',
              code: 'EK_CSV_SCHEMA',
              message: 'The CSV record does not satisfy the declared columns',
            }),
          ]),
        });
      }
    },
  });
  return {
    api,
    close() {
      for (const scope of scopes) scope.stop();
    },
  };
}
/** Construct an isolated codec facade with finite native stream admission. */
export function createCsvService(settings: DataCsvPluginSettings): CsvService {
  return service(capture(settings), () => undefined).api;
}
/** Optional capability, registered only by the explicit factory. */
export const CSV_CAPABILITY: unique symbol = Symbol('arkenivajs.csv');
/** Register an application-owned codec and cancel active streams on shutdown. */
export function dataCsvPlugin(settings: DataCsvPluginSettings): Plugin {
  const setting = capture(settings),
    instances = new WeakMap<object, { close(): void }>();
  return {
    id: 'data-csv',
    version: '0.1.0',
    capabilities: new Set(['csv']),
    init(context) {
      let active = true;
      const managed = service(setting, () => {
        if (!active) throw failure('EK_RESOURCE_CLOSED');
      });
      context.provide(CSV_CAPABILITY, managed.api);
      instances.set(context, {
        close() {
          active = false;
          managed.close();
        },
      });
    },
    close(context) {
      instances.get(context)?.close();
      instances.delete(context);
    },
  };
}
