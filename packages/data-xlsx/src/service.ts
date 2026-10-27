// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { performance } from 'node:perf_hooks';
import type {
  ExcelService,
  WorkbookReader,
  WorkbookWriter,
  XlsxOptions,
  XlsxRow,
  WorkbookReceipt,
  XlsxCell,
} from './contracts.js';
import { options } from './settings.js';
import type { Settings } from './settings.js';
import { fields, failure, sheetName, integer } from './validation.js';
import { row, styleBudget } from './cells.js';
import { input } from './input.js';
import { Book, operation, cursor } from './runtime.js';
import { recorder } from './observation.js';
import type { Observers } from './observation.js';

const optionNames = [
  'maxSheets',
  'maxRowsPerSheet',
  'maxCells',
  'maxUncompressedBytes',
  'formulaPolicy',
  'readMode',
  'temporaryStorage',
] as const;
function call(value: unknown, settings: Settings, withOperation = false) {
  const data = fields(value ?? {}, [
      ...optionNames,
      ...(withOperation ? ['signal', 'timeoutMs'] : []),
    ]),
    merged: Record<string, unknown> = { ...settings.defaults };
  for (const key of optionNames) if (data[key] !== undefined) merged[key] = data[key];
  const runtime = operation(
    {
      ...(data.signal === undefined ? {} : { signal: data.signal as AbortSignal }),
      ...(data.timeoutMs === undefined ? {} : { timeoutMs: data.timeoutMs as number }),
    },
    settings.timeoutMs,
  );
  return {
    policy: options(merged as XlsxOptions),
    operation: {
      ...(runtime.signal ? { signal: runtime.signal } : {}),
      timeoutMs: runtime.timeoutMs,
    },
  };
}
function immutable<T>(value: T): T {
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    for (const item of Object.values(value)) immutable(item);
    Object.freeze(value);
  }
  return value;
}
export function managedService(
  settings: Settings,
  applicationSignal: AbortSignal,
  ready: () => boolean,
  observers: Observers = {},
) {
  const books = new Set<Book>(),
    observe = recorder(observers);
  let closed = false;
  const check = () => {
    if (closed || applicationSignal.aborted || !ready()) throw failure('EK_RESOURCE_CLOSED');
  };
  const admit = () => {
    check();
    if (books.size >= settings.maxConcurrent) throw failure('EK_XLSX_LIMIT');
    const book = new Book(settings, () => books.delete(book), observe);
    books.add(book);
    return book;
  };
  const abort = () => {
    closed = true;
    for (const book of books) book.stop(failure('EK_ABORTED'));
  };
  applicationSignal.addEventListener('abort', abort, { once: true });
  const service = Object.freeze<ExcelService>({
    async open(source, requested) {
      check();
      const captured = call(requested, settings, true),
        book = admit(),
        started = performance.now();
      try {
        return await book.use(captured.operation, async (scope) => {
          let cancelInput: (() => void) | undefined;
          const loading = input(source, captured.policy, scope).then((captured) => {
            cancelInput = () => book.track(captured.cleanup());
            book.cancelled.addEventListener('abort', cancelInput, { once: true });
            if (book.cancelled.aborted) cancelInput();
            return captured;
          });
          const capturedInput = await scope.wait(loading);
          let names: readonly string[];
          try {
            scope.check();
            book.start(capturedInput.path);
            const result = await scope.wait(
              book.rpc('open', {
                options: captured.policy,
                maximum: settings.maxInputBytes,
                ...(capturedInput.path
                  ? { path: capturedInput.path }
                  : { bytes: capturedInput.data }),
              }),
            );
            if (
              !Array.isArray(result) ||
              !result.length ||
              result.length > captured.policy.maxSheets
            )
              throw failure();
            names = Object.freeze(result.map(sheetName));
          } finally {
            if (cancelInput) book.cancelled.removeEventListener('abort', cancelInput);
            await capturedInput.cleanup();
          }
          observe.complete('open', 'ok', performance.now() - started);
          let active = false,
            position = 0;
          const reader = Object.freeze<WorkbookReader>({
            sheetNames: names,
            rows(name, opts) {
              check();
              book.lock();
              const runtime = operation(opts, settings.timeoutMs);
              const index = names.indexOf(sheetName(name));
              if (
                index < 0 ||
                active ||
                (captured.policy.readMode === 'stream' && index !== position)
              )
                throw failure('EK_XLSX_UNSUPPORTED');
              return cursor(
                (async function* (): AsyncGenerator<XlsxRow> {
                  check();
                  if (active || (captured.policy.readMode === 'stream' && index !== position))
                    throw failure('EK_XLSX_UNSUPPORTED');
                  const reading = book.begin({
                    timeoutMs: runtime.timeoutMs,
                    ...(runtime.signal ? { signal: runtime.signal } : {}),
                  });
                  active = true;
                  let complete = false,
                    cells = 0,
                    rows = 0;
                  const started = performance.now();
                  try {
                    await reading.wait(book.rpc('begin', { name }));
                    for (;;) {
                      const next = fields(await reading.wait(book.rpc('next')), ['done', 'value']);
                      if (next.done === true) {
                        complete = true;
                        position++;
                        break;
                      }
                      if (next.done !== false) throw failure();
                      const data = fields(next.value, ['rowIndex', 'cells']);
                      if (++rows === 1)
                        observe.measure('first-row.duration.ms', performance.now() - started);
                      cells += Array.isArray(data.cells) ? data.cells.length : 0;
                      yield immutable({
                        rowIndex: integer(data.rowIndex, captured.policy.maxRowsPerSheet),
                        cells: row(data.cells, captured.policy),
                      });
                      reading.check();
                    }
                  } catch (error) {
                    const normalized = error instanceof KitError ? error : failure();
                    book.stop(normalized);
                    throw normalized;
                  } finally {
                    active = false;
                    book.end(reading);
                    const duration = performance.now() - started;
                    observe.measure('cells', cells);
                    if (duration > 0)
                      observe.measure('cells.per.second', (cells * 1000) / duration);
                    observe.complete('read', complete ? 'ok' : 'error', duration);
                    if (!complete) await book.close();
                  }
                })(),
                book,
              );
            },
            async close() {
              await book.close();
            },
          });
          return reader;
        });
      } catch (error) {
        observe.complete('open', 'error', performance.now() - started);
        book.stop();
        throw error;
      }
    },
    create(requested) {
      check();
      const policy = call(requested, settings).policy,
        book = admit(),
        names: string[] = [],
        counts: number[] = [],
        styles = styleBudget(policy);
      let started = false,
        initializedSheets = 0,
        cells = 0,
        finished = false,
        inputBytes = 0;
      const initialize = async (scope: Parameters<Parameters<Book['use']>[1]>[0]) => {
        if (!started) {
          book.start();
          await scope.wait(
            book.rpc('create', { options: policy, maximum: settings.maxOutputBytes }),
          );
          started = true;
        }
        while (initializedSheets < names.length) {
          await scope.wait(book.rpc('sheet', { name: names[initializedSheets] }));
          initializedSheets++;
        }
      };
      const writer = Object.freeze<WorkbookWriter>({
        addSheet(raw) {
          check();
          book.lock();
          if (finished) throw failure('EK_RESOURCE_CLOSED');
          const name = sheetName(raw);
          if (
            names.length >= policy.maxSheets ||
            names.some((current) => current.toLowerCase() === name.toLowerCase())
          )
            throw failure('EK_XLSX_LIMIT');
          const index = names.length;
          names.push(name);
          counts.push(0);
          return Object.freeze({
            async addRows(
              source: Iterable<readonly XlsxCell[]> | AsyncIterable<readonly XlsxCell[]>,
            ) {
              check();
              if (finished) throw failure('EK_RESOURCE_CLOSED');
              await book.use(undefined, async (scope) => {
                await initialize(scope);
                if (
                  !source ||
                  (typeof source[Symbol.asyncIterator as keyof typeof source] !== 'function' &&
                    typeof source[Symbol.iterator as keyof typeof source] !== 'function')
                )
                  throw failure();
                const iterator =
                  Symbol.asyncIterator in source
                    ? source[Symbol.asyncIterator]()
                    : source[Symbol.iterator]();
                let done = false;
                try {
                  for (;;) {
                    scope.check();
                    const next = await scope.wait(Promise.resolve(iterator.next()));
                    if (next.done) {
                      done = true;
                      break;
                    }
                    const normalized = row(next.value, policy),
                      size = Buffer.byteLength(JSON.stringify(normalized));
                    inputBytes += size;
                    if (
                      size > 2 * 1024 * 1024 ||
                      inputBytes > policy.maxUncompressedBytes ||
                      ++counts[index]! > policy.maxRowsPerSheet ||
                      (cells += normalized.length) > policy.maxCells
                    )
                      throw failure('EK_XLSX_LIMIT');
                    styles(normalized);
                    await scope.wait(
                      book.rpc('append', { index, row: normalized, options: policy }),
                    );
                  }
                } finally {
                  if (!done && iterator.return) {
                    try {
                      book.track(Promise.resolve(iterator.return()));
                    } catch {
                      /* The original failure is authoritative. */
                    }
                  }
                }
              });
            },
          });
        },
        async write(target, requestedOperation) {
          check();
          if (finished) throw failure('EK_RESOURCE_CLOSED');
          if (typeof target !== 'function' || !names.length) throw failure();
          const startedAt = performance.now();
          return book
            .use(requestedOperation, async (scope) => {
              finished = true;
              await initialize(scope);
              const value = fields(await scope.wait(book.rpc('finish')), [
                  'sheetCount',
                  'writtenRows',
                  'outputBytes',
                ]),
                receipt: WorkbookReceipt = {
                  sheetCount: integer(value.sheetCount, policy.maxSheets),
                  writtenRows: integer(
                    value.writtenRows,
                    policy.maxRowsPerSheet * policy.maxSheets,
                    0,
                  ),
                  outputBytes: integer(value.outputBytes, settings.maxOutputBytes),
                };
              let delivered = 0,
                attempted = false;
              try {
                for (;;) {
                  const chunk = await scope.wait(book.rpc('chunk'));
                  if (chunk === null) break;
                  if (!(chunk instanceof Uint8Array)) throw failure();
                  delivered += chunk.byteLength;
                  if (delivered > receipt.outputBytes) throw failure();
                  attempted = true;
                  await scope.wait(Promise.resolve().then(() => target(chunk)));
                }
                if (delivered !== receipt.outputBytes) throw failure();
                await book.complete(scope);
                observe.measure('output.bytes', receipt.outputBytes);
                observe.measure('cells', cells);
                observe.complete('write', 'ok', performance.now() - startedAt);
                return Object.freeze(receipt);
              } catch (error) {
                if (attempted)
                  throw failure(error instanceof KitError ? error.code : 'EK_XLSX_FORMAT', true);
                throw error;
              }
            })
            .catch((error: unknown) => {
              observe.complete('write', 'error', performance.now() - startedAt);
              throw error;
            });
        },
        async close() {
          await book.close();
        },
      });
      return writer;
    },
  });
  return {
    service,
    async close() {
      abort();
      applicationSignal.removeEventListener('abort', abort);
      await Promise.all([...books].map((book) => book.close()));
    },
  };
}
