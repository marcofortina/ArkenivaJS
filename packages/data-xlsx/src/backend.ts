// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Readable, Writable } from 'node:stream';
import ExcelJS from 'exceljs';
import { SaxesParser } from 'saxes';
import { fromBufferPromise } from 'yauzl';
import type { Entry } from 'yauzl';
import type { XlsxCell, XlsxCellStyle, XlsxCellValue, XlsxRow } from './contracts.js';
import type { Options } from './settings.js';
import { inspect } from './archive.js';
import { cell, style, primitive } from './cells.js';
import { failure, integer } from './validation.js';

interface SheetModel {
  readonly id: number;
  readonly rId: string;
  readonly name: string;
}
interface NativeSheet {
  readonly name: string;
  [Symbol.asyncIterator](): AsyncGenerator<ExcelJS.Row>;
}
/** Narrow ports for the pinned runtime methods missing or inaccurately inherited in upstream declarations. */
interface PrimedReader {
  model: { sheets: readonly SheetModel[] };
  workbookRels: readonly { Id: string; Target: string }[];
  sharedStrings: unknown[];
  _parseWorkbook(input: AsyncIterable<Buffer>): Promise<void>;
  _parseRels(input: AsyncIterable<Buffer>): Promise<void>;
  _parseStyles(input: AsyncIterable<Buffer>): Promise<void>;
  _parseSharedStrings(input: AsyncIterable<Buffer>): AsyncGenerator<unknown>;
  _parseWorksheet(input: AsyncIterable<Buffer>, sheetNo: string): Iterable<{ value: NativeSheet }>;
}

function nativeStyle(input: XlsxCellStyle): Partial<ExcelJS.Style> {
  return {
    ...(input.numberFormat === undefined ? {} : { numFmt: input.numberFormat }),
    ...(input.fontName !== undefined ||
    input.fontSize !== undefined ||
    input.bold !== undefined ||
    input.italic !== undefined ||
    input.fontColorHex !== undefined
      ? {
          font: {
            ...(input.fontName === undefined ? {} : { name: input.fontName }),
            ...(input.fontSize === undefined ? {} : { size: input.fontSize }),
            ...(input.bold === undefined ? {} : { bold: input.bold }),
            ...(input.italic === undefined ? {} : { italic: input.italic }),
            ...(input.fontColorHex === undefined
              ? {}
              : { color: { argb: 'FF' + input.fontColorHex.slice(1) } }),
          },
        }
      : {}),
    ...(input.fillColorHex === undefined
      ? {}
      : {
          fill: {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FF' + input.fillColorHex.slice(1) },
          },
        }),
    ...(input.horizontalAlignment === undefined
      ? {}
      : { alignment: { horizontal: input.horizontalAlignment } }),
  };
}
function nativeValue(input: XlsxCellValue): ExcelJS.CellValue {
  if (input && typeof input === 'object' && !(input instanceof Date)) {
    return {
      formula: input.formula,
      ...(input.cachedValue === undefined || input.cachedValue === null
        ? {}
        : { result: input.cachedValue }),
    };
  }
  return input;
}
function themeColors(input: Buffer | undefined): ReadonlyMap<number, string> {
  const result = new Map<number, string>();
  if (!input) return result;
  const names = [
      'lt1',
      'dk1',
      'lt2',
      'dk2',
      'accent1',
      'accent2',
      'accent3',
      'accent4',
      'accent5',
      'accent6',
      'hlink',
      'folHlink',
    ],
    parser = new SaxesParser({ xmlns: false });
  let active = false,
    index = -1;
  parser.on('opentag', (node) => {
    const name = node.name.split(':').at(-1)!;
    if (name === 'clrScheme') active = true;
    else if (active && names.includes(name)) index = names.indexOf(name);
    else if (active && index >= 0 && ['srgbClr', 'sysClr'].includes(name)) {
      const value = name === 'srgbClr' ? node.attributes.val : node.attributes.lastClr;
      if (!value || !/^[0-9A-Fa-f]{6}$/.test(value) || result.has(index))
        throw failure('EK_XLSX_UNSUPPORTED');
      result.set(index, '#' + value.toUpperCase());
    }
  });
  parser.on('closetag', (node) => {
    const name = node.name.split(':').at(-1)!;
    if (name === 'clrScheme') active = false;
    if (names.includes(name)) index = -1;
  });
  parser.write(input.toString('utf8')).close();
  return result;
}
function projectedStyle(
  current: Partial<ExcelJS.Style>,
  theme: ReadonlyMap<number, string>,
): XlsxCellStyle | undefined {
  const value: Record<string, unknown> = Object.create(null);
  const color = (input: Partial<ExcelJS.Color> & { readonly tint?: number }): string => {
    if (input.argb !== undefined && /^FF[0-9A-Fa-f]{6}$/.test(input.argb))
      return '#' + input.argb.slice(2);
    if (
      input.theme !== undefined &&
      (input.tint === undefined || input.tint === 0) &&
      theme.has(input.theme)
    )
      return theme.get(input.theme)!;
    throw failure('EK_XLSX_UNSUPPORTED');
  };
  if (current.numFmt !== undefined && current.numFmt !== 'General')
    value.numberFormat = current.numFmt;
  if (current.font?.name !== undefined) value.fontName = current.font.name;
  if (current.font?.size !== undefined) value.fontSize = current.font.size;
  if (current.font?.bold !== undefined) value.bold = current.font.bold;
  if (current.font?.italic !== undefined) value.italic = current.font.italic;
  if (current.font?.color) value.fontColorHex = color(current.font.color);
  if (current.fill?.type === 'pattern' && current.fill.pattern === 'solid') {
    if (!current.fill.fgColor) throw failure('EK_XLSX_UNSUPPORTED');
    value.fillColorHex = color(current.fill.fgColor);
  } else if (
    current.fill?.type === 'gradient' ||
    (current.fill?.type === 'pattern' && !['none', 'gray125'].includes(current.fill.pattern))
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  if (current.alignment?.horizontal !== undefined) {
    if (!['left', 'center', 'right'].includes(current.alignment.horizontal))
      throw failure('EK_XLSX_UNSUPPORTED');
    value.horizontalAlignment = current.alignment.horizontal;
  }
  if (
    current.border &&
    Object.values(current.border).some(
      (edge) => edge && typeof edge === 'object' && 'style' in edge,
    )
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  if (
    current.font &&
    ['underline', 'strike', 'outline', 'shadow', 'vertAlign'].some((key) =>
      Boolean(Reflect.get(current.font!, key)),
    )
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  if (
    current.alignment &&
    Object.entries(current.alignment).some(
      ([key, value]) =>
        key !== 'horizontal' && value !== undefined && value !== false && value !== 0,
    )
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  return Object.keys(value).length ? style(value) : undefined;
}

/** Prime only native metadata parsers, then construct native row readers in workbook order without temp staging. */
export async function openReader(input: Buffer, options: Options) {
  const inspected = await inspect(input, options),
    theme = themeColors(inspected.metadata.get('xl/theme/theme1.xml')),
    native = new ExcelJS.stream.xlsx.WorkbookReader(Readable.from([]), {
      worksheets: 'emit',
      sharedStrings: 'cache',
      styles: 'cache',
      hyperlinks: 'ignore',
    }) as unknown as PrimedReader;
  const part = (name: string) => {
    const value = inspected.metadata.get(name);
    if (!value) throw failure();
    return Readable.from([value]) as AsyncIterable<Buffer>;
  };
  await native._parseRels(part('xl/_rels/workbook.xml.rels'));
  await native._parseWorkbook(part('xl/workbook.xml'));
  if (inspected.metadata.has('xl/styles.xml')) await native._parseStyles(part('xl/styles.xml'));
  if (inspected.metadata.has('xl/sharedStrings.xml'))
    for await (const value of native._parseSharedStrings(part('xl/sharedStrings.xml'))) void value;
  else native.sharedStrings = [];
  const zip = await fromBufferPromise(input, {
      autoClose: false,
      lazyEntries: true,
      validateEntrySizes: true,
      strictFileNames: true,
    }),
    entries = new Map<string, Entry>();
  try {
    for await (const entry of zip.eachEntry()) entries.set(entry.fileName, entry);
  } catch {
    zip.close();
    throw failure();
  }
  const sheets = new Map<string, { entry: Entry; number: string; path: string }>();
  try {
    if (native.model.sheets.length !== inspected.names.length) throw failure();
    for (const model of native.model.sheets) {
      const rel = native.workbookRels.find((value) => value.Id === model.rId),
        match = rel && /^worksheets\/sheet([1-9][0-9]*)\.xml$/.exec(rel.Target),
        entry = rel && entries.get('xl/' + rel.Target);
      if (!match || !entry || !inspected.names.includes(model.name))
        throw failure('EK_XLSX_UNSUPPORTED');
      sheets.set(model.name, { entry, number: match[1]!, path: entry.fileName });
    }
    if (sheets.size !== inspected.names.length) throw failure();
  } catch (error) {
    zip.close();
    throw error;
  }
  return {
    names: inspected.names,
    async *rows(name: string): AsyncGenerator<XlsxRow> {
      const descriptor = sheets.get(name);
      if (!descriptor) throw failure('EK_XLSX_UNSUPPORTED');
      const stream = await zip.openReadStreamPromise(descriptor.entry);
      try {
        for (const item of native._parseWorksheet(
          stream as AsyncIterable<Buffer>,
          descriptor.number,
        )) {
          if (item.value.name !== name) throw failure();
          for await (const current of item.value) {
            const cells: XlsxCell[] = [];
            for (let index = 1; index <= current.cellCount; index++) {
              const source = current.getCell(index),
                raw = source.value;
              let value: XlsxCellValue;
              if (raw && typeof raw === 'object' && !(raw instanceof Date)) {
                if (!('formula' in raw) || typeof raw.formula !== 'string')
                  throw failure('EK_XLSX_UNSUPPORTED');
                const corrected = inspected.cellValues.get(descriptor.path)?.get(source.address),
                  cached =
                    corrected === undefined
                      ? 'result' in raw && raw.result !== undefined
                        ? primitive(raw.result)
                        : undefined
                      : corrected;
                value = {
                  formula: raw.formula,
                  ...(cached === undefined ? {} : { cachedValue: cached }),
                };
              } else
                value =
                  inspected.cellValues.get(descriptor.path)?.get(source.address) ??
                  (raw === undefined
                    ? null
                    : raw instanceof Date
                      ? new Date(Date.prototype.getTime.call(raw))
                      : primitive(raw));
              const presentation = projectedStyle(source.style, theme);
              cells.push(cell(presentation ? { value, style: presentation } : value, options));
            }
            yield { rowIndex: integer(current.number, options.maxRowsPerSheet), cells };
          }
        }
      } finally {
        stream.destroy();
      }
    },
    close() {
      zip.close();
      inspected.metadata.clear();
      sheets.clear();
      entries.clear();
      input.fill(0);
    },
  };
}

interface ZipWriter {
  append(input: unknown, options: Record<string, unknown>): unknown;
  on(event: 'error', listener: (error: unknown) => void): unknown;
  abort(): void;
}
interface NativeOutput extends ExcelJS.stream.xlsx.WorkbookWriter {
  zip: ZipWriter;
}
interface DeferredMetadata {
  addThemes(this: ExcelJS.stream.xlsx.WorkbookWriter): Promise<void>;
  addOfficeRels(this: ExcelJS.stream.xlsx.WorkbookWriter): Promise<void>;
}
const nativePrototype = ExcelJS.stream.xlsx.WorkbookWriter.prototype as unknown as DeferredMetadata;
/** Defer constructor metadata until the per-instance accounting hook is attached. */
class BoundedWriter extends ExcelJS.stream.xlsx.WorkbookWriter {
  override addThemes(): Promise<void> {
    return Promise.resolve().then(() => nativePrototype.addThemes.call(this));
  }
  override addOfficeRels(): Promise<void> {
    return Promise.resolve().then(() => nativePrototype.addOfficeRels.call(this));
  }
}
/** Native streaming XML and ZIP writers retain only finite output; no worksheet row model is accumulated. */
export function createWriter(options: Options, maxOutputBytes: number) {
  const chunks: Buffer[] = [],
    sheets: ExcelJS.Worksheet[] = [];
  let outputBytes = 0,
    expandedBytes = 0,
    writtenRows = 0,
    error: unknown;
  const account = (size: number) => {
    expandedBytes += size;
    if (expandedBytes > options.maxUncompressedBytes) throw failure('EK_XLSX_LIMIT');
  };
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) {
        error = failure('EK_XLSX_LIMIT');
        done(error as Error);
        return;
      }
      chunks.push(Buffer.from(chunk));
      done();
    },
  });
  sink.on('error', (cause) => {
    error = cause;
  });
  const nativeOptions = {
    stream: sink,
    useStyles: true,
    useSharedStrings: true,
    creator: 'ArkenivaJS',
    lastModifiedBy: 'ArkenivaJS',
    created: new Date(0),
    modified: new Date(0),
    zip: { zlib: { level: 6 } },
  };
  const book = new BoundedWriter(nativeOptions) as NativeOutput;
  let rejectOutput!: (error: unknown) => void;
  const failed = new Promise<never>((_resolve, reject) => {
    rejectOutput = reject;
  });
  void failed.catch(() => undefined);
  sink.on('error', rejectOutput);
  book.zip.on('error', (cause) => {
    error = cause;
    rejectOutput(cause);
  });
  void (book as unknown as { promise: Promise<unknown> }).promise.catch((cause: unknown) => {
    error = cause;
    rejectOutput(cause);
  });
  const append = book.zip.append.bind(book.zip);
  book.zip.append = (input, attributes) => {
    if (typeof input === 'string' || Buffer.isBuffer(input)) account(Buffer.byteLength(input));
    else if (
      input &&
      typeof input === 'object' &&
      'write' in input &&
      typeof input.write === 'function'
    ) {
      const original = input.write.bind(input) as (...args: unknown[]) => unknown;
      input.write = (...args: unknown[]) => {
        const value = args[0];
        if (typeof value === 'string' || Buffer.isBuffer(value)) account(Buffer.byteLength(value));
        else if (
          value &&
          typeof value === 'object' &&
          'toBuffer' in value &&
          typeof value.toBuffer === 'function' &&
          'length' in value &&
          typeof value.length === 'number' &&
          Number.isSafeInteger(value.length) &&
          value.length >= 0
        )
          account(value.length);
        else throw failure();
        return original(...args);
      };
    }
    return append(input, { ...attributes, date: new Date('1980-01-01T00:00:00Z'), mode: 0o600 });
  };
  return {
    addSheet(name: string) {
      sheets.push(book.addWorksheet(name));
    },
    addRows(index: number, rows: readonly (readonly XlsxCell[])[]) {
      const sheet = sheets[index];
      if (!sheet) throw failure();
      for (const cells of rows) {
        const nativeRow = sheet.addRow([]);
        if (!cells.length) nativeRow.height = 15;
        for (let position = 0; position < cells.length; position++) {
          const source = cell(cells[position], options),
            styled =
              source &&
              typeof source === 'object' &&
              !(source instanceof Date) &&
              'value' in source;
          const target = nativeRow.getCell(position + 1);
          target.value = nativeValue(styled ? source.value : (source as XlsxCellValue));
          if (styled && source.style) target.style = nativeStyle(source.style);
        }
        nativeRow.commit();
        writtenRows++;
      }
      if (error) throw error;
    },
    async finish() {
      if (error) throw error;
      await Promise.race([book.commit(), failed]);
      if (error) throw error;
      return { chunks, receipt: { sheetCount: sheets.length, writtenRows, outputBytes } };
    },
    close() {
      book.zip.abort();
      sink.destroy();
      for (const chunk of chunks) chunk.fill(0);
      chunks.length = 0;
    },
  };
}
export type ReaderBackend = Awaited<ReturnType<typeof openReader>>;
export type WriterBackend = ReturnType<typeof createWriter>;
