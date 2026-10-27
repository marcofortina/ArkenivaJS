// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

export type InputBytes = Uint8Array | AsyncIterable<Uint8Array>;
export type XlsxCellValue =
  | string
  | number
  | boolean
  | null
  | Date
  | Readonly<{ formula: string; cachedValue?: string | number | boolean | null }>;
export interface XlsxCellStyle {
  readonly numberFormat?: string;
  readonly fontName?: string;
  readonly fontSize?: number;
  readonly bold?: boolean;
  readonly italic?: boolean;
  readonly fontColorHex?: string;
  readonly fillColorHex?: string;
  readonly horizontalAlignment?: 'left' | 'center' | 'right';
}
export type XlsxCell = XlsxCellValue | Readonly<{ value: XlsxCellValue; style?: XlsxCellStyle }>;
export interface XlsxOptions {
  readonly maxSheets?: number;
  readonly maxRowsPerSheet?: number;
  readonly maxCells?: number;
  readonly maxUncompressedBytes?: number;
  readonly formulaPolicy?: 'reject' | 'preserve' | 'strip';
  readonly readMode?: 'stream' | 'random-access';
  readonly temporaryStorage?: Readonly<{ directory: string; maxBytes: number; cleanup: 'always' }>;
}
export interface XlsxRow {
  readonly rowIndex: number;
  readonly cells: readonly XlsxCell[];
}
export interface WorkbookReader {
  readonly sheetNames: readonly string[];
  rows(sheetName: string, options?: OperationOptions): AsyncIterable<XlsxRow>;
  close(): Promise<void>;
}
export interface WorksheetWriter {
  addRows(rows: Iterable<readonly XlsxCell[]> | AsyncIterable<readonly XlsxCell[]>): Promise<void>;
}
export interface WorkbookReceipt {
  readonly sheetCount: number;
  readonly writtenRows: number;
  readonly outputBytes: number;
}
export interface WorkbookWriter {
  addSheet(name: string): WorksheetWriter;
  write(
    target: (chunk: Uint8Array) => Promise<void>,
    options?: OperationOptions,
  ): Promise<WorkbookReceipt>;
  close(): Promise<void>;
}
export interface ExcelService {
  open(source: InputBytes, options?: XlsxOptions & OperationOptions): Promise<WorkbookReader>;
  create(options?: XlsxOptions): WorkbookWriter;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface DataXlsxPluginSettings {
  readonly defaults: XlsxOptions;
  readonly policy: BoundedRuntimePolicy;
}
