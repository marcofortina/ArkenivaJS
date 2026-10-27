// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

export interface PdfLimits {
  readonly maxBytes?: number;
  readonly maxPages?: number;
  readonly maxTextItems?: number;
  readonly maxDecodeMs?: number;
}
export interface PdfInfo {
  readonly pages: number;
  readonly encrypted: boolean;
  readonly signed: boolean;
  readonly title?: string;
  readonly author?: string;
}
export interface PdfTextItem {
  readonly text: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}
export interface PdfTextPage {
  readonly page: number;
  readonly items: readonly PdfTextItem[];
}
export interface PdfTextSpec {
  readonly page: number;
  readonly text: string;
  readonly x: number;
  readonly y: number;
  readonly font: string;
  readonly size: number;
  readonly colorHex: string;
  readonly rotationDegrees?: number;
}
export interface PdfBuilder {
  addText(
    text: string,
    page: number,
    x: number,
    y: number,
    options: Readonly<{ font: string; size: number; colorHex: string }>,
  ): void;
  save(options?: OperationOptions): Promise<Uint8Array>;
}
export interface PdfService {
  create(options?: PdfLimits): PdfBuilder;
  inspect(source: Uint8Array, options?: PdfLimits & OperationOptions): Promise<PdfInfo>;
  extractText(
    source: Uint8Array,
    options?: PdfLimits & OperationOptions,
  ): Promise<readonly PdfTextPage[]>;
  merge(inputs: readonly Uint8Array[], options?: PdfLimits & OperationOptions): Promise<Uint8Array>;
  addText(
    source: Uint8Array,
    spec: PdfTextSpec,
    options?: PdfLimits & OperationOptions,
  ): Promise<Uint8Array>;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface DocumentsPdfPluginSettings {
  readonly defaults: PdfLimits;
  readonly fontAllowlist: readonly string[];
  readonly policy: BoundedRuntimePolicy;
}
