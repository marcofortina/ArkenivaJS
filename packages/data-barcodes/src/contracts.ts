// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** Explicitly supported carrier formats; decoded contents never authenticate a subject. */
export type BarcodeSymbology = 'QR' | 'CODE128' | 'EAN13';
/** Per-operation limits can tighten, but cannot increase, deployment limits. */
export interface CodeOptions {
  readonly format?: 'png' | 'svg';
  readonly widthPixels?: number;
  readonly maxPixels?: number;
  readonly errorCorrection?: 'L' | 'M' | 'Q' | 'H';
}
/** Data from one natively detected symbol; confidence is omitted when unavailable. */
export interface DecodedCode {
  readonly text: string;
  readonly symbology: BarcodeSymbology;
  readonly confidence?: number;
}
/** Finite process admission, deadline and byte limits; no application work queue. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Immutable per-application image and process policy. */
export interface DataCodesPluginSettings {
  readonly defaults: CodeOptions;
  readonly policy: BoundedRuntimePolicy;
}
/** PNG/SVG generation and PNG/JPEG detection use native libraries in owned processes. */
export interface CodeService {
  /** Encode a bounded, well-formed Unicode string through qrcode. */
  generateQr(text: string, options?: CodeOptions): Promise<Uint8Array>;
  /** Encode one explicit symbology; EAN13 requires a complete valid check digit. */
  generateBarcode(
    value: string,
    symbology: BarcodeSymbology,
    options?: CodeOptions,
  ): Promise<Uint8Array>;
  /** Detect one supported symbol; a valid image with no detected symbol returns an empty list. */
  decode(
    image: Uint8Array,
    options?: CodeOptions & OperationOptions,
  ): Promise<readonly DecodedCode[]>;
}
