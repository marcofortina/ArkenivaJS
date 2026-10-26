// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
/** Owned bytes or a single-pass asynchronous byte source; never a path or URL. */
export type InputBytes = Uint8Array | AsyncIterable<Uint8Array>;
/** A bounded single-pass byte stream; consumers must exhaust it to verify completion. */
export type OutputBytes = AsyncIterable<Uint8Array>;
/** Explicit archive, expansion, path-depth and computation ceilings. */
export interface CompressionLimits {
  readonly maxCompressedBytes?: number;
  readonly maxUncompressedBytes?: number;
  readonly maxRatio?: number;
  readonly maxEntries?: number;
  readonly maxDepth?: number;
  readonly maxEntryBytes?: number;
  readonly maxCpuTimeMs?: number;
}
/** A normalized relative name and verified bounded entry contents; never an extracted path. */
export interface ArchiveEntry {
  readonly path: string;
  readonly type: 'file' | 'directory';
  readonly sizeBytes?: number;
  readonly data: OutputBytes;
}
/** A safe relative name and explicit byte source; trailing slash denotes an empty directory. */
export interface ArchiveInputEntry {
  readonly path: string;
  readonly data: InputBytes;
}
/** Deployment-owned operation admission and positive deadline. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Immutable bounds apply to every facade operation; no hidden filesystem extraction. */
export interface DataCompressionPluginSettings {
  readonly defaults: CompressionLimits;
  readonly policy: BoundedRuntimePolicy;
}
/** GZIP and ZIP operations never download resources or write archive paths to disk. */
export interface CompressionService {
  /** Stream native GZIP output under finite byte and time budgets. */
  gzip(source: InputBytes, options?: CompressionLimits & OperationOptions): OutputBytes;
  /** Stream native verified GZIP decompression with expansion bounds. */
  gunzip(source: InputBytes, options?: CompressionLimits & OperationOptions): OutputBytes;
  /** Encode safe names and bounded streams with fflate ZIP/DEFLATE. */
  createZip(
    entries: Iterable<ArchiveInputEntry> | AsyncIterable<ArchiveInputEntry>,
    options?: CompressionLimits & OperationOptions,
  ): OutputBytes;
  /** Preflight bounded central-directory metadata, then verify one bounded entry at a time. */
  iterateZip(
    input: InputBytes,
    options?: CompressionLimits & OperationOptions,
  ): AsyncIterable<ArchiveEntry>;
}
