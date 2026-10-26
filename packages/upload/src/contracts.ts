// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, RouteContext } from '@arkenivajs/core';

/** Fixed startup route methods; registration at READY is deliberately unavailable. */
export type UploadMethod = 'POST' | 'PUT';
/** Actual wire and parser limits, independently of Content-Length assertions. */
export interface UploadPolicy {
  readonly maxRequestBytes: number;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxFields: number;
  readonly maxFieldBytes: number;
  readonly maxParts: number;
  readonly allowedMediaTypes: readonly string[];
}
/** A public upload requires an explicit application security-review reason. */
export type UploadAuth =
  | Readonly<{ required: true; scopes?: readonly string[] }>
  | Readonly<{ required: false; reason: string }>;
/** Bounded text from the native multipart parser, never a trusted identity claim. */
export interface MultipartFieldPart {
  readonly kind: 'field';
  readonly fieldName: string;
  readonly value: string;
}
/** Display metadata is untrusted; the application owns all persistence and content inspection. */
export interface MultipartFilePart {
  readonly kind: 'file';
  readonly fieldName: string;
  readonly filename: string;
  readonly declaredMediaType: string;
  readonly stream: AsyncIterable<Uint8Array>;
  discard(options?: OperationOptions): Promise<void>;
}
export type MultipartPart = MultipartFieldPart | MultipartFilePart;
/** Consume or explicitly discard every file before advancing the ordered, single-pass source. */
export interface UploadRequest {
  readonly context: RouteContext;
  readonly parts: AsyncIterable<MultipartPart>;
}
export interface UploadRoute {
  readonly path: string;
  readonly method: UploadMethod;
  readonly policy: UploadPolicy;
  readonly auth: UploadAuth;
  readonly responseSchema: object;
  readonly handler: (request: UploadRequest) => Promise<unknown> | unknown;
}
/** Aggregate counters contain neither client metadata nor tenant identifiers. */
export interface UploadStats {
  readonly activeRequests: number;
  readonly receivedRequests: number;
  readonly successfulRequests: number;
  readonly rejectedRequests: number;
  readonly observedBytes: number;
}
export interface UploadService {
  stats(): UploadStats;
}
export interface UploadPluginSettings {
  readonly routes: readonly UploadRoute[];
}
