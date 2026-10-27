// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
export interface XmlOptions {
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  readonly maxAttributes?: number;
  readonly forbidDtd?: true;
  readonly externalEntities?: false;
  readonly namespaceMode?: 'preserve' | 'expanded';
}
export interface XmlDocument {
  readonly root: Readonly<Record<string, unknown>>;
}
export interface SchemaValidationError {
  readonly path: string;
  readonly code: string;
  readonly message: string;
}
export interface XmlValidationReport {
  readonly valid: boolean;
  readonly messages: readonly SchemaValidationError[];
}
export interface XmlService {
  parse(source: Uint8Array | string, options?: XmlOptions & OperationOptions): Promise<XmlDocument>;
  stringify(data: XmlDocument, options?: XmlOptions): Promise<string>;
  validateXsd(
    xmlBytes: Uint8Array,
    schemaId: string,
    options?: OperationOptions,
  ): Promise<XmlValidationReport>;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface DataXmlPluginSettings {
  readonly defaults: XmlOptions;
  readonly xsdSchemaFiles?: Readonly<Record<string, string>>;
  readonly policy: BoundedRuntimePolicy;
}
