// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export interface JsonOptions {
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  readonly indentSpaces?: number;
}
export type JsonPointer = string;
export type JsonMappingExpr =
  | Readonly<{ op: 'copy'; path: JsonPointer; required?: boolean }>
  | Readonly<{ op: 'literal'; value: unknown }>
  | Readonly<{ op: 'coalesce'; args: readonly JsonMappingExpr[] }>
  | Readonly<{ op: 'concat'; args: readonly JsonMappingExpr[]; separator?: string }>
  | Readonly<{ op: 'to-string' | 'to-number' | 'to-boolean'; value: JsonMappingExpr }>
  | Readonly<{ op: 'array-map'; path: JsonPointer; item: JsonMappingExpr; maxItems: number }>;
export interface JsonMappingV1 {
  readonly schemaVersion: '1.0.0';
  readonly id: string;
  readonly inputSchemaId: string;
  readonly outputSchemaId: string;
  readonly fields: Readonly<Record<string, JsonMappingExpr>>;
  readonly limits: Readonly<{
    maxDepth: number;
    maxNodes: number;
    maxArrayItems: number;
    maxOutputBytes: number;
  }>;
}
/** The finite deployment manifest permits complete validation before application readiness. */
export interface JsonMappingRegistry {
  readonly ids: readonly string[];
  get(mappingId: string): JsonMappingV1 | null;
}
export interface SchemaValidationError {
  readonly path: string;
  readonly code: string;
  readonly message: string;
}
export type ValidationResult<T> =
  | Readonly<{ valid: true; value: T; errors: readonly [] }>
  | Readonly<{ valid: false; errors: readonly SchemaValidationError[] }>;
export type JsonValidation = ValidationResult<unknown>;
export interface JsonService {
  parse(text: string, options?: JsonOptions): unknown;
  stringify(value: unknown, options?: JsonOptions): string;
  validate(value: unknown, schemaId: string): ValidationResult<unknown>;
  transform(value: unknown, mappingId: string): unknown;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface DataJsonPluginSettings {
  readonly defaults: JsonOptions;
  readonly schemas: Readonly<Record<string, object>>;
  readonly mappings: JsonMappingRegistry;
  readonly policy: BoundedRuntimePolicy;
}
