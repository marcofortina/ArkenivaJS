// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { AuthService, OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';
import type { TrustedSecurityAuthority } from '@arkenivajs/security-apikey';
export type { TrustedSecurityAuthority } from '@arkenivajs/security-apikey';

export interface ScimRecord {
  readonly id: string;
  readonly externalId?: string;
  readonly schemas: readonly string[];
  readonly meta?: Readonly<{ version?: string; resourceType?: string }>;
  readonly [key: string]: unknown;
}
export type ScimPatch = Readonly<{
  schemas: readonly string[];
  Operations: readonly Readonly<{
    op: 'add' | 'replace' | 'remove';
    path?: string;
    value?: unknown;
  }>[];
}>;
export interface ScimPage {
  readonly startIndex: number;
  readonly itemsPerPage: number;
  readonly totalResults: number;
  readonly Resources: readonly ScimRecord[];
}
export interface ScimFilter {
  readonly expression: string;
  readonly startIndex?: number;
  readonly count?: number;
  readonly sortBy?: string;
  readonly sortOrder?: 'ascending' | 'descending';
}
/** Every storage operation must bind ownership and version predicates atomically in the actual shared backend. */
export interface ScimProvider {
  list(
    filter: ScimFilter,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<ScimPage>;
  get(
    id: string,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<ScimRecord | null>;
  create(
    record: ScimRecord,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<ScimRecord>;
  replace(
    id: string,
    record: ScimRecord,
    ifMatch: string | undefined,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<ScimRecord>;
  patch(
    id: string,
    patch: ScimPatch,
    ifMatch: string | undefined,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<ScimRecord>;
  delete(
    id: string,
    ifMatch: string | undefined,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<void>;
}
export interface ScimHttpRequest {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: unknown;
  readonly auth: VerifiedTenantContext;
}
export interface ScimHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}
export interface ScimCapabilities {
  readonly patch: true;
  readonly bulk: false;
  readonly filter: true;
  readonly sort: boolean;
  readonly etag: boolean;
}
export interface ScimService {
  registerUsers(provider: ScimProvider): void;
  registerGroups(provider: ScimProvider): void;
  handle(request: ScimHttpRequest, options?: OperationOptions): Promise<ScimHttpResponse>;
  validatePatch(patch: unknown): ScimPatch;
  listCapabilities(): ScimCapabilities;
}
export interface ScimPluginSettings {
  readonly users: ScimProvider;
  readonly groups: ScimProvider;
  readonly authority: TrustedSecurityAuthority;
  readonly maxPageSize: number;
  readonly maxFilterDepth: number;
  readonly capabilities: ScimCapabilities;
  readonly maxRequestBytes: number;
  readonly maxConcurrent: number;
}
/** Standalone HTTP work needs the same actual authentication and authorization boundaries as the plugin. */
export interface ScimServiceSettings {
  readonly environment?: 'development' | 'test' | 'production';
  readonly maxPageSize?: number;
  readonly maxFilterDepth?: number;
  readonly auth?: AuthService;
  readonly authority?: TrustedSecurityAuthority;
}
