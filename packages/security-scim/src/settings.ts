// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { AuthService } from '@arkenivajs/core';
import type {
  ScimServiceSettings,
  ScimProvider,
  ScimCapabilities,
  TrustedSecurityAuthority,
  ScimPluginSettings,
} from './contracts.js';
import { fields, method, integer, failure } from './validation.js';
import { types } from 'node:util';

export function testOnly(input: unknown): boolean {
  if (!input || typeof input !== 'object' || types.isProxy(input)) return false;
  for (const name of ['usage', 'securityLevel']) {
    let current: object | null = input;
    for (let depth = 0; current && depth < 32; depth++) {
      if (types.isProxy(current)) throw failure('EK_CONFIG_INVALID');
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor) {
        if (!('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
        if (descriptor.value === 'test-only') return true;
        break;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
    if (current && !Object.getOwnPropertyDescriptor(current, name))
      throw failure('EK_CONFIG_INVALID');
  }
  return false;
}

export function provider(input: ScimProvider, environment: string): ScimProvider {
  if (environment !== 'test' && testOnly(input)) throw failure('EK_CONFIG_INVALID');
  return Object.freeze({
    list: method<ScimProvider['list']>(input, 'list'),
    get: method<ScimProvider['get']>(input, 'get'),
    create: method<ScimProvider['create']>(input, 'create'),
    replace: method<ScimProvider['replace']>(input, 'replace'),
    patch: method<ScimProvider['patch']>(input, 'patch'),
    delete: method<ScimProvider['delete']>(input, 'delete'),
  });
}
export interface Settings {
  readonly environment: 'development' | 'test' | 'production';
  readonly maxPageSize: number;
  readonly maxFilterDepth: number;
  readonly maxRequestBytes: number;
  readonly maxConcurrent: number;
  readonly auth: AuthService | undefined;
  readonly authority: TrustedSecurityAuthority | undefined;
  readonly capabilities: ScimCapabilities;
}
export function capture(input: ScimServiceSettings): Settings {
  const value = fields(input, [
    'maxPageSize',
    'maxFilterDepth',
    'auth',
    'authority',
    'environment',
  ]);
  const environment = value.environment ?? 'production';
  if (
    !['production', 'development', 'test'].includes(environment as string) ||
    (environment !== 'test' && [value.auth, value.authority].some(testOnly))
  )
    throw failure('EK_CONFIG_INVALID');
  const auth =
    value.auth === undefined
      ? undefined
      : Object.freeze({
          verifyBearer: method<AuthService['verifyBearer']>(value.auth, 'verifyBearer'),
          requireScope: method<AuthService['requireScope']>(value.auth, 'requireScope'),
          requireAssurance: method<AuthService['requireAssurance']>(value.auth, 'requireAssurance'),
          tenantFrom: method<AuthService['tenantFrom']>(value.auth, 'tenantFrom'),
        });
  const authority =
    value.authority === undefined
      ? undefined
      : Object.freeze({
          require: method<TrustedSecurityAuthority['require']>(value.authority, 'require'),
        });
  return Object.freeze({
    environment: environment as Settings['environment'],
    maxPageSize: integer(value.maxPageSize ?? 100, 1000),
    maxFilterDepth: integer(value.maxFilterDepth ?? 8, 16),
    maxRequestBytes: 262144,
    maxConcurrent: 8,
    auth,
    authority,
    capabilities: Object.freeze<ScimCapabilities>({
      patch: true,
      bulk: false,
      filter: true,
      sort: true,
      etag: true,
    }),
  });
}

export function pluginSettings(input: ScimPluginSettings) {
  const value = fields(input, [
    'users',
    'groups',
    'authority',
    'maxPageSize',
    'maxFilterDepth',
    'capabilities',
    'maxRequestBytes',
    'maxConcurrent',
  ]);
  const capabilities = fields(value.capabilities, ['patch', 'bulk', 'filter', 'sort', 'etag']);
  if (
    capabilities.patch !== true ||
    capabilities.bulk !== false ||
    capabilities.filter !== true ||
    typeof capabilities.sort !== 'boolean' ||
    typeof capabilities.etag !== 'boolean'
  )
    throw failure('EK_CONFIG_INVALID');
  return Object.freeze({
    users: provider(value.users as ScimProvider, 'test'),
    groups: provider(value.groups as ScimProvider, 'test'),
    authority: Object.freeze({
      require: method<TrustedSecurityAuthority['require']>(value.authority, 'require'),
    }),
    maxPageSize: integer(value.maxPageSize, 1000),
    maxFilterDepth: integer(value.maxFilterDepth, 16),
    maxRequestBytes: integer(value.maxRequestBytes, 262144),
    maxConcurrent: integer(value.maxConcurrent, 128),
    capabilities: Object.freeze(capabilities) as unknown as ScimCapabilities,
    testOnly: [value.users, value.groups, value.authority].some(testOnly),
  });
}
