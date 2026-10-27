// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type { SecretProvider } from '@arkenivajs/security-crypto';
export type { SecretProvider, SecretValue } from '@arkenivajs/security-crypto';

export interface LdapSettings {
  readonly url: string;
  readonly baseDn: string;
  readonly userFilterTemplate: string;
  readonly groupSearchBaseDn: string;
  readonly serviceBindDnRef: string;
  readonly serviceBindPasswordRef: string;
  readonly secretProvider: SecretProvider;
  readonly tlsTrustBundleRef?: string;
  readonly requireStartTls?: boolean;
  readonly maxEntries?: number;
  readonly maxGroupDepth?: number;
  readonly timeoutMs?: number;
  /** Attribute names approved by the application; credential attributes are always forbidden. */
  readonly allowedAttributes?: readonly string[];
  /** Standalone factories default to production; plugin settings must match the core environment. */
  readonly environment?: 'development' | 'test' | 'production';
}
export interface LdapUser {
  readonly dn: string;
  readonly uid: string;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
}
export interface LdapGroup {
  readonly dn: string;
  readonly name: string;
}
export interface LdapEntry {
  readonly dn: string;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
}
export interface LdapSearchQuery {
  readonly baseDn: string;
  readonly filter: Readonly<{ template: string; values: Readonly<Record<string, string>> }>;
  readonly attributes: readonly string[];
  readonly maxEntries?: number;
  readonly pageSize?: number;
}
export interface LdapService {
  findUser(
    query: Readonly<{ username: string }>,
    options?: OperationOptions,
  ): Promise<LdapUser | null>;
  getGroups(userDn: string, options?: OperationOptions): Promise<readonly LdapGroup[]>;
  search(query: LdapSearchQuery, options?: OperationOptions): AsyncIterable<LdapEntry>;
  verifyCredentials(
    identity: Readonly<{ username: string }>,
    password: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  ping(options?: OperationOptions): Promise<boolean>;
}
/** Private one-request worker input; passwords never enter arguments, environment, logs or disk. */
export interface WorkerInput {
  readonly operation: 'find' | 'groups' | 'search' | 'verify' | 'ping';
  readonly url: string;
  readonly startTls: boolean;
  readonly bindDn: string;
  readonly bindPassword: string;
  readonly ca?: string;
  readonly baseDn: string;
  readonly groupBase: string;
  readonly template: string;
  readonly allowedAttributes: readonly string[];
  readonly maxEntries: number;
  readonly maxDepth: number;
  readonly timeoutMs: number;
  readonly query?: LdapSearchQuery;
  readonly username?: string;
  readonly password?: string;
  readonly userDn?: string;
}
