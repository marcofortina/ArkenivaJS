// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
export interface SoapResult<T = unknown> {
  readonly data: T;
  readonly headers: Readonly<Record<string, string>>;
  readonly status: number;
  readonly correlationId: string;
}
export interface SoapDescription {
  readonly serviceId: string;
  readonly operations: readonly string[];
  readonly protocol: '1.1' | '1.2';
}
export interface SoapClient {
  call<T = unknown>(
    operation: string,
    input: unknown,
    options?: OperationOptions,
  ): Promise<SoapResult<T>>;
  describe(): SoapDescription;
  close(): Promise<void>;
  /** The actual approved native client remains owned and constrained by its application. */
  native(): unknown;
}
export interface SoapService {
  createClient(serviceId: string, options?: OperationOptions): Promise<SoapClient>;
}
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface SoapServiceProfile {
  readonly id: string;
  readonly wsdlFile: string;
  readonly endpoint: string;
  readonly allowedOperations: readonly string[];
  readonly protocol: '1.1' | '1.2';
  readonly credentialsRef?: string;
  readonly trustedCaRef?: string;
  readonly maxResponseBytes: number;
}
export interface SoapPluginSettings {
  readonly services: readonly SoapServiceProfile[];
  readonly secretProvider: SecretProvider;
  readonly policy: BoundedRuntimePolicy;
}
