// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** Externally managed secret bytes with an opaque immutable version and optional expiry. */
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
/** Trusted application configuration supplies this provider; references are never raw keys. */
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
/** Version-aware HMAC port for distributed security stores; raw keys never enter a store. */
export interface KeyedDigestProvider {
  readonly algorithm: 'HMAC-SHA256';
  digest(
    domain: string,
    parts: readonly string[],
    keyRef: string,
    options?: OperationOptions,
  ): Promise<string>;
  verify(
    domain: string,
    parts: readonly string[],
    expected: string,
    keyRef: string,
    options?: OperationOptions,
  ): Promise<boolean>;
}
/** Finite per-instance admission, deadline and byte budgets; no hidden operation queue. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Explicit approved references, resolved only through the configured external provider. */
export interface CryptoPluginSettings {
  readonly secrets: SecretProvider;
  readonly signingKeyRefs: readonly string[];
  readonly encryptionKeyRefs: readonly string[];
  readonly policy: BoundedRuntimePolicy;
}
/** Versioned authenticated envelope; persist bytes losslessly and retain its key version. */
export interface SealedEnvelope {
  readonly version: 1;
  readonly keyId: string;
  readonly algorithm: 'AES-256-GCM';
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}
/** Bounded native cryptography; application code supplies authenticated tenant/purpose AAD. */
export interface CryptoService {
  encrypt(
    plaintext: Uint8Array,
    keyRef: string,
    aad?: Uint8Array,
    options?: OperationOptions,
  ): Promise<SealedEnvelope>;
  decrypt(
    envelope: SealedEnvelope,
    keyRef: string,
    aad?: Uint8Array,
    options?: OperationOptions,
  ): Promise<Uint8Array>;
  hmac(input: Uint8Array, keyRef: string, options?: OperationOptions): Promise<Uint8Array>;
  verifyMac(
    input: Uint8Array,
    mac: Uint8Array,
    keyRef: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  sign(input: Uint8Array, keyRef: string, options?: OperationOptions): Promise<Uint8Array>;
  verifySignature(
    input: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    options?: OperationOptions,
  ): Promise<boolean>;
}
