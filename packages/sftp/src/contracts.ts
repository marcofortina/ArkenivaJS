// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** External versioned key material; provider-owned bytes are never mutated. */
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
/** Deployment-owned secret authority, with cooperative cancellation and finite deadlines. */
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
/** Trusted named endpoint, host-key pins and approved absolute remote roots. */
export interface SftpConnectionProfile {
  readonly name: string;
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly privateKeyRef: string;
  readonly knownHostSha256: readonly string[];
  readonly allowedRemoteRoots: readonly string[];
}
/** Finite admission, operation duration and directional byte budgets. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Explicit startup configuration; profiles and command catalogs are never request data. */
export interface SftpPluginSettings {
  readonly connections: readonly SftpConnectionProfile[];
  readonly secretProvider: SecretProvider;
  readonly policy: BoundedRuntimePolicy;
  readonly allowedCommands?: Readonly<
    Record<string, Readonly<{ executable: string; arguments: readonly string[] }>>
  >;
}
/** Observed transferred bytes and optional digest; this does not certify durable publication. */
export interface TransferReceipt {
  readonly remotePath: string;
  readonly transferredBytes: number;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly sha256?: string;
}
/** Per-call transfer bounds; overwrite defaults to exclusive creation. */
export interface SftpOptions extends OperationOptions {
  readonly overwrite?: 'fail' | 'replace';
  readonly maxBytes?: number;
}
/** Required atomic guarantees must be proven before any remote mutation. */
export interface SftpRenameOptions extends OperationOptions {
  readonly overwrite?: 'fail' | 'replace';
  readonly requireAtomic?: boolean;
}
/** Server-capability proof and destination existence observed before submission. */
export interface SftpRenameReceipt {
  readonly source: string;
  readonly destination: string;
  readonly atomicity: 'confirmed' | 'not-guaranteed';
  readonly replaced: boolean;
}
/** Immutable directory metadata; listing never follows a link entry. */
export interface SftpEntry {
  readonly path: string;
  readonly sizeBytes: number;
  readonly type: 'file' | 'directory' | 'link';
}
/** Lifecycle-owned transfers and publication under deployment-approved roots. */
export interface SftpService {
  /** Stream independent bounded chunks; interruption can leave an explicit partial outcome. */
  upload(
    connection: string,
    source: AsyncIterable<Uint8Array>,
    remotePath: string,
    options?: SftpOptions,
  ): Promise<TransferReceipt>;
  /** Await destination backpressure and enforce the output budget throughout transfer. */
  download(
    connection: string,
    remotePath: string,
    destination: (part: Uint8Array) => Promise<void>,
    options?: SftpOptions,
  ): Promise<TransferReceipt>;
  /** Read a finite native directory cursor without following symlinks. */
  list(
    connection: string,
    remoteDir: string,
    options?: OperationOptions,
  ): Promise<readonly SftpEntry[]>;
  /** Use native rename semantics and never silently delete an existing destination. */
  rename(
    connection: string,
    sourcePath: string,
    destinationPath: string,
    options?: SftpRenameOptions,
  ): Promise<SftpRenameReceipt>;
  /** Expose the actual approved SDK to trusted application code that deliberately narrows it. */
  native(connection: string): unknown;
}
/** Jointly bounded stdout/stderr; truncation cannot imply confirmed remote success. */
export interface CommandReceipt {
  readonly exitCode: number | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  readonly truncated: boolean;
}
/** Execute only trusted catalog IDs with literal, separately bound arguments. */
export interface SshService {
  exec(
    connection: string,
    commandId: string,
    args: Readonly<Record<string, string>>,
    options?: OperationOptions,
  ): Promise<CommandReceipt>;
}
