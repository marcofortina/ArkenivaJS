// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** A successful receipt is returned only after the durable backend acknowledges commit. */
export type DurableMutationReceipt = Readonly<{ committed: boolean; version?: string }>;
/** Indexed ownership metadata is separate from the application fields. */
export interface SecurityIndexedRecord {
  readonly id: string;
  readonly ownerKey: string;
  readonly version: string;
  readonly expiresAt?: string;
  readonly fields: Readonly<Record<string, unknown>>;
}
/** All predicates must hold or no mutation in the batch commits. */
export interface SecurityAtomicMutation {
  readonly namespace: string;
  readonly id: string;
  readonly expectedVersion: string | null;
  readonly next: Readonly<Record<string, unknown>> | null;
  readonly ownerKey: string;
}
/** Shared one-use and versioned state; read returns backend version metadata with the fields. */
export interface SecurityStateStore {
  claimOnce(
    namespace: string,
    digest: string,
    expiresAt: string,
    options?: OperationOptions,
  ): Promise<boolean>;
  compareAndSet(
    namespace: string,
    id: string,
    expectedVersion: string | null,
    next: Readonly<Record<string, unknown>> | null,
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt>;
  read(
    namespace: string,
    id: string,
    options?: OperationOptions,
  ): Promise<Readonly<Record<string, unknown>> | null>;
}
/** Durable all-or-nothing batches, bounded ownership indexes and monotonic revocation epochs. */
export interface SecurityTransactionalStore extends SecurityStateStore {
  atomicBatch(
    mutations: readonly SecurityAtomicMutation[],
    options?: OperationOptions,
  ): Promise<DurableMutationReceipt>;
  listByOwner(
    namespace: string,
    ownerKey: string,
    limit: number,
    options?: OperationOptions,
  ): Promise<readonly SecurityIndexedRecord[]>;
  bumpOwnerEpoch(namespace: string, ownerKey: string, options?: OperationOptions): Promise<number>;
  currentOwnerEpoch(
    namespace: string,
    ownerKey: string,
    options?: OperationOptions,
  ): Promise<number>;
}
