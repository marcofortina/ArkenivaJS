// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import type {
  TenantRegistryActivationCheckpoint,
  TenantRegistrySnapshotV1_1,
} from './contracts.js';
import { registryFailure } from './errors.js';

export function data(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw registryFailure();
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== 'string' || (allowed && !allowed.includes(key))) throw registryFailure();
    const field = Object.getOwnPropertyDescriptor(input, key);
    if (!field || !('value' in field) || !field.enumerable) throw registryFailure();
    output[key] = field.value;
  }
  return output;
}

export function captureMethod<T extends (...args: never[]) => unknown>(
  input: unknown,
  name: string,
): T {
  if (!input || typeof input !== 'object') throw registryFailure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 64; depth++) {
    if (types.isProxy(current)) throw registryFailure();
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field) || typeof field.value !== 'function' || types.isProxy(field.value))
        throw registryFailure();
      const callback = field.value;
      return ((...args: Parameters<T>): ReturnType<T> => Reflect.apply(callback, input, args)) as T;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw registryFailure();
}

/** A deadline aborts outstanding cooperative I/O and prevents late publication after timeout. */
export async function registryOperation<T>(
  work: (options: Required<OperationOptions>, check: () => void) => Promise<T>,
  input: OperationOptions = {},
): Promise<T> {
  const controller = new AbortController();
  try {
    const value = data(input, ['signal', 'timeoutMs']);
    const timeoutMs = value.timeoutMs === undefined ? 30000 : value.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || (timeoutMs as number) < 1) throw registryFailure();
    const signal =
      value.signal === undefined
        ? controller.signal
        : AbortSignal.any([controller.signal, captureAbortSignal(value.signal)]);
    const options = { timeoutMs: timeoutMs as number, signal };
    const deadline = performance.now() + options.timeoutMs;
    const check = () => {
      signal.throwIfAborted();
      if (performance.now() >= deadline) {
        controller.abort();
        throw registryFailure();
      }
    };
    return await within(() => work(options, check), options);
  } catch {
    throw registryFailure();
  } finally {
    controller.abort();
  }
}

/** Local startup history is bounded; durable cross-process enforcement is an injected authority. */
export class ActivationHistory {
  private readonly revisions = new Map<string, string>();
  private current: TenantRegistrySnapshotV1_1 | undefined;
  private readonly checkpoint: TenantRegistryActivationCheckpoint['accept'] | undefined;
  constructor(checkpoint?: TenantRegistryActivationCheckpoint) {
    this.checkpoint =
      checkpoint === undefined
        ? undefined
        : captureMethod<TenantRegistryActivationCheckpoint['accept']>(checkpoint, 'accept');
  }
  async accept(
    snapshot: TenantRegistrySnapshotV1_1,
    scope: string,
    options: Required<OperationOptions>,
    check: () => void,
  ) {
    check();
    const previous = this.revisions.get(snapshot.revision),
      current = this.current;
    if (
      (previous !== undefined && previous !== snapshot.contentChecksum) ||
      (current &&
        (snapshot.activationGeneration < current.activationGeneration ||
          (snapshot.activationGeneration === current.activationGeneration &&
            (snapshot.revision !== current.revision ||
              snapshot.contentChecksum !== current.contentChecksum ||
              snapshot.activatedAt !== current.activatedAt)))) ||
      (previous === undefined && this.revisions.size >= 10000)
    )
      throw registryFailure();
    if (this.checkpoint)
      await this.checkpoint(
        {
          scope,
          activationGeneration: snapshot.activationGeneration,
          revision: snapshot.revision,
          contentChecksum: snapshot.contentChecksum,
        },
        options,
      );
    check();
    this.revisions.set(snapshot.revision, snapshot.contentChecksum);
    this.current = snapshot;
  }
}
