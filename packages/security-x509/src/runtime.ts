// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { MtlsTrustProvider, X509PluginSettings } from './contracts.js';
import { nativeCertificate, fingerprint, parseError } from './certificate.js';

export const failure = (code: ErrorCode = 'EK_X509_UNTRUSTED') =>
  new KitError({ code, message: 'The certificate operation could not complete safely' });
export const invalid = () => failure('EK_CONFIG_INVALID');

/** Capture exact data properties without invoking accessors or caller serialization hooks. */
export function data(value: unknown, names: readonly string[]): Record<string, unknown> {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw parseError();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== 'string' || !names.includes(key)) throw parseError();
      const field = descriptors[key]!;
      if (!('value' in field)) throw parseError();
      result[key] = field.value;
    }
    return result;
  } catch {
    throw parseError();
  }
}
export function list(value: unknown, maximum: number, minimum = 0): unknown[] {
  try {
    if (!Array.isArray(value)) throw parseError();
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value as unknown;
    if (
      !Number.isSafeInteger(length) ||
      (length as number) < minimum ||
      (length as number) > maximum
    )
      throw parseError();
    const result: unknown[] = [];
    const fields = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(fields).length !== (length as number) + 1) throw parseError();
    for (let index = 0; index < (length as number); index++) {
      const field = fields[String(index)];
      if (!field || !('value' in field)) throw parseError();
      result.push(field.value);
    }
    return result;
  } catch {
    throw parseError();
  }
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw invalid();
  return value as number;
}
function signal(value: unknown): asserts value is AbortSignal {
  try {
    if (!(value instanceof AbortSignal)) throw invalid();
    let current: object | null = value;
    while (current !== AbortSignal.prototype) {
      if (!current) throw invalid();
      for (const key of ['aborted', 'reason', 'addEventListener', 'removeEventListener'])
        if (Object.getOwnPropertyDescriptor(current, key)) throw invalid();
      current = Object.getPrototypeOf(current) as object | null;
    }
    Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value);
  } catch {
    throw invalid();
  }
}
function providerMethod(value: unknown): MtlsTrustProvider['verifyChainAndRevocation'] {
  if (!value || typeof value !== 'object') throw invalid();
  let current: object | null = value;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, 'verifyChainAndRevocation');
    if (field) {
      if (!('value' in field) || typeof field.value !== 'function') throw invalid();
      return field.value.bind(value) as MtlsTrustProvider['verifyChainAndRevocation'];
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw invalid();
}
function providerUsage(value: object): unknown {
  let current: object | null = value;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, 'usage');
    if (field) {
      if (!('value' in field) || !['production', 'test-only'].includes(field.value as string))
        throw invalid();
      return field.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}
export function captureSettings(input: X509PluginSettings) {
  try {
    const settings = data(input, ['trustRoots', 'trustProvider', 'policy']);
    const policy = data(settings.policy, [
      'maxConcurrent',
      'timeoutMs',
      'maxInputBytes',
      'maxOutputBytes',
    ]);
    const maxConcurrent = integer(policy.maxConcurrent, 1024),
      timeoutMs = integer(policy.timeoutMs, 120000);
    const maxInputBytes =
      policy.maxInputBytes === undefined ? 1048576 : integer(policy.maxInputBytes, 1048576);
    const maxOutputBytes =
      policy.maxOutputBytes === undefined ? 65536 : integer(policy.maxOutputBytes, 1048576);
    if (maxInputBytes * maxConcurrent > 134217728) throw invalid();
    if (
      !settings.trustRoots ||
      typeof settings.trustRoots !== 'object' ||
      Array.isArray(settings.trustRoots)
    )
      throw invalid();
    const fields = Object.getOwnPropertyDescriptors(settings.trustRoots),
      keys = Reflect.ownKeys(fields);
    if (keys.length < 1 || keys.length > 64) throw invalid();
    const roots = new Map<string, readonly ReturnType<typeof nativeCertificate>[]>(),
      sets = new Set<string>();
    let bytes = 0;
    for (const key of keys) {
      if (typeof key !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(key))
        throw invalid();
      const field = fields[key]!;
      if (!('value' in field)) throw invalid();
      const certificates = list(field.value, 16, 1).map((value) =>
        nativeCertificate(value as Uint8Array),
      );
      const identities = certificates
        .map((certificate) => {
          bytes += certificate.raw.length;
          if (!certificate.ca || bytes > maxInputBytes) throw invalid();
          return fingerprint(certificate.fingerprint256);
        })
        .sort();
      if (new Set(identities).size !== identities.length || sets.has(identities.join(',')))
        throw invalid();
      sets.add(identities.join(','));
      roots.set(key, Object.freeze(certificates));
    }
    const verify = providerMethod(settings.trustProvider);
    return Object.freeze({
      maxConcurrent,
      timeoutMs,
      maxInputBytes,
      maxOutputBytes,
      roots,
      verify,
      usage: providerUsage(settings.trustProvider as object),
    });
  } catch {
    throw invalid();
  }
}
export type Settings = ReturnType<typeof captureSettings>;
export interface Call {
  readonly options: OperationOptions;
  check(): void;
}

/** A provider that ignores cancellation keeps its admission slot until it actually settles. */
export function createRuntime(settings: Settings) {
  const shutdown = new AbortController(),
    active = new Set<AbortController>();
  let closed = false;
  const checkOpen = () => {
    if (closed) throw failure('EK_RESOURCE_CLOSED');
  };
  async function run<T>(
    input: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
  ): Promise<T> {
    checkOpen();
    let options: OperationOptions;
    try {
      options = data(input === undefined ? {} : input, ['signal', 'timeoutMs']) as OperationOptions;
    } catch {
      throw invalid();
    }
    const timeoutMs =
      options.timeoutMs === undefined
        ? settings.timeoutMs
        : integer(options.timeoutMs, settings.timeoutMs);
    if (options.signal !== undefined) signal(options.signal);
    if (options.signal?.aborted) throw failure('EK_ABORTED');
    if (active.size >= settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    const controller = new AbortController();
    const combined = AbortSignal.any([
      shutdown.signal,
      controller.signal,
      ...(options.signal ? [options.signal] : []),
    ]);
    const deadline = performance.now() + timeoutMs;
    const check = () => {
      checkOpen();
      if (combined.aborted) throw failure('EK_ABORTED');
      if (performance.now() >= deadline) throw failure('EK_TIMEOUT');
    };
    active.add(controller);
    const task = Promise.resolve().then(async () => {
      try {
        check();
        const result = await work({
          options: Object.freeze({ signal: combined, timeoutMs }),
          check,
        });
        check();
        return result;
      } finally {
        active.delete(controller);
      }
    });
    try {
      return await within(() => task, { signal: combined, timeoutMs });
    } catch (error) {
      if (error instanceof KitError) throw failure(error.code);
      throw failure();
    } finally {
      controller.abort();
    }
  }
  return {
    run,
    checkOpen,
    bootstrap(applicationSignal: AbortSignal) {
      checkOpen();
      signal(applicationSignal);
      if (applicationSignal.aborted) throw failure('EK_ABORTED');
      const now = Date.now();
      for (const roots of settings.roots.values())
        for (const root of roots)
          if (root.validFromDate.getTime() > now || root.validToDate.getTime() <= now)
            throw invalid();
    },
    close() {
      if (!closed) {
        closed = true;
        shutdown.abort();
      }
    },
  };
}
