// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { CryptoPluginSettings, SecretValue } from './contracts.js';

export const failure = (code: ErrorCode) =>
  new KitError({ code, message: 'The cryptographic operation could not complete safely' });
export const invalid = () => failure('EK_CONFIG_INVALID');
export const format = () => failure('EK_CRYPTO_FORMAT');
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)!.get!;
const arrayBuffer = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'buffer',
)!.get!;

/** Read bounded data properties without invoking accessors or serialization callbacks. */
export function data(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw format();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const name of Reflect.ownKeys(descriptors)) {
    if (typeof name !== 'string' || !names.includes(name)) throw format();
    const field = descriptors[name]!;
    if (!('value' in field)) throw format();
    result[name] = field.value;
  }
  return result;
}
export function text(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 512 ||
    [...value].some((character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127)
  )
    throw format();
}
/** Copy through native typed-array operations, rejecting shared backing memory and hooks. */
export function bytes(value: unknown, maximum: number, exact?: number): Buffer {
  try {
    if (!(value instanceof Uint8Array)) throw format();
    const length: number = byteLength.call(value);
    if (
      length > maximum ||
      (exact !== undefined && length !== exact) ||
      arrayBuffer.call(value) instanceof SharedArrayBuffer
    )
      throw format();
    const result = Buffer.alloc(length);
    Uint8Array.prototype.set.call(result, value);
    return result;
  } catch {
    throw format();
  }
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw invalid();
  return value as number;
}
function validateSignal(value: unknown): asserts value is AbortSignal {
  try {
    if (!(value instanceof AbortSignal)) throw invalid();
    let current: object | null = value;
    while (current !== AbortSignal.prototype) {
      if (!current) throw invalid();
      for (const name of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
        if (Object.getOwnPropertyDescriptor(current, name)) throw invalid();
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
    Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value);
  } catch {
    throw invalid();
  }
}
function references(input: unknown): ReadonlySet<string> {
  if (!Array.isArray(input) || input.length > 1024) throw invalid();
  const fields = Object.getOwnPropertyDescriptors(input),
    result = new Set<string>();
  if (Reflect.ownKeys(fields).length !== input.length + 1) throw invalid();
  for (let index = 0; index < input.length; index++) {
    const field = fields[String(index)];
    if (!field || !('value' in field)) throw invalid();
    text(field.value);
    if (result.has(field.value)) throw invalid();
    result.add(field.value);
  }
  return result;
}
function getMethod(
  provider: unknown,
): (reference: string, options?: OperationOptions) => Promise<SecretValue> {
  if (!provider || typeof provider !== 'object') throw invalid();
  let current: object | null = provider;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, 'get');
    if (field) {
      if (!('value' in field) || typeof field.value !== 'function') throw invalid();
      return field.value.bind(provider) as (
        reference: string,
        options?: OperationOptions,
      ) => Promise<SecretValue>;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw invalid();
}
function providerUsage(provider: unknown): 'production' | 'test-only' | undefined {
  if (!provider || typeof provider !== 'object') throw invalid();
  let current: object | null = provider;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, 'usage');
    if (field) {
      if (!('value' in field) || !['production', 'test-only'].includes(field.value as string))
        throw invalid();
      return field.value as 'production' | 'test-only';
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}
export function captureSettings(input: CryptoPluginSettings) {
  try {
    const settings = data(input, ['secrets', 'signingKeyRefs', 'encryptionKeyRefs', 'policy']);
    const policy = data(settings.policy, [
      'maxConcurrent',
      'timeoutMs',
      'maxInputBytes',
      'maxOutputBytes',
    ]);
    const maxConcurrent = integer(policy.maxConcurrent, 1024),
      timeoutMs = integer(policy.timeoutMs, 120000);
    const maxInputBytes =
      policy.maxInputBytes === undefined ? 1048576 : integer(policy.maxInputBytes, 16777216);
    const maxOutputBytes =
      policy.maxOutputBytes === undefined
        ? maxInputBytes + 28
        : integer(policy.maxOutputBytes, 16777244);
    if (maxInputBytes * maxConcurrent > 134217728) throw invalid();
    const signing = references(settings.signingKeyRefs),
      encryption = references(settings.encryptionKeyRefs);
    if (signing.size + encryption.size < 1) throw invalid();
    return Object.freeze({
      maxConcurrent,
      timeoutMs,
      maxInputBytes,
      maxOutputBytes,
      signing,
      encryption,
      get: getMethod(settings.secrets),
      usage: providerUsage(settings.secrets),
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
/** An unsettled provider retains its slot even after the public timeout. */
export function createRuntime(settings: Settings) {
  const shutdown = new AbortController(),
    active = new Set<AbortController>();
  let closed = false;
  async function run<T>(
    input: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
  ): Promise<T> {
    if (closed) throw failure('EK_RESOURCE_CLOSED');
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
    if (options.signal !== undefined) validateSignal(options.signal);
    if (options.signal?.aborted) throw failure('EK_ABORTED');
    if (active.size >= settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    const controller = new AbortController();
    const signal = AbortSignal.any([
      shutdown.signal,
      controller.signal,
      ...(options.signal ? [options.signal] : []),
    ]);
    const deadline = performance.now() + timeoutMs;
    const check = () => {
      if (closed) throw failure('EK_RESOURCE_CLOSED');
      if (signal.aborted) throw failure('EK_ABORTED');
      if (performance.now() >= deadline) throw failure('EK_TIMEOUT');
    };
    active.add(controller);
    const task = Promise.resolve().then(async () => {
      try {
        check();
        const result = await work({ options: Object.freeze({ signal, timeoutMs }), check });
        try {
          check();
        } catch (error) {
          if (result instanceof Uint8Array) Uint8Array.prototype.fill.call(result, 0);
          throw error;
        }
        return result;
      } finally {
        active.delete(controller);
      }
    });
    // Observe owned work even if the public wait expires before invoking its factory.
    void task.catch(() => undefined);
    try {
      return await within(() => task, { signal, timeoutMs });
    } catch (error) {
      if (error instanceof KitError) throw failure(error.code);
      throw format();
    } finally {
      controller.abort();
    }
  }
  async function key(reference: string, allowed: ReadonlySet<string>, call: Call, exact?: number) {
    text(reference);
    if (!allowed.has(reference)) throw failure('EK_CRYPTO_KEY_UNAVAILABLE');
    call.check();
    let material: Buffer | undefined;
    try {
      const result = await settings.get(reference, call.options);
      call.check();
      const secret = data(result, ['bytes', 'keyVersion', 'expiresAt']);
      text(secret.keyVersion);
      if (secret.expiresAt !== undefined) {
        if (
          typeof secret.expiresAt !== 'string' ||
          !Number.isFinite(Date.parse(secret.expiresAt)) ||
          new Date(secret.expiresAt).toISOString() !== secret.expiresAt ||
          Date.parse(secret.expiresAt) <= Date.now()
        )
          throw format();
      }
      material = bytes(secret.bytes, 16384, exact);
      if (material.length < 32) throw format();
      return { material, version: secret.keyVersion };
    } catch (error) {
      material?.fill(0);
      call.check();
      if (
        error instanceof KitError &&
        ['EK_ABORTED', 'EK_TIMEOUT', 'EK_RESOURCE_CLOSED'].includes(error.code)
      )
        throw failure(error.code);
      throw failure('EK_CRYPTO_KEY_UNAVAILABLE');
    }
  }
  return {
    run,
    key,
    close() {
      if (!closed) {
        closed = true;
        shutdown.abort();
      }
    },
    async bootstrap(signal: AbortSignal) {
      await run({ signal }, async (call) => {
        for (const reference of new Set([...settings.encryption, ...settings.signing])) {
          const secret = await key(
            reference,
            settings.encryption.has(reference) ? settings.encryption : settings.signing,
            call,
            settings.encryption.has(reference) ? 32 : undefined,
          );
          secret.material.fill(0);
        }
      });
    },
  };
}
