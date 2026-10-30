// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute, resolve } from 'node:path';
import { types, toUSVString } from 'node:util';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import type { SoapPluginSettings, SoapServiceProfile, SecretProvider } from './contracts.js';
import { failure, hasControls } from './validation.js';

export function fields(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    Array.isArray(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure('EK_CONFIG_INVALID');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure('EK_CONFIG_INVALID');
    result[key] = descriptor.value;
  }
  return result;
}
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
export function text(value: unknown, maximum = 256): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    hasControls(value)
  )
    throw failure('EK_CONFIG_INVALID');
  return value;
}
export function array(input: unknown, maximum: number): unknown[] {
  if (
    !Array.isArray(input) ||
    types.isProxy(input) ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure('EK_CONFIG_INVALID');
  return Array.from({ length: input.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
    return descriptor.value;
  });
}
function property(input: unknown, key: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input))
    throw failure('EK_CONFIG_INVALID');
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw failure('EK_CONFIG_INVALID');
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) {
      if (!('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure('EK_CONFIG_INVALID');
  return undefined;
}
function captureSettings(input: SoapPluginSettings) {
  const root = fields(input, ['services', 'secretProvider', 'policy']),
    policy = fields(root.policy, ['maxConcurrent', 'timeoutMs', 'maxInputBytes', 'maxOutputBytes']);
  const get = property(root.secretProvider, 'get'),
    usage = property(root.secretProvider, 'usage');
  if (
    typeof get !== 'function' ||
    types.isProxy(get) ||
    (usage !== undefined && !['production', 'test-only'].includes(usage as string))
  )
    throw failure('EK_CONFIG_INVALID');
  const services = array(root.services, 16).map((input): SoapServiceProfile => {
    const value = fields(input, [
      'id',
      'wsdlFile',
      'endpoint',
      'allowedOperations',
      'protocol',
      'credentialsRef',
      'trustedCaRef',
      'maxResponseBytes',
    ]);
    const id = text(value.id, 64),
      wsdlFile = text(value.wsdlFile, 4096),
      endpoint = new URL(text(value.endpoint, 2048));
    if (
      !/^[a-z][a-z0-9._-]*$/.test(id) ||
      !isAbsolute(wsdlFile) ||
      resolve(wsdlFile) !== wsdlFile ||
      endpoint.protocol !== 'https:' ||
      endpoint.username ||
      endpoint.password ||
      endpoint.hash ||
      !['1.1', '1.2'].includes(value.protocol as string)
    )
      throw failure('EK_CONFIG_INVALID');
    const allowedOperations = array(value.allowedOperations, 128).map((value) => {
      const operation = text(value, 128);
      if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(operation)) throw failure('EK_CONFIG_INVALID');
      return operation;
    });
    if (!allowedOperations.length || new Set(allowedOperations).size !== allowedOperations.length)
      throw failure('EK_CONFIG_INVALID');
    return Object.freeze({
      id,
      wsdlFile,
      endpoint: endpoint.href,
      allowedOperations: Object.freeze(allowedOperations),
      protocol: value.protocol as '1.1' | '1.2',
      maxResponseBytes: integer(value.maxResponseBytes, 8388608),
      ...(value.credentialsRef === undefined ? {} : { credentialsRef: text(value.credentialsRef) }),
      ...(value.trustedCaRef === undefined ? {} : { trustedCaRef: text(value.trustedCaRef) }),
    });
  });
  if (!services.length || new Set(services.map((value) => value.id)).size !== services.length)
    throw failure('EK_CONFIG_INVALID');
  return Object.freeze({
    services: Object.freeze(services),
    get: (reference: string, options?: OperationOptions) =>
      Reflect.apply(get, root.secretProvider, [reference, options]) as ReturnType<
        SecretProvider['get']
      >,
    testOnly: usage === 'test-only',
    maxConcurrent: integer(policy.maxConcurrent, 4),
    timeoutMs: integer(policy.timeoutMs, 60000),
    maxInputBytes: integer(policy.maxInputBytes ?? 1048576, 8388608),
    maxOutputBytes: integer(policy.maxOutputBytes ?? 1048576, 8388608),
  });
}
export function capture(input: SoapPluginSettings) {
  try {
    return captureSettings(input);
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
export function operation(input: OperationOptions | undefined, maximum: number): OperationOptions {
  const data = fields(input === undefined ? {} : input, ['timeoutMs', 'signal']);
  return {
    timeoutMs: data.timeoutMs === undefined ? maximum : integer(data.timeoutMs, maximum),
    ...(data.signal === undefined ? {} : { signal: captureAbortSignal(data.signal) }),
  };
}
