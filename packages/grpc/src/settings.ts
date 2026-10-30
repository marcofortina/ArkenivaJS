// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute, resolve } from 'node:path';
import { types } from 'node:util';
import { copyData, freezeData, captureAbortSignal } from '@arkenivajs/core/support';
import type {
  GrpcPluginSettings,
  GrpcPolicy,
  GrpcCallOptions,
  GrpcHandler,
  TrustedSecurityAuthority,
} from './contracts.js';
import type { TlsProfile } from '@arkenivajs/security-mtls';
import { failure } from './errors.js';

export function fields(value: unknown): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    Array.isArray(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value))
  )
    throw failure('EK_CONFIG_INVALID');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      !property ||
      !('value' in property)
    )
      throw failure('EK_CONFIG_INVALID');
    result[key] = property.value;
  }
  return result;
}
function property(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value))
    throw failure('EK_CONFIG_INVALID');
  let current: object | null = value;
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
export function integer(value: unknown, max: number, min = 1): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
export function name(value: unknown): string {
  if (typeof value !== 'string' || value.length > 256 || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(value))
    throw failure('EK_CONFIG_INVALID');
  return value;
}
function names(value: unknown): readonly string[] {
  const data = copyData(value);
  if (!Array.isArray(data) || data.length < 1 || data.length > 128)
    throw failure('EK_CONFIG_INVALID');
  const result = data.map(name);
  if (new Set(result).size !== result.length) throw failure('EK_CONFIG_INVALID');
  return Object.freeze(result);
}
export function policy(input: GrpcPolicy): GrpcPolicy {
  const data = fields(input);
  if (typeof data.requireAuthentication !== 'boolean') throw failure('EK_CONFIG_INVALID');
  return Object.freeze({
    maxInboundBytes: integer(data.maxInboundBytes, 8388608),
    maxOutboundBytes: integer(data.maxOutboundBytes, 8388608),
    concurrencyLimit: integer(data.concurrencyLimit, 1024),
    requireAuthentication: data.requireAuthentication,
    methodAllowlist: names(data.methodAllowlist),
  });
}
export function handlers(
  input: Readonly<Record<string, GrpcHandler>>,
): Readonly<Record<string, GrpcHandler>> {
  const result: Record<string, GrpcHandler> = Object.create(null);
  const entries = Object.entries(fields(input));
  if (!entries.length || entries.length > 128) throw failure('EK_CONFIG_INVALID');
  for (const [key, value] of entries) {
    name(key);
    if (typeof value !== 'function' || types.isProxy(value)) throw failure('EK_CONFIG_INVALID');
    result[key] = value as GrpcHandler;
  }
  return Object.freeze(result);
}
export function capture(input: GrpcPluginSettings) {
  try {
    const data = fields(input),
      limits = fields(data.policy),
      authorize = property(data.authority, 'require'),
      usage = property(data.authority, 'usage');
    if (
      typeof authorize !== 'function' ||
      types.isProxy(authorize) ||
      (usage !== undefined && !['production', 'test-only'].includes(usage as string))
    )
      throw failure('EK_CONFIG_INVALID');
    const profiles = freezeData(copyData(data.tlsProfiles)) as Readonly<Record<string, TlsProfile>>;
    const keys = Object.keys(fields(profiles));
    if (keys.length < 1 || keys.length > 16) throw failure('EK_CONFIG_INVALID');
    keys.forEach(name);
    const services = copyData(data.services);
    if (!Array.isArray(services) || !services.length || services.length > 16)
      throw failure('EK_CONFIG_INVALID');
    const captured = services.map((input) => {
      const profile = fields(input),
        serviceName = name(profile.name),
        descriptorFile = profile.descriptorFile;
      if (
        typeof descriptorFile !== 'string' ||
        descriptorFile.length > 4096 ||
        !isAbsolute(descriptorFile) ||
        resolve(descriptorFile) !== descriptorFile
      )
        throw failure('EK_CONFIG_INVALID');
      let endpoint: string | undefined;
      if (profile.endpoint !== undefined) {
        if (
          typeof profile.endpoint !== 'string' ||
          !/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(profile.endpoint)
        )
          throw failure('EK_CONFIG_INVALID');
        const url = new URL('https://' + profile.endpoint),
          port = Number(profile.endpoint.split(':').at(-1));
        if (!url.hostname || port < 1 || port > 65535) throw failure('EK_CONFIG_INVALID');
        endpoint = profile.endpoint;
      }
      let listener: Readonly<{ host: string; port: number; tlsProfile: string }> | undefined;
      if (profile.listener !== undefined) {
        const bind = fields(profile.listener);
        if (
          typeof bind.host !== 'string' ||
          !/^[A-Za-z0-9.-]+$/.test(bind.host) ||
          !keys.includes(name(bind.tlsProfile))
        )
          throw failure('EK_CONFIG_INVALID');
        listener = Object.freeze({
          host: bind.host,
          port: integer(bind.port, 65535, 0),
          tlsProfile: bind.tlsProfile as string,
        });
      }
      if (!endpoint && !listener) throw failure('EK_CONFIG_INVALID');
      const tlsProfile =
        profile.tlsProfile === undefined
          ? keys.length === 1
            ? keys[0]
            : undefined
          : name(profile.tlsProfile);
      if (endpoint && (!tlsProfile || !keys.includes(tlsProfile)))
        throw failure('EK_CONFIG_INVALID');
      return Object.freeze({
        name: serviceName,
        descriptorFile,
        allowedMethods: names(profile.allowedMethods),
        maxMessageBytes: integer(profile.maxMessageBytes, 8388608),
        ...(endpoint ? { endpoint } : {}),
        ...(tlsProfile ? { tlsProfile } : {}),
        ...(listener ? { listener } : {}),
      });
    });
    if (new Set(captured.map((profile) => profile.name)).size !== captured.length)
      throw failure('EK_CONFIG_INVALID');
    const listeners = new Map<string, string>();
    for (const { listener } of captured)
      if (listener) {
        const key = listener.host + ':' + listener.port,
          previous = listeners.get(key);
        if (previous && previous !== listener.tlsProfile) throw failure('EK_CONFIG_INVALID');
        listeners.set(key, listener.tlsProfile);
      }
    const bindings = Object.entries(fields(data.handlers)).map(([key, value]) => {
      name(key);
      const binding = fields(value);
      return Object.freeze({
        descriptor: name(binding.descriptor),
        handlers: handlers(binding.handlers as Record<string, GrpcHandler>),
        policy: policy(binding.policy as GrpcPolicy),
      });
    });
    return Object.freeze({
      services: Object.freeze(captured),
      bindings: Object.freeze(bindings),
      tlsProfiles: profiles,
      require: (...args: Parameters<TrustedSecurityAuthority['require']>) =>
        Reflect.apply(authorize, data.authority, args) as ReturnType<
          TrustedSecurityAuthority['require']
        >,
      testOnly: usage === 'test-only',
      maxConcurrent: integer(limits.maxConcurrent, 1024),
      timeoutMs: integer(limits.timeoutMs, 60000),
      maxInputBytes: integer(limits.maxInputBytes ?? 1048576, 8388608),
      maxOutputBytes: integer(limits.maxOutputBytes ?? 1048576, 8388608),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
export function operation(input: GrpcCallOptions | undefined, maximum: number) {
  const data = fields(input ?? {});
  if (Object.keys(data).some((key) => !['signal', 'timeoutMs', 'metadata'].includes(key)))
    throw failure('EK_CONFIG_INVALID');
  const metadata: Record<string, string> = Object.create(null);
  let bytes = 0;
  if (data.metadata !== undefined)
    for (const [key, value] of Object.entries(fields(data.metadata))) {
      if (
        !/^[a-z][a-z0-9_.-]{0,63}$/.test(key) ||
        key.startsWith('grpc-') ||
        key.endsWith('-bin') ||
        typeof value !== 'string' ||
        !/^[\x20-\x7e]*$/.test(value)
      )
        throw failure('EK_CONFIG_INVALID');
      bytes += key.length + value.length;
      if (bytes > 16384 || Object.keys(metadata).length >= 128) throw failure('EK_CONFIG_INVALID');
      metadata[key] = value;
    }
  return {
    timeoutMs: data.timeoutMs === undefined ? maximum : integer(data.timeoutMs, maximum),
    ...(data.signal === undefined ? {} : { signal: captureAbortSignal(data.signal) }),
    metadata,
  };
}
