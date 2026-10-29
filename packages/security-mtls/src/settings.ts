// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP } from 'node:net';
import { types } from 'node:util';
import type {
  MtlsCredentialProvider,
  MtlsPluginSettings,
  MtlsTrustProvider,
  TlsProfile,
} from './contracts.js';
import { data, invalid, list } from './runtime.js';

export function text(value: unknown, maximum = 512): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    [...value].some((character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127)
  )
    throw invalid();
}
export function hostname(value: unknown): asserts value is string {
  text(value, 253);
  if (
    !isIP(value) &&
    !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/.test(
      value,
    )
  )
    throw invalid();
}
export function strings(value: unknown, maximum: number, minimum = 1): readonly string[] {
  const result = list(value, maximum, minimum).map((entry) => {
    text(entry, 2048);
    return entry;
  });
  if (new Set(result).size !== result.length) throw invalid();
  return Object.freeze(result);
}
export function profile(value: unknown): TlsProfile {
  const fields = data(value, [
    'trustRootsRef',
    'certRef',
    'keyRef',
    'allowedIdentities',
    'minTlsVersion',
    'alpnProtocols',
    'revocation',
  ]);
  text(fields.trustRootsRef);
  text(fields.certRef);
  text(fields.keyRef);
  const allowedIdentities = strings(fields.allowedIdentities, 64);
  for (const identity of allowedIdentities) {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(identity) && !isIP(identity)) {
      const uri = new URL(identity);
      if (
        uri.username ||
        uri.password ||
        uri.href !== identity ||
        (uri.protocol === 'spiffe:' && (!uri.hostname || uri.port || uri.hash || uri.search))
      )
        throw invalid();
    } else hostname(identity);
  }
  const minTlsVersion = fields.minTlsVersion ?? 'TLSv1.3';
  if (
    !['TLSv1.2', 'TLSv1.3'].includes(minTlsVersion as string) ||
    !['crl-required', 'ocsp-required', 'approved-online-checker'].includes(
      fields.revocation as string,
    )
  )
    throw invalid();
  const alpnProtocols =
    fields.alpnProtocols === undefined ? undefined : strings(fields.alpnProtocols, 16);
  if (
    alpnProtocols?.some((entry) => Buffer.byteLength(entry) > 255 || !/^[\x21-\x7e]+$/.test(entry))
  )
    throw invalid();
  return Object.freeze({
    trustRootsRef: fields.trustRootsRef,
    certRef: fields.certRef,
    keyRef: fields.keyRef,
    allowedIdentities,
    minTlsVersion: minTlsVersion as 'TLSv1.2' | 'TLSv1.3',
    ...(alpnProtocols === undefined ? {} : { alpnProtocols }),
    revocation: fields.revocation as TlsProfile['revocation'],
  });
}
export function profileKey(value: TlsProfile): string {
  return JSON.stringify(profile(value));
}
function method(value: unknown, name: string): (...args: never[]) => unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw invalid();
  let current: object | null = value;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw invalid();
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field) || typeof field.value !== 'function' || types.isProxy(field.value))
        throw invalid();
      const captured = field.value;
      // Callable metadata cannot replace the configured provider or its original receiver.
      return (...args: never[]) => Reflect.apply(captured, value, args) as unknown;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw invalid();
}
function usage(value: object): boolean {
  if (types.isProxy(value)) throw invalid();
  let current: object | null = value;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw invalid();
    const field = Object.getOwnPropertyDescriptor(current, 'usage');
    if (field) {
      if (!('value' in field) || !['production', 'test-only'].includes(field.value as string))
        throw invalid();
      return field.value === 'test-only';
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw invalid();
  return false;
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw invalid();
  return value as number;
}
export function captureSettings(input: MtlsPluginSettings) {
  try {
    const fields = data(input, [
      'profiles',
      'credentialProvider',
      'trustProvider',
      'reloadMode',
      'policy',
    ]);
    if (fields.reloadMode !== 'explicit') throw invalid();
    const policy = data(fields.policy, [
      'maxConcurrent',
      'timeoutMs',
      'maxInputBytes',
      'maxOutputBytes',
    ]);
    const maxConcurrent = integer(policy.maxConcurrent, 1024),
      timeoutMs = integer(policy.timeoutMs, 120000);
    const maxInputBytes =
        policy.maxInputBytes === undefined ? 1048576 : integer(policy.maxInputBytes, 1048576),
      maxOutputBytes =
        policy.maxOutputBytes === undefined ? 1048576 : integer(policy.maxOutputBytes, 1048576);
    if (
      maxInputBytes * maxConcurrent > 134217728 ||
      !fields.profiles ||
      typeof fields.profiles !== 'object' ||
      Array.isArray(fields.profiles)
    )
      throw invalid();
    const descriptors = Object.getOwnPropertyDescriptors(fields.profiles),
      keys = Reflect.ownKeys(descriptors),
      profiles = new Map<string, TlsProfile>();
    if (keys.length < 1 || keys.length > 64) throw invalid();
    for (const key of keys) {
      if (typeof key !== 'string') throw invalid();
      text(key, 128);
      const field = descriptors[key]!;
      if (!('value' in field)) throw invalid();
      const captured = profile(field.value),
        id = profileKey(captured);
      if (profiles.has(id)) throw invalid();
      profiles.set(id, captured);
    }
    const load = method(fields.credentialProvider, 'load') as MtlsCredentialProvider['load'],
      verify = method(
        fields.trustProvider,
        'verifyChainAndRevocation',
      ) as MtlsTrustProvider['verifyChainAndRevocation'];
    const credentialsTestOnly = usage(fields.credentialProvider as object),
      trustTestOnly = usage(fields.trustProvider as object);
    return Object.freeze({
      maxConcurrent,
      timeoutMs,
      maxInputBytes,
      maxOutputBytes,
      profiles,
      load,
      verify,
      testOnly: credentialsTestOnly || trustTestOnly,
    });
  } catch {
    throw invalid();
  }
}
export type Settings = ReturnType<typeof captureSettings>;
