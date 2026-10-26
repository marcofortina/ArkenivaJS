// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { BlockList, isIP, SocketAddress } from 'node:net';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { ApiKeyPolicy, IdentitySubject } from './contracts.js';

export const failure = (code: ErrorCode = 'EK_APIKEY_INVALID', unknown = false) =>
  new KitError({
    code,
    message: 'The API key operation could not complete safely',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
export const invalid = () => failure('EK_CONFIG_INVALID');
/** Snapshot ordinary data without invoking accessors or serialization callbacks. */
export function data(input: unknown, names: readonly string[]): Record<string, unknown> {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid();
    const result = Object.create(null) as Record<string, unknown>;
    for (const name of Reflect.ownKeys(input)) {
      if (typeof name !== 'string' || !names.includes(name)) throw invalid();
      const field = Object.getOwnPropertyDescriptor(input, name);
      if (!field || !('value' in field)) throw invalid();
      result[name] = field.value;
    }
    return result;
  } catch {
    throw invalid();
  }
}
export function text(input: unknown, max = 512): asserts input is string {
  if (
    typeof input !== 'string' ||
    !input.length ||
    input.length > max ||
    [...input].some(
      (character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127,
    ) ||
    Buffer.from(input).toString() !== input
  )
    throw invalid();
}
export function integer(input: unknown, max: number): number {
  if (!Number.isSafeInteger(input) || (input as number) < 1 || (input as number) > max)
    throw invalid();
  return input as number;
}
export function instant(input: unknown): string {
  text(input, 32);
  const millis = Date.parse(input);
  if (
    !Number.isSafeInteger(millis) ||
    millis < 0 ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(input)
  )
    throw invalid();
  const normalized = new Date(millis).toISOString();
  if (normalized !== input && normalized.replace('.000Z', 'Z') !== input) throw invalid();
  return normalized;
}
export function id(input: unknown): asserts input is string {
  if (
    typeof input !== 'string' ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input)
  )
    throw invalid();
}
export function strings(input: unknown, max: number, itemMax = 128): readonly string[] {
  if (
    !Array.isArray(input) ||
    input.length > max ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw invalid();
  const result: string[] = [];
  for (let index = 0; index < input.length; index++) {
    const field = Object.getOwnPropertyDescriptor(input, String(index));
    if (!field || !('value' in field)) throw invalid();
    text(field.value, itemMax);
    if (result.includes(field.value)) throw invalid();
    result.push(field.value);
  }
  return Object.freeze(result);
}
/** Persisted authority hints are bounded JSON; they confer no runtime provenance. */
export function snapshot(input: unknown): unknown {
  let nodes = 0;
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > 512 || depth > 12) throw invalid();
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      if (
        value.length > 8192 ||
        Buffer.from(value).toString() !== value ||
        value.includes('\u0000')
      )
        throw invalid();
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) return value;
    if (!value || typeof value !== 'object') throw invalid();
    if (Array.isArray(value)) {
      if (value.length > 128 || Reflect.ownKeys(value).length !== value.length + 1) throw invalid();
      return Array.from({ length: value.length }, (_, index) => {
        const field = Object.getOwnPropertyDescriptor(value, String(index));
        if (!field || !('value' in field)) throw invalid();
        return visit(field.value, depth + 1);
      });
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw invalid();
    const keys = Reflect.ownKeys(value);
    if (keys.length > 64) throw invalid();
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (
        typeof key !== 'string' ||
        key.length > 128 ||
        ['__proto__', 'prototype', 'constructor'].includes(key) ||
        key.includes('\u0000') ||
        Buffer.from(key).toString() !== key
      )
        throw invalid();
      const field = Object.getOwnPropertyDescriptor(value, key);
      if (!field || !('value' in field)) throw invalid();
      result[key] = visit(field.value, depth + 1);
    }
    return result;
  };
  try {
    const result = visit(input, 0);
    if (Buffer.byteLength(JSON.stringify(result)) > 16384) throw invalid();
    return freezeData(result);
  } catch {
    throw invalid();
  }
}
export function subject(input: unknown): IdentitySubject {
  const value = data(snapshot(input), ['issuer', 'subject', 'tenant']);
  text(value.issuer);
  text(value.subject);
  if (value.tenant !== undefined) {
    const tenant = data(value.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']);
    text(tenant.tenantId, 128);
    instant(tenant.verifiedAt);
    if (!['oidc', 'service-identity'].includes(tenant.source as string)) throw invalid();
    const identity = data(tenant.identity, [
      'issuer',
      'subject',
      'audience',
      'scopes',
      'claims',
      'assurance',
    ]);
    if (identity.issuer !== value.issuer || identity.subject !== value.subject) throw invalid();
    strings(identity.audience, 64, 512);
    strings(identity.scopes, 64);
    if (!identity.claims || typeof identity.claims !== 'object' || Array.isArray(identity.claims))
      throw invalid();
    if (
      identity.assurance !== undefined &&
      !['single-factor', 'mfa', 'phishing-resistant'].includes(identity.assurance as string)
    )
      throw invalid();
  }
  return freezeData({ ...value }) as unknown as IdentitySubject;
}
export const binding = (value: IdentitySubject) =>
  JSON.stringify([value.issuer, value.subject, value.tenant?.tenantId ?? null]);
export function ip(input: unknown): string {
  text(input, 64);
  if (
    input.includes('%') ||
    !isIP(input) ||
    (input.includes(':') &&
      (input.includes('.') ||
        new SocketAddress({ address: input, family: 'ipv6' }).address.startsWith('::ffff:')))
  )
    throw invalid();
  return input;
}
export function network(input: string): { address: string; bits: number; family: 'ipv4' | 'ipv6' } {
  const parts = input.split('/');
  if (parts.length !== 2 || !/^(0|[1-9][0-9]{0,2})$/.test(parts[1]!)) throw invalid();
  const address = ip(parts[0]),
    bits = Number(parts[1]),
    family = isIP(address) === 4 ? 'ipv4' : 'ipv6';
  if (bits > (family === 'ipv4' ? 32 : 128)) throw invalid();
  new BlockList().addSubnet(address, bits, family);
  return { address, bits, family };
}
export function policy(input: unknown): ApiKeyPolicy {
  const value = data(input, ['scopes', 'expiresAt', 'allowedIpRanges']),
    scopes = strings(value.scopes, 64),
    expiresAt = instant(value.expiresAt);
  if (scopes.some((scope) => !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(scope))) throw invalid();
  let allowedIpRanges: readonly string[] | undefined;
  if (value.allowedIpRanges !== undefined) {
    allowedIpRanges = strings(value.allowedIpRanges, 32, 80);
    if (!allowedIpRanges.length) throw invalid();
    for (const range of allowedIpRanges) network(range);
  }
  return Object.freeze({
    scopes,
    expiresAt,
    ...(allowedIpRanges === undefined ? {} : { allowedIpRanges }),
  });
}
export function permitted(
  clientIp: string | undefined,
  ranges: readonly string[] | undefined,
): boolean {
  if (!ranges) return true;
  if (!clientIp) return false;
  const list = new BlockList();
  for (const range of ranges) {
    const { address, bits, family } = network(range);
    list.addSubnet(address, bits, family);
  }
  return list.check(clientIp, isIP(clientIp) === 4 ? 'ipv4' : 'ipv6');
}
