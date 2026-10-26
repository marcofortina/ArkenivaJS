// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { DnsPluginSettings, DnsRecordMap, DnsRecordType } from './contracts.js';

export const recordTypes: readonly DnsRecordType[] = Object.freeze([
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'TXT',
  'CAA',
  'NAPTR',
]);
export type DnsCode =
  | 'EK_DNS_CONFIG'
  | 'EK_DNS_NOT_FOUND'
  | 'EK_DNS_TEMPORARY'
  | 'EK_DNS_TIMEOUT'
  | 'EK_ABORTED'
  | 'EK_RESOURCE_CLOSED';
export const failure = (code: DnsCode) =>
  new KitError({
    code,
    message:
      code === 'EK_DNS_CONFIG'
        ? 'The DNS configuration or query is invalid'
        : code === 'EK_DNS_NOT_FOUND'
          ? 'The DNS query returned no matching records'
          : code === 'EK_DNS_TIMEOUT'
            ? 'The DNS operation deadline expired'
            : code === 'EK_ABORTED'
              ? 'The DNS operation was cancelled'
              : code === 'EK_RESOURCE_CLOSED'
                ? 'The DNS service is closed'
                : 'The DNS resolver is temporarily unavailable',
    retryable: code === 'EK_DNS_TEMPORARY' || code === 'EK_DNS_TIMEOUT',
  });
export function fields(input: unknown, keys?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
  )
    throw failure('EK_DNS_CONFIG');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== 'string' || (keys && !keys.includes(key))) throw failure('EK_DNS_CONFIG');
    const item = Object.getOwnPropertyDescriptor(input, key);
    if (!item || !('value' in item)) throw failure('EK_DNS_CONFIG');
    result[key] = item.value;
  }
  return result;
}
export function integer(value: unknown, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max)
    throw failure('EK_DNS_CONFIG');
  return value as number;
}
export function array(input: unknown, maximum: number, minimum = 0): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    input.length < minimum ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure('EK_DNS_CONFIG');
  const result: unknown[] = [];
  for (let i = 0; i < input.length; i++) {
    const item = Object.getOwnPropertyDescriptor(input, String(i));
    if (!item || !('value' in item)) throw failure('EK_DNS_CONFIG');
    result.push(item.value);
  }
  return result;
}
export function text(input: unknown, maximum = 4096): string {
  if (
    typeof input !== 'string' ||
    input.length > maximum ||
    Buffer.byteLength(input) > maximum ||
    toUSVString(input) !== input
  )
    throw failure('EK_DNS_CONFIG');
  return input;
}
export function hostname(input: unknown, literal = false): string {
  const raw = text(input, 1024);
  if (literal && isIP(raw)) return raw;
  if (raw === '.') return raw;
  if (!raw || /[\s/\\:#?@]/u.test(raw)) throw failure('EK_DNS_CONFIG');
  const normalized = domainToASCII(raw).toLowerCase(),
    name = normalized.endsWith('.') ? normalized.slice(0, -1) : normalized;
  if (
    !name ||
    name.length > 253 ||
    name
      .split('.')
      .some(
        (label) =>
          !label || label.length > 63 || !/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(label),
      )
  )
    throw failure('EK_DNS_CONFIG');
  return normalized;
}
function server(input: unknown): string {
  const value = text(input, 128);
  if (isIP(value) && !value.includes('%')) return value;
  if (/[\s/\\?#@]/u.test(value)) throw failure('EK_DNS_CONFIG');
  const parsed = new URL('udp://' + value),
    address = parsed.hostname.replace(/^\[|\]$/g, '');
  if (
    !isIP(address) ||
    address.includes('%') ||
    !parsed.port ||
    parsed.pathname ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password
  )
    throw failure('EK_DNS_CONFIG');
  integer(Number(parsed.port), 1, 65535);
  return (isIP(address) === 6 ? '[' + address + ']' : address) + ':' + parsed.port;
}
export function capture(input: DnsPluginSettings) {
  try {
    const value = fields(input, ['resolvers', 'defaultResolver', 'maxConcurrency', 'timeoutMs']),
      seen = new Set<string>();
    const resolvers = array(value.resolvers, 64, 1).map((input) => {
      const profile = fields(input, ['name', 'servers']),
        name = text(profile.name, 63);
      if (!/^[a-z][a-z0-9-]{0,62}$/.test(name) || seen.has(name)) throw failure('EK_DNS_CONFIG');
      seen.add(name);
      const servers = array(profile.servers, 16, 1).map(server);
      if (new Set(servers).size !== servers.length) throw failure('EK_DNS_CONFIG');
      return Object.freeze({ name, servers: Object.freeze(servers) });
    });
    const defaultResolver =
      value.defaultResolver === undefined ? resolvers[0]!.name : text(value.defaultResolver, 63);
    if (!seen.has(defaultResolver)) throw failure('EK_DNS_CONFIG');
    return Object.freeze({
      resolvers: Object.freeze(resolvers),
      defaultResolver,
      maxConcurrency: integer(value.maxConcurrency, 1, 1024),
      timeoutMs: integer(value.timeoutMs, 1, 120000),
    });
  } catch {
    throw failure('EK_DNS_CONFIG');
  }
}
export type Captured = ReturnType<typeof capture>;
export function safeFailure(cause: unknown): KitError {
  try {
    const code =
      cause && typeof cause === 'object'
        ? Object.getOwnPropertyDescriptor(cause, 'code')?.value
        : undefined;
    if (['ENODATA', 'ENOTFOUND', 'EAI_NONAME', 'EAI_NODATA'].includes(code))
      return failure('EK_DNS_NOT_FOUND');
    if (code === 'ETIMEOUT') return failure('EK_DNS_TIMEOUT');
    if (
      [
        'EINVAL',
        'EBADNAME',
        'EBADFAMILY',
        'ERR_INVALID_ARG_VALUE',
        'ERR_INVALID_ARG_TYPE',
      ].includes(code)
    )
      return failure('EK_DNS_CONFIG');
  } catch {
    /* Resolver and native payload diagnostics remain private. */
  }
  return failure('EK_DNS_TEMPORARY');
}
export function normalize<T extends DnsRecordType>(
  type: T,
  input: unknown,
): readonly DnsRecordMap[T][] {
  const nativeName = (value: unknown) => (value === '' ? '.' : hostname(value));
  const nativeFields = (value: unknown, keys?: readonly string[]) => {
    const data = fields(value, keys ? [...keys, 'type'] : undefined);
    if (data.type !== undefined && data.type !== type) throw failure('EK_DNS_CONFIG');
    delete data.type;
    return data;
  };
  const records = type === 'SOA' ? [input] : array(input, 1024);
  const values = records.map((value) => {
    if (type === 'A' || type === 'AAAA') {
      const record =
        typeof value === 'string' ? { address: value } : nativeFields(value, ['address', 'ttl']);
      const address = text(record.address, 45);
      if (isIP(address) !== (type === 'A' ? 4 : 6)) throw failure('EK_DNS_CONFIG');
      return Object.freeze({
        address,
        ...('ttl' in record && record.ttl !== undefined
          ? { ttlSeconds: integer(record.ttl, 0, 4294967295) }
          : {}),
      });
    }
    if (type === 'CNAME' || type === 'NS' || type === 'PTR')
      return Object.freeze({ hostname: nativeName(value) });
    if (type === 'TXT')
      return Object.freeze({
        segments: Object.freeze(array(value, 256, 1).map((segment) => text(segment, 1024))),
      });
    if (type === 'MX') {
      const r = nativeFields(value, ['exchange', 'priority']);
      return Object.freeze({
        exchange: nativeName(r.exchange),
        priority: integer(r.priority, 0, 65535),
      });
    }
    if (type === 'SRV') {
      const r = nativeFields(value, ['name', 'port', 'priority', 'weight']);
      return Object.freeze({
        name: nativeName(r.name),
        port: integer(r.port, 0, 65535),
        priority: integer(r.priority, 0, 65535),
        weight: integer(r.weight, 0, 65535),
      });
    }
    if (type === 'SOA') {
      const r = nativeFields(value, [
        'nsname',
        'hostmaster',
        'serial',
        'refresh',
        'retry',
        'expire',
        'minttl',
      ]);
      return Object.freeze({
        nsname: nativeName(r.nsname),
        hostmaster: nativeName(r.hostmaster),
        serial: integer(r.serial, 0, 4294967295),
        refresh: integer(r.refresh, 0, 4294967295),
        retry: integer(r.retry, 0, 4294967295),
        expire: integer(r.expire, 0, 4294967295),
        minttl: integer(r.minttl, 0, 4294967295),
      });
    }
    if (type === 'CAA') {
      const r = nativeFields(value),
        keys = Object.keys(r).filter((key) => key !== 'critical');
      if (keys.length !== 1 || !/^[a-z0-9-]{1,15}$/.test(keys[0]!)) throw failure('EK_DNS_CONFIG');
      return Object.freeze({
        critical: integer(r.critical, 0, 255),
        tag: keys[0]!,
        value: text(r[keys[0]!]),
      });
    }
    const r = nativeFields(value, [
      'order',
      'preference',
      'flags',
      'service',
      'regexp',
      'replacement',
    ]);
    return Object.freeze({
      order: integer(r.order, 0, 65535),
      preference: integer(r.preference, 0, 65535),
      flags: text(r.flags),
      service: text(r.service),
      regexp: text(r.regexp),
      replacement: nativeName(r.replacement),
    });
  });
  if (Buffer.byteLength(JSON.stringify(values)) > 1048576) throw failure('EK_DNS_CONFIG');
  return Object.freeze(values) as readonly DnsRecordMap[T][];
}
