// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP, SocketAddress } from 'node:net';
import { isAbsolute, normalize } from 'node:path';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { validateServerTlsFiles } from '@arkenivajs/core/support';
import type { ServerTlsFiles } from '@arkenivajs/core';
import type { SocketNetworkAddress, SocketServerKind } from './contracts.js';

export const DEFAULT_SOCKET_MAX_CONNECTIONS = 1024;
export const DEFAULT_SOCKET_IDLE_TIMEOUT_MS = 60000;
export const DEFAULT_SOCKET_MAX_PENDING_WRITE_BYTES = 1048576;
export const DEFAULT_SOCKET_SHUTDOWN_TIMEOUT_MS = 30000;
export const DEFAULT_SOCKET_TLS_HANDSHAKE_TIMEOUT_MS = 10000;
export const DEFAULT_UDP_MAX_DATAGRAM_BYTES = 1200;
export const DEFAULT_UDP_MAX_CONCURRENT_HANDLERS = 256;
export const DEFAULT_UDP_MAX_QUEUED_DATAGRAMS = 1024;
export const DEFAULT_UDP_MAX_REPLY_BYTES = 1200;

export const failure = (code: ErrorCode, cause?: unknown) =>
  new KitError({
    code,
    ...(cause === undefined ? {} : { cause }),
    message:
      code === 'EK_SOCKET_CONFIG'
        ? 'The socket configuration is invalid'
        : code === 'EK_SOCKET_BIND'
          ? 'The socket listener could not bind'
          : code === 'EK_SOCKET_CAPACITY'
            ? 'The socket resource limit was reached'
            : code === 'EK_SOCKET_DATAGRAM'
              ? 'The datagram or destination is invalid'
              : code === 'EK_SOCKET_STATE'
                ? 'The socket operation is invalid in this state'
                : code === 'EK_SOCKET_CLOSED'
                  ? 'The socket is closed'
                  : code === 'EK_TIMEOUT'
                    ? 'The socket operation deadline expired'
                    : code === 'EK_ABORTED'
                      ? 'The socket operation was cancelled'
                      : code === 'EK_UNSUPPORTED_CAPABILITY'
                        ? 'The socket capability is unavailable'
                        : code === 'EK_SOCKET_TLS_HANDSHAKE'
                          ? 'The secure socket handshake failed'
                          : 'The socket operation failed',
  });

function captureFields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure('EK_SOCKET_CONFIG');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== 'string' || (allowed && !allowed.includes(key)))
      throw failure('EK_SOCKET_CONFIG');
    const property = Object.getOwnPropertyDescriptor(input, key);
    if (!property || !('value' in property)) throw failure('EK_SOCKET_CONFIG');
    result[key] = property.value;
  }
  return result;
}
export function fields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  try {
    return captureFields(input, allowed);
  } catch {
    throw failure('EK_SOCKET_CONFIG');
  }
}
export function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw failure('EK_SOCKET_CONFIG');
  return value as number;
}
export function array(value: unknown, maximum: number): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw failure('EK_SOCKET_CONFIG');
  const result: unknown[] = [];
  for (let i = 0; i < value.length; i++) {
    const property = Object.getOwnPropertyDescriptor(value, String(i));
    if (!property || !('value' in property)) throw failure('EK_SOCKET_CONFIG');
    result.push(property.value);
  }
  return result;
}
function flag(value: unknown, fallback: boolean) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw failure('EK_SOCKET_CONFIG');
  return value;
}
function captureAddress(input: unknown): SocketNetworkAddress {
  const data = fields(input, ['address', 'family', 'port']);
  if (
    typeof data.address !== 'string' ||
    data.address.includes('%') ||
    !['IPv4', 'IPv6'].includes(data.family as string) ||
    isIP(data.address) !== (data.family === 'IPv4' ? 4 : 6)
  )
    throw failure('EK_SOCKET_DATAGRAM');
  const normalized = new SocketAddress({
    address: data.address,
    family: data.family === 'IPv4' ? 'ipv4' : 'ipv6',
    port: integer(data.port, 1, 65535),
  });
  return Object.freeze({
    address: normalized.address,
    port: normalized.port,
    family: data.family as 'IPv4' | 'IPv6',
  });
}
export function address(input: unknown): SocketNetworkAddress {
  try {
    return captureAddress(input);
  } catch {
    throw failure('EK_SOCKET_DATAGRAM');
  }
}
export const addressKey = (value: SocketNetworkAddress) =>
  `${value.family}/${value.address}/${value.port}`;
function captureSettings(kind: SocketServerKind, input: unknown) {
  const common = ['name', 'shutdownTimeoutMs'],
    stream = ['maxConnections', 'idleTimeoutMs', 'maxPendingWriteBytes'],
    network = ['host', 'port', 'ipv6Only'];
  const data = fields(input, [
    ...common,
    ...(kind === 'udp'
      ? [
          'family',
          ...network,
          'maxDatagramBytes',
          'maxConcurrentHandlers',
          'maxQueuedDatagrams',
          'maxReplyBytes',
          'maxReplyAmplificationFactor',
          'allowOutboundDestinations',
          'destinationAllowlist',
        ]
      : [
          ...stream,
          ...(kind === 'unix'
            ? ['path', 'mode']
            : [...network, ...(kind === 'tls' ? ['tls', 'handshakeTimeoutMs'] : [])]),
        ]),
  ]);
  if (typeof data.name !== 'string' || !/^[a-z][a-z0-9-]{0,62}$/.test(data.name))
    throw failure('EK_SOCKET_CONFIG');
  const shutdownTimeoutMs = integer(
    data.shutdownTimeoutMs ?? DEFAULT_SOCKET_SHUTDOWN_TIMEOUT_MS,
    1,
    120000,
  );
  if (Object.values(data).some((value) => value === null)) throw failure('EK_SOCKET_CONFIG');
  const connection = {
    maxConnections: integer(data.maxConnections ?? DEFAULT_SOCKET_MAX_CONNECTIONS, 1, 100000),
    idleTimeoutMs: integer(data.idleTimeoutMs ?? DEFAULT_SOCKET_IDLE_TIMEOUT_MS, 1, 86400000),
    maxPendingWriteBytes: integer(
      data.maxPendingWriteBytes ?? DEFAULT_SOCKET_MAX_PENDING_WRITE_BYTES,
      1,
      16777216,
    ),
  };
  if (kind === 'unix') {
    if (
      typeof data.path !== 'string' ||
      !isAbsolute(data.path) ||
      normalize(data.path) !== data.path ||
      data.path.includes('\0') ||
      Buffer.byteLength(data.path) > 103
    )
      throw failure('EK_SOCKET_CONFIG');
    const mode = integer(data.mode ?? 0o600, 0o400, 0o600);
    if ((mode & ~0o600) !== 0) throw failure('EK_SOCKET_CONFIG');
    return Object.freeze({
      kind,
      name: data.name,
      shutdownTimeoutMs,
      ...connection,
      path: data.path,
      mode,
    });
  }
  const family = kind === 'udp' ? data.family : undefined;
  if (kind === 'udp' && family !== 'udp4' && family !== 'udp6') throw failure('EK_SOCKET_CONFIG');
  const host = data.host === undefined ? (family === 'udp6' ? '::1' : '127.0.0.1') : data.host;
  if (
    typeof host !== 'string' ||
    host.includes('%') ||
    !isIP(host) ||
    (family && isIP(host) !== (family === 'udp4' ? 4 : 6))
  )
    throw failure('EK_SOCKET_CONFIG');
  const port = integer(data.port, 0, 65535),
    ipv6Only = flag(data.ipv6Only, true);
  if (data.ipv6Only !== undefined && isIP(host) !== 6) throw failure('EK_SOCKET_CONFIG');
  const binding = { host, port, ipv6Only };
  if (kind === 'udp') {
    const enabled = flag(data.allowOutboundDestinations, false),
      allowlist = new Set<string>();
    for (const item of array(
      data.destinationAllowlist === undefined ? [] : data.destinationAllowlist,
      256,
    )) {
      if (typeof item !== 'string' || /[\s/\\?#@]/u.test(item)) throw failure('EK_SOCKET_CONFIG');
      const parsed = new URL('udp://' + item),
        name = parsed.hostname.replace(/^\[|\]$/g, '');
      if (parsed.pathname || !parsed.port || !isIP(name)) throw failure('EK_SOCKET_CONFIG');
      const target = address({
        address: name,
        port: Number(parsed.port),
        family: isIP(name) === 4 ? 'IPv4' : 'IPv6',
      });
      if (isIP(name) !== (family === 'udp4' ? 4 : 6) || allowlist.has(addressKey(target)))
        throw failure('EK_SOCKET_CONFIG');
      allowlist.add(addressKey(target));
    }
    if (enabled !== Boolean(allowlist.size)) throw failure('EK_SOCKET_CONFIG');
    return Object.freeze({
      kind,
      name: data.name,
      shutdownTimeoutMs,
      ...binding,
      family: family as 'udp4' | 'udp6',
      maxDatagramBytes: integer(data.maxDatagramBytes ?? DEFAULT_UDP_MAX_DATAGRAM_BYTES, 1, 65507),
      maxConcurrentHandlers: integer(
        data.maxConcurrentHandlers ?? DEFAULT_UDP_MAX_CONCURRENT_HANDLERS,
        1,
        4096,
      ),
      maxQueuedDatagrams: integer(
        data.maxQueuedDatagrams ?? DEFAULT_UDP_MAX_QUEUED_DATAGRAMS,
        1,
        16384,
      ),
      maxReplyBytes: integer(data.maxReplyBytes ?? DEFAULT_UDP_MAX_REPLY_BYTES, 1, 65507),
      maxReplyAmplificationFactor: integer(data.maxReplyAmplificationFactor ?? 1, 1, 16),
      allowlist,
    });
  }
  return Object.freeze({
    kind,
    name: data.name,
    shutdownTimeoutMs,
    ...connection,
    ...binding,
    ...(kind === 'tls'
      ? {
          tls: validateServerTlsFiles(data.tls as ServerTlsFiles),
          handshakeTimeoutMs: integer(
            data.handshakeTimeoutMs ?? DEFAULT_SOCKET_TLS_HANDSHAKE_TIMEOUT_MS,
            1,
            120000,
          ),
        }
      : {}),
  });
}
export function capture(kind: SocketServerKind, input: unknown) {
  try {
    return captureSettings(kind, input);
  } catch {
    throw failure('EK_SOCKET_CONFIG');
  }
}
export type Captured = ReturnType<typeof capture>;
/** Validate operation policy before allocating or mutating native resources. */
export function operation(input: OperationOptions | undefined, defaultMs: number) {
  const data = fields(input === undefined ? {} : input, ['timeoutMs', 'signal']);
  let signal: AbortSignal | undefined;
  try {
    if (data.signal !== undefined) {
      // Node 22's any() alone accepts some structural lookalikes.
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(data.signal);
      signal = AbortSignal.any([data.signal as AbortSignal]);
    }
  } catch {
    throw failure('EK_SOCKET_CONFIG');
  }
  return {
    signal,
    timeoutMs: Math.min(
      data.timeoutMs === undefined ? defaultMs : integer(data.timeoutMs, 1, 120000),
      defaultMs,
    ),
  };
}
