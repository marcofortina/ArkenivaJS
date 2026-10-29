// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { X509Certificate } from 'node:crypto';
import { types } from 'node:util';
import { DEFAULT_MIN_VERSION, createSecureContext, rootCertificates } from 'node:tls';
import type { ConnectionOptions } from 'nats';
import { KitError } from '@arkenivajs/core';
import type { NatsBusOptions } from './types.js';

export interface NatsConfiguration {
  readonly native: ConnectionOptions;
  readonly prefix: string;
}
const invalid = (message: string, cause?: unknown) =>
  new KitError({ code: 'EK_CONFIG_INVALID', message, ...(cause === undefined ? {} : { cause }) });

function policyProperty(input: object, name: string): unknown {
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw invalid('NATS policy proxies are not supported');
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!('value' in descriptor)) throw invalid('NATS policy requires data properties');
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw invalid('NATS policy prototype depth exceeds its bounded limit');
  return undefined;
}

/** Capture executable policy independently from environment data and native resources. */
export function natsPolicy(input: NatsBusOptions): Readonly<NatsBusOptions> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    Array.isArray(input) ||
    Object.values(Object.getOwnPropertyDescriptors(input)).some((entry) => !('value' in entry)) ||
    Object.keys(input).some(
      (key) => !['connectionStringEnv', 'onError', 'logger', 'telemetry', 'meter'].includes(key),
    )
  )
    throw invalid('NATS requires an explicit asynchronous error strategy and supported policy');
  const callback = policyProperty(input, 'onError');
  if (typeof callback !== 'function' || types.isProxy(callback))
    throw invalid('NATS requires an explicit asynchronous error strategy');
  const variable = policyProperty(input, 'connectionStringEnv') ?? 'NATS_URL';
  if (typeof variable !== 'string' || !/^[A-Z_][A-Z0-9_]{0,127}(?![\s\S])/.test(variable))
    throw invalid('Invalid NATS connection environment reference');
  return Object.freeze({
    ...input,
    connectionStringEnv: variable,
    onError: (...args: Parameters<NatsBusOptions['onError']>) =>
      Reflect.apply(callback, input, args),
  });
}

function pem(path: string, secret = false): string {
  if (!isAbsolute(path) || /[\0\r\n]/.test(path))
    throw new Error('NATS TLS paths must be absolute');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.size < 1 ||
      stat.size > 1_048_576 ||
      (secret && (stat.mode & 0o077) !== 0)
    )
      throw new Error('NATS TLS files require bounded regular data and private key permissions');
    const bytes = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used !== stat.size) throw new Error('NATS TLS file changed during capture');
    const text = bytes.subarray(0, used).toString('utf8');
    if (!Buffer.from(text).equals(bytes.subarray(0, used)))
      throw new Error('NATS TLS files require UTF-8 PEM');
    if (!secret) new X509Certificate(text);
    return text;
  } finally {
    closeSync(fd);
  }
}

/** Only reviewed public SDK options are used; transport security cannot be disabled through URL flags. */
export function natsConfiguration(variable: string): NatsConfiguration {
  const value = process.env[variable];
  if (!value)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'The NATS connection environment value is missing',
    });
  try {
    if (Buffer.byteLength(value) > 65536 || /[\0\r\n#]/.test(value))
      throw new Error('Invalid NATS URL syntax');
    if (
      process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ||
      !['TLSv1.2', 'TLSv1.3'].includes(DEFAULT_MIN_VERSION)
    )
      throw new Error(
        'NATS requires certificate validation and a TLS 1.2 or newer process minimum',
      );
    const url = new URL(value),
      host = url.hostname.replace(/^\[|\]$/g, '');
    const user = decodeURIComponent(url.username),
      pass = decodeURIComponent(url.password);
    const validHost =
      isIP(host) !== 0 ||
      (host.length <= 253 &&
        host
          .split('.')
          .every((label) =>
            /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/.test(label),
          ));
    if (
      url.protocol !== 'tls:' ||
      !validHost ||
      !user ||
      !pass ||
      /[\0\r\n]/.test(user + pass) ||
      Buffer.byteLength(user) > 1024 ||
      Buffer.byteLength(pass) > 1024 ||
      !['', '/'].includes(url.pathname) ||
      !url.port ||
      Number(url.port) < 1 ||
      Number(url.port) > 65535
    )
      throw new Error('NATS requires explicit TLS host, port and scoped credentials');
    for (const key of url.searchParams.keys())
      if (
        !['caFile', 'certFile', 'keyFile', 'prefix'].includes(key) ||
        url.searchParams.getAll(key).length !== 1
      )
        throw new Error('Unsupported or duplicate NATS URL option');
    const prefix = url.searchParams.get('prefix');
    if (
      !prefix ||
      !/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.(?![\s\S])/.test(prefix) ||
      prefix.length > 128
    )
      throw new Error('NATS requires an explicit bounded subject namespace ending with a dot');
    const caFile = url.searchParams.get('caFile'),
      certFile = url.searchParams.get('certFile'),
      keyFile = url.searchParams.get('keyFile');
    if ((certFile === null) !== (keyFile === null))
      throw new Error('NATS client certificate and key must be configured together');
    const ca = caFile === null ? rootCertificates.join('\n') : pem(caFile);
    const cert = certFile === null ? undefined : pem(certFile),
      key = keyFile === null ? undefined : pem(keyFile, true);
    createSecureContext({
      ca,
      ...(cert === undefined ? {} : { cert }),
      ...(key === undefined ? {} : { key }),
      minVersion: 'TLSv1.2',
    });
    return Object.freeze({
      prefix,
      native: Object.freeze({
        servers: ['tls://' + url.host],
        user,
        pass,
        tls: Object.freeze({
          ca,
          ...(cert === undefined ? {} : { cert }),
          ...(key === undefined ? {} : { key }),
          handshakeFirst: true,
        }),
        reconnect: true,
        maxReconnectAttempts: 5,
        reconnectTimeWait: 200,
        reconnectJitter: 100,
        reconnectJitterTLS: 100,
        waitOnFirstConnect: false,
        timeout: 5000,
        pingInterval: 1000,
        maxPingOut: 2,
        ignoreClusterUpdates: true,
        noRandomize: true,
        debug: false,
      }),
    });
  } catch (cause) {
    throw invalid('Invalid NATS connection, namespace or TLS policy', cause);
  }
}
