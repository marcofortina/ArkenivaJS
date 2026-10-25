// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { checkServerIdentity, rootCertificates } from 'node:tls';
import type { ConnectionOptions } from 'node:tls';
import { randomInt } from 'node:crypto';
import type { RedisClientOptions } from 'redis';
import { KitError } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import { permanentRedisError } from './errors.js';

/** Only explicitly supported native transport and queue settings enter the SDK. */
export type RedisNativeOptions = Pick<
  RedisClientOptions,
  | 'username'
  | 'password'
  | 'database'
  | 'socket'
  | 'commandsQueueMaxLength'
  | 'disableOfflineQueue'
  | 'maintNotifications'
  | 'disableClientInfo'
>;
/** A portable namespace is independent of the raw native client command API. */
export interface RedisConfiguration {
  readonly native: RedisNativeOptions;
  readonly prefix: string;
}

/** Reconnect the transport only; failed command queues are never retained for replay. */
export function redisReconnect(retries: number, cause: Error): false | number {
  if (!Number.isSafeInteger(retries) || retries < 0 || retries >= 5 || permanentRedisError(cause))
    return false;
  return Math.min(100 * 2 ** retries, 1000) + randomInt(0, 100);
}

function certificate(path: string): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 1_048_576)
      throw new Error('Invalid Redis CA file');
    const buffer = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used !== stat.size) throw new Error('Redis CA file changed during capture');
    return buffer.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

/** Validate and capture one explicitly configured URL without native URL-option coercion. */
export function redisConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): RedisConfiguration {
  const variable = definition.connectionStringEnv;
  if (!variable || !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Redis connectionStringEnv is required',
    });
  const value = process.env[variable];
  if (!value)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Redis connection string environment value is missing',
    });
  try {
    if (
      definition.driver !== 'redis' ||
      definition.endpoints !== undefined ||
      definition.poolMin !== undefined ||
      definition.poolMax !== undefined
    )
      throw new Error('Redis requires one connection string without SQL pool options');
    if (Buffer.byteLength(value) > 65_536 || /[\0\r\n]/.test(value) || value.includes('#'))
      throw new Error('Invalid Redis URL syntax');
    const url = new URL(value),
      host = url.hostname.replace(/^\[|\]$/g, '');
    const validHost =
      isIP(host) !== 0 ||
      (host.length <= 253 &&
        host
          .split('.')
          .every((label) =>
            /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/.test(label),
          ));
    const username = decodeURIComponent(url.username),
      password = decodeURIComponent(url.password);
    const databaseText = url.pathname.slice(1) || '0',
      database = Number(databaseText);
    if (
      !['redis:', 'rediss:'].includes(url.protocol) ||
      !validHost ||
      !username ||
      !password ||
      /[\0\r\n]/.test(username + password) ||
      !/^\d+(?![\s\S])/.test(databaseText) ||
      !Number.isSafeInteger(database) ||
      database > 2_147_483_647 ||
      (url.port !== '' && (Number(url.port) < 1 || Number(url.port) > 65535))
    )
      throw new Error('Explicit Redis host, credentials and a valid database index are required');
    for (const key of url.searchParams.keys())
      if (!['sslca', 'prefix'].includes(key) || url.searchParams.getAll(key).length !== 1)
        throw new Error('Unsupported or duplicate Redis URL option');
    const local =
      environment !== 'production' &&
      (host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.')));
    const tls = url.protocol === 'rediss:';
    if (!tls && !local) throw new Error('Redis network connections require verified TLS');
    const ca = url.searchParams.get('sslca');
    if (ca !== null && (!tls || !isAbsolute(ca) || /[\0\r\n]/.test(ca)))
      throw new Error('Redis sslca requires TLS and an absolute file path');
    const prefix = url.searchParams.get('prefix') ?? '';
    if (prefix !== '' && !/^[A-Za-z0-9][A-Za-z0-9:_-]{0,126}:(?![\s\S])/.test(prefix))
      throw new Error('Redis prefix must be a bounded namespace ending with a colon');
    const secure: ConnectionOptions = {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ca: ca === null ? [...rootCertificates] : certificate(ca),
      ...(isIP(host) ? {} : { servername: host }),
      checkServerIdentity: (_name, peer) => checkServerIdentity(host, peer),
    };
    const base = {
      host,
      port: url.port ? Number(url.port) : 6379,
      connectTimeout: 5000,
      reconnectStrategy: redisReconnect,
    };
    return {
      prefix,
      native: {
        username,
        password,
        database,
        socket: tls ? { ...base, ...secure, tls: true } : { ...base, tls: false },
        disableOfflineQueue: true,
        commandsQueueMaxLength: 128,
        maintNotifications: 'disabled',
        disableClientInfo: true,
      },
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Redis connection, namespace or TLS policy',
      cause,
    });
  }
}
