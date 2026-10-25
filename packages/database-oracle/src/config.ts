// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';
import { KitError, DEFAULT_POOL_ACQUIRE_TIMEOUT_MS } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import type { PoolAttributes } from 'oracledb';

/** Explicit credentials and transport policy are captured before any pool is opened. */
export function oracleConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): PoolAttributes {
  const variable = definition.connectionStringEnv;
  if (!variable || !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Oracle connectionStringEnv is required',
    });
  const value = process.env[variable];
  if (!value)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Oracle connection string environment value is missing',
    });
  try {
    if (definition.driver !== 'oracle' || definition.endpoints !== undefined)
      throw new Error('Oracle requires a connection-string definition');
    const minimum = definition.poolMin ?? 0,
      maximum = definition.poolMax ?? 10;
    if (
      !Number.isSafeInteger(minimum) ||
      !Number.isSafeInteger(maximum) ||
      minimum < 0 ||
      maximum < 1 ||
      minimum > maximum
    )
      throw new Error('Invalid Oracle pool bounds');
    if (/[\0\r\n]/.test(value) || value.includes('#')) throw new Error('Invalid Oracle URL syntax');
    const url = new URL(value);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const user = decodeURIComponent(url.username),
      password = decodeURIComponent(url.password);
    const service = decodeURIComponent(url.pathname.slice(1));
    const validHost =
      isIP(host) !== 0 ||
      (host.length <= 253 &&
        host
          .split('.')
          .every((label) =>
            /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/.test(label),
          ));
    if (
      url.protocol !== 'oracle:' ||
      !validHost ||
      !user ||
      !password ||
      !/^[A-Za-z0-9_.-]+(?![\s\S])/.test(service) ||
      (url.port !== '' &&
        (!Number.isSafeInteger(Number(url.port)) ||
          Number(url.port) < 1 ||
          Number(url.port) > 65535)) ||
      /[\0\r\n]/.test(user + password)
    )
      throw new Error('Explicit Oracle host, credentials and service are required');
    for (const key of url.searchParams.keys())
      if (!['ssl', 'wallet'].includes(key) || url.searchParams.getAll(key).length !== 1)
        throw new Error('Unsupported or duplicate Oracle URL option');
    const local =
      environment !== 'production' &&
      (host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.')));
    const ssl = url.searchParams.get('ssl') ?? (local ? 'disable' : 'verify-full');
    if (!['disable', 'verify-full'].includes(ssl) || (ssl === 'disable' && !local))
      throw new Error('Oracle network connections require verified TLS');
    const wallet = url.searchParams.get('wallet');
    if (
      wallet !== null &&
      (ssl !== 'verify-full' || !isAbsolute(wallet) || /[\0\r\n]/.test(wallet))
    )
      throw new Error('Oracle wallet requires verified TLS and an absolute directory');
    return {
      user,
      password,
      connectString: `${ssl === 'disable' ? 'tcp' : 'tcps'}://${url.hostname}:${url.port || (ssl === 'disable' ? '1521' : '2484')}/${service}`,
      sslServerDNMatch: true,
      sslAllowWeakDNMatch: false,
      ...(wallet === null ? {} : { walletLocation: wallet }),
      poolAlias: `arkenivajs-${randomUUID()}`,
      poolMin: minimum,
      poolMax: maximum,
      poolIncrement: 1,
      queueTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
      queueMax: Math.max(maximum, 128),
      connectTimeout: 5,
      transportConnectTimeout: 5,
      retryCount: 0,
      poolPingInterval: 0,
      poolPingTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
      homogeneous: true,
      externalAuth: false,
      events: false,
      stmtCacheSize: 100,
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Oracle connection or TLS policy',
      cause,
    });
  }
}
