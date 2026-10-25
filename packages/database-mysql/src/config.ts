// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { KitError, DEFAULT_POOL_ACQUIRE_TIMEOUT_MS } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import type { PoolOptions } from 'mysql2';

/** Native pools have a startup warm floor and a fixed maximum retained capacity. */
export interface MysqlConfiguration {
  readonly pool: PoolOptions;
  readonly minimum: number;
}

/** Capture only the named environment value; native URL option coercion is deliberately avoided. */
export function mysqlConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): MysqlConfiguration {
  if (definition.driver !== 'mysql' || definition.endpoints !== undefined)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MySQL requires a connection-string definition',
    });
  const variable = definition.connectionStringEnv;
  if (!variable || !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'MySQL connectionStringEnv is required',
    });
  const connectionString = process.env[variable];
  if (!connectionString)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'MySQL connection string environment value is missing',
    });
  const minimum = definition.poolMin ?? 0;
  const maximum = definition.poolMax ?? 10;
  if (
    !Number.isSafeInteger(minimum) ||
    !Number.isSafeInteger(maximum) ||
    minimum < 0 ||
    maximum < 1 ||
    minimum > maximum
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MySQL pool bounds must be safe integers with 0 <= min <= max',
    });
  try {
    if (/[\r\n\0]/.test(connectionString) || connectionString.includes('#'))
      throw new Error('Invalid MySQL URL syntax');
    const url = new URL(connectionString);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const user = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    const database = decodeURIComponent(url.pathname.slice(1));
    if (
      url.protocol !== 'mysql:' ||
      !host ||
      !user ||
      !database ||
      database.includes('/') ||
      /[\0\r\n]/.test(database) ||
      /[\0\r\n]/.test(user + password)
    )
      throw new Error('Explicit MySQL host, user and database are required');
    for (const key of url.searchParams.keys())
      if (!['ssl', 'sslca'].includes(key) || url.searchParams.getAll(key).length !== 1)
        throw new Error('Unsupported or duplicate MySQL URL option');
    const local =
      environment !== 'production' &&
      (host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.')));
    const policy = url.searchParams.get('ssl') ?? (local ? 'disable' : 'verify-full');
    if (!['disable', 'verify-full'].includes(policy) || (policy === 'disable' && !local))
      throw new Error('MySQL network connections require verified TLS');
    if (policy === 'verify-full' && (isIP(host) !== 0 || !/[A-Za-z]/.test(host)))
      throw new Error('Verified MySQL TLS requires a DNS hostname with this native driver');
    const caPath = url.searchParams.get('sslca');
    if (caPath !== null && (policy === 'disable' || !isAbsolute(caPath) || caPath.includes('\0')))
      throw new Error('MySQL sslca requires verified TLS and an absolute file path');
    const ca = caPath === null ? undefined : readFileSync(caPath);
    if (ca !== undefined && (ca.length === 0 || ca.length > 1_048_576))
      throw new Error('Invalid MySQL CA bundle size');
    return {
      minimum,
      pool: {
        host,
        user,
        password,
        database,
        port: url.port ? Number(url.port) : 3306,
        ...(policy === 'verify-full'
          ? {
              ssl: {
                rejectUnauthorized: true,
                verifyIdentity: true,
                minVersion: 'TLSv1.2',
                ...(ca === undefined ? {} : { ca }),
              },
            }
          : {}),
        charset: 'UTF8MB4_UNICODE_CI',
        timezone: 'Z',
        supportBigNumbers: true,
        bigNumberStrings: true,
        decimalNumbers: false,
        dateStrings: true,
        jsonStrings: true,
        rowsAsArray: false,
        namedPlaceholders: false,
        multipleStatements: false,
        flags: ['-LOCAL_FILES'],
        connectTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
        waitForConnections: true,
        connectionLimit: maximum,
        maxIdle: maximum,
        queueLimit: Math.max(maximum, 128),
        maxPreparedStatements: 100,
        resetOnRelease: false,
        enableKeepAlive: true,
        disableEval: true,
      },
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid MySQL connection or TLS policy',
      cause,
    });
  }
}
