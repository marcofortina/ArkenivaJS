// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { checkServerIdentity, rootCertificates } from 'node:tls';
import type { ConnectionOptions } from 'node:tls';
import { KitError, DEFAULT_POOL_ACQUIRE_TIMEOUT_MS } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import type { PoolConfig } from 'mariadb';

/** Native pools have a startup warm floor and a fixed maximum retained capacity. */
export interface MariadbConfiguration {
  readonly pool: PoolConfig;
  readonly minimum: number;
}

/** Capture only the named environment value; native URL option coercion is deliberately avoided. */
export function mariadbConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): MariadbConfiguration {
  if (definition.driver !== 'mariadb' || definition.endpoints !== undefined)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MariaDB requires a connection-string definition',
    });
  const variable = definition.connectionStringEnv;
  if (!variable || !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'MariaDB connectionStringEnv is required',
    });
  const connectionString = process.env[variable];
  if (!connectionString)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'MariaDB connection string environment value is missing',
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
      message: 'MariaDB pool bounds must be safe integers with 0 <= min <= max',
    });
  try {
    if (/[\r\n\0]/.test(connectionString) || connectionString.includes('#'))
      throw new Error('Invalid MariaDB URL syntax');
    const url = new URL(connectionString);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const user = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    const database = decodeURIComponent(url.pathname.slice(1));
    if (
      url.protocol !== 'mariadb:' ||
      !host ||
      !user ||
      !database ||
      database.includes('/') ||
      /[\0\r\n]/.test(database) ||
      /[\0\r\n]/.test(user + password)
    )
      throw new Error('Explicit MariaDB host, user and database are required');
    for (const key of url.searchParams.keys())
      if (!['ssl', 'sslca'].includes(key) || url.searchParams.getAll(key).length !== 1)
        throw new Error('Unsupported or duplicate MariaDB URL option');
    const local =
      environment !== 'production' &&
      (host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.')));
    const policy = url.searchParams.get('ssl') ?? (local ? 'disable' : 'verify-full');
    if (!['disable', 'verify-full'].includes(policy) || (policy === 'disable' && !local))
      throw new Error('MariaDB network connections require verified TLS');
    const caPath = url.searchParams.get('sslca');
    if (caPath !== null && (policy === 'disable' || !isAbsolute(caPath) || caPath.includes('\0')))
      throw new Error('MariaDB sslca requires verified TLS and an absolute file path');
    const ca = caPath === null ? [...rootCertificates] : readFileSync(caPath);
    if (ca.length === 0 || ca.length > 1_048_576) throw new Error('Invalid MariaDB CA bundle size');
    // Explicit roots prevent native password/fingerprint fallback from relaxing TLS verification.
    const ssl: (ConnectionOptions & { rejectUnauthorized: true }) | undefined =
      policy === 'verify-full'
        ? {
            ca,
            host,
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            ...(isIP(host) ? {} : { servername: host }),
            checkServerIdentity: (_servername, certificate) =>
              checkServerIdentity(host, certificate),
          }
        : undefined;
    return {
      minimum,
      pool: {
        host,
        user,
        password,
        database,
        port: url.port ? Number(url.port) : 3306,
        ...(ssl === undefined ? {} : { ssl }),
        charset: 'utf8mb4',
        collation: 'UTF8MB4_UNICODE_CI',
        timezone: '+00:00',
        bigIntAsNumber: false,
        insertIdAsNumber: false,
        decimalAsNumber: false,
        checkNumberRange: true,
        dateStrings: true,
        autoJsonMap: false,
        rowsAsArray: false,
        metaAsArray: false,
        namedPlaceholders: false,
        multipleStatements: false,
        permitLocalInfile: false,
        connectTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
        acquireTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
        initializationTimeout: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
        connectionLimit: maximum,
        minimumIdle: minimum,
        idleTimeout: 10,
        minDelayValidation: 0,
        prepareCacheLength: 100,
        resetAfterUse: false,
        noControlAfterUse: false,
        trace: false,
        logParam: false,
        logger: {},
      },
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid MariaDB connection or TLS policy',
      cause,
    });
  }
}
