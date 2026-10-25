// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { checkServerIdentity } from 'node:tls';
import { isIP } from 'node:net';
import { KitError, DEFAULT_POOL_ACQUIRE_TIMEOUT_MS } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';
import { parse, toClientConfig } from 'pg-connection-string';
import type { PoolConfig } from 'pg';

/** Native connection policy is derived only at startup from the named root definition. */
export function postgresConfiguration(
  name: string,
  definition: DatabaseDefinition,
  environment: Environment,
  service: string,
): PoolConfig {
  if (definition.driver !== 'postgresql' || definition.endpoints !== undefined)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'PostgreSQL requires a connection-string definition',
    });
  const variable = definition.connectionStringEnv;
  if (!variable || !/^[A-Z_][A-Z0-9_]*$/.test(variable) || /[\r\n]$/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'PostgreSQL connectionStringEnv is required',
    });
  const connectionString = process.env[variable];
  if (!connectionString)
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'PostgreSQL connection string environment value is missing',
    });
  const min = definition.poolMin ?? 0,
    max = definition.poolMax ?? 10;
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || max <= 0 || min > max)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'PostgreSQL pool bounds must be safe integers with 0 <= min <= max',
    });
  try {
    if (!/^postgres(?:ql)?:\/\//i.test(connectionString) || connectionString.includes('#'))
      throw new Error('Unsupported PostgreSQL connection string syntax');
    // The native parser also supports an empty URL host with an explicit Unix socket host.
    const parsed = parse(connectionString);
    if (parsed.port && !/^[0-9]+(?![\s\S])/.test(parsed.port))
      throw new Error('Invalid PostgreSQL port');
    if (typeof parsed.ssl === 'string') throw new Error('Invalid PostgreSQL TLS policy');
    if (
      parsed.sslmode !== undefined &&
      !['disable', 'prefer', 'require', 'verify-ca', 'verify-full', 'no-verify'].includes(
        String(parsed.sslmode),
      )
    )
      throw new Error('Invalid PostgreSQL TLS mode');
    const config = toClientConfig(parsed);
    if (!config.host || !config.user || !config.database)
      throw new Error('Explicit PostgreSQL host, user and database are required');
    if (
      config.port !== undefined &&
      (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535)
    )
      throw new Error('Invalid PostgreSQL port');
    const host = config.host;
    const socket = host.startsWith('/');
    const loopback =
      host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.'));
    const local = socket || (environment !== 'production' && loopback);
    let ssl = config.ssl;
    if (ssl === undefined) ssl = local ? false : {};
    if (typeof ssl !== 'boolean' && (ssl === null || typeof ssl !== 'object'))
      throw new Error('Invalid PostgreSQL TLS policy');
    if (ssl === false && !local)
      throw new Error('PostgreSQL network connections require verified TLS');
    if (socket && ssl !== false)
      throw new Error('PostgreSQL Unix socket connections do not use TLS');
    if (ssl !== false) {
      if (typeof ssl === 'object' && ssl.rejectUnauthorized === false)
        throw new Error('Unverified PostgreSQL TLS is forbidden');
      ssl = {
        ...(typeof ssl === 'object' ? ssl : {}),
        rejectUnauthorized: true,
        // pg omits SNI for IP literals; identity still belongs to the configured endpoint.
        checkServerIdentity: (_servername, certificate) => checkServerIdentity(host, certificate),
      };
    }
    if (config.client_encoding && !/^utf-?8$/i.test(config.client_encoding))
      throw new Error('The portable PostgreSQL adapter requires UTF-8');
    const password = config.password;
    if (password !== undefined && typeof password !== 'string')
      throw new Error('PostgreSQL credentials must come from the configured environment value');
    return {
      ...config,
      host,
      user: config.user,
      database: config.database,
      // A callback prevents pg from consulting ambient PGPASSWORD or an implicit .pgpass file.
      password: () => password ?? '',
      ssl,
      min,
      max,
      connectionTimeoutMillis: DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
      idleTimeoutMillis: 10_000,
      application_name: config.application_name ?? `${service}:${name}`.slice(0, 63),
      client_encoding: 'UTF8',
      enableChannelBinding: true,
      query_timeout: 0,
      pipeline: false,
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid PostgreSQL connection or TLS policy',
      cause,
    });
  }
}
