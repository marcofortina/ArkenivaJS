// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, PluginContext } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import {
  SQL_DRIVER_REGISTRY,
  SQL_SUPPORT_ID,
  sqlSupportPlugin,
} from '@arkenivajs/database/support';
import type { SqlDriverRegistry } from '@arkenivajs/database/support';
import { oracleConfiguration } from './config.js';
import { OracleConnection } from './connection.js';

/** Install root-configured Oracle pools; imports and factory calls open no native resources. */
export function oraclePlugin(options: { mode?: 'thin' | 'thick' } = {}): Plugin {
  if (
    !options ||
    typeof options !== 'object' ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => key !== 'mode') ||
    (options.mode !== undefined && !['thin', 'thick'].includes(options.mode))
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Oracle mode must be thin or thick' });
  const mode = options.mode ?? 'thin';
  const applications = new WeakMap<PluginContext, readonly OracleConnection[]>();
  const plugin: ComposablePlugin = {
    id: 'database-oracle',
    version: '0.1.0',
    capabilities: new Set(['database.oracle']),
    dependencies: [SQL_SUPPORT_ID],
    [SUPPORT_PLUGINS]: [sqlSupportPlugin],
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'oracle',
      );
      if (!definitions.length)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'At least one Oracle database definition is required',
        });
      const prepared = definitions.map(
        ([name, definition]) =>
          [name, oracleConfiguration(definition, context.options.service.environment)] as const,
      );
      const registry = context.require<SqlDriverRegistry>(SQL_DRIVER_REGISTRY);
      const pools: OracleConnection[] = [];
      try {
        for (const [name, config] of prepared) {
          const pool = await OracleConnection.create(name, config, registry.observation, mode, {
            signal: context.require<AbortSignal>(APPLICATION_SIGNAL),
          });
          pools.push(pool);
          const health = await pool.queryOne<{ healthy: string }>(
            { text: 'SELECT 1 AS "healthy" FROM DUAL' },
            { signal: context.require<AbortSignal>(APPLICATION_SIGNAL) },
          );
          if (health?.healthy !== '1')
            throw new KitError({
              code: 'EK_DATABASE_CONNECT',
              message: 'Oracle startup health check failed',
              retryable: true,
            });
          registry.register(name, 'oracle', pool);
        }
        applications.set(context, pools);
      } catch (cause) {
        const closed = await Promise.allSettled(pools.map((pool) => pool.close()));
        const failures = closed
          .filter((result) => result.status === 'rejected')
          .map((result) => result.reason as unknown);
        if (failures.length)
          throw new KitError({
            code: 'EK_DATABASE_CONNECT',
            message: 'Oracle startup and cleanup failed',
            cause: new AggregateError([cause, ...failures]),
          });
        throw cause;
      }
    },
    async health(context, options) {
      const pools = applications.get(context);
      if (!pools?.length) return false;
      for (const pool of pools) if ((await pool.ping(options)) !== true) return false;
      return true;
    },
    async close(context) {
      const pools = applications.get(context) ?? [];
      applications.delete(context);
      const closed = await Promise.allSettled(pools.map((pool) => pool.close()));
      const failures = closed
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason as unknown);
      if (failures.length)
        throw new KitError({
          code: 'EK_DATABASE_UNAVAILABLE',
          message: 'Oracle pool shutdown failed',
          cause: new AggregateError(failures),
        });
    },
  };
  return plugin;
}
