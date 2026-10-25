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
import { mysqlConfiguration } from './config.js';
import { MysqlConnection } from './connection.js';

/** Install root-configured MySQL pools; imports and factory calls open no native resources. */
export function mysqlPlugin(): Plugin {
  const applications = new WeakMap<PluginContext, readonly MysqlConnection[]>();
  const plugin: ComposablePlugin = {
    id: 'database-mysql',
    version: '0.1.0',
    capabilities: new Set(['database.mysql']),
    dependencies: [SQL_SUPPORT_ID],
    [SUPPORT_PLUGINS]: [sqlSupportPlugin],
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'mysql',
      );
      if (!definitions.length)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'At least one MySQL database definition is required',
        });
      const prepared = definitions.map(
        ([name, definition]) =>
          [name, mysqlConfiguration(definition, context.options.service.environment)] as const,
      );
      const registry = context.require<SqlDriverRegistry>(SQL_DRIVER_REGISTRY);
      const pools: MysqlConnection[] = [];
      try {
        for (const [name, config] of prepared) {
          const pool = new MysqlConnection(name, config, registry.observation);
          pools.push(pool);
          await pool.warm();
          const health = await pool.queryOne<{ healthy: string }>(
            { text: 'SELECT 1 AS healthy' },
            { signal: context.require<AbortSignal>(APPLICATION_SIGNAL) },
          );
          if (health?.healthy !== '1')
            throw new KitError({
              code: 'EK_DATABASE_CONNECT',
              message: 'MySQL startup health check failed',
              retryable: true,
            });
          registry.register(name, 'mysql', pool);
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
            message: 'MySQL startup and cleanup failed',
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
          message: 'MySQL pool shutdown failed',
          cause: new AggregateError(failures),
        });
    },
  };
  return plugin;
}
