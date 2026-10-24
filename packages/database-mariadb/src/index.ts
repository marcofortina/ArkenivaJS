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
import { mariadbConfiguration } from './config.js';
import { MariadbConnection } from './connection.js';

/** Install root-configured MariaDB pools; imports and factory calls open no native resources. */
export function mariadbPlugin(): Plugin {
  const applications = new WeakMap<PluginContext, readonly MariadbConnection[]>();
  const plugin: ComposablePlugin = {
    id: 'database-mariadb',
    version: '0.1.0',
    capabilities: new Set(['database.mariadb']),
    dependencies: [SQL_SUPPORT_ID],
    [SUPPORT_PLUGINS]: [sqlSupportPlugin],
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'mariadb',
      );
      if (!definitions.length)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'At least one MariaDB database definition is required',
        });
      const prepared = definitions.map(
        ([name, definition]) =>
          [name, mariadbConfiguration(definition, context.options.service.environment)] as const,
      );
      const registry = context.require<SqlDriverRegistry>(SQL_DRIVER_REGISTRY);
      const pools: MariadbConnection[] = [];
      try {
        for (const [name, config] of prepared) {
          const pool = new MariadbConnection(name, config, registry.observation);
          pools.push(pool);
          await pool.warm({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
          const health = await pool.queryOne<{ healthy: number }>(
            { text: 'SELECT 1 AS healthy' },
            { signal: context.require<AbortSignal>(APPLICATION_SIGNAL) },
          );
          if (health?.healthy !== 1)
            throw new KitError({
              code: 'EK_DATABASE_CONNECT',
              message: 'MariaDB startup health check failed',
              retryable: true,
            });
          registry.register(name, 'mariadb', pool);
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
            message: 'MariaDB startup and cleanup failed',
            cause: new AggregateError([cause, ...failures]),
          });
        throw cause;
      }
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
          message: 'MariaDB pool shutdown failed',
          cause: new AggregateError(failures),
        });
    },
  };
  return plugin;
}
