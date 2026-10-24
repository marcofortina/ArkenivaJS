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
import { postgresConfiguration } from './config.js';
import { PostgresConnection } from './connection.js';

/** Install named PostgreSQL pools from root configuration; no native resource opens before start. */
export function postgresPlugin(): Plugin {
  const applications = new WeakMap<PluginContext, readonly PostgresConnection[]>();
  const plugin: ComposablePlugin = {
    id: 'database-postgres',
    version: '0.1.0',
    capabilities: new Set(['database.postgresql']),
    dependencies: [SQL_SUPPORT_ID],
    [SUPPORT_PLUGINS]: [sqlSupportPlugin],
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'postgresql',
      );
      if (!definitions.length)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'At least one PostgreSQL database definition is required',
        });
      const prepared = definitions.map(
        ([name, definition]) =>
          [
            name,
            postgresConfiguration(
              name,
              definition,
              context.options.service.environment,
              context.options.service.name,
            ),
          ] as const,
      );
      const registry = context.require<SqlDriverRegistry>(SQL_DRIVER_REGISTRY);
      const pools: PostgresConnection[] = [];
      try {
        for (const [name, config] of prepared) {
          const pool = new PostgresConnection(name, config, registry.observation);
          pools.push(pool);
          const health = await pool.queryOne<{ healthy: number }>(
            { text: 'SELECT 1 AS healthy' },
            { signal: context.require<AbortSignal>(APPLICATION_SIGNAL) },
          );
          if (health?.healthy !== 1)
            throw new KitError({
              code: 'EK_DATABASE_CONNECT',
              message: 'PostgreSQL startup health check failed',
              retryable: true,
            });
          registry.register(name, 'postgresql', pool);
        }
        applications.set(context, pools);
      } catch (cause) {
        const closed = await Promise.allSettled(pools.map((pool) => pool.close()));
        const cleanup = closed
          .filter((result) => result.status === 'rejected')
          .map((result) => result.reason as unknown);
        if (cleanup.length)
          throw new KitError({
            code: 'EK_DATABASE_CONNECT',
            message: 'PostgreSQL startup and cleanup failed',
            cause: new AggregateError([cause, ...cleanup]),
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
          message: 'PostgreSQL pool shutdown failed',
          cause: new AggregateError(failures),
        });
    },
  };
  return plugin;
}
