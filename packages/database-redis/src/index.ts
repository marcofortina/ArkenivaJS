import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { ApplicationOptions, Plugin, RedisProvider } from '@arkenivajs/core';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { redisConfiguration } from './config.js';
import { RedisConnection } from './connection.js';
import type { RedisObservationPorts } from './connection.js';

const OBSERVATION = Symbol('arkenivajs.redis.observation');
const SUPPORT_ID = 'database-redis-observation';
const observationPlugin: SupportPluginFactory = (root) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
      ['meter', COMPONENTS.meter],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = root.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ capability, key, owner: owner.id }] : [];
  });
  return {
    id: SUPPORT_ID,
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map(({ owner }) => owner))],
    init(context) {
      context.provide(
        OBSERVATION,
        Object.freeze(
          Object.fromEntries(
            owners.map(({ capability, key }) => [capability, context.require(key)]),
          ),
        ),
      );
    },
    close() {
      /* Observation references have no independent resource lifetime. */
    },
  };
};

interface Owner {
  connection?: RedisConnection;
  active: boolean;
  closed: boolean;
}

/** Install one explicitly configured Redis provider; factory/application creation opens no socket. */
export function redisPlugin(): Plugin {
  const applications = new WeakMap<ApplicationOptions, Owner>();
  const plugin: ComposablePlugin = {
    id: 'database-redis',
    version: '0.1.0',
    capabilities: new Set(['redis', 'database.redis']),
    dependencies: [SUPPORT_ID],
    [SUPPORT_PLUGINS]: [observationPlugin],
    [PREPARE_PLUGIN](context) {
      const owner: Owner = { active: false, closed: false };
      applications.set(context.options, owner);
      const available = (): RedisConnection => {
        if (owner.closed || ['CLOSED', 'FAILED'].includes(context.state()))
          throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Redis provider is closed' });
        if (!owner.active || !owner.connection || !['READY', 'DRAINING'].includes(context.state()))
          throw new KitError({
            code: 'EK_LIFECYCLE_STATE',
            message: 'Redis provider is not active',
          });
        return owner.connection;
      };
      const provider: RedisProvider = Object.freeze<RedisProvider>({
        get: async (key, options) => available().get(key, options),
        set: async (key, value, options) => available().set(key, value, options),
        del: async (keys, options) => available().del(keys, options),
        increment: async (key, amount, options) => available().increment(key, amount, options),
        publish: async (channel, message, options) =>
          available().publish(channel, message, options),
        native: () => available().native(),
      });
      return new Map([[COMPONENTS.redis, provider]]);
    },
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'redis',
      );
      if (definitions.length !== 1)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'Exactly one Redis database definition is required',
        });
      const [name, definition] = definitions[0]!;
      const configuration = redisConfiguration(definition, context.options.service.environment);
      const owner = applications.get(context.options)!;
      try {
        owner.connection = new RedisConnection(
          name,
          configuration,
          context.require<RedisObservationPorts>(OBSERVATION),
        );
        await owner.connection.start({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      } catch (cause) {
        owner.closed = true;
        try {
          await owner.connection?.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Redis initialization and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw cause;
      }
    },
    [ACTIVATE_PLUGIN](context) {
      applications.get(context.options)!.active = true;
    },
    async close(context) {
      const owner = applications.get(context.options);
      if (!owner) return;
      applications.delete(context.options);
      owner.active = false;
      owner.closed = true;
      await owner.connection?.close();
    },
  };
  return plugin;
}
