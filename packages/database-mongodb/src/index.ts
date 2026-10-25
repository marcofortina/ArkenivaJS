import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { ApplicationOptions, Plugin, DocumentProvider } from '@arkenivajs/core';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { mongoConfiguration } from './config.js';
import { MongoConnection } from './connection.js';
import type { MongoObservationPorts } from './connection.js';
import { mongoError } from './errors.js';

const OBSERVATION = Symbol('arkenivajs.mongodb.observation');
const SUPPORT_ID = 'database-mongodb-observation';
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
      /* Observation references do not own independent native resources. */
    },
  };
};
interface Owner {
  connection?: MongoConnection;
  active: boolean;
  closed: boolean;
}

/** Install a native MongoDB provider without resolving secrets or opening a connection during creation. */
export function mongodbPlugin(): Plugin {
  const applications = new WeakMap<ApplicationOptions, Owner>();
  const plugin: ComposablePlugin = {
    id: 'database-mongodb',
    version: '0.1.0',
    capabilities: new Set(['mongo', 'database.mongodb']),
    dependencies: [SUPPORT_ID],
    [SUPPORT_PLUGINS]: [observationPlugin],
    [PREPARE_PLUGIN](context) {
      const owner: Owner = { active: false, closed: false };
      applications.set(context.options, owner);
      const available = (): MongoConnection => {
        if (owner.closed || ['CLOSED', 'FAILED'].includes(context.state()))
          throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'MongoDB provider is closed' });
        if (!owner.active || !owner.connection || !['READY', 'DRAINING'].includes(context.state()))
          throw new KitError({
            code: 'EK_LIFECYCLE_STATE',
            message: 'MongoDB provider is not active',
          });
        return owner.connection;
      };
      const provider = Object.freeze<DocumentProvider>({
        findOne: async (collection, filter, options) =>
          available().findOne(collection, filter, options),
        findMany: async (collection, filter, options) =>
          available().findMany(collection, filter, options),
        insertOne: async (collection, document, options) =>
          available().insertOne(collection, document, options),
        updateOne: async (collection, filter, update, options) =>
          available().updateOne(collection, filter, update, options),
        deleteOne: async (collection, filter, options) =>
          available().deleteOne(collection, filter, options),
        aggregate: async (collection, pipeline, options) =>
          available().aggregate(collection, pipeline, options),
        withTransaction: async (handler, options) => available().withTransaction(handler, options),
        native: () => available().native(),
      });
      return new Map([[COMPONENTS.mongo, provider]]);
    },
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'mongodb',
      );
      if (definitions.length !== 1)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'Exactly one MongoDB database definition is required',
        });
      const [name, definition] = definitions[0]!,
        configuration = mongoConfiguration(definition, context.options.service.environment),
        owner = applications.get(context.options)!;
      try {
        owner.connection = new MongoConnection(
          name,
          configuration,
          context.require<MongoObservationPorts>(OBSERVATION),
        );
        await owner.connection.start({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      } catch (cause) {
        owner.closed = true;
        try {
          await owner.connection?.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_DATABASE_CONNECT',
            message: 'MongoDB initialization and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw mongoError(cause);
      }
    },
    [ACTIVATE_PLUGIN](context) {
      applications.get(context.options)!.active = true;
    },
    async health(context, options) {
      const owner = applications.get(context.options);
      if (!owner || owner.closed || !owner.connection) return false;
      return owner.connection.health(options);
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
