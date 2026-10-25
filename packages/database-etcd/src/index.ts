// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { ApplicationOptions, Plugin, EtcdProvider } from '@arkenivajs/core';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { etcdConfiguration } from './config.js';
import { EtcdConnection } from './connection.js';
import type { EtcdObservationPorts } from './connection.js';
import { etcdError } from './errors.js';

const OBSERVATION = Symbol('arkenivajs.etcd.observation');
const SUPPORT_ID = 'database-etcd-observation';
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
      /* Observation references have no independent remote lifetime. */
    },
  };
};
interface Owner {
  connection?: EtcdConnection;
  active: boolean;
  closed: boolean;
}

/** Install the actual etcd3 provider without resolving secrets or opening sockets during creation. */
export function etcdPlugin(): Plugin {
  const applications = new WeakMap<ApplicationOptions, Owner>();
  const plugin: ComposablePlugin = {
    id: 'database-etcd',
    version: '0.1.0',
    capabilities: new Set(['etcd', 'database.etcd']),
    dependencies: [SUPPORT_ID],
    [SUPPORT_PLUGINS]: [observationPlugin],
    [PREPARE_PLUGIN](context) {
      const owner: Owner = { active: false, closed: false };
      applications.set(context.options, owner);
      const available = (): EtcdConnection => {
        if (owner.closed || ['CLOSED', 'FAILED'].includes(context.state()))
          throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd provider is closed' });
        if (!owner.active || !owner.connection || !['READY', 'DRAINING'].includes(context.state()))
          throw new KitError({
            code: 'EK_LIFECYCLE_STATE',
            message: 'etcd provider is not active',
          });
        return owner.connection;
      };
      const provider = Object.freeze<EtcdProvider>({
        get: async (key, options) => available().get(key, options),
        put: async (key, value, options) => available().put(key, value, options),
        delete: async (key, options) => available().delete(key, options),
        watch: async (prefix, options) => available().watch(prefix, options),
        grantLease: async (ttl, options) => available().grantLease(ttl, options),
        compareAndSwap: async (input, options) => available().compareAndSwap(input, options),
        native: () => available().native(),
      });
      return new Map([[COMPONENTS.etcd, provider]]);
    },
    async init(context) {
      const definitions = Object.entries(context.options.databases ?? {}).filter(
        ([, definition]) => definition.driver === 'etcd',
      );
      if (definitions.length !== 1)
        throw new KitError({
          code: 'EK_CONFIG_MISSING',
          message: 'Exactly one etcd database definition is required',
        });
      const [name, definition] = definitions[0]!;
      const configuration = etcdConfiguration(definition, context.options.service.environment);
      const owner = applications.get(context.options)!;
      try {
        owner.connection = new EtcdConnection(
          name,
          configuration,
          context.require<EtcdObservationPorts>(OBSERVATION),
        );
        await owner.connection.start({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      } catch (cause) {
        owner.closed = true;
        try {
          await owner.connection?.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd initialization and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw etcdError(cause);
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
