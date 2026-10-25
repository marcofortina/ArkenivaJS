import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { ApplicationOptions, MessageBus, OperationOptions, Plugin } from '@arkenivajs/core';
import { ACTIVATE_PLUGIN, PREPARE_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { NatsBus } from './connection.js';
import { natsConfiguration, natsPolicy } from './config.js';
import type { ManagedMessageBus, NatsBusOptions } from './types.js';
export type { MessageBus, MessageEnvelope, Subscription } from '@arkenivajs/core';
export type {
  ManagedMessageBus,
  NatsBusOptions,
  MessageFailure,
  MessageBusStats,
} from './types.js';

/** Create a standalone owner only through explicit configuration and startup. */
export async function createNatsBus(
  options: NatsBusOptions,
  operation?: OperationOptions,
): Promise<ManagedMessageBus> {
  const policy = natsPolicy(options);
  const owner = new NatsBus(natsConfiguration(policy.connectionStringEnv!), policy);
  await owner.start(operation);
  return owner;
}

export interface MessagingPluginOptions extends Omit<
  NatsBusOptions,
  'logger' | 'telemetry' | 'meter'
> {
  readonly dependencies?: readonly string[];
}
const OBSERVATION = Symbol('messaging.observation');
const observationPlugin: SupportPluginFactory = (root) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
      ['meter', COMPONENTS.meter],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = root.plugins?.find((entry) => entry.capabilities.has(capability));
    return owner ? [{ capability, key, id: owner.id }] : [];
  });
  return {
    id: 'messaging-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map((entry) => entry.id))],
    init(context) {
      context.provide(
        OBSERVATION,
        Object.freeze(
          Object.fromEntries(owners.map((entry) => [entry.capability, context.require(entry.key)])),
        ),
      );
    },
    close() {},
  };
};

/** Prepare a frozen portable facade without opening a connection or granting foreign component access. */
export function messagingPlugin(options: MessagingPluginOptions): Plugin {
  if (
    !options ||
    typeof options !== 'object' ||
    Array.isArray(options) ||
    Object.values(Object.getOwnPropertyDescriptors(options)).some((entry) => !('value' in entry)) ||
    Object.keys(options).some(
      (key) => !['connectionStringEnv', 'onError', 'dependencies'].includes(key),
    ) ||
    (options.dependencies !== undefined &&
      (!Array.isArray(options.dependencies) ||
        !options.dependencies.every((id) => typeof id === 'string')))
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid messaging plugin policy' });
  const { dependencies = [], ...input } = options;
  const policy = natsPolicy(input);
  const applications = new WeakMap<
    ApplicationOptions,
    { connection?: NatsBus; active: boolean; closed: boolean }
  >();
  const plugin: ComposablePlugin = {
    id: 'messaging',
    version: '0.1.0',
    capabilities: new Set(['messaging']),
    dependencies: ['messaging-observation', ...dependencies],
    [SUPPORT_PLUGINS]: [observationPlugin],
    [PREPARE_PLUGIN](context) {
      const owner: { connection?: NatsBus; active: boolean; closed: boolean } = {
        active: false,
        closed: false,
      };
      applications.set(context.options, owner);
      const available = () => {
        if (owner.closed || ['CLOSED', 'FAILED'].includes(context.state()))
          throw new KitError({
            code: 'EK_RESOURCE_CLOSED',
            message: 'Messaging provider is closed',
          });
        if (!owner.active || !owner.connection || !['READY', 'DRAINING'].includes(context.state()))
          throw new KitError({
            code: 'EK_LIFECYCLE_STATE',
            message: 'Messaging provider is not active',
          });
        return owner.connection;
      };
      const facade: MessageBus = Object.freeze<MessageBus>({
        publish: async (topic, payload, operation) =>
          available().publish(topic, payload, operation),
        subscribe: async (topic, handler, operation) =>
          available().subscribe(topic, handler, operation),
      });
      return new Map([[COMPONENTS.messaging, facade]]);
    },
    async init(context) {
      const owner = applications.get(context.options)!;
      try {
        owner.connection = new NatsBus(natsConfiguration(policy.connectionStringEnv!), {
          ...policy,
          ...context.require<Pick<NatsBusOptions, 'logger' | 'telemetry' | 'meter'>>(OBSERVATION),
        });
        await owner.connection.start({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      } catch (cause) {
        owner.closed = true;
        applications.delete(context.options);
        throw cause;
      }
    },
    [ACTIVATE_PLUGIN](context) {
      applications.get(context.options)!.active = true;
    },
    async health(context, operation) {
      const owner = applications.get(context.options);
      return owner && !owner.closed && owner.connection
        ? owner.connection.health(operation)
        : false;
    },
    async close(context) {
      const owner = applications.get(context.options);
      if (!owner) return;
      applications.delete(context.options);
      owner.active = false;
      owner.closed = true;
      await owner.connection?.close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
  };
  return plugin;
}
