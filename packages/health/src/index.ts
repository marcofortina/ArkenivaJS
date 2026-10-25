import { KitError, COMPONENTS } from '@arkenivajs/core';
import type {
  HealthRegistry,
  ApplicationOptions,
  Plugin,
  PluginContext,
  OperationOptions,
  Telemetry,
  Logger,
} from '@arkenivajs/core';
import { PREPARE_PLUGIN, SUPPORT_PLUGINS, HEALTH_PROBES } from '@arkenivajs/core/support';
import type {
  ComposablePlugin,
  SupportPluginFactory,
  PluginHealthProbe,
} from '@arkenivajs/core/support';
import { createHealthRegistry, healthPolicy } from './registry.js';
import type { ManagedHealthRegistry } from './registry.js';
export { createHealthRegistry } from './registry.js';
export type { HealthOptions, HealthCheck, ManagedHealthRegistry } from './registry.js';
export type { HealthRegistry } from '@arkenivajs/core';

export interface PluginHealthCheck {
  readonly name: string;
  /** Context access is restricted to the health plugin's explicit declared dependencies. */
  readonly check: (context: PluginContext, options: OperationOptions) => Promise<boolean> | boolean;
}
export interface HealthPluginOptions {
  readonly checks?: readonly PluginHealthCheck[];
  readonly timeoutMs?: number;
  readonly dependencies?: readonly string[];
}
const OBSERVATION = Symbol('health.observation');
const observations: SupportPluginFactory = (root) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
    ] as const
  ).flatMap(([name, key]) => {
    const owner = root.plugins?.find((plugin) => plugin.capabilities.has(name));
    return owner ? [{ name, key, id: owner.id }] : [];
  });
  return {
    id: 'health-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map((owner) => owner.id))],
    init(context) {
      context.provide(
        OBSERVATION,
        Object.freeze(
          Object.fromEntries(owners.map((owner) => [owner.name, context.require(owner.key)])),
        ),
      );
    },
    close() {},
  };
};

/** Activate only after named dependency probes pass; the HTTP layer obtains safe readiness separately. */
export function healthPlugin(input: HealthPluginOptions = {}): Plugin {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    Object.keys(input).some((key) => !['checks', 'timeoutMs', 'dependencies'].includes(key)) ||
    (input.checks !== undefined && !Array.isArray(input.checks)) ||
    (input.dependencies !== undefined &&
      (!Array.isArray(input.dependencies) ||
        input.dependencies.some((id) => typeof id !== 'string')))
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health plugin policy' });
  const timeoutMs = input.timeoutMs,
    checks = (input.checks ?? []).map((entry) => ({
      name: entry?.name,
      check: typeof entry?.check === 'function' ? entry.check.bind(entry) : entry?.check,
    }));
  // Reuse the same pure metadata validation before any application-owned resource can initialize.
  healthPolicy({
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
    checks,
  });
  const dependencies = Object.freeze([...(input.dependencies ?? [])]),
    owners = new WeakMap<
      ApplicationOptions,
      { registry?: ManagedHealthRegistry; closed: boolean; state: () => string }
    >();
  const plugin: ComposablePlugin = {
    id: 'health',
    version: '0.1.0',
    capabilities: new Set(['health']),
    dependencies: [...dependencies, 'health-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      const automatic = (context.options.plugins ?? []).filter(
        (entry) => typeof (entry as ComposablePlugin).health === 'function',
      );
      healthPolicy({
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        checks: [
          ...checks,
          ...automatic.map((entry) => ({
            name: 'plugin.' + entry.id,
            check: (entry as ComposablePlugin).health,
          })),
        ],
      });
      const owner: { registry?: ManagedHealthRegistry; closed: boolean; state: () => string } = {
        closed: false,
        state: context.state,
      };
      owners.set(context.options, owner);
      const facade: HealthRegistry = Object.freeze({
        live: () => ({ status: 'live' as const }),
        ready: async () =>
          !owner.closed && owner.registry && context.state() === 'READY'
            ? owner.registry.ready()
            : { status: 'not_ready' as const, failing: Object.freeze(['application']) },
      });
      return new Map([[COMPONENTS.health, facade]]);
    },
    async init(context) {
      const owner = owners.get(context.options)!;
      owner.registry = createHealthRegistry({
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        checks: [
          ...context.require<readonly PluginHealthProbe[]>(HEALTH_PROBES),
          ...checks.map((entry) => ({
            name: entry.name,
            check: (operation: OperationOptions) => entry.check(context, operation),
          })),
        ],
        isReady: () => !owner.closed && owners.has(context.options) && owner.state() === 'READY',
        ...context.require<{ telemetry?: Telemetry; logger?: Logger }>(OBSERVATION),
      });
      try {
        await owner.registry.start();
      } catch (cause) {
        owner.closed = true;
        try {
          await owner.registry.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_HEALTH_NOT_READY',
            message: 'Health startup and probe cleanup failed',
            cause: new AggregateError([cause, cleanup]),
            details: { cleanupFailed: true },
          });
        } finally {
          owners.delete(context.options);
        }
        throw cause;
      }
    },
    async close(context) {
      const owner = owners.get(context.options);
      if (!owner) return;
      owner.closed = true;
      await owner.registry?.close();
      owners.delete(context.options);
    },
  };
  return plugin;
}
