import { performance } from 'node:perf_hooks';
import type {
  Application,
  ApplicationOptions,
  LifecycleState,
  Plugin,
  PluginContext,
  Logger,
  ConfigService,
} from './contracts.js';
import { KitError } from './errors.js';
import { ConfigStore, copyData, freezeData, within } from './support.js';
import { APPLICATION_SCHEMA, SEMVER_PATTERN } from './application-schema.js';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from './composition.js';
import type { ComposablePlugin, SupportPluginFactory } from './composition.js';

/** EK-CORE-002: explicit capability keys; no optional adapters load implicitly. */
export const COMPONENTS = Object.freeze({
  logger: Symbol('arkenivajs.logger'),
  config: Symbol('arkenivajs.config'),
  api: Symbol('arkenivajs.api'),
  http: Symbol('arkenivajs.http'),
  auth: Symbol('arkenivajs.auth'),
  cache: Symbol('arkenivajs.cache'),
  messaging: Symbol('arkenivajs.messaging'),
  sql: Symbol('arkenivajs.sql'),
  redis: Symbol('arkenivajs.redis'),
  etcd: Symbol('arkenivajs.etcd'),
  mongo: Symbol('arkenivajs.mongo'),
  telemetry: Symbol('arkenivajs.telemetry'),
  meter: Symbol('arkenivajs.meter'),
  diagnostics: Symbol('arkenivajs.diagnostics'),
  health: Symbol('arkenivajs.health'),
});
/** Cooperative startup cancellation is available through the kernel context. */
export const APPLICATION_SIGNAL = Symbol('arkenivajs.signal');
/** Stable default shutdown deadline in integer milliseconds. */
export const DEFAULT_SHUTDOWN_TIMEOUT_MS = 30_000;

function readonlyCapabilities(input: ReadonlySet<string>): ReadonlySet<string> {
  const set = new Set(input);
  if ([...set].some((value) => typeof value !== 'string' || value.length === 0)) {
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid plugin capability' });
  }
  const view: ReadonlySet<string> = Object.freeze({
    size: set.size,
    has: (value: string) => set.has(value),
    entries: () => set.entries(),
    keys: () => set.keys(),
    values: () => set.values(),
    [Symbol.iterator]: () => set[Symbol.iterator](),
    forEach(
      callback: (value: string, key: string, set: ReadonlySet<string>) => void,
      thisArg?: unknown,
    ) {
      for (const value of set) callback.call(thisArg, value, value, view);
    },
  });
  return view;
}

function capturePlugin(plugin: Plugin): ComposablePlugin {
  const composition = plugin as ComposablePlugin;
  if (
    !plugin ||
    typeof plugin.id !== 'string' ||
    !/^[a-z][a-z0-9.-]{0,79}(?![\s\S])/.test(plugin.id) ||
    typeof plugin.version !== 'string' ||
    !new RegExp(SEMVER_PATTERN).test(plugin.version) ||
    typeof plugin.init !== 'function' ||
    typeof plugin.close !== 'function' ||
    (composition[PREPARE_PLUGIN] !== undefined &&
      typeof composition[PREPARE_PLUGIN] !== 'function') ||
    (composition[ACTIVATE_PLUGIN] !== undefined &&
      typeof composition[ACTIVATE_PLUGIN] !== 'function') ||
    (composition[DRAIN_PLUGIN] !== undefined && typeof composition[DRAIN_PLUGIN] !== 'function') ||
    (composition[SUPPORT_PLUGINS] !== undefined &&
      (!Array.isArray(composition[SUPPORT_PLUGINS]) ||
        composition[SUPPORT_PLUGINS].length > 64 ||
        composition[SUPPORT_PLUGINS].some((factory) => typeof factory !== 'function'))) ||
    !plugin.capabilities ||
    typeof plugin.capabilities.has !== 'function' ||
    typeof plugin.capabilities[Symbol.iterator] !== 'function' ||
    (plugin.dependencies !== undefined &&
      (!Array.isArray(plugin.dependencies) ||
        !plugin.dependencies.every((d) => typeof d === 'string')))
  ) {
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid plugin definition' });
  }
  return Object.freeze({
    id: plugin.id,
    version: plugin.version,
    init: plugin.init.bind(plugin),
    close: plugin.close.bind(plugin),
    ...(composition[PREPARE_PLUGIN]
      ? { [PREPARE_PLUGIN]: composition[PREPARE_PLUGIN].bind(plugin) }
      : {}),
    ...(composition[ACTIVATE_PLUGIN]
      ? { [ACTIVATE_PLUGIN]: composition[ACTIVATE_PLUGIN].bind(plugin) }
      : {}),
    ...(composition[DRAIN_PLUGIN]
      ? { [DRAIN_PLUGIN]: composition[DRAIN_PLUGIN].bind(plugin) }
      : {}),
    ...(composition[SUPPORT_PLUGINS]
      ? { [SUPPORT_PLUGINS]: Object.freeze([...composition[SUPPORT_PLUGINS]]) }
      : {}),
    dependencies: Object.freeze([...(plugin.dependencies ?? [])]),
    capabilities: readonlyCapabilities(plugin.capabilities),
  });
}

function expandSupport(
  roots: readonly ComposablePlugin[],
  options: ApplicationOptions,
): ComposablePlugin[] {
  const plugins = [...roots];
  const factories = new Map<SupportPluginFactory, ComposablePlugin>();
  const knownIds = new Set(roots.map((plugin) => plugin.id));
  for (let index = 0; index < plugins.length; index++) {
    const owner = plugins[index]!;
    for (const factory of owner[SUPPORT_PLUGINS] ?? []) {
      let support = factories.get(factory);
      if (!support) {
        if (plugins.length >= 256 || factories.size >= 256)
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Support plugin expansion limit reached',
          });
        let definition: Plugin;
        try {
          definition = factory(options);
          if ((definition as unknown) instanceof Promise) {
            void (definition as unknown as Promise<unknown>).catch(() => undefined);
            throw new Error('Support plugin factories must be synchronous');
          }
          support = capturePlugin(definition);
        } catch (cause) {
          if (cause instanceof KitError) throw cause;
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Support plugin factory failed',
            cause,
          });
        }
        if (knownIds.has(support.id))
          throw new KitError({
            code: 'EK_PLUGIN_DUPLICATE',
            message: 'Support plugin id conflicts with another definition',
          });
        knownIds.add(support.id);
        factories.set(factory, support);
        plugins.push(support);
      }
      if (!owner.dependencies?.includes(support.id))
        throw new KitError({
          code: 'EK_PLUGIN_DEPENDENCY',
          message: 'Support plugin requires an explicit dependency',
        });
    }
  }
  return plugins;
}

function ordered(input: readonly Plugin[]): ComposablePlugin[] {
  const map = new Map<string, ComposablePlugin>();
  for (const definition of input) {
    const plugin = capturePlugin(definition);
    if (map.has(plugin.id))
      throw new KitError({ code: 'EK_PLUGIN_DUPLICATE', message: 'Duplicate plugin id' });
    map.set(plugin.id, plugin);
  }

  const result: ComposablePlugin[] = [],
    visiting = new Set<string>(),
    visited = new Set<string>();
  const visit = (id: string): void => {
    if (visited.has(id)) return;
    const plugin = map.get(id);
    if (!plugin || visiting.has(id))
      throw new KitError({
        code: 'EK_PLUGIN_DEPENDENCY',
        message: 'Missing or cyclic plugin dependency',
      });
    visiting.add(id);
    for (const dependency of plugin.dependencies ?? []) visit(dependency);
    visiting.delete(id);
    visited.add(id);
    result.push(plugin);
  };
  const priority = (plugin: Plugin): number =>
    ['config', 'logger', 'telemetry', 'meter'].findIndex((capability) =>
      plugin.capabilities.has(capability),
    );
  const candidates = [...map.values()].sort(
    (left, right) =>
      (priority(left) < 0 ? 4 : priority(left)) - (priority(right) < 0 ? 4 : priority(right)),
  );
  for (const plugin of candidates) visit(plugin.id);
  return result;
}

/** EK-CORE-001/002: validated, isolated application with serialized transitions. */
export async function createApplication(options: ApplicationOptions): Promise<Application> {
  if (!options || typeof options !== 'object' || Array.isArray(options))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Application options must be an object',
    });
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if (Object.values(descriptors).some((d) => !('value' in d)))
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Options must be data properties' });
  const { plugins: requested = [], ...data } = options;
  // Executable trust policy is captured separately from reloadable configuration data.
  let assuranceResolver: NonNullable<ApplicationOptions['security']>['assuranceResolver'];
  if (data.security && typeof data.security === 'object') {
    const securityDescriptors = Object.getOwnPropertyDescriptors(data.security);
    const resolver = securityDescriptors.assuranceResolver;
    if (resolver) {
      if (!('value' in resolver) || typeof resolver.value !== 'function')
        throw new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid assurance resolver' });
      assuranceResolver = resolver.value as NonNullable<
        ApplicationOptions['security']
      >['assuranceResolver'];
      delete securityDescriptors.assuranceResolver;
      data.security = Object.create(Object.getPrototypeOf(data.security), securityDescriptors);
    }
  }
  if (!Array.isArray(requested))
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Plugins must be an array' });
  const initialConfig = new ConfigStore(copyData(data) as Record<string, unknown>, {
    schema: APPLICATION_SCHEMA,
  });
  const roots = requested.map(capturePlugin);
  if (new Set(roots.map((plugin) => plugin.id)).size !== roots.length)
    throw new KitError({ code: 'EK_PLUGIN_DUPLICATE', message: 'Duplicate plugin id' });
  const wiring = Object.freeze({
    ...freezeData(copyData(data)),
    ...(assuranceResolver
      ? {
          security: Object.freeze({
            ...(initialConfig.get('security') as NonNullable<ApplicationOptions['security']>),
            assuranceResolver,
          }),
        }
      : {}),
  });
  const plugins = ordered(
    expandSupport(roots, Object.freeze({ ...wiring, plugins: Object.freeze(roots) })),
  );
  for (const capability of Object.keys(COMPONENTS)) {
    if (plugins.filter((plugin) => plugin.capabilities.has(capability)).length > 1)
      throw new KitError({
        code: 'EK_PLUGIN_DUPLICATE',
        message: 'Duplicate singleton capability',
      });
  }
  const configured = initialConfig.get('databases') as ApplicationOptions['databases'];
  const nonSql = new Set<string>();
  for (const definition of Object.values(configured ?? {})) {
    if (plugins.filter((p) => p.capabilities.has(`database.${definition.driver}`)).length !== 1)
      throw new KitError({
        code: 'EK_PLUGIN_DEPENDENCY',
        message: 'Database driver plugin missing',
      });
    if (['redis', 'etcd', 'mongodb'].includes(definition.driver)) {
      if (
        nonSql.has(definition.driver) ||
        definition.poolMin !== undefined ||
        definition.poolMax !== undefined
      )
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Unsupported non-SQL instance or pool setting',
        });
      nonSql.add(definition.driver);
    }
    if ((definition.poolMin ?? 0) > (definition.poolMax ?? Infinity))
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid pool range' });
  }
  for (const [field, capability] of [
    ['http', 'api'],
    ['security', 'auth'],
    ['telemetry', 'telemetry'],
    ['metering', 'meter'],
  ] as const) {
    if (data[field] !== undefined && !plugins.some((p) => p.capabilities.has(capability)))
      throw new KitError({
        code: 'EK_PLUGIN_DEPENDENCY',
        message: 'Configured capability has no plugin',
      });
  }
  const immutableOptions = Object.freeze({ ...wiring, plugins: Object.freeze(plugins) });
  const values = new Map<symbol, { owner: string; value: unknown }>();
  const controller = new AbortController();
  let state: LifecycleState = 'CREATED';
  let starting: Promise<void> | undefined, stopping: Promise<void> | undefined;
  let shutdownDeadline: number | undefined;
  let startupCleanupErrors: readonly unknown[] = [];
  const started: { plugin: ComposablePlugin; context: PluginContext }[] = [];
  const component = <T>(key: symbol): T => {
    if (!values.has(key))
      throw new KitError({
        code: 'EK_UNSUPPORTED_CAPABILITY',
        message: 'Capability not installed',
      });
    return values.get(key)!.value as T;
  };
  for (const plugin of plugins) {
    const bindings = plugin[PREPARE_PLUGIN]?.(
      Object.freeze({ options: immutableOptions, state: () => state }),
    );
    if (bindings === undefined) continue;
    if (!bindings || typeof bindings[Symbol.iterator] !== 'function')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Prepared bindings must be iterable',
      });
    for (const [key, value] of bindings) {
      const capability = Object.entries(COMPONENTS).find(([, symbol]) => symbol === key)?.[0];
      if (!capability || !plugin.capabilities.has(capability) || value == null)
        throw new KitError({
          code: 'EK_PLUGIN_DEPENDENCY',
          message: 'Prepared binding requires its declared capability',
        });
      if (values.has(key))
        throw new KitError({
          code: 'EK_PLUGIN_DUPLICATE',
          message: 'Prepared capability already provided',
        });
      values.set(key, { owner: plugin.id, value });
    }
  }
  const cleanup = async (deadline: number): Promise<unknown[]> => {
    const errors: unknown[] = [];
    for (const { plugin, context } of started.splice(0).reverse()) {
      try {
        const remaining = Math.ceil(deadline - performance.now());
        const closing = Promise.resolve().then(() => plugin.close(context));
        if (remaining <= 0) {
          // Invoke every close hook, but do not extend a shared expired deadline.
          void closing.catch(() => undefined);
          errors.push(new KitError({ code: 'EK_TIMEOUT', message: 'Shutdown deadline exhausted' }));
        } else {
          await within(() => closing, { timeoutMs: remaining });
        }
      } catch (error) {
        errors.push(error);
      } finally {
        for (const [key, value] of values) if (value.owner === plugin.id) values.delete(key);
      }
    }
    return errors;
  };
  const application = {
    get state() {
      return state;
    },
    get logger() {
      return component<Logger>(COMPONENTS.logger);
    },
    get config() {
      return values.has(COMPONENTS.config)
        ? component<ConfigService>(COMPONENTS.config)
        : initialConfig;
    },
    start(): Promise<void> {
      if (state === 'INITIALIZING') return starting!;
      if (state === 'READY') return Promise.resolve();
      if (state !== 'CREATED')
        return Promise.reject(
          new KitError({
            code: 'EK_LIFECYCLE_STATE',
            message: 'Cannot start application in this state',
          }),
        );
      state = 'INITIALIZING';
      starting = (async () => {
        try {
          for (const plugin of plugins) {
            let initializing = true;
            const context: PluginContext = Object.freeze({
              get logger() {
                return component<Logger>(COMPONENTS.logger);
              },
              options: immutableOptions,
              provide<T>(key: symbol, instance: T): void {
                if (!initializing || state !== 'INITIALIZING' || controller.signal.aborted)
                  throw new KitError({
                    code: 'EK_LIFECYCLE_STATE',
                    message: 'Provider registry is frozen',
                  });
                if (values.has(key))
                  throw new KitError({
                    code: 'EK_PLUGIN_DUPLICATE',
                    message: 'Capability already provided',
                  });
                values.set(key, { owner: plugin.id, value: instance });
              },
              require<T>(key: symbol): T {
                if (key === APPLICATION_SIGNAL) return controller.signal as T;
                const entry = values.get(key);
                if (
                  !entry ||
                  (entry.owner !== plugin.id && !plugin.dependencies?.includes(entry.owner))
                )
                  throw new KitError({
                    code: 'EK_PLUGIN_DEPENDENCY',
                    message: 'Capability requires explicit dependency',
                  });
                return entry.value as T;
              },
            });
            try {
              // Hooks receive the cooperative signal through require(APPLICATION_SIGNAL).
              const initializing = Promise.resolve()
                .then(() => plugin.init(context))
                .then(async () => {
                  if (state === 'FAILED' || state === 'CLOSED') {
                    // A hook that ignores cancellation still releases late successful resources.
                    await within(() => plugin.close(context), {
                      timeoutMs: DEFAULT_SHUTDOWN_TIMEOUT_MS,
                    });
                  } else {
                    started.push({ plugin, context });
                  }
                });
              await within(() => initializing, { signal: controller.signal });
            } finally {
              initializing = false;
            }
          }
          // Resource initialization and route registration finish before listeners bind.
          const activationOrder = [...started].sort(
            (left, right) =>
              Number(left.plugin.capabilities.has('api')) -
              Number(right.plugin.capabilities.has('api')),
          );
          for (const { plugin, context } of activationOrder) {
            const activate = plugin[ACTIVATE_PLUGIN];
            if (activate) await within(() => activate(context), { signal: controller.signal });
          }
          state = 'READY';
        } catch (cause) {
          state = 'FAILED';
          const errors = await cleanup(
            shutdownDeadline ?? performance.now() + DEFAULT_SHUTDOWN_TIMEOUT_MS,
          );
          startupCleanupErrors = errors;
          values.clear();
          state = 'CLOSED';
          const failure = new KitError({
            code:
              cause instanceof KitError && ['EK_ABORTED', 'EK_MFA_POLICY'].includes(cause.code)
                ? cause.code
                : 'EK_PLUGIN_FAILED',
            message: 'Application startup failed',
            cause,
            details: { cleanupFailureCount: errors.length },
          });
          Object.defineProperty(failure, 'cleanupErrors', { value: new AggregateError(errors) });
          throw failure;
        }
      })();
      return starting;
    },
    stop(options: { timeoutMs?: number } = {}): Promise<void> {
      if (!options || typeof options !== 'object' || Array.isArray(options))
        return Promise.reject(
          new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Shutdown options must be an object',
          }),
        );
      const timeoutMs = options.timeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
        return Promise.reject(
          new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid shutdown timeout' }),
        );
      if (state === 'CLOSED') return Promise.resolve();
      if (stopping) return stopping;
      const deadline = performance.now() + timeoutMs;
      shutdownDeadline = deadline;
      if (state === 'INITIALIZING')
        controller.abort(
          new KitError({ code: 'EK_ABORTED', message: 'Startup cancelled by shutdown' }),
        );
      else state = 'DRAINING';
      stopping = (async () => {
        let startupTimeout: unknown;
        const timer = setTimeout(
          () =>
            controller.abort(
              new KitError({ code: 'EK_TIMEOUT', message: 'Shutdown deadline reached' }),
            ),
          Math.min(timeoutMs, 2_147_483_647),
        );
        try {
          // Cancellation of startup is expected here; start callers still see its rejection.
          if (starting) {
            try {
              await within(() => starting!, { timeoutMs });
            } catch (error) {
              if (error instanceof KitError && error.code === 'EK_TIMEOUT') startupTimeout = error;
              // Startup callers retain the primary failure; shutdown reports cleanup failures.
            }
          }
          // Startup rollback can change the state while the awaited promise settles.
          if ((state as LifecycleState) !== 'CLOSED') state = 'DRAINING';
          const errors = [...startupCleanupErrors];
          // Drain listeners while their downstream services are still available.
          for (const { plugin, context } of [...started].reverse()) {
            const drain = plugin[DRAIN_PLUGIN];
            if (!drain) continue;
            try {
              const remaining = Math.ceil(deadline - performance.now());
              const draining = Promise.resolve().then(() => drain(context));
              if (remaining <= 0) {
                void draining.catch(() => undefined);
                errors.push(
                  new KitError({
                    code: 'EK_TIMEOUT',
                    message: 'Shutdown deadline exhausted during drain',
                  }),
                );
              } else await within(() => draining, { timeoutMs: remaining });
            } catch (error) {
              errors.push(error);
            }
          }
          errors.push(...(await cleanup(deadline)));
          if (startupTimeout) errors.push(startupTimeout);
          values.clear();
          state = 'CLOSED';
          if (errors.length)
            throw new KitError({
              code: errors.some((e) => e instanceof KitError && e.code === 'EK_TIMEOUT')
                ? 'EK_TIMEOUT'
                : 'EK_PLUGIN_FAILED',
              message: 'Application cleanup failed',
              cause: new AggregateError(errors),
              details: { cleanupFailureCount: errors.length },
            });
        } finally {
          clearTimeout(timer);
        }
      })();
      return stopping;
    },
  };
  const optional = new Set(['auth', 'cache', 'messaging', 'redis', 'etcd', 'mongo']);
  for (const [name, key] of Object.entries(COMPONENTS)) {
    if (name === 'logger' || name === 'config') continue;
    Object.defineProperty(application, name, {
      get: () => (optional.has(name) && !values.has(key) ? undefined : component(key)),
      enumerable: true,
    });
  }
  return Object.freeze(application) as Application;
}
