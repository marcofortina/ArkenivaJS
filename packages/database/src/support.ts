import { AsyncLocalStorage } from 'node:async_hooks';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import type {
  ApplicationOptions,
  DatabaseDriver,
  LifecycleState,
  Logger,
  OperationOptions,
  SqlProvider,
  SqlQueryOptions,
  SqlResult,
  SqlStatement,
  SqlTransaction,
  Telemetry,
  UsageMeter,
} from '@arkenivajs/core';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
export { captureSqlStatement } from './lexer.js';
export { SqlDeadline } from './deadline.js';

/** Internal adapter registry; consumers use app.sql rather than registering pools. */
export const SQL_DRIVER_REGISTRY = Symbol('arkenivajs.sql.drivers');
/** The common coordinator is an explicitly declared dependency of every SQL driver. */
export const SQL_SUPPORT_ID = 'database';

/** SQL driver identity matches root configuration rather than the compiler's dialect shorthand. */
export type RelationalDriver = Extract<
  DatabaseDriver,
  'postgresql' | 'mysql' | 'mariadb' | 'oracle'
>;

/**
 * One native driver's named connection. Implementations own pools, bounded fetching,
 * exact bind compilation, cancellation, transaction pinning and exactly-once release.
 */
export interface SqlConnectionAdapter extends SqlTransaction {
  /** Fetch at most two rows; reject on the second without fetching a third. */
  queryOne<T extends object = Record<string, unknown>>(
    statement: SqlStatement,
    options?: OperationOptions,
  ): Promise<T | null>;
  /** Never replay the callback; preserve unknown commit outcomes and rollback failures. */
  transaction<T>(
    handler: (tx: SqlTransaction) => Promise<T>,
    options?: OperationOptions,
  ): Promise<T>;
  ping(options?: OperationOptions): Promise<boolean>;
  stats(): Readonly<Record<string, number | null>>;
  native(): unknown;
}

/** Optional abstract diagnostic ports are captured through declared plugin dependencies. */
export interface SqlObservationPorts {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}

/** Registration is open only during initialization; each native driver retains cleanup ownership. */
export interface SqlDriverRegistry {
  readonly observation: SqlObservationPorts;
  register(name: string, driver: RelationalDriver, adapter: SqlConnectionAdapter): void;
}

const relational = new Set<string>(['postgresql', 'mysql', 'mariadb', 'oracle']);
function fail(
  code: 'EK_CONFIG_INVALID' | 'EK_LIFECYCLE_STATE' | 'EK_DATABASE_TRANSACTION',
  message: string,
): never {
  throw new KitError({ code, message });
}

function queryOptions(options: SqlQueryOptions = {}): SqlQueryOptions {
  if (!options || typeof options !== 'object' || Array.isArray(options))
    fail('EK_CONFIG_INVALID', 'SQL query options must be an object');
  const maxRows = options.maxRows ?? 10_000;
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 100_000)
    fail('EK_CONFIG_INVALID', 'SQL maxRows must be an integer from 1 to 100000');
  return { ...options, maxRows };
}

interface ManagedRouter {
  readonly provider: SqlProvider;
  readonly registry: SqlDriverRegistry;
  wire(observation: SqlObservationPorts): void;
  activate(): void;
  close(): void;
}

function createRouter(options: ApplicationOptions, state: () => LifecycleState): ManagedRouter {
  const definitions = options.databases ?? {};
  const adapters = new Map<string, SqlConnectionAdapter>();
  const transactions = new AsyncLocalStorage<symbol>();
  let active = false,
    closed = false,
    observation: SqlObservationPorts = Object.freeze({});
  const available = (name: string): SqlConnectionAdapter => {
    if (!active || closed) fail('EK_LIFECYCLE_STATE', 'SQL provider is not active');
    if (typeof name !== 'string' || !Object.hasOwn(definitions, name) || !adapters.has(name))
      fail('EK_CONFIG_INVALID', 'Unknown relational connection name');
    return adapters.get(name)!;
  };
  const outsideTransaction = (): void => {
    if (transactions.getStore() !== undefined)
      fail(
        'EK_DATABASE_TRANSACTION',
        'Use the owned transaction handle instead of reentering the pool',
      );
  };
  const provider: SqlProvider = Object.freeze({
    async query<T extends object = Record<string, unknown>>(
      name: string,
      statement: SqlStatement,
      input?: SqlQueryOptions,
    ): Promise<SqlResult<T>> {
      outsideTransaction();
      return available(name).query<T>(statement, queryOptions(input));
    },
    async queryOne<T extends object = Record<string, unknown>>(
      name: string,
      statement: SqlStatement,
      input?: OperationOptions,
    ): Promise<T | null> {
      outsideTransaction();
      return available(name).queryOne<T>(statement, input);
    },
    async execute(
      name: string,
      statement: SqlStatement,
      input?: OperationOptions,
    ): Promise<SqlResult> {
      outsideTransaction();
      return available(name).execute(statement, input);
    },
    async transaction<T>(
      name: string,
      handler: (tx: SqlTransaction) => Promise<T>,
      input?: OperationOptions,
    ): Promise<T> {
      outsideTransaction();
      const adapter = available(name);
      if (typeof handler !== 'function')
        fail('EK_CONFIG_INVALID', 'SQL transaction handler must be a function');
      const token = Symbol('transaction');
      let invoked = false;
      return adapter.transaction(async (native) => {
        if (invoked) fail('EK_DATABASE_TRANSACTION', 'SQL transaction callback must run only once');
        invoked = true;
        let running = true;
        const owned = (): void => {
          if (!running || transactions.getStore() !== token)
            fail('EK_DATABASE_TRANSACTION', 'Transaction handle is outside its owning callback');
          available(name);
        };
        const tx: SqlTransaction = Object.freeze({
          async query<R extends object = Record<string, unknown>>(
            statement: SqlStatement,
            query?: SqlQueryOptions,
          ): Promise<SqlResult<R>> {
            owned();
            return native.query<R>(statement, queryOptions(query));
          },
          async execute(statement: SqlStatement, execute?: OperationOptions): Promise<SqlResult> {
            owned();
            return native.execute(statement, execute);
          },
        });
        try {
          return await transactions.run(token, () => handler(tx));
        } finally {
          running = false;
        }
      }, input);
    },
    async ping(name: string, input?: OperationOptions): Promise<boolean> {
      outsideTransaction();
      return available(name).ping(input);
    },
    stats(name: string): Readonly<Record<string, number | null>> {
      return available(name).stats();
    },
    native(name: string): unknown {
      return available(name).native();
    },
  });
  return {
    provider,
    registry: Object.freeze({
      get observation() {
        return observation;
      },
      register(name: string, driver: RelationalDriver, adapter: SqlConnectionAdapter): void {
        if (closed || active || state() !== 'INITIALIZING')
          fail('EK_LIFECYCLE_STATE', 'SQL registration is closed');
        if (
          !Object.hasOwn(definitions, name) ||
          !relational.has(driver) ||
          definitions[name]!.driver !== driver ||
          adapters.has(name)
        )
          fail('EK_CONFIG_INVALID', 'SQL registration must match one unregistered named driver');
        for (const method of [
          'query',
          'queryOne',
          'execute',
          'transaction',
          'ping',
          'stats',
          'native',
        ] as const)
          if (!adapter || typeof adapter[method] !== 'function')
            fail('EK_CONFIG_INVALID', 'SQL adapter must implement every portable method');
        // Capture methods once without changing the pool owner's identity or lifetime.
        adapters.set(
          name,
          Object.freeze({
            query: adapter.query.bind(adapter),
            queryOne: adapter.queryOne.bind(adapter),
            execute: adapter.execute.bind(adapter),
            transaction: adapter.transaction.bind(adapter),
            ping: adapter.ping.bind(adapter),
            stats: adapter.stats.bind(adapter),
            native: adapter.native.bind(adapter),
          }),
        );
      },
    }),
    wire(ports) {
      observation = Object.freeze({ ...ports });
    },
    activate() {
      for (const [name, definition] of Object.entries(definitions))
        if (relational.has(definition.driver) && !adapters.has(name))
          fail('EK_CONFIG_INVALID', 'A configured relational connection was not registered');
      active = true;
    },
    close() {
      closed = true;
      active = false;
      adapters.clear();
      transactions.disable();
    },
  };
}

/**
 * One resource-free coordinator per application. SQL drivers declare this same
 * factory under SUPPORT_PLUGINS and depend on SQL_SUPPORT_ID; no extra user plugin
 * argument or global registry is required.
 */
export const sqlSupportPlugin: SupportPluginFactory = (root): ComposablePlugin => {
  const ports = [
    ['logger', COMPONENTS.logger],
    ['telemetry', COMPONENTS.telemetry],
    ['meter', COMPONENTS.meter],
  ] as const;
  const owners = ports.flatMap(([capability, key]) => {
    const owner = root.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ capability, key, owner: owner.id }] : [];
  });
  const routers = new WeakMap<object, ManagedRouter>();
  const router = (options: ApplicationOptions): ManagedRouter => {
    const value = routers.get(options);
    if (!value) fail('EK_LIFECYCLE_STATE', 'SQL coordinator has not been prepared');
    return value;
  };
  return {
    id: SQL_SUPPORT_ID,
    version: '0.1.0',
    capabilities: new Set(['sql']),
    dependencies: [...new Set(owners.map(({ owner }) => owner))],
    [PREPARE_PLUGIN](context) {
      const value = createRouter(context.options, context.state);
      routers.set(context.options, value);
      return new Map([[COMPONENTS.sql, value.provider]]);
    },
    init(context) {
      const value = router(context.options);
      const observation = Object.fromEntries(
        owners.map(({ capability, key }) => [capability, context.require(key)]),
      );
      value.wire(observation);
      context.provide(SQL_DRIVER_REGISTRY, value.registry);
    },
    [ACTIVATE_PLUGIN](context) {
      router(context.options).activate();
    },
    close(context) {
      router(context.options).close();
      routers.delete(context.options);
    },
  };
};
