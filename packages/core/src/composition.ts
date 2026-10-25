import type {
  ApplicationOptions,
  LifecycleState,
  Plugin,
  PluginContext,
  OperationOptions,
} from './contracts.js';

/** Resource-free adapter composition runs only after application data validates. */
export const PREPARE_PLUGIN = Symbol('arkenivajs.prepare');
/** Final activation runs after every init hook; inbound listeners activate last. */
export const ACTIVATE_PLUGIN = Symbol('arkenivajs.activate');
/** Stop inbound work before dependencies enter reverse-order resource cleanup. */
export const DRAIN_PLUGIN = Symbol('arkenivajs.drain');
/** Declarative resource-free support dependencies are resolved once per application. */
export const SUPPORT_PLUGINS = Symbol('arkenivajs.support');
/** Kernel-owned readonly health callbacks retain each initialized plugin's original scoped context. */
export const HEALTH_PROBES = Symbol('arkenivajs.health-probes');
export interface PluginHealthProbe {
  readonly name: string;
  readonly check: (options: OperationOptions) => Promise<boolean>;
}
/** Pure synchronous metadata factory; it must not open pools, listeners, timers or transports. */
export type SupportPluginFactory = (options: Readonly<ApplicationOptions>) => ComposablePlugin;
/** Read-only composition context exposes no foreign service registry. */
export interface PreparationContext {
  readonly options: ApplicationOptions;
  readonly state: () => LifecycleState;
}
/** Optional adapter hooks preserve the public Plugin init/close contract. */
export interface ComposablePlugin extends Plugin {
  /** Optional SPI readiness hook; it must perform bounded readonly checks on owned resources. */
  health?(context: PluginContext, options: OperationOptions): Promise<boolean> | boolean;
  readonly [SUPPORT_PLUGINS]?: readonly SupportPluginFactory[];
  [PREPARE_PLUGIN]?(context: PreparationContext): ReadonlyMap<symbol, unknown>;
  [ACTIVATE_PLUGIN]?(context: PluginContext): Promise<void> | void;
  [DRAIN_PLUGIN]?(context: PluginContext): Promise<void> | void;
}
