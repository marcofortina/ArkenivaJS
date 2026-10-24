import type { ApplicationOptions, LifecycleState, Plugin, PluginContext } from './contracts.js';

/** Resource-free adapter composition runs only after application data validates. */
export const PREPARE_PLUGIN = Symbol('arkenivajs.prepare');
/** Final activation runs after every init hook; inbound listeners activate last. */
export const ACTIVATE_PLUGIN = Symbol('arkenivajs.activate');
/** Stop inbound work before dependencies enter reverse-order resource cleanup. */
export const DRAIN_PLUGIN = Symbol('arkenivajs.drain');
/** Declarative resource-free support dependencies are resolved once per application. */
export const SUPPORT_PLUGINS = Symbol('arkenivajs.support');
/** Pure synchronous metadata factory; it must not open pools, listeners, timers or transports. */
export type SupportPluginFactory = (options: Readonly<ApplicationOptions>) => ComposablePlugin;
/** Read-only composition context exposes no foreign service registry. */
export interface PreparationContext {
  readonly options: ApplicationOptions;
  readonly state: () => LifecycleState;
}
/** Optional adapter hooks preserve the public Plugin init/close contract. */
export interface ComposablePlugin extends Plugin {
  readonly [SUPPORT_PLUGINS]?: readonly SupportPluginFactory[];
  [PREPARE_PLUGIN]?(context: PreparationContext): ReadonlyMap<symbol, unknown>;
  [ACTIVATE_PLUGIN]?(context: PluginContext): Promise<void> | void;
  [DRAIN_PLUGIN]?(context: PluginContext): Promise<void> | void;
}
