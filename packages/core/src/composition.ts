import type { ApplicationOptions, LifecycleState, Plugin, PluginContext } from './contracts.js';

/** Resource-free adapter composition runs only after application data validates. */
export const PREPARE_PLUGIN = Symbol('arkenivajs.prepare');
/** Final activation runs after every init hook; inbound listeners activate last. */
export const ACTIVATE_PLUGIN = Symbol('arkenivajs.activate');
/** Read-only composition context exposes no foreign service registry. */
export interface PreparationContext {
  readonly options: ApplicationOptions;
  readonly state: () => LifecycleState;
}
/** Optional adapter hooks preserve the public Plugin init/close contract. */
export interface ComposablePlugin extends Plugin {
  [PREPARE_PLUGIN]?(context: PreparationContext): ReadonlyMap<symbol, unknown>;
  [ACTIVATE_PLUGIN]?(context: PluginContext): Promise<void> | void;
}
