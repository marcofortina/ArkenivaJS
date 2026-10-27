// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type {
  DataJsonPluginSettings,
  JsonService,
  JsonValidation,
  JsonOptions,
} from './contracts.js';
import { capture } from './settings.js';
import { Runtime } from './runtime.js';
import { observations, OBSERVATION, recorder } from './observation.js';
import type { Observers } from './observation.js';

export const JSON_CAPABILITY: unique symbol = Symbol('arkenivajs.json');
/** Install only an explicitly configured, startup-validated native JSON service. */
export function dataJsonPlugin(settings: DataJsonPluginSettings): Plugin {
  const configured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Runtime>();
  const plugin: ComposablePlugin = {
    id: 'data-json',
    version: '0.1.0',
    capabilities: new Set(['json']),
    dependencies: ['json-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw new Error('The JSON lifecycle was not prepared');
      const runtime = await Runtime.create(
        configured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        recorder(context.require<Observers>(OBSERVATION)),
      );
      instances.set(context, runtime);
      context.provide<JsonService>(
        JSON_CAPABILITY,
        Object.freeze({
          parse: (text: string, options?: JsonOptions) =>
            runtime.call('parse', text, undefined, options),
          stringify: (value: unknown, options?: JsonOptions) =>
            runtime.call('stringify', value, undefined, options) as string,
          validate: (value: unknown, schemaId: string) =>
            runtime.call('validate', value, schemaId) as JsonValidation,
          transform: (value: unknown, mappingId: string) =>
            runtime.call('transform', value, mappingId),
        }),
      );
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.close();
    },
    async close(context) {
      try {
        await instances.get(context)?.close();
      } finally {
        instances.delete(context);
      }
    },
  };
  return plugin;
}
