// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { SoapPluginSettings, SoapService } from './contracts.js';
import { capture } from './settings.js';
import { Runtime } from './runtime.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';
import type { Observers } from './observation.js';

export const SOAP_CAPABILITY: unique symbol = Symbol('arkenivajs.soap');
/** Register only explicitly configured, owned SOAP clients after offline startup validation. */
export function soapPlugin(input: SoapPluginSettings): Plugin {
  const settings = capture(input),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Runtime>();
  const plugin: ComposablePlugin = {
    id: 'soap',
    version: '0.1.0',
    capabilities: new Set(['soap']),
    dependencies: ['soap-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (!ready || (settings.testOnly && context.options.service.environment !== 'test'))
        throw failure('EK_CONFIG_INVALID');
      const runtime = new Runtime(
        settings,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require<Observers>(OBSERVATION),
      );
      instances.set(context, runtime);
      await runtime.initialize();
      context.provide<SoapService>(
        SOAP_CAPABILITY,
        Object.freeze({
          createClient: runtime.createClient.bind(runtime),
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
