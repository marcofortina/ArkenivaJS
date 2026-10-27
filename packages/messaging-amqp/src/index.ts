// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { AmqpPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { managedService } from './service.js';
import { observations, OBSERVATION } from './observation.js';
import { failure } from './validation.js';
/** Symbol reserved for the explicitly installed optional native AMQP adapter. */
export const AMQP_CAPABILITY: unique symbol = Symbol('arkenivajs.messaging.amqp');
/** Install only an explicit native AMQPS capability with a trusted static topology catalog. */
export function amqpPlugin(settings: AmqpPluginSettings): Plugin {
  const captured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managedService>>();
  const plugin: ComposablePlugin = {
    id: 'messaging-amqp',
    version: '0.1.0',
    capabilities: new Set(['messaging-amqp']),
    dependencies: ['amqp-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (
        !ready ||
        (captured.resolverUsage === 'test-only' && context.options.service.environment !== 'test')
      )
        throw failure('EK_AMQP_CONFIG');
      const managed = managedService(
        captured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require(OBSERVATION),
      );
      instances.set(context, managed);
      await managed.init();
      context.provide(AMQP_CAPABILITY, managed.service);
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
