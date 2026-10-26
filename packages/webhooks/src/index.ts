// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL, COMPONENTS } from '@arkenivajs/core';
import type { Logger, Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS, DRAIN_PLUGIN, PREPARE_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { WebhooksPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { failure } from './validation.js';
import { createService } from './service.js';
import type { Observers } from './service.js';

export type * from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
/** Optional per-application capability; no global replay state or automatically registered receiver. */
export const WEBHOOKS_CAPABILITY: unique symbol = Symbol('arkenivajs.webhooks');
const OBSERVERS = Symbol('webhooks.observers');
const observers: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'webhooks-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [logger?.id, telemetry?.id].filter((id): id is string => id !== undefined),
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        ...(logger ? { logger: context.require<Logger>(COMPONENTS.logger) } : {}),
        ...(telemetry ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
      });
    },
    close() {},
  };
};
/** Capture typed providers and destination policy before native transports or listeners are used. */
export function webhooksPlugin(input: WebhooksPluginSettings): Plugin {
  const settings = capture(input),
    instances = new WeakMap<object, ReturnType<typeof createService>>(),
    readiness = new WeakMap<object, () => boolean>();
  const plugin: ComposablePlugin = {
    id: 'webhooks',
    version: '0.1.0',
    capabilities: new Set(['webhooks']),
    dependencies: ['webhooks-observers'],
    [SUPPORT_PLUGINS]: [observers],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw failure();
      const managed = createService(
        settings,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        context.options.service.environment === 'test',
        context.require(OBSERVERS),
        ready,
      );
      context.provide(WEBHOOKS_CAPABILITY, managed.service);
      instances.set(context, managed);
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
