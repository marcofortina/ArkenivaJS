// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Logger, Telemetry } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { SecurityHttpPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { createNative } from './native.js';
import { failure } from './validation.js';
import { providerTask } from './provider-task.js';
import type { ProviderTask } from './provider-task.js';
import type { Observers } from './observation.js';

export type * from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
export const SECURITY_HTTP_CAPABILITY: unique symbol = Symbol('arkenivajs.security-http');
const KEY_TASK = Symbol('security-http.key-task');
const OBSERVERS = Symbol('security-http.observers');
/** Explicit HTTP hardening with runtime-authorized, durable session-bound CSRF. */
export function securityHttpPlugin(input: SecurityHttpPluginSettings): Plugin {
  const settings = capture(input),
    instances = new WeakMap<object, Awaited<ReturnType<typeof createNative>>>(),
    readiness = new WeakMap<object, () => boolean>();
  const keyOwner: SupportPluginFactory = () => ({
    id: 'security-http-key-owner',
    version: '0.1.0',
    capabilities: new Set(),
    init(context) {
      context.provide(
        KEY_TASK,
        providerTask(settings, context.require<AbortSignal>(APPLICATION_SIGNAL)),
      );
    },
    async close(context) {
      await context.require<ProviderTask>(KEY_TASK).close();
    },
  });
  const observers: SupportPluginFactory = (options) => {
    const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
      telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
    return {
      id: 'security-http-observers',
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
  const plugin: ComposablePlugin = {
    id: 'security-http',
    version: '0.1.0',
    capabilities: new Set(['security-http']),
    dependencies: ['api', 'security-http-key-owner', 'security-http-observers'],
    [SUPPORT_PLUGINS]: [keyOwner, observers],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options),
        test = context.options.service.environment === 'test';
      if (!ready || (!test && settings.productionUnsafe)) throw failure();
      const managed = await createNative(
        settings,
        context.require<ManagedApiServer>(COMPONENTS.api).native(),
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        test,
        context.require<ProviderTask>(KEY_TASK),
        context.require<Observers>(OBSERVERS),
      );
      try {
        instances.set(context, managed);
        context.provide(SECURITY_HTTP_CAPABILITY, managed.service);
      } catch {
        await managed.close();
        instances.delete(context);
        throw failure();
      }
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
