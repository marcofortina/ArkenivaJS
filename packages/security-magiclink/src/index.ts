// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { MagicLinksPluginSettings, MagicLinkService } from './contracts.js';
import { capture } from './settings.js';
import { Service } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';

export const MAGICLINK_CAPABILITY: unique symbol = Symbol('arkenivajs.magiclink');
/** Register explicit one-use credentials without implicitly installing an HTTP or mail route. */
export function magicLinksPlugin(input: MagicLinksPluginSettings): Plugin {
  const settings = capture(input),
    states = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Service>();
  const plugin: ComposablePlugin = {
    id: 'magiclink',
    version: '0.1.0',
    capabilities: new Set(['magiclink']),
    dependencies: ['logging', 'magiclink-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      states.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = states.get(context.options);
      if (!ready || (settings.testOnly && context.options.service.environment !== 'test'))
        throw failure('EK_CONFIG_INVALID');
      const service = new Service(
        settings,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        {
          logger: context.logger,
          ...(context.require<Telemetry | undefined>(OBSERVATION)
            ? { telemetry: context.require<Telemetry>(OBSERVATION) }
            : {}),
        },
      );
      instances.set(context, service);
      try {
        await service.bootstrap();
        context.provide<MagicLinkService>(
          MAGICLINK_CAPABILITY,
          Object.freeze({
            issue: service.issue.bind(service),
            consume: service.consume.bind(service),
            revoke: service.revoke.bind(service),
          }),
        );
      } catch (error) {
        await service.close();
        throw error;
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
