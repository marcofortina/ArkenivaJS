// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { KafkaPluginSettings } from './contracts.js';
import { settings as capture } from './settings.js';
import { managedService } from './service.js';
import { observations, OBSERVATION } from './observation.js';
import { failure } from './validation.js';

/** Explicit named native Kafka producer and consumer capability. */
export const KAFKA_CAPABILITY: unique symbol = Symbol('arkenivajs.messaging.kafka');

/** Install independently owned Kafka clients with verified TLS, manual offsets and bounded admission. */
export function kafkaPlugin(settings: KafkaPluginSettings): Plugin {
  const captured = capture(settings);
  const readiness = new WeakMap<object, () => boolean>();
  const instances = new WeakMap<object, ReturnType<typeof managedService>>();
  const plugin: ComposablePlugin = {
    id: 'messaging-kafka',
    version: '0.1.0',
    capabilities: new Set(['messaging-kafka']),
    dependencies: ['kafka-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw failure('EK_LIFECYCLE_STATE');
      const owner = managedService(
        captured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.options.service.environment,
        undefined,
        context.require(OBSERVATION),
      );
      instances.set(context, owner);
      await owner.init();
      context.provide(KAFKA_CAPABILITY, owner.service);
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
