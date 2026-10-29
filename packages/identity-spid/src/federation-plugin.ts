// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL, COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { ItalianEidPluginSettings, ItalianIdentitySystem } from './contracts.js';
import type { FederationTenantVerifier } from './identity-mapping.js';
import { capture } from './settings.js';
import { managed } from './service.js';
import { failure } from './validation.js';
import { observationPlugin } from './observation.js';
import type { Observers } from './observation.js';

/** Compose an explicit Italian profile over the existing application-owned services. */
export function createItalianFederationPlugin(
  system: ItalianIdentitySystem,
  capability: symbol,
  input: ItalianEidPluginSettings,
): Plugin {
  if (typeof capability !== 'symbol') throw failure('EK_EID_PROFILE');
  const captured = capture(input, 'test', system),
    observation = observationPlugin(system),
    prepared = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Awaited<ReturnType<typeof managed>>>();
  const plugin: ComposablePlugin = {
    id: system,
    version: '0.1.0',
    capabilities: new Set([system]),
    [SUPPORT_PLUGINS]: [observation.factory],
    dependencies: ['security', 'crypto', system + '-observation'],
    [PREPARE_PLUGIN](context) {
      prepared.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = prepared.get(context.options),
        environment = context.options.service.environment;
      if (!ready || (captured.testOnly && environment !== 'test')) throw failure('EK_EID_PROFILE');
      const settings = Object.freeze({ ...captured, environment }),
        instance = await managed(
          settings,
          context.require<CryptoService>(CRYPTO_CAPABILITY),
          context.require<FederationTenantVerifier>(COMPONENTS.auth),
          context.require<AbortSignal>(APPLICATION_SIGNAL),
          ready,
          context.require<Observers>(observation.key),
        );
      instances.set(context, instance);
      try {
        await instance.bootstrap();
        context.provide(capability, instance.service);
      } catch (error) {
        await instance.close();
        instances.delete(context);
        throw error;
      }
    },
    async health(context, options) {
      return (await instances.get(context)?.health(options)) ?? false;
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
