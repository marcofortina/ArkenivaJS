// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL, COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { ItalianEidPluginSettings } from './contracts.js';
import type { FederationTenantVerifier } from './identity-mapping.js';
import { capture } from './settings.js';
import { managed } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';
import type { Observers } from './observation.js';

export type * from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
export const SPID_CAPABILITY: unique symbol = Symbol('arkenivajs.identity.spid');

/** Install only explicit SPID profiles and borrow the current application's security and Crypto services. */
export function spidPlugin(input: ItalianEidPluginSettings): Plugin {
  const captured = capture(input, 'test'),
    prepared = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Awaited<ReturnType<typeof managed>>>();
  const plugin: ComposablePlugin = {
    id: 'spid',
    version: '0.1.0',
    capabilities: new Set(['spid']),
    [SUPPORT_PLUGINS]: [observations],
    dependencies: ['security', 'crypto', 'spid-observation'],
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
          context.require<Observers>(OBSERVATION),
        );
      instances.set(context, instance);
      try {
        await instance.bootstrap();
        context.provide(SPID_CAPABILITY, instance.service);
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
