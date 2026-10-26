// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import type { CryptoPluginSettings } from './contracts.js';
import { captureSettings, invalid } from './runtime.js';
import { createService } from './service.js';

export type {
  SecretValue,
  SecretProvider,
  KeyedDigestProvider,
  BoundedRuntimePolicy,
  CryptoPluginSettings,
  SealedEnvelope,
  CryptoService,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';

/** Stable explicit binding for the optional native cryptographic service. */
export const CRYPTO_CAPABILITY: unique symbol = Symbol('arkenivajs.crypto');

/** Validate configuration now; resolve external keys and create independent state at startup. */
export function cryptoPlugin(input: CryptoPluginSettings): Plugin {
  const settings = captureSettings(input);
  const instances = new WeakMap<object, ReturnType<typeof createService>>();
  return {
    id: 'crypto',
    version: '0.1.0',
    capabilities: new Set(['crypto']),
    async init(context) {
      if (settings.usage === 'test-only' && context.options.service.environment !== 'test')
        throw invalid();
      const runtime = createService(settings);
      try {
        await runtime.bootstrap(context.require<AbortSignal>(APPLICATION_SIGNAL));
        context.provide(CRYPTO_CAPABILITY, runtime.service);
        instances.set(context, runtime);
      } catch (error) {
        runtime.close();
        throw error;
      }
    },
    close(context) {
      instances.get(context)?.close();
      instances.delete(context);
    },
  };
}
