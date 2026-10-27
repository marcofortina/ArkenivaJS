// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS, PREPARE_PLUGIN, DRAIN_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { OAuthClientPluginSettings } from './contracts.js';
import { captureSettings } from './runtime.js';
import { invalid } from './validation.js';
import { createService } from './service.js';
import { OBSERVATION, observations } from './observation.js';

export type {
  IdentitySubject,
  DurableMutationReceipt,
  SecurityIndexedRecord,
  SecurityAtomicMutation,
  SecurityStateStore,
  SecurityTransactionalStore,
  SecretValue,
  SecretProvider,
  TrustedSecurityAuthority,
  SecurityStoreSettings,
  OAuthClientRegistration,
  OAuthClientPluginSettings,
  OAuthAuthorizationStart,
  OAuthAuthorizationCallback,
  OAuthGrant,
  OAuthClientService,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
/** Stable per-application capability; installation never enables an HTTP route implicitly. */
export const OAUTH_CLIENT_CAPABILITY: unique symbol = Symbol('arkenivajs.oauth-client');
/** Capture trusted providers, validate startup and register a separately owned oauth-client service. */
export function oauthClientPlugin(input: OAuthClientPluginSettings): Plugin {
  const settings = captureSettings(input),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof createService>>();
  const plugin: ComposablePlugin = {
    id: 'oauth-client',
    version: '0.1.0',
    capabilities: new Set(['oauth-client']),
    dependencies: ['logging', 'crypto', 'oauth-client-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw invalid();
      if (
        (settings.testOnly || settings.allowLoopback) &&
        context.options.service.environment !== 'test'
      )
        throw invalid();
      const instance = createService(
        settings,
        context.require<CryptoService>(CRYPTO_CAPABILITY),
        context.logger,
        context.require<Telemetry | undefined>(OBSERVATION),
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
      );
      try {
        await instance.bootstrap(context.require<AbortSignal>(APPLICATION_SIGNAL));
        context.provide(OAUTH_CLIENT_CAPABILITY, instance.service);
        instances.set(context, instance);
      } catch (error) {
        await instance.close();
        throw error;
      }
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.close();
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
