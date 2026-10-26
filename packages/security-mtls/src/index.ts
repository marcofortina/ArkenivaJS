// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { MtlsPluginSettings } from './contracts.js';
import { captureSettings } from './settings.js';
import { invalid } from './runtime.js';
import { createService } from './service.js';
import { OBSERVATION, observations } from './observation.js';

export type {
  TlsProfile,
  TlsMaterial,
  TlsClientOptions,
  TlsServerOptions,
  NativeTlsOptions,
  VerifiedPeerIdentity,
  TlsTrustVerificationPolicy,
  MtlsTrustProvider,
  MtlsCredentialProvider,
  BoundedRuntimePolicy,
  MtlsPluginSettings,
  MtlsService,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
/** Explicit per-application service identity capability; native TLS alone never grants application identity. */
export const MTLS_CAPABILITY: unique symbol = Symbol('arkenivajs.mtls');
/** Resolve complete validated credential snapshots before any dependent application listener activates. */
export function mtlsPlugin(input: MtlsPluginSettings): Plugin {
  const settings = captureSettings(input),
    instances = new WeakMap<object, ReturnType<typeof createService>>();
  const plugin: ComposablePlugin = {
    id: 'mtls',
    version: '0.1.0',
    capabilities: new Set(['mtls']),
    dependencies: ['mtls-observation'],
    [SUPPORT_PLUGINS]: [observations],
    async init(context) {
      if (settings.testOnly && context.options.service.environment !== 'test') throw invalid();
      const runtime = createService(settings, context.require<Telemetry | undefined>(OBSERVATION));
      try {
        await runtime.bootstrap(context.require<AbortSignal>(APPLICATION_SIGNAL));
        context.provide(MTLS_CAPABILITY, runtime.service);
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
  return plugin;
}
