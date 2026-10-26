// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { X509PluginSettings } from './contracts.js';
import { captureSettings, invalid } from './runtime.js';
import { createService } from './service.js';
import { OBSERVATION, observations } from './observation.js';

export type {
  X509Info,
  CertificateFingerprints,
  CertificateValidation,
  TlsTrustVerificationPolicy,
  VerifiedPeerIdentity,
  MtlsTrustProvider,
  BoundedRuntimePolicy,
  X509PluginSettings,
  X509Service,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';

/** Explicit application-local certificate capability; parsing never authenticates an identity. */
export const X509_CAPABILITY: unique symbol = Symbol('arkenivajs.x509');

/** Snapshot configured CA sets before startup and create independent lifecycle-owned services. */
export function x509Plugin(input: X509PluginSettings): Plugin {
  const settings = captureSettings(input),
    instances = new WeakMap<object, ReturnType<typeof createService>>();
  const plugin: ComposablePlugin = {
    id: 'x509',
    version: '0.1.0',
    capabilities: new Set(['x509']),
    dependencies: ['x509-observation'],
    [SUPPORT_PLUGINS]: [observations],
    init(context) {
      if (settings.usage === 'test-only' && context.options.service.environment !== 'test')
        throw invalid();
      const runtime = createService(settings, context.require<Telemetry | undefined>(OBSERVATION));
      try {
        runtime.bootstrap(context.require<AbortSignal>(APPLICATION_SIGNAL));
        context.provide(X509_CAPABILITY, runtime.service);
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
