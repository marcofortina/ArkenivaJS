// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { SamlService, SamlSettings } from './contracts.js';
import { capture } from './settings.js';
import { managed } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';
import type { Observers } from './observation.js';
export type * from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';

export const SAML_CAPABILITY: unique symbol = Symbol('arkenivajs.security.saml');
/** Standalone calls own bounded native workers and never create a local user session. */
export function createSamlService(input: SamlSettings): SamlService {
  return managed(capture(input)).service;
}
export function samlPlugin(input: SamlSettings): Plugin {
  const settings = capture(input),
    prepared = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managed>>();
  const plugin: ComposablePlugin = {
    id: 'security-saml',
    version: '0.1.0',
    capabilities: new Set(['security-saml']),
    [SUPPORT_PLUGINS]: [observations],
    dependencies: ['saml-observation'],
    [PREPARE_PLUGIN](context) {
      prepared.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = prepared.get(context.options);
      if (!ready || settings.environment !== context.options.service.environment) throw failure();
      const owner = managed(
        settings,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require<Observers>(OBSERVATION),
      );
      instances.set(context, owner);
      try {
        await owner.bootstrap();
        context.provide(SAML_CAPABILITY, owner.service);
      } catch (error) {
        await owner.close();
        instances.delete(context);
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
