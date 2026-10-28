// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL, COMPONENTS } from '@arkenivajs/core';
import type { AuthService, Plugin } from '@arkenivajs/core';
import {
  PREPARE_PLUGIN,
  ACTIVATE_PLUGIN,
  DRAIN_PLUGIN,
  SUPPORT_PLUGINS,
} from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import { MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import type { MtlsService } from '@arkenivajs/security-mtls';
import type { GrpcPluginSettings, GrpcService } from './contracts.js';
import { capture } from './settings.js';
import { Runtime } from './runtime.js';
import { failure } from './errors.js';
import { observations, OBSERVATION } from './observation.js';
import type { Observers } from './observation.js';

export const GRPC_CAPABILITY: unique symbol = Symbol('arkenivajs.grpc');
const AUTHENTICATION = Symbol('grpc.authentication');
const authentication: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('auth'));
  return {
    id: 'grpc-authentication',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      context.provide<AuthService | undefined>(
        AUTHENTICATION,
        owner ? context.require<AuthService>(COMPONENTS.auth) : undefined,
      );
    },
    close() {},
  };
};
/** Capture trusted configuration without opening channels or listeners at factory time. */
export function grpcPlugin(input: GrpcPluginSettings): Plugin {
  const settings = capture(input),
    states = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Runtime>();
  const authenticated = settings.bindings.some((binding) => binding.policy.requireAuthentication);
  const plugin: ComposablePlugin = {
    id: 'grpc',
    version: '0.1.0',
    capabilities: new Set(['grpc']),
    dependencies: ['mtls', 'grpc-observation', 'grpc-authentication'],
    [SUPPORT_PLUGINS]: [observations, authentication],
    [PREPARE_PLUGIN](context) {
      states.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = states.get(context.options);
      const auth = context.require<AuthService | undefined>(AUTHENTICATION);
      if (
        !ready ||
        (authenticated && !auth) ||
        (settings.testOnly && context.options.service.environment !== 'test')
      )
        throw failure('EK_CONFIG_INVALID');
      const runtime = new Runtime(
        settings,
        context.require<MtlsService>(MTLS_CAPABILITY),
        auth,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require<Observers>(OBSERVATION),
      );
      instances.set(context, runtime);
      try {
        await runtime.initialize();
        context.provide<GrpcService>(
          GRPC_CAPABILITY,
          Object.freeze({
            registerService: runtime.registerService.bind(runtime),
            client: runtime.client.bind(runtime),
            nativeServer: runtime.nativeServer.bind(runtime),
            close: runtime.close.bind(runtime),
          }),
        );
      } catch (error) {
        await runtime.close();
        throw error;
      }
    },
    async [ACTIVATE_PLUGIN](context) {
      await instances.get(context)?.activate();
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
