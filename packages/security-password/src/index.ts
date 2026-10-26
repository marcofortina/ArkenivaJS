// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { PasswordPluginSettings } from './contracts.js';
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
  PasswordPolicy,
  PasswordHash,
  PasswordVerification,
  OneTimeSecret,
  ResetIssue,
  PasswordBreachProvider,
  PasswordResetCommitter,
  PasswordPluginSettings,
  PasswordService,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
/** Stable per-application capability; installation never enables an HTTP route implicitly. */
export const PASSWORD_CAPABILITY: unique symbol = Symbol('arkenivajs.password');
/** Capture trusted providers, validate startup and register a separately owned password service. */
export function passwordPlugin(input: PasswordPluginSettings): Plugin {
  const settings = captureSettings(input),
    instances = new WeakMap<object, ReturnType<typeof createService>>();
  const plugin: ComposablePlugin = {
    id: 'password',
    version: '0.1.0',
    capabilities: new Set(['password']),
    dependencies: ['logging', 'password-observation'],
    [SUPPORT_PLUGINS]: [observations],
    async init(context) {
      if (settings.testOnly && context.options.service.environment !== 'test') throw invalid();
      const instance = createService(
        settings,
        context.logger,
        context.require<Telemetry | undefined>(OBSERVATION),
      );
      try {
        await instance.bootstrap(context.require<AbortSignal>(APPLICATION_SIGNAL));
        context.provide(PASSWORD_CAPABILITY, instance.service);
        instances.set(context, instance);
      } catch (error) {
        instance.close();
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
