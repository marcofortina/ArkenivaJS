// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { LdapService, LdapSettings } from './contracts.js';
import { capture } from './settings.js';
import { managedService } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';

export type {
  LdapSettings,
  LdapService,
  LdapUser,
  LdapGroup,
  LdapEntry,
  LdapSearchQuery,
  SecretProvider,
  SecretValue,
} from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
export const LDAP_CAPABILITY: unique symbol = Symbol('arkenivajs.security.ldap');
/** Standalone operations own fresh bounded clients and release every socket before completion. */
export function createLdapService(settings: LdapSettings): LdapService {
  return managedService(capture(settings)).service;
}
export function ldapPlugin(settings: LdapSettings): Plugin {
  const captured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managedService>>();
  const plugin: ComposablePlugin = {
    id: 'security-ldap',
    version: '0.1.0',
    capabilities: new Set(['security-ldap']),
    dependencies: ['ldap-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    init(context) {
      const ready = readiness.get(context.options);
      if (!ready || captured.environment !== context.options.service.environment) throw failure();
      const managed = managedService(
        captured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require(OBSERVATION),
      );
      context.provide(LDAP_CAPABILITY, managed.service);
      instances.set(context, managed);
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
