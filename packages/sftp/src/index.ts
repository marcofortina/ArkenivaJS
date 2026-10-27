// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { SftpPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { managedService } from './service.js';
import { observations, OBSERVATION } from './observation.js';
import { failure } from './validation.js';

export type * from './contracts.js';
export const SFTP_CAPABILITY: unique symbol = Symbol('arkenivajs.sftp');
export const SSH_CAPABILITY: unique symbol = Symbol('arkenivajs.ssh');
/** Pin and authenticate every named profile before exposing its native client at READY. */
export function sftpPlugin(settings: SftpPluginSettings): Plugin {
  const captured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managedService>>();
  const plugin: ComposablePlugin = {
    id: 'sftp',
    version: '0.1.0',
    capabilities: new Set(['sftp', 'ssh']),
    dependencies: ['sftp-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (
        !ready ||
        (captured.providerUsage === 'test-only' && context.options.service.environment !== 'test')
      )
        throw failure('EK_CONFIG_INVALID');
      const managed = managedService(
        captured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require(OBSERVATION),
      );
      instances.set(context, managed);
      await managed.init();
      context.provide(SFTP_CAPABILITY, managed.sftp);
      context.provide(SSH_CAPABILITY, managed.ssh);
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
