// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { DataXlsxPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { managedService } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';

export type * from './contracts.js';
export const XLSX_CAPABILITY: unique symbol = Symbol('arkenivajs.xlsx');
/** Register only an explicit, application-owned, bounded XLSX capability. */
export function dataXlsxPlugin(settings: DataXlsxPluginSettings): Plugin {
  const captured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managedService>>();
  const plugin: ComposablePlugin = {
    id: 'data-xlsx',
    version: '0.1.0',
    capabilities: new Set(['xlsx']),
    dependencies: ['xlsx-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw failure('EK_RESOURCE_CLOSED');
      const managed = managedService(
        captured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        context.require(OBSERVATION),
      );
      instances.set(context, managed);
      context.provide(XLSX_CAPABILITY, managed.service);
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
