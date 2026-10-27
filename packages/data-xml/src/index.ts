// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { DataXmlPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { Runtime } from './runtime.js';
import { service } from './service.js';
/** Reserved capability for the explicitly installed optional XML adapter. */
export const XML_CAPABILITY: unique symbol = Symbol('arkenivajs.xml');
/** Install a bounded native XML codec only through explicit capability registration. */
export function dataXmlPlugin(settings: DataXmlPluginSettings): Plugin {
  const configured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, Runtime>();
  const plugin: ComposablePlugin = {
    id: 'data-xml',
    version: '0.1.0',
    capabilities: new Set(['xml']),
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw new Error('The XML lifecycle was not prepared');
      const runtime = new Runtime(
        configured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
      );
      instances.set(context, runtime);
      context.provide(XML_CAPABILITY, service(runtime));
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
