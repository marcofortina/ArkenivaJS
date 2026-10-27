// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type { DataXmlPluginSettings } from './contracts.js';
import { capture } from './settings.js';
import { Runtime } from './runtime.js';
import { service } from './service.js';
import { Xsd } from './xsd.js';
import { observations, OBSERVATION, recorder } from './observation.js';
import type { Observers } from './observation.js';
/** Reserved capability for the explicitly installed optional XML adapter. */
export const XML_CAPABILITY: unique symbol = Symbol('arkenivajs.xml');
/** Install a bounded native XML codec only through explicit capability registration. */
export function dataXmlPlugin(settings: DataXmlPluginSettings): Plugin {
  const configured = capture(settings),
    readiness = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, { runtime: Runtime; xsd?: Xsd }>();
  const plugin: ComposablePlugin = {
    id: 'data-xml',
    version: '0.1.0',
    capabilities: new Set(['xml']),
    dependencies: ['xml-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = readiness.get(context.options);
      if (!ready) throw new Error('The XML lifecycle was not prepared');
      const runtime = new Runtime(
        configured,
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready,
        recorder(context.require<Observers>(OBSERVATION)),
      );
      const managed: { runtime: Runtime; xsd?: Xsd } = { runtime };
      instances.set(context, managed);
      const xsd = await Xsd.create(runtime);
      if (xsd) managed.xsd = xsd;
      context.provide(XML_CAPABILITY, service(runtime, xsd));
    },
    async [DRAIN_PLUGIN](context) {
      const managed = instances.get(context);
      await managed?.runtime.close();
      await managed?.xsd?.close();
    },
    async close(context) {
      try {
        const managed = instances.get(context);
        await managed?.runtime.close();
        await managed?.xsd?.close();
      } finally {
        instances.delete(context);
      }
    },
  };
  return plugin;
}
