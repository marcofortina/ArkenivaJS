// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';

export const OBSERVATION = Symbol('oauth-client.observation');
/** Observe only through an explicitly installed adapter, using the existing scoped support SPI. */
export const observations: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'oauth-client-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      context.provide(OBSERVATION, owner ? context.require(COMPONENTS.telemetry) : undefined);
    },
    close() {},
  };
};
