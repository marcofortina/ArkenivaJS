// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';

export const OBSERVATION = Symbol('mtls.observation');
/** Reuse the kernel's scoped support SPI; no implicit concrete telemetry adapter is loaded. */
export const observations: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'mtls-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      context.provide(OBSERVATION, owner ? context.require(COMPONENTS.telemetry) : undefined);
    },
    close() {},
  };
};
