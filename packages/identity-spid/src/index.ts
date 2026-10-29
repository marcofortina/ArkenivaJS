// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin } from '@arkenivajs/core';
import type { ItalianEidPluginSettings } from './contracts.js';
import { createItalianFederationPlugin } from './federation-plugin.js';

export type * from './contracts.js';
export type { OperationOptions } from '@arkenivajs/core';
export const SPID_CAPABILITY: unique symbol = Symbol('arkenivajs.identity.spid');

/** Install only explicit SPID profiles using the existing application-owned native backend. */
export function spidPlugin(input: ItalianEidPluginSettings): Plugin {
  return createItalianFederationPlugin('spid', SPID_CAPABILITY, input);
}
