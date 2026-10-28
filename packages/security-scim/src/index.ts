// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
export { scimPlugin, SCIM_CAPABILITY } from './plugin.js';
import type { ScimService, ScimServiceSettings } from './contracts.js';
import { capture } from './settings.js';
import { managed } from './service.js';

/** Direct use still requires actual bearer verification and an independent trusted authorization policy. */
export function createScimService(settings: ScimServiceSettings): ScimService {
  return managed(capture(settings)).service;
}
