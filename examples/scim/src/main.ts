// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createScimService } from '@arkenivajs/security-scim';
import type { ScimServiceSettings, ScimService } from '@arkenivajs/security-scim';

/** Application supplies its actual bearer verifier and independent provisioning authorization policy. */
export function createExampleService(settings: ScimServiceSettings): ScimService {
  return createScimService(settings);
}
