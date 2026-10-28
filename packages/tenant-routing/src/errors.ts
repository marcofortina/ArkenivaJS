// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';

/** Configuration failures never carry filesystem paths, registry bodies or provider exceptions. */
export const registryFailure = () =>
  new KitError({ code: 'EK_TROUTE_REGISTRY', message: 'Invalid tenant routing registry' });
