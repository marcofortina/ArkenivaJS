// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createIdentifiersService } from '@arkenivajs/data-identifiers';

/** Exercise only public identifier methods without an application or external services. */
export function runUtilities() {
  const ids = createIdentifiersService({ allowVersions: [4, 7] }),
    v4 = ids.uuidV4(),
    v7 = ids.uuidV7();
  return Object.freeze({
    v4Version: ids.parseUuid(v4).version,
    v7Version: ids.parseUuid(v7).version,
    malformedRejected: !ids.isUuid('invalid'),
    canonicalPolicyEnforced: !ids.isUuid(v4.toUpperCase()),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(runUtilities()));
