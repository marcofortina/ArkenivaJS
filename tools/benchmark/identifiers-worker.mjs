// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import {
  identifierWorkload,
  nativeIdentifiers,
  verifyIdentifiers,
} from './identifiers-workload.mjs';
runPureWorker({
  name: 'identifiers',
  retainRawSamples: true,
  native: nativeIdentifiers,
  async framework() {
    const { dataIdentifiersPlugin, IDENTIFIERS_CAPABILITY } =
      await import('@arkenivajs/data-identifiers');
    return {
      plugin: dataIdentifiersPlugin({ allowVersions: [4, 7] }),
      key: IDENTIFIERS_CAPABILITY,
    };
  },
  verify: verifyIdentifiers,
  workload: identifierWorkload,
});
