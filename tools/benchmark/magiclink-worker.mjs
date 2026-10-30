// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeMagiclink,
  magiclinkSettings,
  verifyMagiclink,
  magiclinkWorkload,
  completeMagiclink,
  magiclinkIterations,
  magiclinkWarmupIterations,
} from './magiclink-workload.mjs';

runPureWorker({
  name: 'magiclink',
  native: nativeMagiclink,
  framework: (fixture) => ({
    plugin: magicLinksPlugin(magiclinkSettings(fixture)),
    key: MAGICLINK_CAPABILITY,
  }),
  verify: verifyMagiclink,
  asynchronous: true,
  iterations: magiclinkIterations,
  warmupIterations: magiclinkWarmupIterations,
  retainRawSamples: true,
  workload: magiclinkWorkload,
  complete: completeMagiclink,
});
