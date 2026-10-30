// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import { runPureWorker } from './pure-worker.mjs';
import { mtlsSettings, nativeMtls, verifyMtls } from './mtls-workload.mjs';

runPureWorker({
  name: 'mtls',
  native: nativeMtls,
  framework: (fixture) => ({ plugin: mtlsPlugin(mtlsSettings(fixture)), key: MTLS_CAPABILITY }),
  verify: verifyMtls,
});
