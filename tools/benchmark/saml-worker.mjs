// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { samlPlugin, SAML_CAPABILITY } from '@arkenivajs/security-saml';
import { runPureWorker } from './pure-worker.mjs';
import { nativeSaml, samlSettings, verifySaml } from './saml-workload.mjs';

runPureWorker({
  name: 'saml',
  native: nativeSaml,
  framework: (fixture) => ({ plugin: samlPlugin(samlSettings(fixture)), key: SAML_CAPABILITY }),
  verify: verifySaml,
});
