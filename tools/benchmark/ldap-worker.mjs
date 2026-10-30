// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { ldapPlugin, LDAP_CAPABILITY } from '@arkenivajs/security-ldap';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  ldapSettings,
  nativeLdap,
  verifyLdap,
  ldapWorkload,
  ldapObservations,
} from './ldap-workload.mjs';

export const ldapAdapter = {
  name: 'ldap',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeLdap,
  framework: (fixture) => ({ plugin: ldapPlugin(ldapSettings(fixture)), key: LDAP_CAPABILITY }),
  verify: verifyLdap,
  workload: ldapWorkload,
  complete: ldapObservations,
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(ldapAdapter);
