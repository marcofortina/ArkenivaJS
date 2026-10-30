// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { ldapPlugin, LDAP_CAPABILITY } from '@arkenivajs/security-ldap';
import { runPureWorker } from './pure-worker.mjs';
import { ldapSettings, nativeLdap, verifyLdap } from './ldap-workload.mjs';

runPureWorker({
  name: 'ldap',
  asynchronous: true,
  native: nativeLdap,
  framework: (fixture) => ({ plugin: ldapPlugin(ldapSettings(fixture)), key: LDAP_CAPABILITY }),
  verify: verifyLdap,
  workload() {
    throw new Error('LDAP sampling requires complete native child process accounting');
  },
});
