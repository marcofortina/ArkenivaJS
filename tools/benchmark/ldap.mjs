// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runPureComparison } from './pure-comparison.mjs';
import { ldapSettings } from './ldap-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; native child resource sampling remains separate',
);
assert.ok(
  process.env.ARKENIVA_LDAP_FIXTURE,
  'The owned private OpenLDAP fixture metadata is required',
);
const metadata = JSON.parse(await readFile(process.env.ARKENIVA_LDAP_FIXTURE, 'utf8'));
const fixture = {
  url: process.env.ARKENIVA_LDAP_COMPARISON_URL ?? 'ldaps://127.0.0.1:16389',
  ...Object.fromEntries(
    ['bindDn', 'bindPassword', 'userPassword', 'baseDn', 'groupBaseDn', 'caPem'].map((name) => [
      name,
      metadata[name],
    ]),
  ),
};
assert.ok(Object.values(fixture).every((value) => typeof value === 'string' && value.length > 0));
ldapSettings(fixture);
await runPureComparison(
  {
    scenarioId: 'ldap-native-directory-verification',
    fixture,
    privacyValues: [...Object.values(fixture), 'alice'],
    privacyField: 'inputOccurrences',
    worker: new URL('./ldap-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'ldapts@9.2.0 with verified TLS and fresh authenticated clients',
      operations: ['ping', 'findUser', 'verifyCredentials'],
      concurrency: 1,
      samplingSupported: false,
    },
    observationCoverage:
      'Actual OpenLDAP service bind, projected user data, absent and filter-injection lookups, successful and rejected user binds in four isolated profiles; real SDK exports exclude directory identities and credentials.',
    limitations:
      'Owned LDAPS fixture and synthetic directory only. Native baseline uses the same SDK/filter/client pattern but omits framework bounded input capture, child process isolation, IPC, lifecycle and hostile-result checks. Native child CPU/RSS is not sampled; timing/resource sampling rejected. No groups, streamed search, STARTTLS, AD staging, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);
