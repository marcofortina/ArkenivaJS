// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runPureComparison } from './pure-comparison.mjs';
import { ldapSettings, requireLdapProcessTreeResource } from './ldap-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full LDAP campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_LDAP_BENCHMARK_DISPOSABLE,
    '1',
    'LDAP smoke measurements require an explicitly disposable runner',
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
const report = await runPureComparison(
  {
    scenarioId: 'ldap-native-directory-verification',
    superviseProcessTree: true,
    fixture,
    privacyValues: [...Object.values(fixture), 'alice'],
    privacyField: 'inputOccurrences',
    worker: new URL('./ldap-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'ldapts@9.2.0 with verified TLS and fresh authenticated clients',
      operations: ['ping', 'findUser', 'verifyCredentials'],
      concurrency: 1,
      samplingSupported: true,
      scenarios: ['verified-service-bind-and-user-search'],
      measuredSamplesPerScenario: measured ? 100 : null,
      warmupCallbacksPerScenario: measured ? 20 : null,
      traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
    },
    observationCoverage:
      'Actual OpenLDAP service bind, projected user data, absent and filter-injection lookups, successful and rejected user binds in four isolated profiles; real SDK exports exclude directory identities and credentials. Explicit smoke retains actual Tinybench latency samples of verified service bind plus exact projected user search, with one independent final native LDAPS readback and actual callback counts. Every measured profile requires quality-checked supervised process-tree observations and physical descendant retirement. The owned CA is explicit input, never ambient trust. STANDARD and DETAILED both use diagnostic trace sampling1.',
    limitations:
      'Owned LDAPS fixture and synthetic directory only. Native baseline uses the same SDK/filter/client pattern but omits framework bounded input capture, child process isolation, IPC, lifecycle and hostile-result checks. Measured-window resource fields remain worker-only. Separate processTreeResource includes whole-lifecycle Node bridge, worker and native descendants, verification, warmup, sampling, export and cleanup; it excludes Python observer and external OpenLDAP. Summed RSS is sampled, non-atomic and counts shared pages repeatedly, not unique physical RAM. Missing or incomplete descendant resources refuse acceptance; no fallback to parent-only accounting. Native policy is not fully equivalent; STANDARD uses diagnostic sampling1 rather than normal production sampling. No groups, streamed search, STARTTLS, AD staging, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);

if (measured)
  for (const row of report.records) requireLdapProcessTreeResource(row.processTreeResource);
