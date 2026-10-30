// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startScimFixture } from './scim-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { scimIterations, scimWarmupIterations } from './scim-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startScimFixture(args[0] === '--smoke');
try {
  const report = await runPureComparison(
    {
      scenarioId: 'scim-native-schema-and-durable-provider-verification',
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./scim-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'scimmy@1.3.5 with the same reviewed corrections',
        commonBackend: 'Existing actual PostgreSQL SCIM application provider',
        tenantOwners: 4,
        samplingSupported: true,
        measuredOperation: 'GET User at the authenticated service boundary',
        samplesPerProfile: args[0] === '--smoke' ? scimIterations : 0,
        warmupReadsPerProfile: args[0] === '--smoke' ? scimWarmupIterations : 0,
        concurrency: 1,
      },
      observationCoverage:
        'Actual signed identities and independently authenticated parent provider enforce four distinct tenant owners. Existing CRUD/idempotency/PATCH/ETag verification remains outside timing. Optional smoke reads one separately seeded live User per tenant through actual JWT, provider bridge, PostgreSQL and SCIMMY representation paths. Every returned body and ETag is checked privately; parent independently verifies 480 provider reads, unchanged version1 seed bodies/owners and four original version4 tombstones. Actual SDK exports exclude tokens, records, tenant IDs and schemas.',
      limitations:
        'Valid fixed User-resource corpus at the service boundary, with the same application SQL provider and parent auth infrastructure on both paths. Native reference is not a full SCIM server and omits framework complete hostile-input, runtime-context provenance, authority and uncertain-outcome policy. Read timings exclude seed setup, CRUD verification, HTTP ingress and independent SQL readback. Child process resources exclude the parent provider/issuer/SQL client and PostgreSQL server. No CRUD performance, Group, production federation, end-to-end HTTP parity, complete resource parity, calibrated budget, five repetitions, one-hour soak or release acceptance claim.',
    },
    args,
  );
  const reads = report.records.reduce((sum, row) => {
      assert.equal(
        row.completion.checkedReads,
        row.completion.sampledReads + row.completion.warmupReads,
      );
      return sum + row.completion.checkedReads;
    }, 0),
    observation = await authority.verify(4, reads),
    encoded = JSON.stringify(observation, null, 2) + '\n';
  for (const value of authority.privacyValues) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}
