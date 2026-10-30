// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startScimFixture } from './scim-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete SCIM provider/server resource sampling remains separate',
);
const authority = await startScimFixture();
try {
  await runPureComparison(
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
        samplingSupported: false,
      },
      observationCoverage:
        'Actual signed identities and independently authenticated parent provider enforce four distinct tenant owners. Native SCIMMY and the public service perform real CRUD, idempotent create retries, bounded pagination and exact PATCH. Two ETag competitors yield one winner; parent independently verifies four version4 SQL tombstones. Actual SDK exports exclude tokens, records, tenant IDs and schemas.',
      limitations:
        'Valid fixed User-resource corpus at the service boundary, with the same application SQL provider and parent auth infrastructure on both paths. Native reference is not a full SCIM server and omits framework complete hostile-input, runtime-context provenance, authority and uncertain-outcome policy. No Group, production federation, complete cross-process resource sampling, full performance campaign or release acceptance claim.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(await authority.verify(4), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
