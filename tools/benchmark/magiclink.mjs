// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startMagiclinkFixture } from './magiclink-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete magic-link provider resource sampling remains separate',
);
const authority = await startMagiclinkFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'magiclink-native-durable-one-use-consumption',
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./magiclink-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend:
          'Node crypto/HMAC with the same signed application authority and PostgreSQL atomic store',
        concurrentAttemptsPerLink: 2,
        successfulConsumptionsPerProfile: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four isolated profiles consume actual framework-issued magic links through the same external HMAC and signed account authority with real transactional PostgreSQL. Two concurrent attempts yield exactly one winner; replay, GET prefetch and wrong purpose fail. Parent independently verifies persisted link state and exact consume quotas. Actual SDK exports exclude bearer secrets, identities and keyed digests.',
      limitations:
        'Positive-corpus native consumption reference is benchmark-only and uses the specified record protocol, native hash primitive and existing shared providers; it is not a production magic-link implementation. It omits full hostile-record handling, startup negative probes, admission, cancellation, retry classification and lifecycle policy. Parent-issued links and test-only authenticated provider bridge do not establish production provider or full cross-pod acceptance. No issue/revoke equivalence, complete provider/server resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'durable-observation.json'),
    JSON.stringify(await authority.verify(4), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
