// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startMagiclinkFixture } from './magiclink-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { magiclinkIterations, magiclinkWarmupIterations } from './magiclink-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startMagiclinkFixture(args[0] === '--smoke');
try {
  const report = await runPureComparison(
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
        samplingSupported: true,
        measuredOperation: 'Shared parent public issue followed by selected consumer receipt',
        samplesPerProfile: args[0] === '--smoke' ? magiclinkIterations : 0,
        warmupPerProfile: args[0] === '--smoke' ? magiclinkWarmupIterations : 0,
        sampledSubjectsPerProfile: 2,
        maximumClaimsPerSampledSubject: 60,
        configuredClaimsPerHour: 64,
      },
      observationCoverage:
        'Four isolated profiles consume actual framework-issued magic links through the same external HMAC and signed account authority with real transactional PostgreSQL. Untimed concurrent attempts yield exactly one winner; replay, GET prefetch and wrong purpose fail. Optional multi-subject smoke times a shared parent public issue then the selected native/public consume receipt, with two independently authenticated subjects per profile and 60 claims each under the unchanged64 limit. Parent independently verifies484 consumed records, exact issue/consume quotas,480 unique nonces and480 replay rejections with unchanged state. Actual SDK exports exclude bearer secrets, identities and keyed digests.',
      limitations:
        'Positive-corpus native consumption reference is benchmark-only and uses the specified record protocol, native hash primitive and existing shared providers; it is not a production magic-link implementation. It omits full hostile-record handling, startup negative probes, admission, cancellation, retry classification and lifecycle policy. Shared parent public issuance is included in each sample but is not a separately implemented native issuer or independently attributed issue latency. Parent-issued links and test-only authenticated provider bridge do not establish production provider or full cross-pod acceptance. No mail transport is configured: delivery count is zero, with no delivery parity or MFA assurance claim. Worker resources exclude parent issuer/provider/SQL client and PostgreSQL server. No issue/revoke equivalence, complete resource parity, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const count = report.records.reduce((sum, row) => {
    assert.equal(
      row.completion.checkedConsumptions,
      row.completion.sampledLinks + row.completion.warmupLinks,
    );
    return sum + row.completion.checkedConsumptions;
  }, 0);
  const encoded = JSON.stringify(await authority.verify(4 + count, count), null, 2) + '\n';
  for (const value of authority.privacyValues) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'durable-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}
