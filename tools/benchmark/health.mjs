// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { startHealthFixture } from './health-fixture.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startHealthFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'health-readiness-probe-comparison',
      fixture: authority.fixture,
      privacyValues: Object.values(authority.fixture),
      privacyField: 'inputOccurrences',
      worker: new URL('./health-worker.mjs', import.meta.url),
      inputs: {
        operations: ['ready'],
        nativeBackend: 'Node HTTP readiness callback',
        snapshotsPerProfile: 9,
        samplesPerOperation: 100,
        warmupIterations: 20,
        concurrency: 1,
      },
      observationCoverage:
        'Actual successful and failed HTTP dependency probes in four isolated profiles; liveness remains independent of dependency readiness. Standard/detailed profiles use the real SDK histogram and export privacy checks.',
      limitations:
        'Local owned HTTP probe comparison. The native baseline omits framework registry lifecycle, startup probes, automatic plugin checks, deadline ownership and concurrent coalescing. Sampling is exploratory; no dedicated-runner budget, release acceptance, five repetitions or one-hour soak claim.',
    },
    args,
  );
  assert.equal(authority.state.ready, true);
  assert.equal(authority.state.failedProbes, 4);
  assert.equal(authority.state.changes, 8);
  assert.ok(authority.state.probes >= (args[0] === '--smoke' ? 516 : 36));
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(
      {
        completedProbeRequests: authority.state.probes,
        failedProbeRequests: authority.state.failedProbes,
        readinessChanges: authority.state.changes,
        dependencyRestored: authority.state.ready,
        releaseGate: false,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
