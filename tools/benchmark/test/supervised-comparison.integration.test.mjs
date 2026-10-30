// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runPureComparison } from '../pure-comparison.mjs';
import { assertRawLatencySamples } from './raw-latency.mjs';

function definition(extra = {}) {
  return {
    scenarioId: 'synthetic-supervised-process-comparison',
    worker: new URL('./fixtures/supervised-comparison-worker.mjs', import.meta.url),
    fixture: { marker: 'owned-opaque-comparison-private-input', controllerPid: process.pid },
    privacyValues: ['owned-opaque-comparison-private-input', 'owned-forbidden-parent-environment'],
    privacyField: 'inputOccurrences',
    inputs: { syntheticOnly: true },
    observationCoverage: 'Synthetic child IPC only; no real service or codec.',
    limitations: 'Synthetic correctness control; no real codec performance or release acceptance.',
    ...extra,
  };
}

test(
  'Opt-in comparison supervises all four real synthetic profiles without replacing measured-window resources',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-comparison-')),
      names = ['DATABASE_URL', 'NODE_OPTIONS', 'ARKENIVA_SUPERVISION_FORBIDDEN_FIXTURE'],
      previous = new Map(names.map((name) => [name, process.env[name]]));
    try {
      process.env.DATABASE_URL = 'owned-forbidden-parent-environment';
      process.env.NODE_OPTIONS = '--no-warnings';
      process.env.ARKENIVA_SUPERVISION_FORBIDDEN_FIXTURE = 'owned-forbidden-parent-environment';
      const report = await runPureComparison(definition({ superviseProcessTree: true }), [
        '--smoke',
        join(directory, 'smoke'),
      ]);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.match(report.processTreeResourceCoverage, /whole-supervised-lifecycle/);
      for (const row of report.records) {
        assert.equal(row.verification.actualNativeChildVerified, true);
        assert.equal(row.verification.privateEnvironmentAbsent, true);
        assert.equal(row.verification.directParent, false);
        assert.equal(row.completion.observedNativeWork, 13);
        assertRawLatencySamples(row.records[0]);
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.ok(
          resource.userCpuSeconds + resource.systemCpuSeconds >=
            ((row.resource.cpuDeltaMicros.user + row.resource.cpuDeltaMicros.system) / 1e6) * 0.99,
        );
        assert.ok(resource.peakConcurrentProcesses >= 3);
        for (const pid of resource.observedPids) await assert.rejects(access('/proc/' + pid));
      }
    } finally {
      for (const [name, value] of previous)
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Default smoke and opt-in verification preserve the original direct fork and report shape',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-legacy-'));
    try {
      for (const [mode, extra] of [
        ['--smoke', {}],
        ['--verify', { superviseProcessTree: true }],
      ]) {
        const report = await runPureComparison(definition(extra), [
          mode,
          join(directory, mode.slice(2)),
        ]);
        assert.equal(Object.hasOwn(report, 'processTreeResourceCoverage'), false);
        for (const row of report.records) {
          assert.equal(row.verification.directParent, true);
          assert.equal(Object.hasOwn(row, 'processTreeResource'), false);
          assert.equal(row.resource === null, mode === '--verify');
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('Invalid supervision flags and unsupported trust anchors fail before comparison effects', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-guards-'));
  try {
    let calls = 0;
    const accessor = definition();
    Object.defineProperty(accessor, 'superviseProcessTree', {
      get() {
        calls++;
        return true;
      },
    });
    const invalid = [
      definition({ superviseProcessTree: 'true' }),
      accessor,
      definition({ superviseProcessTree: true, trustAnchorFile: join(directory, 'unused-ca.pem') }),
    ];
    for (const [index, candidate] of invalid.entries()) {
      const output = join(directory, 'invalid-' + index);
      await assert.rejects(runPureComparison(candidate, ['--smoke', output]));
      await assert.rejects(access(output));
    }
    assert.equal(calls, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'Actual inaccessible descendant RSS cannot produce an accepted supervised comparison',
  { timeout: 30000 },
  async (t) => {
    const capabilities = (await readFile('/proc/self/status', 'utf8')).match(
      /^CapEff:\s+([a-f0-9]+)/m,
    );
    if ((BigInt('0x' + capabilities[1]) & (1n << 19n)) !== 0n) {
      t.skip('CAP_SYS_PTRACE prevents reproducing this inaccessible-RSS control');
      return;
    }
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-partial-')),
      output = join(directory, 'refused'),
      base = definition({ superviseProcessTree: true });
    base.fixture.inaccessible = true;
    try {
      await assert.rejects(runPureComparison(base, ['--smoke', output]), /coverage is incomplete/);
      await assert.rejects(access(join(output, 'report.json')));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
