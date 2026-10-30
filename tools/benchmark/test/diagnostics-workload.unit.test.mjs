// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createDiagnostics } from '@arkenivajs/diagnostics';
import {
  nativeDiagnostics,
  diagnosticsSettings,
  verifyDiagnostics,
  diagnosticsWorkload,
} from '../diagnostics-workload.mjs';

test('Native and public diagnostics retain actual process units and bounded cumulative CPU evidence', () => {
  for (const service of [nativeDiagnostics(), createDiagnostics(diagnosticsSettings)]) {
    try {
      assert.equal(verifyDiagnostics(service).checkedSnapshots, 20);
      assert.equal(diagnosticsWorkload(service).snapshot().processId, process.pid);
    } finally {
      service.close();
    }
    assert.throws(() => service.snapshot());
    service.close();
  }
});

test(
  'Isolated process diagnostics distinguish functional verification from optional sampling',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-diagnostics-harness-')),
      script = fileURLToPath(new URL('../diagnostics.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 20000,
          maxBuffer: 1048576,
        });
        const report = JSON.parse(await readFile(join(output, 'report.json'), 'utf8'));
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.deepEqual(report.records.map((row) => row.mode).sort(), [
          'BASELINE',
          'DETAILED',
          'FRAMEWORK',
          'STANDARD',
        ]);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.equal(report.collector.receivedBodies, 0);
        for (const row of report.records) {
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality)
            for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
              assert.equal(row.quality[key], 0);
          assert.equal(row.verification.checkedSnapshots, 20);
          assert.equal(row.verification.nativeCpuBoundsVerified, true);
          assert.equal(row.verification.processScopeOnly, true);
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'snapshot');
            assert.ok(operation.sampleCount >= 10000);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
