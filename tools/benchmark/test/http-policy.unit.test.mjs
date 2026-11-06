// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pairedComparison, runOrder } from '../http-analysis.mjs';
import {
  httpBenchmarkPolicy,
  compareHttpMetric,
  parseHttpBenchmarkArguments,
} from '../http-policy.mjs';

test('An explicit pilot retains sustained timing with one complete matched four-mode trial', () => {
  const plan = httpBenchmarkPolicy('pilot');
  assert.equal(plan.warmupSeconds, 60);
  assert.equal(plan.measuredSeconds, 180);
  assert.equal(plan.repeats, 1);
  assert.deepEqual(plan.order, runOrder(1, 137));
  assert.deepEqual(plan.order.map((row) => row.mode).sort(), [
    'BASELINE',
    'DETAILED',
    'FRAMEWORK',
    'STANDARD',
  ]);
  assert.ok(plan.order.every((row) => row.repeat === 1));
});

test('Pilot selection leaves existing campaign, smoke and soak execution budgets intact', () => {
  const campaign = httpBenchmarkPolicy('campaign');
  assert.deepEqual(campaign, {
    warmupSeconds: 60,
    measuredSeconds: 180,
    repeats: 5,
    order: runOrder(5, 137),
  });
  assert.deepEqual(httpBenchmarkPolicy('smoke'), {
    warmupSeconds: 1,
    measuredSeconds: 3,
    repeats: 1,
    order: runOrder(1, 137),
  });
  assert.deepEqual(httpBenchmarkPolicy('soak'), {
    warmupSeconds: 60,
    measuredSeconds: 3600,
    repeats: 1,
    order: [{ repeat: 1, mode: 'STANDARD' }],
  });
  assert.throws(() => httpBenchmarkPolicy('unknown'));
});

test('A pilot exposes descriptive changes without confidence, variance or release acceptance', () => {
  const result = compareHttpMetric([10], [12], 'pilot');
  assert.ok(Math.abs(result.meanChangePercent - 20) < 1e-10);
  assert.equal(result.pairedRepeats, 1);
  assert.equal(result.confidence95Percent, null);
  assert.equal(result.coefficientOfVariationBaseline, null);
  assert.equal(result.sufficientlyRepeated, false);
  assert.equal(result.calibrationStatus, 'NOT_CALIBRATED');
  assert.equal(result.releaseGate, false);
  assert.throws(() => compareHttpMetric([10, 10], [12, 12], 'pilot'));
  assert.throws(() => compareHttpMetric([0], [12], 'pilot'));
  assert.throws(() => compareHttpMetric([10], [12, 12], 'pilot'));
  assert.deepEqual(compareHttpMetric([10], [12], 'smoke'), pairedComparison([10], [12]));
  assert.deepEqual(
    compareHttpMetric([10, 11], [12, 13], 'campaign'),
    pairedComparison([10, 11], [12, 13]),
  );
});

test('The CLI requires an explicit pilot option and rejects ambiguous policy arguments', () => {
  assert.deepEqual(parseHttpBenchmarkArguments(['/owned/evidence', '--pilot']), {
    directory: '/owned/evidence',
    policy: 'pilot',
  });
  assert.deepEqual(parseHttpBenchmarkArguments(['/owned/evidence']), {
    directory: '/owned/evidence',
    policy: 'campaign',
  });
  for (const args of [
    [],
    [''],
    ['/owned/evidence', '--campaign'],
    ['/owned/evidence', '--pilot', '--soak'],
    ['/owned/evidence', '--pilto'],
  ])
    assert.throws(() => parseHttpBenchmarkArguments(args));
});

test('A pilot refuses missing disposable fixtures before creating report artifacts', () => {
  const directory = mkdtempSync(join(tmpdir(), 'arkenivajs-http-pilot-'));
  try {
    const output = join(directory, 'uncreated-report');
    const result = spawnSync(
      process.execPath,
      [fileURLToPath(new URL('../http.mjs', import.meta.url)), output, '--pilot'],
      {
        env: { PATH: process.env.PATH },
        encoding: 'utf8',
        timeout: 10000,
      },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(
      result.stderr,
      /^The HTTP benchmark failed; inspect the protected external artifacts\n$/,
    );
    assert.equal(existsSync(output), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
