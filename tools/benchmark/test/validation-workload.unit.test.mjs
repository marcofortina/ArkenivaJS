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
import { createValidationService } from '@arkenivajs/data-validation';
import {
  nativeValidation,
  validationFixture,
  validationSettings,
  validationWorkload,
  verifyValidation,
} from '../validation-workload.mjs';

test('Bare native and public validation preserve semantic outcomes on the same fixed inert corpus', () => {
  const native = nativeValidation(),
    framework = createValidationService(validationSettings);
  for (const service of [native, framework])
    assert.equal(verifyValidation(service, validationFixture).checkedCases, 18);
  const a = validationWorkload(native, validationFixture),
    b = validationWorkload(framework, validationFixture);
  for (const operation of Object.keys(a)) assert.deepEqual(a[operation](), b[operation]());
  assert.deepEqual(validationFixture.document, { quantity: 2, active: true });
  assert.deepEqual(validationFixture.invalidDocument, { quantity: '2', active: true });
});

test(
  'Isolated validation profiles distinguish verification from sampling and omit all input values',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-validation-harness-')),
      script = fileURLToPath(new URL('../validation.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 20000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.deepEqual(report.records.map((row) => row.mode).sort(), [
          'BASELINE',
          'DETAILED',
          'FRAMEWORK',
          'STANDARD',
        ]);
        assert.equal(report.collector.inputOccurrences, 0);
        for (const value of Object.values(validationFixture))
          if (typeof value === 'string') assert.equal(encoded.includes(value), false);
        for (const profile of report.records) {
          assert.equal(profile.verification.checkedCases, 18);
          assert.equal(profile.records.length, mode === '--smoke' ? 9 : 0);
          if (mode === '--verify') assert.equal(profile.resource, null);
          for (const operation of profile.records) {
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
