// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertRawLatencySamples } from './raw-latency.mjs';

for (const [controller, scenario, recordCount] of [
  ['foundation', 'foundation-local-exploration', 12],
  ['metering', 'metering-local-exploration', 2],
  ['sql', 'sql-compiler-local-exploration', 4],
])
  test(
    `Actual legacy ${controller} CLI retains bounded measured samples and cleans its private temporary workspace`,
    { timeout: 30000 },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-legacy-raw-'));
      try {
        const { stdout } = await promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../' + controller + '.mjs', import.meta.url))],
          {
            cwd: fileURLToPath(new URL('../../../', import.meta.url)),
            env: { ...process.env, TMPDIR: directory },
            timeout: 25000,
            maxBuffer: 8 * 1024 ** 2,
          },
        );
        const report = JSON.parse(stdout);
        assert.equal(report.scenarioId, scenario);
        assert.equal(report.measured, true);
        assert.equal(report.releaseGate, false);
        assert.equal(report.nodeVersion, process.version);
        assert.match(report.gitSha, /^[0-9a-f]{40}$/);
        assert.equal(typeof report.workingTreeDirty, 'boolean');
        assert.equal(report.records.length, recordCount);
        for (const record of report.records) {
          assertRawLatencySamples({
            ...record,
            latencyNanoseconds: Object.fromEntries(
              Object.entries(record.latencyMs).map(([name, value]) => [name, value * 1e6]),
            ),
          });
          const expected =
            controller === 'sql'
              ? 10000
              : controller === 'metering'
                ? 1000
                : record.scenarioId.includes('capability')
                  ? 10000
                  : ['configuration-load', 'application-lifecycle'].includes(record.scenarioId)
                    ? 100
                    : 1000;
          assert.equal(record.sampleCount, expected);
          if (controller === 'sql') assert.equal(record.totalCompilerInvocations, 11000);
          if (controller === 'metering' && record.mode === 'jsonl') {
            assert.equal(record.stats.dropped, 0);
            assert.equal(record.stats.failedExports, 0);
            assert.ok(record.stats.exported >= 1100);
          }
        }
        assert.doesNotMatch(
          stdout,
          /fake-benchmark-password|benchmark-tenant|https:\/\/issuer.invalid/,
        );
        assert.deepEqual(await readdir(directory), []);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
