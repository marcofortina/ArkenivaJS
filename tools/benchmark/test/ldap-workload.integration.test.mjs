// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { requireLdapProcessTreeResource } from '../ldap-workload.mjs';

test(
  'Four LDAPS profiles execute real directory binds and lookups without private telemetry or incomplete resource claims',
  { timeout: 30000 },
  async () => {
    assert.ok(process.env.ARKENIVA_LDAP_FIXTURE);
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-ldap-harness-')),
      script = fileURLToPath(new URL('../ldap.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(encoded, /alice|ldaps:\/\/127\.0\.0\.1/);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.processTreeResource, undefined);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          verifiedServiceBind: true,
          actualUserFound: true,
          absentUser: true,
          filterInjectionAbsent: true,
          correctPassword: true,
          incorrectPasswordRejected: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', join(directory, 'untrusted')], {
          env: { ...process.env, ARKENIVA_LDAP_COMPARISON_URL: 'ldaps://127.0.0.1:16390' },
          timeout: 10000,
          maxBuffer: 1048576,
        }),
      );
      const rejected = join(directory, 'sample'),
        env = { ...process.env };
      delete env.ARKENIVA_LDAP_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          env,
          timeout: 5000,
          maxBuffer: 1048576,
        }),
      );
      await assert.rejects(access(rejected), { code: 'ENOENT' });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Explicit LDAP smoke measures verified fresh-client search with complete supervised descendant observations',
  { timeout: 145000, skip: process.env.ARKENIVA_LDAP_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-ldap-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../ldap.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /alice|ldaps:\/\/127\.0\.0\.1/);
      assert.match(report.processTreeResourceCoverage, /whole-supervised-lifecycle/);
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0],
          observed = row.completion;
        assert.equal(measured.operation, 'verified-service-bind-and-user-search');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          observed.actualSearchCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(observed.successfulProjectedSearches, observed.actualSearchCallbacks);
        assert.equal(observed.activeSearchCallbacks, 0);
        assert.equal(observed.peakConcurrentCallbacks, 1);
        assert.equal(observed.independentVerifiedReadbacks, 1);
        requireLdapProcessTreeResource(row.processTreeResource);
        assert.ok(
          row.processTreeResource.observedProcessCount >= (row.mode === 'BASELINE' ? 2 : 3),
        );
        assert.ok(
          row.processTreeResource.userCpuSeconds + row.processTreeResource.systemCpuSeconds > 0,
        );
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
