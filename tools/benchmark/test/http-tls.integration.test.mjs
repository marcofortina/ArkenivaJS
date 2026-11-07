// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runHttpBenchmark } from '../http.mjs';

test(
  'Direct HTTPS JSON128B smoke reconciles real Go trust controls, native handshakes, responses and server resources in all four profiles',
  { timeout: 150000 },
  async () => {
    assert.equal(process.env.ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE, '1');
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVAJS_OTLP_ENDPOINT);
    assert.ok(process.env.ARKENIVA_BENCHMARK_K6);
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-https-smoke-test-')),
      before = (await readdir('/tmp'))
        .filter((name) => name.startsWith('arkenivajs-http-tls-'))
        .sort();
    try {
      const output = join(directory, 'report');
      assert.equal((await runHttpBenchmark(output, 'smoke', 'https')).completedRuns, 4);
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.releaseGate, false);
      assert.equal(report.scenarioId, 'direct-https-http11-json128');
      assert.equal(report.workload.repeats, 1);
      assert.deepEqual(report.workload.routes, ['json']);
      assert.equal(report.workload.warmupSeconds, 1);
      assert.equal(report.workload.measuredSeconds, 3);
      assert.equal(report.runs.length, 4);
      assert.doesNotMatch(
        encoded,
        /arkenivajs-http-tls-|BEGIN (?:EC )?PRIVATE KEY|BEGIN CERTIFICATE/,
      );
      for (const run of report.runs) {
        const applicationLog = await readFile(
          join(output, String(run.repeat).padStart(2, '0') + '-' + run.mode, 'application.jsonl'),
          'utf8',
        );
        assert.doesNotMatch(
          applicationLog,
          /arkenivajs-http-tls-|BEGIN (?:EC )?PRIVATE KEY|BEGIN CERTIFICATE/,
        );
        assert.equal(applicationLog.includes('x'.repeat(94)), false);
        for (const control of ['untrusted', 'wrong-name']) {
          const controlLog = await readFile(
            join(
              output,
              String(run.repeat).padStart(2, '0') + '-' + run.mode,
              'tls-control-' + control + '-load.log',
            ),
            'utf8',
          );
          assert.doesNotMatch(
            controlLog,
            /Request Failed|wrong\.invalid|https:\/\/localhost|x509:|BEGIN (?:EC )?PRIVATE KEY/,
          );
        }
        assert.deepEqual(Object.keys(run.routes), ['json']);
        const count = run.routes.json.requests,
          observed = run.server,
          native = run.tlsControls.native;
        assert.ok(count > 0);
        assert.equal(observed.counts.completed, count);
        for (const name of [
          'failed',
          'active',
          'authenticationVerified',
          'authenticationRejected',
          'authorizedOperations',
          'databaseQueries',
        ])
          assert.equal(observed.counts[name], 0);
        assert.equal(observed.logAudit.httpCompleted, count);
        assert.equal(observed.logAudit.authenticationVerified, 0);
        assert.equal(observed.tls.http11Requests, count);
        assert.equal(observed.tls.unexpectedHttpVersions, 0);
        assert.equal(observed.tls.handshakeErrors, 0);
        assert.equal(observed.tls.observerFailures, 0);
        assert.ok(observed.tls.successfulHandshakes > 0);
        assert.equal(observed.tls.tlsVersions['TLSv1.3'], observed.tls.successfulHandshakes);
        assert.equal(run.clientTls.http11Responses, count);
        assert.equal(run.clientTls.tls13Responses, count);
        assert.equal(
          Object.values(run.clientTls.ciphers).reduce((sum, value) => sum + value, 0),
          count,
        );
        assert.equal(run.clientTls.requestDurationExcludesConnectAndHandshake, true);
        assert.ok(run.clientTls.handshakeDurationMs.min >= 0);
        assert.equal(native.wrongNameRejected, true);
        assert.equal(native.untrustedCaRejected, true);
        assert.equal(native.positive.tls.authorized, true);
        assert.equal(native.positive.tls.sessionReused, false);
        assert.equal(native.positive.tls.alpn, 'http/1.1');
        assert.equal(native.positive.byteIdentityVerified, true);
        assert.equal(native.positive.physicalClientClosed, true);
        assert.deepEqual(
          run.tlsControls.go.map((value) => value.expectedErrorCode),
          [1310, 1311, 0],
        );
        assert.ok(run.tlsControls.go.every((value) => value.verified && value.attempts === 1));
        assert.equal(run.tlsControls.excludedFromMeasuredInterval, true);
        assert.ok(observed.cpuDeltaMicros.user > 0 && observed.rssBytes.max > 0);
        if (observed.api) assert.equal(observed.api.observerFailures, 0);
        if (observed.afterFlush.meter) {
          assert.equal(observed.afterFlush.meter.enqueued, 0);
          assert.equal(observed.afterFlush.meter.exported, 0);
          assert.equal(observed.afterFlush.meter.dropped, 0);
          assert.equal(observed.afterFlush.meter.failedExports, 0);
          for (const name of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
            assert.equal(observed.afterFlush.telemetry[name], 0);
        }
      }
      assert.deepEqual(
        (await readdir('/tmp')).filter((name) => name.startsWith('arkenivajs-http-tls-')).sort(),
        before,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
