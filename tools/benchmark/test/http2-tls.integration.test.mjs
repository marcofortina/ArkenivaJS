// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { runHttpBenchmark } from '../http.mjs';

for (const transport of ['http2', 'http1-fallback']) {
  test(
    'Secure ' +
      transport +
      ' JSON128B reconciles actual Go protocol/session observations on an allowHTTP1 listener',
    { timeout: 150000 },
    async () => {
      assert.equal(process.env.ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE, '1');
      assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
      assert.ok(process.env.ARKENIVAJS_OTLP_ENDPOINT);
      assert.ok(process.env.ARKENIVA_BENCHMARK_K6);
      const directory = await mkdtemp('/tmp/arkenivajs-http2-smoke-test-'),
        before = (await readdir('/tmp'))
          .filter((name) => name.startsWith('arkenivajs-http-tls-'))
          .sort(),
        h2 = transport === 'http2';
      try {
        const output = join(directory, 'report');
        assert.equal((await runHttpBenchmark(output, 'smoke', transport)).completedRuns, 4);
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.releaseGate, false);
        assert.equal(
          report.scenarioId,
          h2 ? 'direct-https-http2-json128' : 'direct-https-http11-fallback-json128',
        );
        assert.equal(report.transport.http2Server, true);
        assert.equal(report.transport.allowHTTP1, true);
        assert.equal(report.transport.httpVersion, h2 ? '2.0' : '1.1');
        assert.deepEqual(report.workload.routes, ['json']);
        assert.equal(report.workload.repeats, 1);
        assert.equal(report.runs.length, 4);
        assert.doesNotMatch(
          encoded,
          /arkenivajs-http-tls-|BEGIN (?:EC )?PRIVATE KEY|BEGIN CERTIFICATE/,
        );
        for (const run of report.runs) {
          const count = run.routes.json.requests,
            server = run.server,
            tls = server.tls,
            native = run.tlsControls.native;
          assert.ok(count > 0);
          assert.deepEqual(Object.keys(run.routes), ['json']);
          assert.equal(server.counts.completed, count);
          for (const key of [
            'active',
            'failed',
            'authenticationVerified',
            'authenticationRejected',
            'authorizedOperations',
            'databaseQueries',
          ])
            assert.equal(server.counts[key], 0);
          assert.equal(server.logAudit.httpCompleted, count);
          assert.equal(server.logAudit.authenticationVerified, 0);
          assert.equal(tls.http2Requests, h2 ? count : 0);
          assert.equal(tls.http11Requests, h2 ? 0 : count);
          assert.equal(tls.unexpectedHttpVersions, 0);
          assert.equal(tls.observerFailures, 0);
          assert.equal(tls.handshakeErrors, 0);
          assert.ok(tls.successfulHandshakes > 0);
          assert.equal(tls.tlsVersions['TLSv1.3'], tls.successfulHandshakes);
          assert.equal(tls.http2SessionsOpened, tls.http2SessionsClosed);
          assert.equal(tls.activeHttp2Sessions, 0);
          assert.equal(tls.http2SessionErrors, 0);
          if (h2) {
            assert.equal(tls.http2SessionsOpened, tls.successfulHandshakes);
            assert.deepEqual(tls.alpn, { h2: tls.successfulHandshakes });
          } else {
            assert.equal(tls.http2SessionsOpened, 0);
            assert.ok(Object.keys(tls.alpn).every((value) => ['none', 'http/1.1'].includes(value)));
          }
          assert.equal(run.clientTls.http2Responses, h2 ? count : 0);
          assert.equal(run.clientTls.http11Responses, h2 ? 0 : count);
          assert.equal(run.clientTls.tls13Responses, count);
          assert.equal(
            Object.values(run.clientTls.ciphers).reduce((sum, value) => sum + value, 0),
            count,
          );
          assert.deepEqual(
            Object.keys(run.clientTls.ciphers).sort(),
            Object.keys(tls.ciphers).sort(),
          );
          assert.equal(native.http2.tls.authorized, true);
          assert.equal(native.http2.tls.sessionReused, false);
          assert.equal(native.http2.tls.alpn, 'h2');
          assert.equal(native.http2.byteIdentityVerified, true);
          assert.equal(native.http2.streamClosed, true);
          assert.equal(native.http2.sessionClosed, true);
          assert.equal(native.http2.tlsSocketClosed, true);
          assert.equal(native.http1Fallback.positive.tls.alpn, 'http/1.1');
          assert.equal(native.http1Fallback.positive.byteIdentityVerified, true);
          assert.equal(native.http1Fallback.positive.physicalClientClosed, true);
          assert.equal(native.http2WrongNameRejected, true);
          assert.equal(native.http2UntrustedCaRejected, true);
          assert.equal(native.http1Fallback.wrongNameRejected, true);
          assert.equal(native.http1Fallback.untrustedCaRejected, true);
          assert.deepEqual(
            run.tlsControls.go.map((value) => value.expectedErrorCode),
            [1310, 1311, 0],
          );
          assert.ok(run.tlsControls.go.every((value) => value.verified && value.attempts === 1));
          assert.ok(server.cpuDeltaMicros.user > 0 && server.rssBytes.max > 0);
          if (server.api) assert.equal(server.api.observerFailures, 0);
          if (server.afterFlush.meter) {
            for (const key of ['enqueued', 'exported', 'dropped', 'failedExports'])
              assert.equal(server.afterFlush.meter[key], 0);
            for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
              assert.equal(server.afterFlush.telemetry[key], 0);
          }
          const location = join(output, String(run.repeat).padStart(2, '0') + '-' + run.mode),
            applicationLog = await readFile(join(location, 'application.jsonl'), 'utf8');
          assert.doesNotMatch(
            applicationLog,
            /arkenivajs-http-tls-|BEGIN (?:EC )?PRIVATE KEY|BEGIN CERTIFICATE/,
          );
          assert.equal(applicationLog.includes('x'.repeat(94)), false);
          for (const control of ['untrusted', 'wrong-name']) {
            const log = await readFile(
              join(location, 'tls-control-' + control + '-load.log'),
              'utf8',
            );
            assert.doesNotMatch(
              log,
              /Request Failed|wrong\.invalid|https:\/\/localhost|x509:|BEGIN (?:EC )?PRIVATE KEY/,
            );
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
}
