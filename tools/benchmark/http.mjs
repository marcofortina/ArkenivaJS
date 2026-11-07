// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork, spawn, execFileSync } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, writeFile, realpath, stat, statfs, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cpus, totalmem, platform, release, arch } from 'node:os';
import { performance } from 'node:perf_hooks';
import { once } from 'node:events';
import { createIssuer } from './http-issuer.mjs';
import {
  httpBenchmarkPolicy,
  compareHttpMetric,
  parseHttpBenchmarkArguments,
} from './http-policy.mjs';
import { createHttpTlsFixture, httpTlsLoadEnvironment, verifyHttpTlsServer } from './http-tls.mjs';
import { verifySecureHttp2Server } from './http2-tls.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const modes = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'];
const routes = ['json', 'authenticated', 'database'];
const expectedBody = JSON.stringify({ ok: true, value: 7, padding: 'x'.repeat(94) });
const exitWithin = async (exited, milliseconds) => {
  let timer;
  try {
    return await Promise.race([
      exited,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};
const optionalFile = async (path) => {
  try {
    return (await readFile(path, 'utf8')).trim();
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'EACCES') return null;
    throw error;
  }
};
const jsonFile = (path, value) =>
  writeFile(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
async function externalDirectory(path) {
  const directory = resolve(path);
  assert.equal(
    await realpath(dirname(directory)),
    dirname(directory),
    'Artifact parents must not contain symlinks',
  );
  for (let parent = dirname(directory); ; parent = dirname(parent)) {
    assert.equal(
      await optionalFile(join(parent, '.git', 'HEAD')),
      null,
      'Benchmark artifacts must remain outside Git',
    );
    try {
      await stat(join(parent, '.git'));
      throw new Error('Benchmark artifacts must remain outside Git');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (parent === dirname(parent)) break;
  }
  await mkdir(directory, { mode: 0o700 });
  return directory;
}
function message(child, expected, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => done(new Error('The benchmark worker missed its control deadline')),
      timeoutMs,
    );
    const receive = (value) => {
      if (value.kind === 'failure') done(new Error(value.message));
      else if (value.kind === expected) done(undefined, value);
      else done(new Error('Unexpected benchmark worker response'));
    };
    const exit = () => done(new Error('The benchmark worker exited before responding'));
    function done(error, value) {
      clearTimeout(timer);
      child.off('message', receive);
      child.off('exit', exit);
      if (error) reject(error);
      else resolve(value);
    }
    child.on('message', receive);
    child.once('exit', exit);
  });
}
async function worker(settings, cpu) {
  const log = createWriteStream(join(settings.directory, 'worker.log'), {
    flags: 'wx',
    mode: 0o600,
  });
  await once(log, 'open');
  const child = fork(fileURLToPath(new URL('http-worker.mjs', import.meta.url)), [], {
    stdio: ['ignore', log, log, 'ipc'],
    execArgv: [],
  });
  const exited = new Promise((resolve) =>
    child.once('exit', (code, signal) => resolve({ code, signal })),
  );
  const control = async (kind, expected) => {
    const pending = message(child, expected);
    child.send({ kind });
    return pending;
  };
  let closing;
  const close = () =>
    (closing ??= (async () => {
      if (child.exitCode === null && child.signalCode === null && child.connected)
        child.send({ kind: 'close' });
      let exit = await exitWithin(exited, 15000);
      if (!exit) {
        child.kill('SIGTERM');
        exit = await exitWithin(exited, 2000);
        if (!exit) {
          child.kill('SIGKILL');
          exit = await exited;
        }
      }
      await new Promise((resolve, reject) => {
        log.once('error', reject);
        log.end(resolve);
      });
      assert.equal(exit.code, 0, 'The benchmark worker failed or exceeded its shutdown deadline');
    })());
  try {
    if (cpu !== undefined)
      execFileSync('taskset', ['-pc', cpu, String(child.pid)], { stdio: 'pipe' });
    const pending = message(child, 'ready');
    child.send(settings);
    const ready = await pending;
    return {
      ...ready,
      begin: () => control('begin', 'began'),
      finish: () => control('finish', 'result'),
      close,
    };
  } catch (cause) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([cause, cleanup], 'Worker initialization and cleanup failed', {
        cause: cleanup,
      });
    }
    throw cause;
  }
}
async function load(configuration, directory, phase, executable, cpu, signal, tlsFixture) {
  const configurationPath = join(directory, phase + '-configuration.json');
  const summaryPath = join(directory, phase + '-summary.json');
  await jsonFile(configurationPath, { ...configuration, summaryPath });
  const log = createWriteStream(join(directory, phase + '-load.log'), { flags: 'wx', mode: 0o600 });
  await once(log, 'open');
  const arguments_ = [
    'run',
    '--quiet',
    '--no-usage-report',
    '--out',
    'json=' + join(directory, phase + '-raw.json.gz'),
    fileURLToPath(new URL('http-load.mjs', import.meta.url)),
  ];
  if (tlsFixture)
    arguments_.splice(1, 0, '--config', tlsFixture.optionsFile, '--insecure-skip-tls-verify=false');
  if (tlsFixture && ['untrusted', 'wrong-name'].includes(configuration.tlsControl))
    arguments_.splice(1, 0, '--log-output=none');
  const command = cpu === undefined ? executable : 'taskset';
  const argumentsWithAffinity =
    cpu === undefined ? arguments_ : ['-c', cpu, executable, ...arguments_];
  const child = spawn(command, argumentsWithAffinity, {
    cwd: directory,
    stdio: ['ignore', log, log],
    signal,
    env: {
      ...(tlsFixture
        ? httpTlsLoadEnvironment(
            process.env,
            tlsFixture,
            configuration.tlsControl === 'untrusted',
            configuration.http2 === true,
          )
        : process.env),
      ARKENIVA_LOAD_CONFIG: configurationPath,
      GOMAXPROCS: '1',
      GOMEMLIMIT: '512MiB',
      K6_NO_USAGE_REPORT: 'true',
    },
  });
  const started = performance.now();
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => child.kill('SIGKILL'),
        (configuration.durationSeconds + 40) * 1000,
      );
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once('close', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error('The load generator failed its checks or deadline'));
      });
    });
    const summary = JSON.parse(await readFile(summaryPath, 'utf8'));
    assert.equal(summary.metrics.response_failures.values.count, 0);
    assert.equal(
      summary.metrics.http_req_failed.values.rate,
      ['untrusted', 'wrong-name'].includes(configuration.tlsControl) ? 1 : 0,
    );
    if (configuration.tlsControl) {
      assert.equal(summary.metrics.http_reqs.values.count, 1);
      assert.equal(summary.metrics.completed_json.values.count, 1);
      if (configuration.tlsControl !== 'trusted')
        assert.equal(summary.metrics.expected_tls_rejections.values.count, 1);
    }
    assert.equal(summary.metrics.dropped_iterations?.values.count ?? 0, 0);
    return { elapsedMs: performance.now() - started, summary };
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await new Promise((resolve, reject) => {
      log.once('error', reject);
      log.end(resolve);
    });
    await unlink(configurationPath);
  }
}
function comparisons(runs, seed, policy, selectedRoutes = routes) {
  const result = [];
  const baseline = runs
    .filter((run) => run.mode === 'BASELINE')
    .sort((a, b) => a.repeat - b.repeat);
  if (!baseline.length) return result;
  for (const mode of modes.slice(1)) {
    const candidate = runs.filter((run) => run.mode === mode).sort((a, b) => a.repeat - b.repeat);
    for (const metric of [
      'cpuSecondsPer1000Requests',
      'rssMean',
      ...selectedRoutes.flatMap((route) => [route + '.p95Ms', route + '.requestsPerSecond']),
    ]) {
      const read = (run) =>
        metric === 'cpuSecondsPer1000Requests'
          ? run.server.cpuSecondsPer1000Requests
          : metric === 'rssMean'
            ? run.server.rssBytes.mean
            : run.routes[metric.split('.')[0]][metric.split('.')[1]];
      result.push({
        mode,
        metric,
        ...compareHttpMetric(baseline.map(read), candidate.map(read), policy, seed),
      });
    }
  }
  return result;
}

/** Run matched workloads in owned processes and retain raw evidence outside the checkout. */
export async function runHttpBenchmark(path, policy = 'campaign', transport = 'http') {
  const plan = httpBenchmarkPolicy(policy);
  assert.ok(['http', 'https', 'http2', 'http1-fallback'].includes(transport));
  const https = transport !== 'http',
    secureHttp2 = transport === 'http2' || transport === 'http1-fallback',
    expectedHttp2 = transport === 'http2',
    expectedHttpVersion = expectedHttp2 ? '2.0' : '1.1',
    selectedRoutes = https ? ['json'] : routes;
  if (https) {
    assert.equal(policy, 'smoke', 'Direct HTTPS currently supports only the bounded smoke policy');
    assert.equal(
      process.env.ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE,
      '1',
      'HTTPS smoke requires an explicitly disposable measurement environment',
    );
  }
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVAJS_OTLP_ENDPOINT);
  assert.ok(process.env.ARKENIVA_BENCHMARK_K6);
  if (policy !== 'smoke') assert.equal(process.env.ARKENIVA_BENCHMARK_RUNNER, 'disposable-vm');
  if (policy !== 'smoke') {
    assert.equal(process.version, 'v24.22.1');
    assert.ok(
      process.env.ARKENIVA_BENCHMARK_FIXTURE_METADATA,
      'Fixture image digests and limits are required',
    );
    const free = await statfs(dirname(resolve(path)));
    assert.ok(
      free.bavail * free.bsize >= 5 * 1024 ** 3,
      'Long measurements require at least 5 GiB of free artifact space',
    );
  }
  const dirty =
    execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim().length >
    0;
  assert.ok(policy === 'smoke' || !dirty, 'Long measurements require a clean committed checkout');
  const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const directory = await externalDirectory(path),
    previousUmask = process.umask(0o077);
  const controller = new AbortController();
  const interrupted = () => controller.abort(new Error('The benchmark was interrupted'));
  process.once('SIGINT', interrupted);
  process.once('SIGTERM', interrupted);
  let issuer, tlsFixture;
  const runs = [],
    seed = 137,
    { warmupSeconds, measuredSeconds, order } = plan;
  try {
    if (https) tlsFixture = await createHttpTlsFixture();
    const metadata = {
      measured: true,
      releaseGate: false,
      policy,
      ...(https
        ? {
            scenarioId: secureHttp2
              ? expectedHttp2
                ? 'direct-https-http2-json128'
                : 'direct-https-http11-fallback-json128'
              : 'direct-https-http11-json128',
            transport: {
              protocol: 'https',
              httpVersion: expectedHttpVersion,
              minimumTlsVersion: 'TLSv1.3',
              certificateKey: 'EC P-256',
              ...(secureHttp2 ? { http2Server: true, allowHTTP1: true } : {}),
            },
          }
        : {}),
      ...(policy === 'pilot'
        ? {
            evidenceKind: 'single-sustained-pilot',
            calibrationStatus: 'NOT_CALIBRATED',
            sufficientlyRepeated: false,
          }
        : {}),
      sha,
      dirty,
      startedAt: new Date().toISOString(),
      node: process.version,
      openssl: process.versions.openssl,
      k6: execFileSync(process.env.ARKENIVA_BENCHMARK_K6, ['version'], { encoding: 'utf8' }).trim(),
      os: {
        platform: platform(),
        kernel: release(),
        architecture: arch(),
        memoryBytes: totalmem(),
        cpuModels: [...new Set(cpus().map((cpu) => cpu.model))],
        cpuCount: cpus().length,
      },
      affinity: {
        controller:
          (await optionalFile('/proc/self/status'))?.match(/^Cpus_allowed_list:\s*(.*)$/m)?.[1] ??
          null,
        serverCpu: process.env.ARKENIVA_BENCHMARK_SERVER_CPU ?? null,
        loadCpu: process.env.ARKENIVA_BENCHMARK_LOAD_CPU ?? null,
      },
      governor: await optionalFile('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'),
      cgroup: {
        cpuMax: await optionalFile('/sys/fs/cgroup/cpu.max'),
        memoryMax: await optionalFile('/sys/fs/cgroup/memory.max'),
      },
      fixtureMetadata: process.env.ARKENIVA_BENCHMARK_FIXTURE_METADATA
        ? JSON.parse(await readFile(process.env.ARKENIVA_BENCHMARK_FIXTURE_METADATA, 'utf8'))
        : null,
      environment: {
        disposablePostgres: true,
        postgresConnectionConfigured: !!process.env.ARKENIVA_POSTGRES_URL,
        collector: process.env.ARKENIVAJS_OTLP_ENDPOINT,
      },
      workload: {
        warmupSeconds,
        measuredSeconds,
        repeats: plan.repeats,
        seed,
        order,
        ratePerRoute: 50,
        routes: selectedRoutes,
        payloadBytes: 128,
        poolMaximum: 2,
        preallocatedVusPerRoute: 25,
        maximumVusPerRoute: 25,
        traceSampling: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 0.1, DETAILED: 1 },
        profiler: {
          DETAILED: 'V8 CPU profile at 10ms sampling; profiler shutdown excluded from measured CPU',
        },
      },
      limitations: [
        'Virtualization and competing physical host activity can increase variance',
        'Warmup and steady phases use separate load processes; the server process remains warm',
        'Server CPU interval includes measured load-process startup and graceful completion',
        https
          ? 'Process CPU/RSS describe JSON128B server work with the existing idle security/PostgreSQL fixture machinery; never exact per-request or tenant attribution'
          : 'Process CPU/RSS are aggregate across three mixed route workloads, never exact per-request or tenant attribution',
        'Raw load data includes observed client bytes, not billed traffic or database-server CPU',
        'Preliminary relative budgets remain unapproved; no release pass is inferred',
        ...(https
          ? [
              'One connection-cold native Node control is not a handshake latency distribution; Node and Go observations remain separate',
              'Measured Go connection pools start empty after separate-process warmup; only the server remains warm',
              'Go request duration excludes TCP and TLS setup; its handshake trend includes zero observations from reused connections, not a handshake count',
              secureHttp2
                ? 'Measured HTTP2 or HTTP1 fallback is selected explicitly against the same allowHTTP1 secure-listener configuration; no sustained pilot, handshake capacity, calibrated overhead, repeated acceptance or one-hour soak claim'
                : 'No HTTP2/fallback, sustained HTTPS pilot, handshake capacity, calibrated overhead, repeated acceptance or one-hour soak claim',
              ...(secureHttp2
                ? [
                    'Native HTTP2 session retirement is awaited at warmup and measured boundaries; server CPU includes measured load shutdown and physical session retirement',
                  ]
                : []),
            ]
          : []),
      ],
    };
    await jsonFile(join(directory, 'environment.json'), metadata);
    issuer = await createIssuer();
    const token = await issuer.token();
    for (const item of order) {
      controller.signal.throwIfAborted();
      const location = join(directory, String(item.repeat).padStart(2, '0') + '-' + item.mode);
      await mkdir(location, { mode: 0o700 });
      const server = await worker(
        {
          ...item,
          directory: location,
          issuer: issuer.origin,
          audience: issuer.audience,
          otlpEndpoint: process.env.ARKENIVAJS_OTLP_ENDPOINT,
          ...(https
            ? {
                transport: 'https',
                ...(secureHttp2 ? { http2: true, expectedHttpVersion } : {}),
                tls: {
                  certificateFile: tlsFixture.certificateFile,
                  privateKeyFile: tlsFixture.privateKeyFile,
                  minVersion: 'TLSv1.3',
                },
              }
            : {}),
        },
        process.env.ARKENIVA_BENCHMARK_SERVER_CPU,
      );
      try {
        const configuration = {
          origin: server.address,
          ...(https
            ? { https: true, ...(secureHttp2 ? { secureHttp2: true, http2: expectedHttp2 } : {}) }
            : { token }),
          expectedBody,
          ratePerRoute: 50,
        };
        let tlsControls;
        if (https) {
          const native = await (secureHttp2 ? verifySecureHttp2Server : verifyHttpTlsServer)({
            origin: server.address,
            certificateFile: tlsFixture.certificateFile,
            expectedBody,
          });
          const go = [];
          for (const [selection, expectedCode] of [
            ['untrusted', 1310],
            ['wrong-name', 1311],
            ['trusted', 0],
          ]) {
            await load(
              { ...configuration, tlsControl: selection, durationSeconds: 1 },
              location,
              'tls-control-' + selection,
              process.env.ARKENIVA_BENCHMARK_K6,
              process.env.ARKENIVA_BENCHMARK_LOAD_CPU,
              controller.signal,
              tlsFixture,
            );
            go.push({ selection, attempts: 1, expectedErrorCode: expectedCode, verified: true });
          }
          tlsControls = { native, go, excludedFromMeasuredInterval: true };
        }
        await load(
          { ...configuration, durationSeconds: warmupSeconds },
          location,
          'warmup',
          process.env.ARKENIVA_BENCHMARK_K6,
          process.env.ARKENIVA_BENCHMARK_LOAD_CPU,
          controller.signal,
          tlsFixture,
        );
        await server.begin();
        const measured = await load(
          { ...configuration, durationSeconds: measuredSeconds },
          location,
          'measured',
          process.env.ARKENIVA_BENCHMARK_K6,
          process.env.ARKENIVA_BENCHMARK_LOAD_CPU,
          controller.signal,
          tlsFixture,
        );
        const observation = (await server.finish()).observations;
        assert.equal(observation.counts.failed, 0);
        assert.equal(observation.counts.active, 0);
        assert.equal(observation.counts.completed, measured.summary.metrics.http_reqs.values.count);
        let clientTls;
        if (https) {
          const values = measured.summary.metrics,
            count = observation.counts.completed,
            serverTls = observation.tls;
          assert.ok(count > 0);
          assert.equal(observation.counts.authenticationVerified, 0);
          assert.equal(observation.counts.authenticationRejected, 0);
          assert.equal(observation.counts.authorizedOperations, 0);
          assert.equal(observation.counts.databaseQueries, 0);
          assert.equal(serverTls.observerFailures, 0);
          assert.equal(serverTls.handshakeErrors, 0);
          assert.equal(serverTls.http11Requests, expectedHttp2 ? 0 : count);
          if (secureHttp2) {
            assert.equal(serverTls.http2Requests, expectedHttp2 ? count : 0);
            assert.equal(serverTls.activeHttp2Sessions, 0);
            assert.equal(serverTls.http2SessionsOpened, serverTls.http2SessionsClosed);
            assert.equal(serverTls.http2SessionErrors, 0);
            if (expectedHttp2)
              assert.equal(serverTls.http2SessionsOpened, serverTls.successfulHandshakes);
            else assert.equal(serverTls.http2SessionsOpened, 0);
          }
          assert.equal(serverTls.unexpectedHttpVersions, 0);
          assert.ok(
            serverTls.successfulHandshakes > 0 &&
              serverTls.resumedHandshakes <= serverTls.successfulHandshakes,
          );
          assert.deepEqual(Object.keys(serverTls.tlsVersions), ['TLSv1.3']);
          for (const counters of [serverTls.tlsVersions, serverTls.ciphers, serverTls.alpn])
            assert.equal(
              Object.values(counters).reduce((sum, value) => sum + value, 0),
              serverTls.successfulHandshakes,
            );
          assert.equal(values.observed_http11_responses.values.count, expectedHttp2 ? 0 : count);
          if (secureHttp2)
            assert.equal(values.observed_http2_responses.values.count, expectedHttp2 ? count : 0);
          assert.equal(values.observed_tls13_responses.values.count, count);
          const ciphers = Object.fromEntries(
            ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']
              .map((name) => [name, values['cipher_' + name].values.count])
              .filter(([, value]) => value > 0),
          );
          assert.equal(
            Object.values(ciphers).reduce((sum, value) => sum + value, 0),
            count,
          );
          assert.deepEqual(Object.keys(ciphers).sort(), Object.keys(serverTls.ciphers).sort());
          clientTls = {
            role: 'independent-Go-k6-load',
            http11Responses: expectedHttp2 ? 0 : count,
            ...(secureHttp2
              ? {
                  http2Responses: expectedHttp2 ? count : 0,
                  expectedHttpVersion,
                  observedAlpnOnServer: serverTls.alpn,
                }
              : {}),
            tls13Responses: count,
            ciphers,
            handshakeDurationMs: values.observed_tls_handshake_ms.values,
            tcpConnectDurationMs: values.observed_tcp_connect_ms.values,
            positiveHandshakeDurationObservations:
              values.positive_handshake_duration_observations.values.count,
            requestDurationExcludesConnectAndHandshake: true,
          };
        }
        if (observation.api) assert.equal(observation.api.observerFailures, 0);
        if (observation.afterFlush.meter) {
          const meter = observation.afterFlush.meter;
          assert.equal(meter.dropped, 0);
          assert.equal(meter.failedExports, 0);
          assert.equal(meter.enqueued, meter.exported);
        }
        if (observation.afterFlush.telemetry) {
          const telemetry = observation.afterFlush.telemetry;
          assert.equal(telemetry.droppedSpans, 0);
          assert.equal(telemetry.droppedMetrics, 0);
          assert.equal(telemetry.exportFailures, 0);
        }
        if (observation.logs) {
          assert.equal(observation.logs.dropped, 0);
          assert.equal(observation.logs.failedWrites, 0);
        }
        const result = {
          ...item,
          startupMs: server.startupMs,
          versions: server.versions,
          server: observation,
          clientWallMs: measured.elapsedMs,
          clientBytesReceived: measured.summary.metrics.data_received.values.count,
          clientBytesSent: measured.summary.metrics.data_sent.values.count,
          ...(https ? { tlsControls, clientTls } : {}),
          routes: Object.fromEntries(
            selectedRoutes.map((route) => {
              const latency = measured.summary.metrics['latency_' + route].values;
              return [
                route,
                {
                  requests: measured.summary.metrics['completed_' + route].values.count,
                  requestsPerSecond:
                    measured.summary.metrics['completed_' + route].values.count / measuredSeconds,
                  p50Ms: latency.med,
                  p95Ms: latency['p(95)'],
                  p99Ms: latency['p(99)'],
                  maxMs: latency.max,
                },
              ];
            }),
          ),
        };
        await jsonFile(join(location, 'observations.json'), result);
        runs.push(result);
        await jsonFile(
          join(directory, 'progress-' + String(runs.length).padStart(2, '0') + '.json'),
          { completed: runs.length, total: order.length, ...item },
        );
        console.log(
          JSON.stringify({
            completed: runs.length,
            total: order.length,
            ...item,
            requests: observation.counts.completed,
          }),
        );
      } finally {
        await server.close();
      }
    }
    const report = {
      ...metadata,
      finishedAt: new Date().toISOString(),
      status: 'MEASURED',
      runs,
      comparisons: comparisons(runs, seed, policy, selectedRoutes),
    };
    await jsonFile(join(directory, 'report.json'), report);
    const rows = [
      'repeat,mode,route,requests,rps,p50_ms,p95_ms,p99_ms,max_ms,cpu_seconds_per_1000_requests,rss_mean_bytes',
    ];
    for (const run of runs)
      for (const [route, values] of Object.entries(run.routes))
        rows.push(
          [
            run.repeat,
            run.mode,
            route,
            values.requests,
            values.requestsPerSecond,
            values.p50Ms,
            values.p95Ms,
            values.p99Ms,
            values.maxMs,
            run.server.cpuSecondsPer1000Requests,
            run.server.rssBytes.mean,
          ].join(','),
        );
    await writeFile(join(directory, 'summary.csv'), rows.join('\n') + '\n', {
      flag: 'wx',
      mode: 0o600,
    });
    return { policy, completedRuns: runs.length, sha, releaseGate: false };
  } catch (cause) {
    await jsonFile(join(directory, 'failure.json'), {
      status: 'FAILED',
      completedRuns: runs.length,
      message:
        'A required benchmark check failed; protected per-run artifacts contain diagnostic evidence',
    });
    throw cause;
  } finally {
    try {
      try {
        await issuer?.close();
      } finally {
        await tlsFixture?.close();
      }
    } finally {
      process.off('SIGINT', interrupted);
      process.off('SIGTERM', interrupted);
      process.umask(previousUmask);
    }
  }
}
if (process.argv[1] && import.meta.url === new URL('file://' + resolve(process.argv[1])).href) {
  try {
    const { directory, policy, transport } = parseHttpBenchmarkArguments(process.argv.slice(2));
    console.log(JSON.stringify(await runHttpBenchmark(directory, policy, transport)));
  } catch {
    console.error('The HTTP benchmark failed; inspect the protected external artifacts');
    process.exitCode = 1;
  }
}
