// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { createCertificateFixture } from '../../examples/certificates/dist/trust-fixture.js';
import { readFile, realpath, mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { countSensitiveValues, fingerprint } from './mfa-privacy.mjs';
import { runOrder } from './http-analysis.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--smoke',
  'Use --smoke with a fresh absolute external report directory',
);
const root = await realpath(fileURLToPath(new URL('../../', import.meta.url))),
  requested = resolve(args[1]);
assert.equal(args[1], requested, 'The report path must be absolute and normalized');
const parent = await realpath(dirname(requested)),
  directory = resolve(parent, basename(requested));
assert.ok(
  directory !== root && !directory.startsWith(root + sep),
  'Benchmark evidence must remain outside the product repository',
);
await mkdir(directory, { mode: 0o700 });
const modes = runOrder(1, 137).map((entry) => entry.mode),
  captures = new Map(),
  reports = [];
const backend = await createCertificateFixture({ testOnly: true });
const fixture = { leafDer: Buffer.from(backend.leafDer), rootDer: Buffer.from(backend.rootDer) };
const trustTasks = new Set(),
  trustControllers = new Map();
let activeMode,
  currentChild,
  totalBodyBytes = 0,
  activeRequests = 0;
const maximumBodyBytes = 1048576,
  maximumTotalBytes = 33554432;
const receiver = createServer({ maxHeaderSize: 4096 }, (request, response) => {
  const capture = captures.get(activeMode);
  if (
    !capture ||
    !['/v1/traces', '/v1/metrics'].includes(request.url) ||
    request.method !== 'POST' ||
    activeRequests >= 8
  ) {
    response.writeHead(503);
    response.end();
    return;
  }
  activeRequests++;
  capture.requests++;
  let bytes = 0,
    finished = false;
  const chunks = [];
  const finish = () => {
    if (!finished) {
      finished = true;
      activeRequests--;
    }
  };
  request.once('aborted', finish);
  request.once('error', finish);
  response.once('close', finish);
  request.on('data', (chunk) => {
    bytes += chunk.length;
    totalBodyBytes += chunk.length;
    if (bytes > maximumBodyBytes || totalBodyBytes > maximumTotalBytes) {
      request.destroy();
      return;
    }
    chunks.push(chunk);
  });
  request.once('end', () => {
    try {
      const body = Buffer.concat(chunks),
        value = JSON.parse(body.toString('utf8'));
      const digest = fingerprint(body);
      if (capture.digests.has(digest)) capture.repeatedBodies++;
      capture.digests.add(digest);
      capture.bodies.push(value);
      capture.bodyBytes += bytes;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    } catch {
      response.writeHead(400);
      response.end();
    } finally {
      finish();
    }
  });
});
receiver.requestTimeout = 2000;
receiver.headersTimeout = 2000;
const startedAt = new Date().toISOString();
try {
  await new Promise((resolve, reject) => {
    receiver.once('error', reject);
    receiver.listen(0, '127.0.0.1', () => {
      receiver.removeListener('error', reject);
      resolve();
    });
  });
  const address = receiver.address();
  assert.ok(address && typeof address !== 'string');
  const collector = 'http://127.0.0.1:' + address.port;
  for (const mode of modes) {
    activeMode = mode;
    const capture = {
      requests: 0,
      bodyBytes: 0,
      repeatedBodies: 0,
      digests: new Set(),
      bodies: [],
    };
    captures.set(mode, capture);
    const parentCpuBefore = process.cpuUsage(),
      parentRssBefore = process.memoryUsage().rss,
      parentAt = performance.now(),
      checksBefore = backend.checks();
    const result = await new Promise((resolve, reject) => {
      let result,
        failed = false,
        failureStage = 'startup',
        noise = 0;
      const child = fork(fileURLToPath(new URL('./x509-worker.mjs', import.meta.url)), [], {
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        serialization: 'advanced',
        execArgv: [],
        env: { ARKENIVA_X509_BENCH_WORKER: JSON.stringify({ mode, collector }) },
      });
      currentChild = child;
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error('Certificate benchmark worker timed out'));
      }, 60000);
      for (const stream of [child.stdout, child.stderr])
        stream.on('data', (chunk) => {
          noise += chunk.length;
          if (noise > 1048576) child.kill('SIGKILL');
        });
      child.on('message', (message) => {
        if (message.type === 'ready') child.send({ type: 'initialize', fixture });
        else if (message.type === 'trust-request') {
          try {
            assert.ok(
              Number.isSafeInteger(message.id) &&
                message.id > 0 &&
                !trustControllers.has(message.id) &&
                trustControllers.size < 1,
            );
            assert.ok(
              message.input?.peerDer instanceof Uint8Array &&
                Buffer.from(message.input.peerDer).equals(fixture.leafDer),
            );
            assert.ok(
              Number.isSafeInteger(message.timeoutMs) &&
                message.timeoutMs > 0 &&
                message.timeoutMs <= 1000,
            );
            const controller = new AbortController();
            trustControllers.set(message.id, controller);
            const task = backend.provider
              .verifyChainAndRevocation(message.input, {
                signal: controller.signal,
                timeoutMs: message.timeoutMs,
              })
              .then(
                (identity) => {
                  if (child.connected)
                    child.send({ type: 'trust-result', id: message.id, identity });
                },
                () => {
                  if (child.connected)
                    child.send({ type: 'trust-result', id: message.id, error: true });
                },
              )
              .finally(() => {
                trustControllers.delete(message.id);
                trustTasks.delete(task);
              });
            trustTasks.add(task);
          } catch {
            failed = true;
            child.kill('SIGKILL');
          }
        } else if (message.type === 'result') result = message;
        else {
          failed = true;
          if (
            message.type === 'failed' &&
            [
              'setup',
              'parse',
              'daysUntilExpiry',
              'getFingerprints',
              'inspectChain',
              'flush',
            ].includes(message.stage)
          )
            failureStage = message.stage;
        }
      });
      child.once('error', () => {
        clearTimeout(timer);
        reject(new Error('Certificate benchmark worker could not start'));
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        currentChild = undefined;
        if (code !== 0 || failed || !result || noise)
          reject(new Error('Certificate benchmark worker failed at ' + failureStage));
        else resolve(result);
      });
    });
    // Keep secret-free evidence of rejected load without treating raw observations as acceptance.
    assert.equal(countSensitiveValues(result.report, new Set(result.fingerprints)), 0);
    await writeFile(
      resolve(directory, mode.toLowerCase() + '-observations.json'),
      JSON.stringify(
        {
          gitSha: execFileSync('git', ['rev-parse', 'HEAD'], {
            cwd: root,
            encoding: 'utf8',
          }).trim(),
          workingTreeDirty:
            execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()
              .length > 0,
          validation: 'UNVERIFIED',
          releaseGate: false,
          observedTrustChecks: backend.checks() - checksBefore,
          pendingTrustTasks: trustTasks.size,
          report: result.report,
        },
        null,
        2,
      ) + '\n',
      { mode: 0o600, flag: 'wx' },
    );
    assert.equal(result.report.mode, mode);
    assert.equal(result.report.records.length, 4);
    for (const record of result.report.records) {
      assert.equal(
        record.schedulingDrops,
        0,
        record.scenarioId + ': offered work missed its schedule',
      );
      assert.equal(
        record.saturationDrops,
        0,
        record.scenarioId + ': offered work exceeded capacity',
      );
      assert.equal(record.errors, 0, record.scenarioId + ': certificate work failed');
      assert.equal(
        record.completedOperations,
        50,
        record.scenarioId + ': incomplete operation count',
      );
    }
    assert.equal(
      result.report.providerReads,
      55,
      'Trust reads must match the complete workload without retries',
    );
    assert.equal(backend.checks() - checksBefore, 55);
    assert.equal(trustTasks.size, 0);
    const findings = capture.bodies.reduce(
      (count, body) => count + countSensitiveValues(body, new Set(result.fingerprints)),
      0,
    );
    assert.equal(
      findings,
      0,
      'Diagnostic exports must contain no certificate identities or material',
    );
    assert.equal(
      result.report.telemetry.droppedSpans +
        result.report.telemetry.droppedMetrics +
        result.report.telemetry.exportFailures,
      0,
    );
    if (['STANDARD', 'DETAILED'].includes(mode)) {
      assert.ok(capture.requests > 0);
      assert.ok(capture.bodies.some((body) => body.resourceSpans));
      assert.ok(capture.bodies.some((body) => body.resourceMetrics));
    } else assert.equal(capture.requests, 0);
    reports.push({
      ...result.report,
      parentProcessResources: {
        elapsedMs: performance.now() - parentAt,
        cpuDeltaMicros: process.cpuUsage(parentCpuBefore),
        observedBoundaryRssMaximumBytes: Math.max(parentRssBefore, process.memoryUsage().rss),
        trustChecks: backend.checks() - checksBefore,
      },
      diagnosticCapture: {
        requests: capture.requests,
        observedOtlpBodyBytes: capture.bodyBytes,
        repeatedBodyCount: capture.repeatedBodies,
        exportRetries: null,
        sensitiveValueFindings: findings,
      },
    });
    capture.bodies.length = 0;
    capture.digests.clear();
    console.log('Certificate smoke profile passed: ' + mode);
  }
  const optionalFile = async (path) => {
    try {
      return (await readFile(path, 'utf8')).trim();
    } catch {
      return null;
    }
  };
  const report = {
    scenarioId: 'x509-local-smoke',
    sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim(),
    workingTreeDirty:
      execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()
        .length > 0,
    startedAt,
    measured: true,
    releaseGate: false,
    modeOrder: modes,
    orderSeed: 137,
    profiles: reports,
    hardware: {
      cpu: cpus()[0]?.model ?? null,
      logicalCpus: cpus().length,
      totalMemoryBytes: totalmem(),
      architecture: arch(),
      platform: platform(),
      kernel: release(),
      governor: await optionalFile('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'),
      cpuAffinity:
        (await optionalFile('/proc/self/status'))?.match(/^Cpus_allowed_list:\s*(.+)$/m)?.[1] ??
        null,
    },
    coverage: {
      corpus:
        'One ephemeral CA and server certificate, identical public DER cloned over closed IPC to every isolated worker; private keys remain in the parent fixture',
      baseline:
        'Direct X509Certificate construction/date/fingerprint utilities and the same independently verified TLS/CRL authority; no emulation of framework admission or metadata validation',
      load: '50 fixed offers/second, concurrency one; missed and saturated offers counted without queuing or catch-up bursts',
      timing:
        'Individual operation promises; common result conformance checks excluded from latency but included in process resource windows',
      resources:
        'Worker process aggregate including setup, warmup, paced waits, SDK background exports and flush; no per-request CPU attribution',
      memory: '10ms samples plus explicit boundaries; not an exact transient allocation maximum',
      provider:
        'Actual loopback native TLS with a pinned ephemeral CA and CRL in the parent, called through identical closed IPC in all profiles',
      diagnostics:
        'Actual SDK OTLP JSON inspected in the parent; parent CPU includes TLS authority, IPC and receiver together over each whole worker lifetime. TCP wire overhead and durable collector storage are not measured',
      unsupported: [
        'calibrated-load',
        'production-capacity',
        'five-independent-campaigns',
        'one-hour-soak',
        'confidence-intervals',
        'exact-export-retry-counter',
      ],
    },
  };
  await writeFile(resolve(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n', {
    mode: 0o600,
    flag: 'wx',
  });
  console.log('All four certificate smoke profiles passed; releaseGate=false');
} finally {
  currentChild?.kill('SIGKILL');
  receiver.closeAllConnections();
  await new Promise((resolve) => receiver.close(resolve));
  for (const controller of trustControllers.values()) controller.abort();
  await Promise.allSettled([...trustTasks]);
  await backend.close();
}
