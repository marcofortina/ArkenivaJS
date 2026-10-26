// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, realpath, mkdir, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiKeyFixture } from '../../examples/postgres/dist-test/integration/api-key-fixture.js';
import { countSensitiveValues, fingerprint } from './mfa-privacy.mjs';
import { runOrder } from './http-analysis.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--smoke',
  'Use --smoke with a fresh absolute external report directory',
);
assert.equal(
  process.env.ARKENIVA_POSTGRES_DISPOSABLE,
  '1',
  'An owned disposable verified-TLS database is required',
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
const sourceFiles = [
  'pnpm-lock.yaml',
  'tools/benchmark/package.json',
  'tools/benchmark/apikey.mjs',
  'tools/benchmark/apikey-worker.mjs',
  'tools/benchmark/apikey-native.mjs',
  'tools/benchmark/http-analysis.mjs',
  'tools/benchmark/mfa-privacy.mjs',
  ...['contracts', 'index', 'observation', 'runtime', 'service', 'validation'].map(
    (name) => 'packages/security-apikey/src/' + name + '.ts',
  ),
  ...['api-key-fixture', 'mfa-issuer', 'security-state-fixture'].map(
    (name) => 'examples/postgres/test/integration/' + name + '.ts',
  ),
  ...['security-state-store', 'security-store-support', 'security-store-contracts'].map(
    (name) => 'examples/postgres/src/' + name + '.ts',
  ),
];
const hashes = async () =>
  Object.fromEntries(
    await Promise.all(
      sourceFiles.map(async (file) => [
        file,
        createHash('sha256')
          .update(await readFile(resolve(root, file)))
          .digest('hex'),
      ]),
    ),
  );
const measuredSources = await hashes(),
  modes = runOrder(1, 193).map((entry) => entry.mode),
  reports = [];
const captures = new Map(),
  controllers = new Map(),
  tasks = new Set();
let activeMode,
  currentChild,
  totalBytes = 0,
  activeRequests = 0,
  backend;
const receiver = createServer({ maxHeaderSize: 4096 }, (request, response) => {
  const capture = captures.get(activeMode);
  if (
    !capture ||
    request.method !== 'POST' ||
    !['/v1/traces', '/v1/metrics'].includes(request.url) ||
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
    totalBytes += chunk.length;
    if (bytes > 1048576 || totalBytes > 33554432) request.destroy();
    else chunks.push(chunk);
  });
  request.once('end', () => {
    try {
      const body = Buffer.concat(chunks),
        value = JSON.parse(body.toString()),
        digest = fingerprint(body);
      if (capture.digests.has(digest)) capture.repeatedBodies++;
      capture.digests.add(digest);
      capture.bodies.push(value);
      capture.bytes += bytes;
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
  backend = await apiKeyFixture();
  const session = await backend.session(),
    issued = await session.run(() =>
      backend.first.keys.issue(session.subject, {
        scopes: ['orders.read'],
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        allowedIpRanges: ['192.0.2.0/24'],
      }),
    );
  const fixture = {
    token: issued.value,
    keyId: issued.id,
    subject: session.subject,
    keyRef: backend.settings.hmacKeyRef,
    context: { clientIp: '192.0.2.15' },
  };
  const providerMethods = new Map();
  for (const name of [
    'read',
    'claimOnce',
    'compareAndSet',
    'atomicBatch',
    'listByOwner',
    'bumpOwnerEpoch',
    'currentOwnerEpoch',
  ])
    providerMethods.set(
      'store.' + name,
      backend.settings.store.store[name].bind(backend.settings.store.store),
    );
  for (const name of ['digest', 'verify'])
    providerMethods.set('hmac.' + name, backend.settings.hmac[name].bind(backend.settings.hmac));
  providerMethods.set(
    'authority.require',
    backend.settings.authority.require.bind(backend.settings.authority),
  );
  const totalAttempts = async () =>
    Number(
      (
        await backend.backend.app.sql.queryOne('main', {
          text: `SELECT COALESCE(sum((body::jsonb->>'count')::bigint),0)::text AS attempts FROM ${backend.backend.schema}.security_records WHERE namespace=:namespace AND id LIKE :pattern`,
          bindings: { namespace: 'apikey.attempts.v1', pattern: 'verify-%' },
        })
      ).attempts,
    );
  const server = await backend.backend.app.sql.queryOne('main', {
    text: "SELECT current_setting('server_version') AS version",
  });
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
    const capture = { requests: 0, bytes: 0, repeatedBodies: 0, digests: new Set(), bodies: [] };
    captures.set(mode, capture);
    const parentCpu = process.cpuUsage(),
      parentRss = process.memoryUsage().rss,
      parentStart = performance.now(),
      before = await totalAttempts(),
      calls = {};
    const result = await new Promise((resolve, reject) => {
      let result,
        failed = false,
        stage = 'startup',
        noise = 0;
      const child = fork(fileURLToPath(new URL('./apikey-worker.mjs', import.meta.url)), [], {
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        serialization: 'advanced',
        execArgv: [],
        env: { ARKENIVA_APIKEY_BENCH_WORKER: JSON.stringify({ mode, collector }) },
      });
      currentChild = child;
      const watchdog = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error('Credential benchmark worker timed out'));
      }, 60000);
      for (const stream of [child.stdout, child.stderr])
        stream.on('data', (chunk) => {
          noise += chunk.length;
          if (noise > 1048576) child.kill('SIGKILL');
        });
      child.on('message', (message) => {
        if (message.type === 'ready') child.send({ type: 'initialize', fixture });
        else if (message.type === 'cancel') controllers.get(message.id)?.abort();
        else if (message.type === 'rpc') {
          try {
            assert.ok(
              Number.isSafeInteger(message.id) &&
                message.id > 0 &&
                !controllers.has(message.id) &&
                controllers.size < 1,
            );
            assert.ok(
              providerMethods.has(message.method) &&
                Array.isArray(message.args) &&
                Buffer.byteLength(JSON.stringify(message.args)) <= 65536,
            );
            assert.ok(
              Number.isSafeInteger(message.timeoutMs) &&
                message.timeoutMs > 0 &&
                message.timeoutMs <= 5000,
            );
            const controller = new AbortController();
            controllers.set(message.id, controller);
            calls[message.method] = (calls[message.method] ?? 0) + 1;
            const timer = setTimeout(() => controller.abort(), message.timeoutMs);
            const task = Promise.resolve()
              .then(() =>
                providerMethods.get(message.method)(...message.args, {
                  signal: controller.signal,
                  timeoutMs: message.timeoutMs,
                }),
              )
              .then(
                (result) => {
                  if (child.connected) child.send({ type: 'rpc-result', id: message.id, result });
                },
                () => {
                  if (child.connected)
                    child.send({ type: 'rpc-result', id: message.id, failed: true });
                },
              )
              .finally(() => {
                clearTimeout(timer);
                controllers.delete(message.id);
                tasks.delete(task);
              });
            tasks.add(task);
          } catch {
            failed = true;
            child.kill('SIGKILL');
          }
        } else if (message.type === 'result') result = message;
        else {
          failed = true;
          if (message.type === 'failed' && ['setup', 'verify', 'flush'].includes(message.stage))
            stage = message.stage;
        }
      });
      child.once('error', () => {
        clearTimeout(watchdog);
        reject(new Error('Credential benchmark worker could not start'));
      });
      child.once('exit', (code) => {
        clearTimeout(watchdog);
        currentChild = undefined;
        if (code !== 0 || failed || !result || noise)
          reject(new Error('Credential benchmark worker failed at ' + stage));
        else resolve(result);
      });
    });
    assert.equal(result.report.mode, mode);
    if (
      result.report.record.completedOperations !== 50 ||
      result.report.record.errors +
        result.report.record.saturationDrops +
        result.report.record.schedulingDrops
    ) {
      await writeFile(
        resolve(directory, 'failure.json'),
        JSON.stringify(
          { status: 'FAIL', mode, record: result.report.record, providerCalls: calls },
          null,
          2,
        ) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      throw new Error(
        'Credential smoke incomplete: errors=' +
          result.report.record.errors +
          ', saturated=' +
          result.report.record.saturationDrops +
          ', late=' +
          result.report.record.schedulingDrops,
      );
    }
    assert.equal(result.report.record.completedOperations, 50);
    assert.equal(
      result.report.record.errors +
        result.report.record.saturationDrops +
        result.report.record.schedulingDrops,
      0,
    );
    assert.deepEqual(calls, {
      'hmac.digest': 57,
      'store.read': 165,
      'store.compareAndSet': 55,
      'hmac.verify': 55,
      'authority.require': 55,
    });
    assert.equal(result.report.providerCalls, 387);
    assert.equal((await totalAttempts()) - before, 55);
    assert.equal(tasks.size, 0);
    const privateValues = new Set(result.fingerprints),
      findings = capture.bodies.reduce(
        (sum, body) => sum + countSensitiveValues(body, privateValues),
        0,
      );
    assert.equal(
      findings,
      0,
      'Credential diagnostics must contain no secret, keyed verifier or account binding',
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
        elapsedMs: performance.now() - parentStart,
        cpuDeltaMicros: process.cpuUsage(parentCpu),
        observedBoundaryRssMaximumBytes: Math.max(parentRss, process.memoryUsage().rss),
        providerCalls: calls,
        durableAttemptIncrements: 55,
      },
      diagnosticCapture: {
        requests: capture.requests,
        observedOtlpBodyBytes: capture.bytes,
        repeatedBodyCount: capture.repeatedBodies,
        exportRetries: null,
        sensitiveValueFindings: findings,
      },
    });
    capture.bodies.length = 0;
    capture.digests.clear();
    console.log('Credential verification smoke profile passed: ' + mode);
  }
  assert.deepEqual(
    await hashes(),
    measuredSources,
    'Benchmark source files must remain unchanged during measurement',
  );
  const optional = async (path) => {
    try {
      return (await readFile(path, 'utf8')).trim();
    } catch {
      return null;
    }
  };
  const report = {
    scenarioId: 'apikey-local-smoke',
    sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim(),
    workingTreeDirty:
      execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()
        .length > 0,
    sourceFilesSha256: measuredSources,
    startedAt,
    measured: true,
    releaseGate: false,
    postgresServerVersion: server.version,
    modeOrder: modes,
    orderSeed: 193,
    profiles: reports,
    hardware: {
      cpu: cpus()[0]?.model ?? null,
      logicalCpus: cpus().length,
      totalMemoryBytes: totalmem(),
      architecture: arch(),
      platform: platform(),
      kernel: release(),
      governor: await optional('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'),
      cpuAffinity:
        (await optional('/proc/self/status'))?.match(/^Cpus_allowed_list:\s*(.+)$/m)?.[1] ?? null,
    },
    coverage: {
      corpus:
        'The same ephemeral token, CIDR policy and verified account binding in every isolated process; HMAC keys, actual signed OIDC authority and verified-TLS PostgreSQL remain in the parent fixture',
      baseline:
        'Direct native HMAC/subnet verification through the same complete durable store and trusted authority workflow; no public-adapter input/admission/audit implementation is emulated',
      load: '25 fixed offers/second, concurrency one; missed and saturated offers counted without queues or catch-up',
      timing:
        'Individual verify promises; result conformance validation excluded from latency and included in process resources',
      resources:
        'Worker aggregate including setup/warmup/paced waits/SDK/flush; parent aggregate includes native HMAC, SQL-provider/authority work, IPC validation and OTLP capture over each entire worker lifetime',
      memory:
        '10ms child samples and explicit boundaries; parent RSS boundaries only, not exact transient maxima',
      diagnostics:
        'Actual OTLP JSON retained only in memory for privacy checks; no raw corpus, sensitive fingerprints or collector bodies in the report',
      unsupported: [
        'other-API-key-method-performance',
        'negative-path-timing-comparison',
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
  console.log('All four credential verification smoke profiles passed; releaseGate=false');
} finally {
  currentChild?.kill('SIGKILL');
  receiver.closeAllConnections();
  await new Promise((resolve) => receiver.close(resolve));
  for (const controller of controllers.values()) controller.abort();
  await Promise.allSettled([...tasks]);
  await backend?.close();
}
