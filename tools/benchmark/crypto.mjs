// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFile, realpath, mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nativeCryptoOperations } from './crypto-native.mjs';
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
const ed = generateKeyPairSync('ed25519'),
  ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const fixture = {
  input: randomBytes(1024),
  aad: randomBytes(32),
  edPublicKey: ed.publicKey.export({ format: 'der', type: 'spki' }),
  ecPublicKey: ec.publicKey.export({ format: 'der', type: 'spki' }),
  values: new Map([
    ['encryption', { bytes: randomBytes(32), keyVersion: randomUUID() }],
    ['hmac', { bytes: randomBytes(32), keyVersion: randomUUID() }],
    [
      'ed',
      { bytes: ed.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: randomUUID() },
    ],
    [
      'ec',
      { bytes: ec.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: randomUUID() },
    ],
  ]),
};
const native = nativeCryptoOperations(
  { get: async (reference) => fixture.values.get(reference) },
  fixture,
);
fixture.envelope = await native.encrypt();
fixture.mac = await native.hmac();
fixture.edSignature = await native.signEd25519();
fixture.ecSignature = await native.signP256();

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
const startedAt = new Date().toISOString();
try {
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
    const result = await new Promise((resolve, reject) => {
      let result,
        failed = false,
        noise = 0;
      const child = fork(fileURLToPath(new URL('./crypto-worker.mjs', import.meta.url)), [], {
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        serialization: 'advanced',
        execArgv: [],
        env: { ARKENIVA_CRYPTO_BENCH_WORKER: JSON.stringify({ mode, collector }) },
      });
      currentChild = child;
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error('Crypto benchmark worker timed out'));
      }, 60000);
      for (const stream of [child.stdout, child.stderr])
        stream.on('data', (chunk) => {
          noise += chunk.length;
          if (noise > 1048576) child.kill('SIGKILL');
        });
      child.on('message', (message) => {
        if (message.type === 'ready') child.send({ type: 'initialize', fixture });
        else if (message.type === 'result') result = message;
        else failed = true;
      });
      child.once('error', () => {
        clearTimeout(timer);
        reject(new Error('Crypto benchmark worker could not start'));
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        currentChild = undefined;
        if (code !== 0 || failed || !result || noise)
          reject(new Error('Crypto benchmark worker failed'));
        else resolve(result);
      });
    });
    assert.equal(result.report.mode, mode);
    assert.equal(result.report.records.length, 8);
    assert.equal(
      result.report.providerReads,
      mode === 'BASELINE' ? 330 : 334,
      'Fixture provider reads must not be retried',
    );
    for (const record of result.report.records) {
      assert.equal(record.completedOperations, 50);
      assert.equal(record.errors + record.saturationDrops + record.schedulingDrops, 0);
    }
    const findings = capture.bodies.reduce(
      (count, body) => count + countSensitiveValues(body, new Set(result.fingerprints)),
      0,
    );
    assert.equal(
      findings,
      0,
      'Diagnostic exports must contain no benchmark cryptographic material',
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
    console.log('Crypto smoke profile passed: ' + mode);
  }
  const optionalFile = async (path) => {
    try {
      return (await readFile(path, 'utf8')).trim();
    } catch {
      return null;
    }
  };
  const report = {
    scenarioId: 'crypto-local-smoke',
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
        'One ephemeral binary corpus and versioned key set, cloned over closed IPC to every isolated worker',
      baseline:
        'Direct native successful operations, same provider reads, binary copying and documented envelope AAD; no framework admission/lifecycle validation emulation',
      load: '50 fixed offers/second, concurrency one; missed and saturated offers counted without queuing or catch-up bursts',
      timing:
        'Individual operation promises; common result conformance checks excluded from latency but included in process resource windows',
      resources:
        'Worker process aggregate including setup, warmup, paced waits, SDK background exports and flush; no per-request CPU attribution',
      memory: '10ms samples plus explicit boundaries; not an exact transient allocation maximum',
      provider:
        'Borrowed in-memory test secrets; HTTPS provider interoperability is a separate executable example',
      diagnostics:
        'Actual SDK OTLP JSON received and inspected in the parent; receiver CPU, TCP wire overhead and durable collector storage are not measured',
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
  console.log('All four crypto smoke profiles passed; releaseGate=false');
} finally {
  currentChild?.kill('SIGKILL');
  receiver.closeAllConnections();
  await new Promise((resolve) => receiver.close(resolve));
  for (const value of fixture.values.values()) value.bytes.fill(0);
  fixture.input.fill(0);
  fixture.aad.fill(0);
  fixture.mac.fill(0);
  fixture.edSignature.fill(0);
  fixture.ecSignature.fill(0);
}
