// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { getFips, verify } from 'node:crypto';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { setInterval, clearInterval, setImmediate } from 'node:timers';
import { createApplication } from '@arkenivajs/core';
import { cryptoPlugin, CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import { createTelemetry } from '@arkenivajs/telemetry';
import { nativeCryptoOperations } from './crypto-native.mjs';
import { quantile } from './http-analysis.mjs';
import { fingerprint } from './mfa-privacy.mjs';

const options = JSON.parse(process.env.ARKENIVA_CRYPTO_BENCH_WORKER ?? '{}');
assert.ok(process.send && ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].includes(options.mode));
const initialization = new Promise((resolve) =>
  process.once('message', (message) => {
    assert.equal(message.type, 'initialize');
    resolve(message.fixture);
  }),
);
process.send({ type: 'ready' });
const fixture = await initialization;
assert.ok(
  fixture.values instanceof Map && fixture.input.length === 1024 && fixture.aad.length === 32,
);
const service = { name: 'crypto-benchmark', version: '1.0.0', environment: 'test' };
const enabled = ['STANDARD', 'DETAILED'].includes(options.mode),
  detailed = options.mode === 'DETAILED';
const sensitive = new Set();
function remember(bytes) {
  for (const encoding of ['hex', 'base64', 'base64url'])
    sensitive.add(fingerprint(Buffer.from(bytes).toString(encoding)));
}
remember(fixture.input);
remember(fixture.aad);
for (const value of fixture.values.values()) remember(value.bytes);
const scenarios = [
  'encrypt',
  'decrypt',
  'hmac',
  'verifyMac',
  'signEd25519',
  'verifyEd25519',
  'signP256',
  'verifyP256',
];
let app,
  telemetry,
  stage = 'setup',
  providerReads = 0;
const cpuBefore = process.cpuUsage(),
  elapsedStart = performance.now(),
  eluBefore = performance.eventLoopUtilization();
let peakRss = process.memoryUsage().rss,
  peakHeap = process.memoryUsage().heapUsed,
  gcCount = 0,
  gcDurationMs = 0;
const memory = setInterval(() => {
  const current = process.memoryUsage();
  peakRss = Math.max(peakRss, current.rss);
  peakHeap = Math.max(peakHeap, current.heapUsed);
}, 10);
const loop = monitorEventLoopDelay({ resolution: 10 });
loop.enable();
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    gcCount++;
    gcDurationMs += entry.duration;
  }
});
observer.observe({ entryTypes: ['gc'] });
try {
  telemetry = createTelemetry({
    service,
    mode: enabled ? (detailed ? 'detailed' : 'standard') : 'off',
    samplingRatio: detailed ? 1 : 0.1,
    ...(enabled ? { endpoint: options.collector, allowInsecureLoopback: true } : {}),
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
    spanQueueCapacity: 2048,
    labelValues: { operation: [...scenarios.map((name) => 'crypto.' + name), 'crypto.provider'] },
  });
  const provider = {
    usage: 'test-only',
    async get(reference) {
      const work = async () => {
        providerReads++;
        const value = fixture.values.get(reference);
        assert.ok(value);
        return value;
      };
      return detailed
        ? telemetry.withSpan('crypto.provider', work, {
            attributes: { operation: 'crypto.provider' },
          })
        : work();
    },
  };
  let operations;
  if (options.mode === 'BASELINE') operations = nativeCryptoOperations(provider, fixture);
  else {
    app = await createApplication({
      service,
      plugins: [
        cryptoPlugin({
          secrets: provider,
          encryptionKeyRefs: ['encryption'],
          signingKeyRefs: ['hmac', 'ed', 'ec'],
          policy: { maxConcurrent: 1, timeoutMs: 1000, maxInputBytes: 4096, maxOutputBytes: 4124 },
        }),
      ],
    });
    await app.start();
    const crypto = app.resolve(CRYPTO_CAPABILITY);
    operations = {
      encrypt: () => crypto.encrypt(fixture.input, 'encryption', fixture.aad),
      decrypt: () => crypto.decrypt(fixture.envelope, 'encryption', fixture.aad),
      hmac: () => crypto.hmac(fixture.input, 'hmac'),
      verifyMac: () => crypto.verifyMac(fixture.input, fixture.mac, 'hmac'),
      signEd25519: () => crypto.sign(fixture.input, 'ed'),
      verifyEd25519: () =>
        crypto.verifySignature(fixture.input, fixture.edSignature, fixture.edPublicKey),
      signP256: () => crypto.sign(fixture.input, 'ec'),
      verifyP256: () =>
        crypto.verifySignature(fixture.input, fixture.ecSignature, fixture.ecPublicKey),
    };
  }
  function validate(name, result) {
    if (name === 'encrypt') {
      assert.equal(result.version, 1);
      assert.equal(result.algorithm, 'AES-256-GCM');
      assert.equal(result.ciphertext.length, fixture.input.length);
      assert.equal(result.nonce.length, 12);
      assert.equal(result.tag.length, 16);
      for (const key of ['nonce', 'ciphertext', 'tag']) {
        remember(result[key]);
        result[key].fill(0);
      }
    } else if (name === 'decrypt') {
      assert.deepEqual(Buffer.from(result), fixture.input);
      remember(result);
      result.fill(0);
    } else if (name === 'hmac') {
      assert.deepEqual(Buffer.from(result), fixture.mac);
      remember(result);
      result.fill(0);
    } else if (name.startsWith('sign')) {
      assert.equal(result.length, 64);
      const ed = name === 'signEd25519';
      assert.equal(
        verify(
          ed ? null : 'sha256',
          fixture.input,
          {
            key: ed ? fixture.edPublicKey : fixture.ecPublicKey,
            format: 'der',
            type: 'spki',
            dsaEncoding: 'ieee-p1363',
          },
          result,
        ),
        true,
      );
      remember(result);
      result.fill(0);
    } else assert.equal(result, true);
  }
  const records = [];
  for (const name of scenarios) {
    stage = name;
    const work = () =>
      enabled
        ? telemetry.measure('crypto.' + name, operations[name], {
            attributes: { operation: 'crypto.' + name },
          })
        : operations[name]();
    for (let index = 0; index < 5; index++) validate(name, await work());
    const latencies = [],
      pending = [];
    let inFlight = 0,
      errors = 0,
      saturationDrops = 0,
      schedulingDrops = 0,
      maximumOfferLagMs = 0;
    const started = performance.now(),
      interval = 20;
    for (let offer = 0; offer < 50; offer++) {
      const target = started + offer * interval;
      if (target > performance.now()) await delay(target - performance.now());
      const lag = Math.max(0, performance.now() - target);
      maximumOfferLagMs = Math.max(maximumOfferLagMs, lag);
      if (lag > interval) {
        schedulingDrops++;
        continue;
      }
      if (inFlight) {
        saturationDrops++;
        continue;
      }
      inFlight++;
      const at = performance.now();
      pending.push(
        Promise.resolve()
          .then(work)
          .then((result) => {
            const elapsed = performance.now() - at;
            validate(name, result);
            latencies.push(elapsed);
          })
          .catch(() => {
            errors++;
          })
          .finally(() => {
            inFlight--;
          }),
      );
    }
    const end = started + 50 * interval;
    if (end > performance.now()) await delay(end - performance.now());
    await Promise.all(pending);
    const windowMs = performance.now() - started;
    const ordered = [...latencies].sort((a, b) => a - b);
    records.push({
      scenarioId: 'crypto.' + name,
      mode: options.mode,
      inputBytes: fixture.input.length,
      warmupOperations: 5,
      offeredOperations: 50,
      completedOperations: latencies.length,
      errors,
      saturationDrops,
      schedulingDrops,
      maximumOfferLagMs,
      offeredRatePerSecond: 50,
      concurrency: 1,
      elapsedMs: windowMs,
      achievedOpsPerSecond: latencies.length / (windowMs / 1000),
      inputBytesPerSecond: (latencies.length * fixture.input.length) / (windowMs / 1000),
      runIterationCount: 1,
      confidenceInterval95: null,
      latencyMs: {
        samples: latencies,
        p50: ordered.length ? quantile(ordered, 0.5) : null,
        p95: ordered.length ? quantile(ordered, 0.95) : null,
        p99: ordered.length ? quantile(ordered, 0.99) : null,
        max: ordered.at(-1) ?? null,
      },
    });
  }
  stage = 'flush';
  await telemetry.flush();
  await app?.stop();
  await telemetry.close();
  await new Promise((resolve) => setImmediate(resolve));
  const current = process.memoryUsage();
  peakRss = Math.max(peakRss, current.rss);
  peakHeap = Math.max(peakHeap, current.heapUsed);
  const stats = telemetry.stats(),
    elu = performance.eventLoopUtilization(eluBefore);
  const eventLoopDelayMs = loop.count
    ? { mean: loop.mean / 1e6, max: loop.max / 1e6, p95: loop.percentile(95) / 1e6 }
    : null;
  process.send({
    type: 'result',
    fingerprints: [...sensitive],
    report: {
      mode: options.mode,
      records,
      node: process.version,
      openssl: process.versions.openssl,
      fips: getFips(),
      elapsedMs: performance.now() - elapsedStart,
      cpuDeltaMicros: process.cpuUsage(cpuBefore),
      memory: {
        peakRssBytes: peakRss,
        peakHeapBytes: peakHeap,
        finalRssBytes: current.rss,
        finalHeapBytes: current.heapUsed,
        sampleIntervalMs: 10,
      },
      gc: { observedCount: gcCount, observedDurationMs: gcDurationMs },
      eventLoopDelayMs,
      eventLoopUtilization: elu,
      providerReads,
      telemetry: stats,
    },
  });
} catch {
  process.send({ type: 'failed', stage });
  process.exitCode = 1;
} finally {
  clearInterval(memory);
  loop.disable();
  observer.disconnect();
  try {
    await app?.stop();
  } catch {
    process.exitCode = 1;
  }
  try {
    await telemetry?.close();
  } catch {
    process.exitCode = 1;
  }
  for (const value of fixture.values.values()) value.bytes.fill(0);
  fixture.input.fill(0);
  fixture.aad.fill(0);
  fixture.mac.fill(0);
  fixture.edSignature.fill(0);
  fixture.ecSignature.fill(0);
  if (process.connected) process.disconnect();
}
