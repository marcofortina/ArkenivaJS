// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { getFips } from 'node:crypto';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { setInterval, clearInterval, setImmediate } from 'node:timers';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import { apiKeyPlugin, APIKEY_CAPABILITY } from '@arkenivajs/security-apikey';
import { loggingPlugin } from '@arkenivajs/logging';
import { createTelemetry } from '@arkenivajs/telemetry';
import { directApiKeyVerifier } from './apikey-native.mjs';
import { rememberSensitiveValues } from './mfa-privacy.mjs';
import { quantile } from './http-analysis.mjs';

const options = JSON.parse(process.env.ARKENIVA_APIKEY_BENCH_WORKER ?? '{}');
assert.ok(process.send && ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].includes(options.mode));
const initialized = new Promise((resolve) =>
  process.once('message', (message) => {
    assert.equal(message.type, 'initialize');
    resolve(message.fixture);
  }),
);
process.send({ type: 'ready' });
const fixture = await initialized,
  sensitive = new Set();
const remember = (value) => rememberSensitiveValues(value, sensitive);
remember(fixture.token);
remember(fixture.token.split('.'));
remember(fixture.subject);
remember(fixture.context);
const enabled = ['STANDARD', 'DETAILED'].includes(options.mode),
  detailed = options.mode === 'DETAILED';
const pending = new Map();
let sequence = 0,
  telemetry,
  app,
  stage = 'setup',
  providerCalls = 0;
process.on('message', (message) => {
  if (message.type !== 'rpc-result') return;
  const current = pending.get(message.id);
  if (!current) return;
  pending.delete(message.id);
  current.cleanup();
  if (message.failed) current.reject(new Error('Disposable credential provider failed'));
  else {
    remember(message.result);
    current.resolve(message.result);
  }
});
function request(method, args, operation = {}) {
  const work = () =>
    new Promise((resolve, reject) => {
      assert.ok(pending.size < 1);
      assert.ok(!operation.signal?.aborted);
      const timeoutMs = operation.timeoutMs ?? 5000;
      assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000);
      const id = ++sequence;
      const finish = () => {
        if (!pending.delete(id)) return;
        cleanup();
        if (process.connected) process.send({ type: 'cancel', id });
        reject(new Error('Disposable credential provider interrupted'));
      };
      const timer = setTimeout(finish, timeoutMs),
        cleanup = () => {
          clearTimeout(timer);
          operation.signal?.removeEventListener('abort', finish);
        };
      pending.set(id, { resolve, reject, cleanup });
      operation.signal?.addEventListener('abort', finish, { once: true });
      if (method === 'authority.require') {
        remember(args[1]);
        remember(args[2]);
      } else if (method.startsWith('hmac.')) {
        remember(args[1]);
        if (method === 'hmac.verify') remember(args[2]);
      } else remember(args);
      providerCalls++;
      process.send({ type: 'rpc', id, method, args, timeoutMs });
    });
  return detailed ? telemetry.withSpan('apikey.provider.' + method, work) : work();
}
const cpuBefore = process.cpuUsage(),
  elapsedStart = performance.now(),
  eluBefore = performance.eventLoopUtilization();
let peakRss = process.memoryUsage().rss,
  peakHeap = process.memoryUsage().heapUsed,
  gcCount = 0,
  gcDurationMs = 0;
const memory = setInterval(() => {
    const value = process.memoryUsage();
    peakRss = Math.max(peakRss, value.rss);
    peakHeap = Math.max(peakHeap, value.heapUsed);
  }, 10),
  loop = monitorEventLoopDelay({ resolution: 10 });
loop.enable();
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    gcCount++;
    gcDurationMs += entry.duration;
  }
});
observer.observe({ entryTypes: ['gc'] });
try {
  const service = { name: 'apikey-benchmark', version: '1.0.0', environment: 'test' };
  telemetry = createTelemetry({
    service,
    mode: enabled ? (detailed ? 'detailed' : 'standard') : 'off',
    samplingRatio: detailed ? 1 : 0.1,
    ...(enabled ? { endpoint: options.collector, allowInsecureLoopback: true } : {}),
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
    spanQueueCapacity: 2048,
  });
  const settings = {
    store: {
      securityLevel: 'test-only',
      operationTimeoutMs: 5000,
      store: {
        read: (namespace, id, op) => request('store.read', [namespace, id], op),
        claimOnce: (namespace, digest, expiresAt, op) =>
          request('store.claimOnce', [namespace, digest, expiresAt], op),
        compareAndSet: (namespace, id, version, next, op) =>
          request('store.compareAndSet', [namespace, id, version, next], op),
        atomicBatch: (mutations, op) => request('store.atomicBatch', [mutations], op),
        listByOwner: (namespace, owner, limit, op) =>
          request('store.listByOwner', [namespace, owner, limit], op),
        bumpOwnerEpoch: (namespace, owner, op) =>
          request('store.bumpOwnerEpoch', [namespace, owner], op),
        currentOwnerEpoch: (namespace, owner, op) =>
          request('store.currentOwnerEpoch', [namespace, owner], op),
      },
    },
    hmac: {
      algorithm: 'HMAC-SHA256',
      usage: 'test-only',
      digest: (domain, parts, ref, op) => request('hmac.digest', [domain, parts, ref], op),
      verify: (domain, parts, expected, ref, op) =>
        request('hmac.verify', [domain, parts, expected, ref], op),
    },
    hmacKeyRef: fixture.keyRef,
    authority: {
      require: (action, subject, context, op) =>
        request('authority.require', [action, subject, context], op),
    },
    maxActiveKeysPerSubject: 4,
    maxVerifyAttemptsPerMinute: 10000,
  };
  let verify;
  if (options.mode === 'BASELINE')
    verify = await directApiKeyVerifier({ ...settings, store: settings.store.store });
  else {
    const observer = {
      id: 'apikey-benchmark-telemetry',
      version: '1.0.0',
      capabilities: new Set(['telemetry']),
      init(context) {
        context.provide(COMPONENTS.telemetry, telemetry);
      },
      close() {},
    };
    app = await createApplication({
      service,
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), apiKeyPlugin(settings), ...(enabled ? [observer] : [])],
    });
    await app.start();
    verify = app.resolve(APIKEY_CAPABILITY).verify;
  }
  const validate = (result) => {
    assert.equal(result.keyId, fixture.keyId);
    assert.equal(result.subject.issuer, fixture.subject.issuer);
    assert.equal(result.subject.subject, fixture.subject.subject);
    assert.equal(result.subject.tenant?.tenantId, fixture.subject.tenant?.tenantId);
    assert.deepEqual(result.scopes, ['orders.read']);
  };
  stage = 'verify';
  for (let count = 0; count < 5; count++) validate(await verify(fixture.token, fixture.context));
  const latencies = [],
    tasks = [],
    errorClasses = {};
  let inFlight = 0,
    errors = 0,
    saturationDrops = 0,
    schedulingDrops = 0,
    maximumOfferLagMs = 0;
  const start = performance.now(),
    interval = 40;
  for (let offer = 0; offer < 50; offer++) {
    const target = start + offer * interval;
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
    tasks.push(
      Promise.resolve()
        .then(() => verify(fixture.token, fixture.context))
        .then((result) => {
          const elapsed = performance.now() - at;
          validate(result);
          latencies.push(elapsed);
        })
        .catch((error) => {
          errors++;
          const category = [
            'EK_APIKEY_STORE',
            'EK_APIKEY_INVALID',
            'EK_TIMEOUT',
            'EK_ABORTED',
            'EK_BACKEND_UNAVAILABLE',
            'ERR_ASSERTION',
          ].includes(error?.code)
            ? error.code
            : 'other';
          errorClasses[category] = (errorClasses[category] ?? 0) + 1;
        })
        .finally(() => {
          inFlight--;
        }),
    );
  }
  if (start + 50 * interval > performance.now())
    await delay(start + 50 * interval - performance.now());
  await Promise.all(tasks);
  const windowMs = performance.now() - start,
    ordered = [...latencies].sort((a, b) => a - b);
  stage = 'flush';
  await telemetry.flush();
  await app?.stop();
  await telemetry.close();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(pending.size, 0);
  const final = process.memoryUsage();
  peakRss = Math.max(peakRss, final.rss);
  peakHeap = Math.max(peakHeap, final.heapUsed);
  process.send({
    type: 'result',
    fingerprints: [...sensitive],
    report: {
      mode: options.mode,
      node: process.version,
      openssl: process.versions.openssl,
      fips: getFips(),
      providerCalls,
      record: {
        scenarioId: 'apikey.verify',
        mode: options.mode,
        warmupOperations: 5,
        offeredOperations: 50,
        completedOperations: latencies.length,
        errors,
        errorClasses,
        saturationDrops,
        schedulingDrops,
        maximumOfferLagMs,
        offeredRatePerSecond: 25,
        concurrency: 1,
        elapsedMs: windowMs,
        achievedOpsPerSecond: latencies.length / (windowMs / 1000),
        inputBytes:
          Buffer.byteLength(fixture.token) + Buffer.byteLength(JSON.stringify(fixture.context)),
        runIterationCount: 1,
        confidenceInterval95: null,
        latencyMs: {
          samples: latencies,
          p50: ordered.length ? quantile(ordered, 0.5) : null,
          p95: ordered.length ? quantile(ordered, 0.95) : null,
          p99: ordered.length ? quantile(ordered, 0.99) : null,
          max: ordered.at(-1) ?? null,
        },
      },
      elapsedMs: performance.now() - elapsedStart,
      cpuDeltaMicros: process.cpuUsage(cpuBefore),
      memory: {
        peakRssBytes: peakRss,
        peakHeapBytes: peakHeap,
        finalRssBytes: final.rss,
        finalHeapBytes: final.heapUsed,
        sampleIntervalMs: 10,
      },
      gc: { observedCount: gcCount, observedDurationMs: gcDurationMs },
      eventLoopUtilization: performance.eventLoopUtilization(eluBefore),
      eventLoopDelayMs: loop.count
        ? { mean: loop.mean / 1e6, max: loop.max / 1e6, p95: loop.percentile(95) / 1e6 }
        : null,
      telemetry: telemetry.stats(),
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
    await telemetry?.close();
  } catch {
    process.exitCode = 1;
  }
  for (const current of pending.values()) {
    current.cleanup();
    current.reject(new Error('Credential benchmark closed'));
  }
  pending.clear();
  if (process.connected) process.disconnect();
}
