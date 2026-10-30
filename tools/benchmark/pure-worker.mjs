// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { setInterval, clearInterval, setImmediate } from 'node:timers';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { quantile } from './http-analysis.mjs';

export function runPureWorker(adapter) {
  process.once('message', (input) => {
    void run(input, adapter).then(
      (result) => {
        process.send({ ok: true, result }, () => process.disconnect());
      },
      () => {
        process.exitCode = 1;
        process.send({ ok: false }, () => process.disconnect());
      },
    );
  });
}

async function run({ mode, fixture, measure, endpoint }, adapter) {
  assert.ok(['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].includes(mode));
  assert.equal(typeof measure, 'boolean');
  let app, telemetry, service, disposeFramework;
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  const loop = monitorEventLoopDelay({ resolution: 10 });
  let gcCount = 0,
    gcDurationMs = 0;
  const observer = new PerformanceObserver((entries) => {
    for (const entry of entries.getEntries()) {
      gcCount++;
      gcDurationMs += entry.duration;
    }
  });
  try {
    if (mode === 'BASELINE') service = await adapter.native(fixture);
    else {
      const { createApplication } = await import('@arkenivajs/core'),
        { loggingPlugin } = await import('@arkenivajs/logging'),
        {
          plugin,
          key,
          loggingOptions,
          plugins: dependencies = [],
          http,
          databases,
          security,
          metering,
          configure,
          dispose,
          telemetryOptions,
        } = await adapter.framework(fixture, mode);
      disposeFramework = dispose;
      const plugins = [
        loggingPlugin({ destination: sink, ...loggingOptions }),
        ...dependencies,
        ...(plugin ? [plugin] : []),
      ];
      if (mode === 'STANDARD' || mode === 'DETAILED') {
        const { telemetryPlugin } = await import('@arkenivajs/telemetry');
        plugins.push(
          telemetryPlugin({
            ...telemetryOptions,
            endpoint,
            allowInsecureLoopback: true,
            exportIntervalMs: 60000,
            exportTimeoutMs: 1000,
          }),
        );
      }
      app = await createApplication({
        service: { name: adapter.name + '-comparison', version: '1.0.0', environment: 'test' },
        ...(http ? { http } : {}),
        ...(databases ? { databases } : {}),
        ...(security ? { security } : {}),
        ...(metering ? { metering } : {}),
        ...(mode === 'STANDARD' || mode === 'DETAILED'
          ? { telemetry: { mode: mode.toLowerCase(), samplingRatio: 1 } }
          : {}),
        plugins,
      });
      await configure?.(app);
      await app.start();
      service = app.resolve(key);
      if (mode === 'STANDARD' || mode === 'DETAILED') telemetry = app.telemetry;
    }
    const verification = await adapter.verify(service, fixture),
      records = [];
    const before = process.memoryUsage(),
      cpu = process.cpuUsage(),
      started = performance.now(),
      elu = performance.eventLoopUtilization();
    let peakRss = before.rss,
      peakHeap = before.heapUsed;
    const sampleMemory = () => {
      const value = process.memoryUsage();
      peakRss = Math.max(peakRss, value.rss);
      peakHeap = Math.max(peakHeap, value.heapUsed);
    };
    const interval = setInterval(sampleMemory, 10);
    loop.enable();
    observer.observe({ entryTypes: ['gc'] });
    try {
      if (measure) {
        const { Bench } = await import('tinybench');
        const iterations = adapter.iterations ?? 10000,
          warmupIterations = adapter.warmupIterations ?? 1000;
        assert.ok(Number.isSafeInteger(iterations) && iterations >= 10 && iterations <= 10000);
        assert.ok(
          Number.isSafeInteger(warmupIterations) &&
            warmupIterations >= 0 &&
            warmupIterations <= 1000,
        );
        for (const [operation, work] of Object.entries(adapter.workload(service, fixture))) {
          let last;
          const bench = new Bench({
            time: 0,
            iterations,
            warmupTime: 0,
            warmupIterations,
            retainSamples: true,
            throws: true,
          });
          bench.add(
            operation,
            adapter.asynchronous
              ? async () => {
                  last = await work();
                }
              : () => {
                  last = work();
                },
          );
          await bench.run();
          const result = bench.tasks[0].result;
          assert.equal(result.state, 'completed');
          const samples = result.latency.samples;
          assert.ok(samples.length >= iterations);
          if (adapter.retainRawSamples === true)
            assert.ok(
              samples.length <= 10000 &&
                samples.every((sample) => Number.isFinite(sample) && sample >= 0),
              'Raw latency samples must be finite, nonnegative and bounded',
            );
          records.push({
            operation,
            sampleCount: samples.length,
            ...(adapter.retainRawSamples === true
              ? { rawLatency: { unit: 'milliseconds', values: [...samples] } }
              : {}),
            warmupIterations,
            latencyNanoseconds: {
              p50: quantile(samples, 0.5) * 1e6,
              p95: quantile(samples, 0.95) * 1e6,
              p99: quantile(samples, 0.99) * 1e6,
            },
            throughputOpsPerSecond: result.throughput.mean,
            lastResultType: typeof last,
          });
        }
      }
      await new Promise((resolve) => setImmediate(resolve));
      sampleMemory();
    } finally {
      clearInterval(interval);
      loop.disable();
      observer.disconnect();
    }
    const resource = measure
      ? {
          elapsedMs: performance.now() - started,
          cpuDeltaMicros: process.cpuUsage(cpu),
          memoryBytes: { rssBefore: before.rss, peakRss, heapBefore: before.heapUsed, peakHeap },
          eventLoopUtilization: performance.eventLoopUtilization(elu).utilization,
          eventLoopDelayMs: Number.isFinite(loop.mean) ? loop.mean / 1e6 : null,
          gcCount,
          gcDurationMs,
        }
      : null;
    const completion = await adapter.complete?.(service, { fixture, measure, records });
    await telemetry?.flush();
    const quality = telemetry?.stats() ?? null;
    if (quality)
      for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
        assert.equal(quality[key], 0);
    return {
      mode,
      nodeVersion: process.version,
      measured: measure,
      releaseGate: false,
      verification,
      ...(completion === undefined ? {} : { completion }),
      records,
      resource,
      quality,
    };
  } finally {
    await app?.stop();
    await disposeFramework?.();
    if (mode === 'BASELINE') await adapter.close?.(service);
    sink.destroy();
  }
}
