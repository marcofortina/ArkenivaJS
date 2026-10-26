// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { setInterval, clearInterval } from 'node:timers';
import { createTotpService } from '@arkenivajs/security-totp';
import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import { createTelemetry } from '@arkenivajs/telemetry';
import { createMeter, createJsonlExporter, parseMeteringEvent } from '@arkenivajs/metering';
import { generate } from 'otplib';
import { totpServiceFixture } from '../../examples/postgres/dist-test/integration/totp-service-fixture.js';
import { webAuthnServiceFixture } from '../../examples/postgres/dist-test/integration/webauthn-service-fixture.js';
import { nativeTotpVerification, nativeWebAuthnVerification } from './mfa-native.mjs';
import { quantile } from './http-analysis.mjs';
import { fingerprint, countSensitiveValues } from './mfa-privacy.mjs';

const options = JSON.parse(process.env.ARKENIVA_MFA_WORKER_SETTINGS ?? '{}');
assert.ok(process.send && ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].includes(options.mode));
assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
const active = new Map();
let sequence = 0;
function request(kind, body) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      active.delete(id);
      reject(new Error('Benchmark browser request timed out'));
    }, 10000);
    active.set(id, { resolve, reject, timer });
    process.send({ kind, id, body });
  });
}
process.on('message', (message) => {
  const current = active.get(message?.id);
  if (!current) return;
  active.delete(message.id);
  clearTimeout(current.timer);
  if (message.failed) current.reject(new Error('Benchmark browser request failed'));
  else current.resolve(message.result);
});
const sensitive = new Set();
const remember = (value) => {
  sensitive.add(fingerprint(value));
  return value;
};
const service = { name: 'mfa-benchmark', version: '1.0.0', environment: 'test' };
const enabled = options.mode === 'STANDARD' || options.mode === 'DETAILED';
const records = [];
let totp, webauthn, telemetry, meter;
let stage = 'setup';
try {
  totp = await totpServiceFixture();
  webauthn = await webAuthnServiceFixture(options.origin);
  let totpOwner = await totp.subject({ acr: 'urn:fixture:reauthenticated' });
  totp.approveReauthentication(totpOwner, 'enroll');
  const enrollment = await totp.service.beginEnrollment(totpOwner);
  remember(enrollment.otpauthUri);
  const seed = remember(new URL(enrollment.otpauthUri).searchParams.get('secret'));
  await totp.service.confirmEnrollment(
    totpOwner,
    enrollment.enrollmentId,
    remember(await generate({ secret: seed, epoch: Math.floor(totp.clock() / 1000) })),
  );
  let webOwner = await webauthn.subject({ acr: 'urn:fixture:reauthenticated' });
  webauthn.approveEnrollment(webOwner);
  const ceremony = await webauthn.service.beginRegistration(webOwner);
  const browserRegistration = await request('registration', ceremony);
  const registered = await webauthn.service.finishRegistration(
    webOwner,
    ceremony.ceremonyId,
    browserRegistration,
  );
  remember(registered.credentialId);
  const account = await webauthn.state.getCredential(
    registered.credentialId,
    webauthn.settings.rpId,
  );
  remember(account.userHandle);
  await request('counterless', { credentialId: registered.credentialId });
  // Owned fixture bootstrap models a device whose lifetime counter is absent; production counters never reset.
  await webauthn.app.sql.execute('main', {
    text: `UPDATE ${webauthn.schema}.mfa_webauthn_credentials SET counter=0,state_version=gen_random_uuid() WHERE credential_id=:id`,
    bindings: { id: registered.credentialId },
  });
  const providers = [totp.settings, webauthn.settings].flatMap((settings) =>
    ['stateStore', 'rateLimitStore', 'evidenceStore', 'subjectAuthority', 'secretProtector']
      .filter((name) => settings[name])
      .flatMap((name) =>
        Object.entries(settings[name])
          .filter(([, value]) => typeof value === 'function')
          .map(([method]) => name + '.' + method),
      ),
  );
  telemetry = createTelemetry({
    service,
    mode: enabled ? (options.mode === 'DETAILED' ? 'detailed' : 'standard') : 'off',
    samplingRatio: options.mode === 'DETAILED' ? 1 : 0.1,
    ...(enabled ? { endpoint: options.collector, allowInsecureLoopback: true } : {}),
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
    spanQueueCapacity: 2048,
    labelValues: {
      operation: [...new Set(['totp.verify', 'webauthn.verify', 'challenge.store', ...providers])],
    },
  });
  let exportAttempts = 0,
    exporterRetries = 0;
  const exportedBatches = new Set();
  const fileExporter = enabled
    ? await createJsonlExporter({
        workspace: options.directory,
        path: 'metering.jsonl',
        maxFileBytes: 134217728,
      })
    : undefined;
  const exporter = fileExporter
    ? {
        kind: fileExporter.kind,
        async export(events, operation) {
          const batch = fingerprint(JSON.stringify(events.map((event) => event.eventId)));
          if (exportedBatches.has(batch)) exporterRetries++;
          else {
            assert.ok(exportedBatches.size < 20000, 'Benchmark batch observation capacity reached');
            exportedBatches.add(batch);
          }
          exportAttempts++;
          return fileExporter.export(events, operation);
        },
        close: (operation) => fileExporter.close(operation),
      }
    : undefined;
  meter = createMeter({
    service,
    auth: {
      isVerifiedTenant: (value) =>
        totp.auth.isVerifiedTenant(value) || webauthn.auth.isVerifiedTenant(value),
    },
    enabled,
    ...(exporter ? { exporter } : {}),
    telemetry,
    currentTraceId: () => telemetry.currentTraceId(),
    usageDefinitions: { 'mfa.operations': 'operations' },
    queueCapacity: 2048,
  });
  const instrument = (settings) => {
    if (options.mode !== 'DETAILED') return settings;
    const result = { ...settings };
    for (const name of [
      'stateStore',
      'rateLimitStore',
      'evidenceStore',
      'subjectAuthority',
      'secretProtector',
    ]) {
      if (!settings[name]) continue;
      result[name] = Object.fromEntries(
        Object.entries(settings[name]).map(([method, value]) => [
          method,
          typeof value === 'function'
            ? (...args) =>
                telemetry.withSpan('mfa.provider', () => value.apply(settings[name], args), {
                  attributes: { operation: name + '.' + method },
                })
            : value,
        ]),
      );
    }
    return result;
  };
  const totpSettings = instrument(totp.settings),
    webSettings = instrument(webauthn.settings);
  const totpService = createTotpService(totpSettings),
    webService = createWebAuthnService(webSettings);
  const totpReference = { ...totp, settings: totpSettings },
    webReference = { ...webauthn, settings: webSettings };
  let enqueueSamples;
  const observe = async (operation, owner, fn) => {
    const work = async () => {
      const result = await fn();
      if (typeof result?.evidenceId === 'string') remember(result.evidenceId);
      return result;
    };
    if (!enabled) return work();
    return telemetry.withSpan(
      'mfa.operation',
      async () => {
        const session = meter.start({ tenant: owner.tenant, operation });
        return meter.run(session, async () => {
          let status = 'error';
          try {
            session.recordOperation('mfa.operations');
            const result = await work();
            status = 'ok';
            return result;
          } finally {
            const began = performance.now();
            const receipt = session.end(status);
            enqueueSamples?.push(performance.now() - began);
            assert.equal(receipt.accepted, true, 'The observed metering event must be enqueued');
          }
        });
      },
      { attributes: { operation } },
    );
  };
  const scenarios = [
    {
      id: 'totp.verify',
      async prepare(index) {
        totp.setTime(totp.clock() + 30000);
        if (index % 5 === 0) totpOwner = await totp.subject();
        const code = remember(
          await generate({ secret: seed, epoch: Math.floor(totp.clock() / 1000) }),
        );
        return {
          owner: totpOwner,
          bytes: 6,
          rejectForged: () =>
            options.mode === 'BASELINE'
              ? nativeTotpVerification(totpReference, { ...totpOwner }, code)
              : totpService.verify({ ...totpOwner }, code),
          call: () =>
            options.mode === 'BASELINE'
              ? nativeTotpVerification(totpReference, totpOwner, code)
              : totpService.verify(totpOwner, code),
        };
      },
    },
    {
      id: 'webauthn.verify',
      async prepare(index) {
        if (index % 5 === 0) {
          webauthn.setTime(webauthn.clock() + 60000);
          webOwner = await webauthn.subject();
        }
        const ceremony = await webauthn.service.beginAuthentication(webOwner);
        remember(ceremony.ceremonyId);
        remember(ceremony.optionsJSON.challenge);
        const response = await request('authentication', ceremony);
        remember(response.response.signature);
        remember(response.response.clientDataJSON);
        remember(response.response.authenticatorData);
        return {
          owner: webOwner,
          bytes: Buffer.byteLength(JSON.stringify(response)),
          rejectForged: () =>
            options.mode === 'BASELINE'
              ? nativeWebAuthnVerification(webReference, { ...webOwner }, ceremony, response)
              : webService.finishAuthentication({ ...webOwner }, ceremony.ceremonyId, response),
          call: () =>
            options.mode === 'BASELINE'
              ? nativeWebAuthnVerification(webReference, webOwner, ceremony, response)
              : webService.finishAuthentication(webOwner, ceremony.ceremonyId, response),
        };
      },
    },
    {
      id: 'challenge.store',
      async prepare() {
        const now = webauthn.clock(),
          id = remember(randomBytes(32).toString('base64url'));
        const record = {
          id,
          purpose: 'webauthn-authenticate',
          issuer: webOwner.issuer,
          subject: webOwner.subject,
          tenantId: webOwner.tenant.tenantId,
          primarySessionId: webOwner.primarySessionId,
          rpId: webauthn.settings.rpId,
          challengeDigest: fingerprint(randomBytes(32)),
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(now + 300000).toISOString(),
        };
        const binding = {
          id,
          purpose: record.purpose,
          issuer: record.issuer,
          subject: record.subject,
          tenantId: record.tenantId,
          primarySessionId: record.primarySessionId,
          rpId: record.rpId,
          now: new Date(now).toISOString(),
        };
        return {
          owner: webOwner,
          bytes: Buffer.byteLength(JSON.stringify(record)),
          claimAgain: () => webSettings.stateStore.claimChallenge(binding),
          call: async () => {
            await webSettings.stateStore.createChallenge(record);
            const claimed = await webSettings.stateStore.claimChallenge(binding);
            assert.ok(claimed, 'The durable challenge must be claimed exactly once');
            return null;
          },
        };
      },
    },
  ];
  for (const scenario of scenarios) {
    stage = scenario.id;
    const preflight = await scenario.prepare(0);
    if (preflight.rejectForged) await assert.rejects(preflight.rejectForged());
    await observe(scenario.id, preflight.owner, preflight.call);
    if (preflight.claimAgain) assert.equal(await preflight.claimAgain(), null);
    else await assert.rejects(preflight.call());
    let index = 0;
    const warmupStarted = performance.now();
    do {
      const input = await scenario.prepare(index++);
      const due = warmupStarted + (index - 1) * 50;
      if (performance.now() < due) await delay(due - performance.now());
      await observe(scenario.id, input.owner, input.call);
    } while (options.full ? performance.now() - warmupStarted < 60000 : index < 2);
    await meter.flush();
    await telemetry.flush();
    const warmupElapsedMs = performance.now() - warmupStarted;
    const attemptsBefore = exportAttempts,
      retriesBefore = exporterRetries;
    const meterBefore = meter.stats(),
      telemetryBefore = telemetry.stats();
    const cpu = process.cpuUsage(),
      start = performance.now(),
      elu = performance.eventLoopUtilization();
    const loop = monitorEventLoopDelay({ resolution: 10 }),
      samples = [],
      memory = [],
      enqueue = [];
    let gcCount = 0,
      gcDurationMs = 0,
      bytes = 0,
      late = 0,
      errors = 0;
    const observer = new PerformanceObserver((list) => {
      for (const item of list.getEntries()) {
        gcCount++;
        gcDurationMs += item.duration;
      }
    });
    observer.observe({ entryTypes: ['gc'] });
    loop.enable();
    const sampler = setInterval(() => memory.push(process.memoryUsage()), 20);
    enqueueSamples = enqueue;
    let completed = 0;
    try {
      do {
        const due = start + (completed * 1000) / 20;
        const input = await scenario.prepare(index++);
        const wait = due - performance.now();
        if (wait > 0) await delay(wait);
        else if (-wait > 50) late++;
        const began = performance.now();
        try {
          await observe(scenario.id, input.owner, input.call);
        } catch {
          errors++;
        }
        samples.push(performance.now() - began);
        bytes += input.bytes;
        completed++;
      } while (options.full ? performance.now() - start < 180000 : completed < 20);
    } finally {
      enqueueSamples = undefined;
      clearInterval(sampler);
      loop.disable();
      observer.disconnect();
    }
    memory.push(process.memoryUsage());
    const elapsedMs = performance.now() - start,
      cpuDelta = process.cpuUsage(cpu),
      utilization = performance.eventLoopUtilization(elu);
    const flushStart = performance.now();
    await meter.flush();
    await telemetry.flush();
    const afterMeter = meter.stats(),
      afterTelemetry = telemetry.stats();
    const difference = (after, before) =>
      Object.fromEntries(Object.keys(after).map((key) => [key, after[key] - (before[key] ?? 0)]));
    const rss = memory.map((value) => value.rss),
      heap = memory.map((value) => value.heapUsed);
    records.push({
      scenarioId: scenario.id,
      mode: options.mode,
      measured: true,
      releaseGate: false,
      startedAt: new Date(performance.timeOrigin + start).toISOString(),
      sampleCount: completed,
      warmupCount: index - completed,
      warmupElapsedMs,
      runIterationCount: 1,
      latencyMs: {
        p50: quantile(samples, 0.5),
        p95: quantile(samples, 0.95),
        p99: quantile(samples, 0.99),
        max: Math.max(...samples),
      },
      rawLatencyMs: samples,
      throughputOpsPerSecond: completed / (elapsedMs / 1000),
      elapsedMs,
      loadProfile: {
        offeredOpsPerSecond: 20,
        concurrency: 1,
        latePreparations: late,
        applicationInputBytes: bytes,
      },
      errors,
      errorRate: errors / completed,
      cpuDeltaMicros: cpuDelta,
      cpuSecondsPer1000Operations: (cpuDelta.user + cpuDelta.system) / 1000 / completed,
      rssBytes: {
        mean: rss.reduce((a, b) => a + b) / rss.length,
        max: Math.max(...rss),
        samples: rss.length,
      },
      heapBytes: { mean: heap.reduce((a, b) => a + b) / heap.length, max: Math.max(...heap) },
      eventLoop: {
        utilization: utilization.utilization,
        delayMs: {
          p50: loop.percentile(50) / 1e6,
          p95: loop.percentile(95) / 1e6,
          p99: loop.percentile(99) / 1e6,
        },
      },
      gc: { count: gcCount, durationMs: gcDurationMs },
      exportFlushMs: performance.now() - flushStart,
      meter: difference(afterMeter, meterBefore),
      exporterAttempts: enabled ? exportAttempts - attemptsBefore : null,
      exporterRetries: enabled ? exporterRetries - retriesBefore : null,
      telemetry: difference(afterTelemetry, telemetryBefore),
      enqueueLatencyMs: enqueue.length
        ? {
            p50: quantile(enqueue, 0.5),
            p95: quantile(enqueue, 0.95),
            p99: quantile(enqueue, 0.99),
          }
        : null,
      pool: { totp: totp.app.sql.stats('main'), webauthn: webauthn.app.sql.stats('main') },
      measurementCoverage: {
        verificationLatencyExcludesInputPreparation: true,
        processCpuIncludesPreparationAndAsyncExport: true,
        quotaClock:
          'Trusted test clock advances between proofs/batches; throughput is not a production per-account quota',
        stateBaseline:
          scenario.id === 'challenge.store'
            ? 'Same shared state SPI in all modes; native SQL adapter overhead is measured separately'
            : 'Direct upstream verifier, equivalent valid-fixture lifecycle and identical backing SQL providers',
        enqueueLatency: enabled
          ? 'Observed synchronous MeterSession.end duration'
          : 'Disabled; no event enqueued',
        retries: 'Observed exporter batch attempts by opaque event-ID digest; no factor retry',
        dedicatedRunner: false,
      },
    });
    assert.equal(errors, 0, 'MFA benchmark operations must succeed');
    assert.equal(afterMeter.dropped, 0);
    assert.equal(afterMeter.failedExports, 0);
    assert.equal(afterTelemetry.droppedSpans, 0);
    assert.equal(afterTelemetry.droppedMetrics, 0);
    assert.equal(afterTelemetry.exportFailures, 0);
  }
  await meter.flush();
  await telemetry.flush();
  if (enabled) {
    const data = await readFile(join(options.directory, 'metering.jsonl'), 'utf8');
    const events = data
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    assert.equal(events.length, meter.stats().exported);
    assert.equal(
      countSensitiveValues(events, sensitive),
      0,
      'Metering must contain no factor or ceremony material',
    );
  }
  const privacy = await request('privacy', { fingerprints: [...sensitive] });
  assert.equal(privacy.leaks, 0, 'OTLP must contain no factor or ceremony material');
  const serverVersion = await webauthn.app.sql.queryOne('main', { text: 'SHOW server_version' });
  await writeFile(
    join(options.directory, 'results.json'),
    JSON.stringify(
      {
        mode: options.mode,
        records,
        environment: {
          postgres: serverVersion.server_version,
          clockEnvironment: 'test',
          browser: options.browser,
        },
        privacy,
        meter: meter.stats(),
        telemetry: telemetry.stats(),
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  );
  process.send({ kind: 'done', records: records.length });
} catch (error) {
  process.send?.({
    kind: 'failed',
    stage,
    frames: error instanceof Error ? error.stack?.split('\n').slice(1, 4) : [],
  });
  process.exitCode = 1;
} finally {
  for (const entry of active.values()) {
    clearTimeout(entry.timer);
    entry.reject(new Error('Benchmark worker closed'));
  }
  try {
    await meter?.close();
  } finally {
    try {
      await telemetry?.close();
    } finally {
      try {
        await totp?.close();
      } finally {
        await webauthn?.close();
      }
    }
  }
  process.disconnect();
}
