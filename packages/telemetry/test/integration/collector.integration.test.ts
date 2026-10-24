import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createTelemetry } from '@arkenivajs/telemetry';

test('EK-OTEL-001 actual collector accepts SDK traces and metrics with trusted workload metadata', async () => {
  const endpoint = process.env.ARKENIVAJS_OTLP_ENDPOINT;
  const evidencePath = process.env.ARKENIVAJS_OTLP_EVIDENCE_PATH;
  assert.ok(endpoint, 'ARKENIVAJS_OTLP_ENDPOINT must select the disposable collector');
  assert.ok(
    evidencePath && isAbsolute(evidencePath),
    'ARKENIVAJS_OTLP_EVIDENCE_PATH must be an absolute path outside the checkout',
  );
  const checkout = fileURLToPath(new URL('../../../../../', import.meta.url));
  const location = relative(checkout, resolve(evidencePath));
  assert.ok(
    location === '..' || location.startsWith('..' + sep) || isAbsolute(location),
    'Collector evidence must stay outside the checkout',
  );
  const began = performance.now();
  while (true) {
    try {
      const ready = await fetch(endpoint, { signal: AbortSignal.timeout(500) });
      await ready.arrayBuffer();
      break;
    } catch (error) {
      if (performance.now() - began > 10000) throw error;
      await delay(100);
    }
  }
  const instanceId = randomUUID();
  const telemetry = createTelemetry({
    service: { name: 'collector-integration', version: '1.0.0', environment: 'test' },
    mode: 'detailed',
    endpoint,
    allowInsecureLoopback: true,
    instanceId,
    workload: {
      namespace: 'integration',
      pod: 'telemetry-pod',
      container: 'application',
      node: 'vm-runner',
    },
    exportTimeoutMs: 3000,
    exportIntervalMs: 10_000,
  });
  let traceId: string | undefined;
  try {
    assert.equal(
      await telemetry.measure('integration.collector', () => {
        traceId = telemetry.currentTraceId();
        return 42;
      }),
      42,
    );
    telemetry.addCounter('integration.operations', 1, { method: 'GET' });
    telemetry.setGauge('arkenivajs.process.memory.rss', process.memoryUsage().rss, {
      service: 'collector-integration',
    });
    await telemetry.flush({ timeoutMs: 5000 });
    assert.equal(telemetry.stats().exportFailures, 0);
    assert.equal(telemetry.stats().pendingSpans, 0);
    assert.match(traceId!, /^[0-9a-f]{32}$/);
    await writeFile(
      evidencePath,
      JSON.stringify({
        instanceId,
        traceId,
        service: 'collector-integration',
        version: '1.0.0',
        environment: 'test',
        namespace: 'integration',
        pod: 'telemetry-pod',
        container: 'application',
        node: 'vm-runner',
        operation: 'integration.collector',
        metric: 'integration.operations',
      }) + '\n',
      { mode: 0o600 },
    );
  } finally {
    await telemetry.close({ timeoutMs: 5000 });
  }
});
