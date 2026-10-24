import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { createMeter, createHttpMeterExporter } from '@arkenivajs/metering';
import type { MeteringEvent, TenantId, VerifiedTenantContext } from '@arkenivajs/core';

/** A real collector must fsync accepted records; independent output checks prove that contract. */
test('EK-METER-001 actual durable collector accepts versioned tenant events and deduplicates stable retry IDs', async () => {
  const endpoint = process.env.ARKENIVAJS_METER_INTEGRATION_ENDPOINT;
  const credential = process.env.ARKENIVAJS_METER_COLLECTOR_AUTHORIZATION;
  const evidencePath = process.env.ARKENIVAJS_METER_EVIDENCE_PATH;
  assert.ok(
    endpoint && credential && evidencePath,
    'Real collector endpoint, disposable authorization and external evidence path are required',
  );
  const token = randomUUID();
  const contexts = new WeakSet<VerifiedTenantContext>();
  const tenant = (id: string): VerifiedTenantContext => {
    const value: VerifiedTenantContext = Object.freeze({
      tenantId: id as TenantId,
      identity: Object.freeze({
        subject: 'test-user',
        issuer: 'https://issuer.invalid',
        audience: ['meter-test'],
        scopes: [],
        claims: {},
      }),
      verifiedAt: new Date().toISOString(),
      source: 'oidc',
    });
    contexts.add(value);
    return value;
  };
  const a = tenant('tenant-A'),
    b = tenant('tenant-B');
  const retained: MeteringEvent[] = [];
  const exporter = createHttpMeterExporter({
    endpoint,
    environment: 'test',
    allowInsecureLoopback: true,
    authorization: () => credential,
  });
  const meter = createMeter({
    service: { name: 'meter-integration', version: '1.0.0', environment: 'test' },
    auth: {
      isVerifiedTenant: (value): value is VerifiedTenantContext =>
        !!value && typeof value === 'object' && contexts.has(value as VerifiedTenantContext),
    },
    batchSize: 2,
    exporter: {
      kind: 'http',
      async export(events, options) {
        retained.push(...events);
        await exporter.export(events, options);
        await exporter.export(events, options);
      },
      close: exporter.close,
    },
  });
  try {
    await Promise.all(
      [a, b].map((context) =>
        meter.measure(
          { tenant: context, operation: 'integration.' + token, requestId: randomUUID() },
          () => {
            meter.current()!.recordOperation('db.query', 2);
            return 'preserved';
          },
        ),
      ),
    );
    await meter.flush();
    assert.equal(retained.length, 2);
    assert.equal(meter.stats().exported, 2);
    assert.equal(meter.stats().failedExports, 0);
    await writeFile(
      evidencePath,
      JSON.stringify({
        operation: 'integration.' + token,
        eventIds: retained.map((event) => event.eventId),
        tenantIds: ['tenant-A', 'tenant-B'],
      }) + '\n',
      { mode: 0o600 },
    );
  } finally {
    await meter.close();
  }
});
