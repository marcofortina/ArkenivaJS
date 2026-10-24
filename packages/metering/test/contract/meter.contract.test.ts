import test from 'node:test';
import assert from 'node:assert/strict';
import type {
  UsageMeter,
  MeterSession,
  MeteringEvent,
  VerifiedTenantContext,
  TenantId,
} from '@arkenivajs/core';
import { createMeter } from '@arkenivajs/metering';
import type { ManagedUsageMeter, MeterExporter } from '@arkenivajs/metering';
const port = (meter: ManagedUsageMeter): UsageMeter => meter;
const session = (meter: UsageMeter, ...args: Parameters<UsageMeter['start']>): MeterSession =>
  meter.start(...args);
const event = (exporter: MeterExporter, events: readonly MeteringEvent[]) =>
  exporter.export(events, { timeoutMs: 1000 });
void [session, event];
test('Metering public port emits only the versioned technical envelope without identity or error internals', async () => {
  const tenant: VerifiedTenantContext = Object.freeze({
    tenantId: 'tenant-contract' as TenantId,
    identity: {
      subject: 'fake-private-subject',
      issuer: 'https://issuer.invalid',
      audience: ['api'],
      scopes: [],
      claims: { secret: 'fake-private-claim' },
    },
    verifiedAt: new Date().toISOString(),
    source: 'oidc',
  });
  const events: MeteringEvent[] = [];
  const managed = createMeter({
    service: { name: 'meter-contract', version: '1.0.0', environment: 'test' },
    auth: { isVerifiedTenant: (value): value is VerifiedTenantContext => value === tenant },
    exporter: {
      kind: 'jsonl',
      async export(batch) {
        events.push(...batch);
      },
      async close() {},
    },
  });
  const meter = port(managed);
  try {
    const primary = new Error('fake-private-error');
    await assert.rejects(
      meter.measure({ tenant, operation: 'contract' }, () => {
        throw primary;
      }),
      (error) => error === primary,
    );
    await meter.flush();
    assert.equal(events.length, 1);
    assert.deepEqual(
      Object.keys(events[0]!).sort(),
      [
        'schemaVersion',
        'eventId',
        'tenantId',
        'operationId',
        'service',
        'serviceVersion',
        'environment',
        'instanceId',
        'operation',
        'startedAt',
        'endedAt',
        'durationMs',
        'status',
        'counters',
        'quality',
      ].sort(),
    );
    assert.equal(events[0]!.schemaVersion, '1.0.0');
    assert.equal(events[0]!.status, 'error');
    assert.ok(!JSON.stringify(events).includes('fake-private'));
  } finally {
    await managed.close();
  }
});
