import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { createMeter } from '@arkenivajs/metering';
import type {
  MeteringEvent,
  VerifiedTenantContext,
  MeterSession,
  TenantId,
} from '@arkenivajs/core';

const tenant = Object.freeze({
  tenantId: 'tenant-property' as TenantId,
  identity: {
    subject: 'test',
    issuer: 'https://issuer.invalid',
    audience: ['api'],
    scopes: [],
    claims: {},
  },
  verifiedAt: new Date().toISOString(),
  source: 'oidc',
}) satisfies VerifiedTenantContext;
test('EK-METER-001 seeded queue pressure preserves unique immutable event IDs and exact enqueue/export/drop accounting', async () => {
  const allIds = new Set<string>();
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.integer({ min: 0, max: 3 }), { minLength: 10, maxLength: 100 }),
      async (actions) => {
        const events: MeteringEvent[] = [];
        const meter = createMeter({
          service: { name: 'meter-property', version: '1.0.0', environment: 'test' },
          auth: { isVerifiedTenant: (value): value is VerifiedTenantContext => value === tenant },
          queueCapacity: 5,
          maxActiveSessions: 100,
          flushIntervalMs: 60_000,
          exporter: {
            kind: 'jsonl',
            async export(batch) {
              events.push(...batch);
            },
            async close() {},
          },
        });
        const sessions: MeterSession[] = [];
        let accepted = 0,
          dropped = 0;
        try {
          for (const action of actions) {
            if (action === 0 || sessions.length === 0)
              sessions.push(meter.start({ tenant, operation: 'property' }));
            else if (action === 1) sessions.at(-1)!.recordOperation('db.query');
            else {
              const session = sessions.pop()!;
              const receipt = session.end(action === 2 ? 'ok' : 'error');
              if (receipt.accepted) accepted++;
              else dropped++;
              assert.throws(() => session.end());
            }
            assert.ok(meter.snapshot().queueDepth <= 5);
            assert.equal(meter.snapshot().activeSessions, sessions.length);
          }
          for (const session of sessions) {
            const receipt = session.end();
            if (receipt.accepted) accepted++;
            else dropped++;
          }
          await meter.flush();
          assert.deepEqual(meter.stats(), {
            enqueued: accepted,
            exported: accepted,
            dropped,
            failedExports: 0,
            queueDepth: 0,
          });
          for (const event of events) {
            for (const id of [event.eventId, event.operationId]) {
              assert.ok(!allIds.has(id));
              allIds.add(id);
            }
            assert.ok(Object.isFrozen(event));
            assert.ok(event.durationMs >= 0);
            assert.ok(event.startedAt <= event.endedAt);
          }
        } finally {
          await meter.close();
        }
      },
    ),
    { seed: 2408, numRuns: 200 },
  );
  assert.ok(allIds.size > 1000);
});
