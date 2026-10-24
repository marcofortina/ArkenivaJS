import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { records } from '../fixtures/events.js';
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
import { parseMeteringEvent } from '@arkenivajs/metering';
test('EK-METER-001 producer envelope validation rejects unknown fields, invalid timestamps and malformed quantities', async () => {
  const event = (await records())[0]!;
  assert.deepEqual(parseMeteringEvent(event), event);
  assert.ok(Object.isFrozen(parseMeteringEvent(event)));
  for (const patch of [
    { schemaVersion: '2.0.0' },
    { subject: 'fake-private' },
    { tenantId: 'tenant\n' },
    { eventId: 'not-unique' },
    { traceId: '0'.repeat(32) },
    { startedAt: '2026-02-30T00:00:00.000Z' },
    { endedAt: '2000-01-01T00:00:00.000Z' },
    { durationMs: -1 },
    { counters: { 'bad\n': { unit: 'operations', source: 'observed', value: 1 } } },
    { counters: { bad: { unit: 'bytes', source: 'observed', value: Infinity } } },
    { quality: { complete: true, droppedChildCount: 0, missing: ['driver_bytes_unavailable'] } },
  ])
    assert.throws(() => parseMeteringEvent({ ...event, ...patch }), code('EK_METER_EXPORT'));
  assert.throws(() => parseMeteringEvent(null), code('EK_METER_EXPORT'));
});
