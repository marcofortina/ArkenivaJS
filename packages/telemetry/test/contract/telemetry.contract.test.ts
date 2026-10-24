import test from 'node:test';
import assert from 'node:assert/strict';
import { createTelemetry } from '@arkenivajs/telemetry';
import type { Telemetry } from '@arkenivajs/core';
test('Telemetry public port retains asynchronous value preservation and synchronous metric methods', async () => {
  const managed = createTelemetry({
    service: { name: 'contract', version: '1.0.0', environment: 'test' },
    mode: 'off',
  });
  const telemetry: Telemetry = managed;
  try {
    assert.equal(await telemetry.measure('test.operation', () => 7), 7);
    assert.equal(telemetry.setGauge('value', 1), undefined);
    await telemetry.flush();
  } finally {
    await managed.close();
  }
});
