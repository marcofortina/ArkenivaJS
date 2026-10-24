import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
const provider = (withSpan: Telemetry['withSpan']): Telemetry => ({
  withSpan,
  measure: withSpan,
  addCounter() {},
  recordHistogram() {},
  setGauge() {},
  flush: async () => {},
});

test('EK-OTEL-001 adapter instrumentation preserves values/errors and never repeats work after diagnostic failure', async () => {
  let calls = 0,
    failures = 0;
  const work = () => {
      calls++;
      return 42;
    },
    fail = () => {
      failures++;
    };
  assert.equal(await instrumentOperation(undefined, 'test', {}, work, fail), 42);
  const error = new Error('fake-business-failure');
  const normal = provider(async (_name, fn) => fn());
  await assert.rejects(
    instrumentOperation(
      normal,
      'test',
      {},
      () => {
        throw error;
      },
      fail,
    ),
    (value) => value === error,
  );
  assert.equal(failures, 0);
  const before = provider(async () => {
    throw new Error('Diagnostic unavailable');
  });
  assert.equal(await instrumentOperation(before, 'test', {}, work, fail), 42);
  const after = provider(async (_name, fn) => {
    await fn();
    throw new Error('Diagnostic export failed');
  });
  assert.equal(await instrumentOperation(after, 'test', {}, work, fail), 42);
  const duplicate = provider(async (_name, fn) => {
    await fn();
    return fn();
  });
  assert.equal(await instrumentOperation(duplicate, 'test', {}, work, fail), 42);
  const missing = provider(async () => undefined as never);
  assert.equal(
    await instrumentOperation(missing, 'test', {}, work, () => {
      throw new Error('Diagnostic callback failed');
    }),
    42,
  );
  const replacement = provider(async (_name, fn) => {
    try {
      return await fn();
    } catch {
      throw new Error('Diagnostic replacement');
    }
  });
  await assert.rejects(
    instrumentOperation(
      replacement,
      'test',
      {},
      () => {
        throw error;
      },
      fail,
    ),
    (value) => value === error,
  );
  assert.equal(calls, 5);
  assert.equal(failures, 4);
  await assert.rejects(
    instrumentOperation(normal, 'test', {}, null as never, fail),
    (value) => value instanceof KitError && value.code === 'EK_CONFIG_INVALID',
  );
});
