import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { KitError } from '@arkenivajs/core';

test('EK-ERR-001 preserves internal cause and immutable typed metadata', () => {
  const cause = new Error('fake-token-123');
  const error = new KitError({ code: 'EK_INTERNAL', message: 'developer detail', cause });
  assert.equal(error.cause, cause);
  assert.equal(error.message, 'developer detail');
  assert.equal(error.retryable, false);
  assert.equal(error.name, 'KitError');
  assert.ok(Object.isFrozen(error.details));
  assert.throws(() => Object.assign(error, { code: 'other' }), TypeError);
});

test('EK-ERR-001 safe JSON omits arbitrary developer secrets and cyclic causes', () => {
  fc.assert(
    fc.property(fc.string(), (secret) => {
      const cause: Record<string, unknown> = { secret };
      cause.self = cause;
      const error = new KitError({
        code: 'EK_CONFIG_INVALID',
        message: secret,
        cause,
        retryable: true,
        details: { token: secret },
      });
      const safe = error.toSafeJSON();
      assert.deepEqual(Object.keys(safe).sort(), ['code', 'message']);
      assert.deepEqual(JSON.parse(JSON.stringify(error)), safe);
      assert.equal(safe.message, 'The operation could not be completed safely.');
    }),
    { seed: 2401, numRuns: 300 },
  );
});

test('EK-ERR-001 invalid runtime options cannot escape the stable error union', () => {
  for (const options of [
    undefined,
    { code: 'private-token', message: 'bad' },
    { code: 'EK_INTERNAL', message: 1 },
    { code: 'EK_INTERNAL', message: 'bad', retryable: 1 },
    { code: 'EK_INTERNAL', message: 'bad', details: { count: Infinity } },
    { code: 'EK_INTERNAL', message: 'bad', details: { nested: {} } },
  ]) {
    assert.throws(() => new KitError(options as never), TypeError);
  }
});
