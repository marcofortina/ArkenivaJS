import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

test('Error boundary emits only the stable public envelope', () => {
  const code: ErrorCode = 'EK_TIMEOUT';
  const error = new KitError({
    code,
    message: 'Internal diagnostic',
    retryable: true,
    cause: new Error('private'),
  });
  const safe: { code: ErrorCode; message: string; requestId?: string } = error.toSafeJSON();
  assert.deepEqual(Object.keys(safe).sort(), ['code', 'message']);
  assert.equal(safe.code, code);
  assert.equal(error.retryable, true);
});
