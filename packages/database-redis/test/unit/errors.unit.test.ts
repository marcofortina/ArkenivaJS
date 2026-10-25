// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import redis from 'redis';
import { KitError } from '@arkenivajs/core';
import { redisError, redisVendor, permanentRedisError } from '../../dist/errors.js';

test('EK-SEC-001 Redis exposes only bounded vendor codes and preserves the original private cause', () => {
  for (const input of [
    undefined,
    null,
    'secret',
    {},
    { code: 1 },
    { code: 'secret-value' },
    { code: 'A'.repeat(65) },
    new redis.SimpleError('lowercase secret'),
    new redis.SimpleError(`${'A'.repeat(65)} secret`),
  ])
    assert.equal(redisVendor(input), undefined);
  assert.equal(redisVendor({ code: 'ECONNRESET' }), 'ECONNRESET');
  assert.equal(redisVendor(new redis.SimpleError('WRONGTYPE secret-key')), 'WRONGTYPE');
  const cause = new redis.SimpleError('WRONGTYPE secret-key secret-value');
  const error = redisError(cause);
  assert.equal(error.code, 'EK_KV_CONFLICT');
  assert.equal(error.cause, cause);
  assert.ok(!error.message.includes('secret'));
  assert.deepEqual(error.details, { vendorCode: 'WRONGTYPE' });
  const kit = new KitError({ code: 'EK_TIMEOUT', message: 'Deadline reached' });
  assert.equal(redisVendor(kit), undefined);
  assert.equal(redisError(kit), kit);
});

test('EK-DB-002 Redis distinguishes acknowledged server errors, aborts and uncertain write acknowledgments', () => {
  assert.equal(redisError(new redis.AbortError()).code, 'EK_ABORTED');
  assert.equal(redisError(new redis.TimeoutError()).code, 'EK_TIMEOUT');
  for (const cause of [
    new redis.ClientClosedError(),
    new redis.ClientOfflineError(),
    new redis.SocketClosedUnexpectedlyError(),
    { code: 'ECONNRESET' },
  ]) {
    assert.equal(redisError(cause).retryable, true);
    const before = redisError(cause, true, false);
    assert.equal(before.details.outcome, undefined);
    const after = redisError(cause, true, true);
    assert.equal(after.details.outcome, 'unknown');
    assert.equal(after.retryable, false);
  }
  const acknowledged = redisError(
    new redis.SimpleError('ARKENIVA_VALUE_LIMIT Value too large'),
    true,
    true,
  );
  assert.equal(acknowledged.code, 'EK_KV_CONFLICT');
  assert.equal(acknowledged.details.limitExceeded, true);
  assert.equal(acknowledged.details.outcome, undefined);
  const timeout = new KitError({
    code: 'EK_TIMEOUT',
    message: 'Deadline reached',
    retryable: true,
  });
  const uncertain = redisError(timeout, true, true);
  assert.equal(uncertain.code, 'EK_TIMEOUT');
  assert.equal(uncertain.details.outcome, 'unknown');
  assert.equal(uncertain.retryable, false);
  assert.equal(redisError(new Error('Unexpected')).retryable, false);
  for (const code of [
    'WRONGPASS',
    'NOAUTH',
    'NOPERM',
    'ERR_TLS_CERT_ALTNAME_INVALID',
    'CERT_HAS_EXPIRED',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  ])
    assert.equal(permanentRedisError({ code }), true);
  assert.equal(permanentRedisError({ code: 'ECONNRESET' }), false);
});
