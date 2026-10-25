// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MongoServerError,
  MongoNetworkError,
  MongoNetworkTimeoutError,
  MongoOperationTimeoutError,
  MongoInvalidArgumentError,
  MongoParseError,
  MongoExpiredSessionError,
  BSON,
} from 'mongodb';
import { KitError } from '@arkenivajs/core';
import { mongoError } from '../../dist/errors.js';

test('MongoDB classifies bounded public SDK errors without copying private server messages into labels', () => {
  const cases = [
    [
      new MongoServerError({ message: 'private', code: 11000 }),
      'EK_DATABASE_CONSTRAINT',
      'DUPLICATE_KEY',
    ],
    [
      new MongoServerError({ message: 'private', code: 121 }),
      'EK_DATABASE_CONSTRAINT',
      'DOCUMENT_VALIDATION',
    ],
    [
      new MongoServerError({ message: 'private', code: 112 }),
      'EK_DATABASE_CONFLICT',
      'WRITE_CONFLICT',
    ],
    [new MongoServerError({ message: 'private', code: 50 }), 'EK_TIMEOUT', 'EXECUTION_TIMEOUT'],
    [
      new MongoServerError({ message: 'private', code: 91 }),
      'EK_DATABASE_UNAVAILABLE',
      'SERVER_SHUTDOWN',
    ],
    [
      new MongoServerError({ message: 'private', code: 999999 }),
      'EK_DOCUMENT_OPERATION',
      'SERVER_ERROR',
    ],
    [new MongoNetworkError('private'), 'EK_DATABASE_UNAVAILABLE', 'NETWORK_UNAVAILABLE'],
    [new MongoNetworkTimeoutError('private'), 'EK_TIMEOUT', 'NETWORK_TIMEOUT'],
    [new MongoOperationTimeoutError('private'), 'EK_TIMEOUT', 'OPERATION_TIMEOUT'],
    [new MongoInvalidArgumentError('private'), 'EK_CONFIG_INVALID', 'INVALID_ARGUMENT'],
    [new MongoParseError('private'), 'EK_CONFIG_INVALID', 'INVALID_ARGUMENT'],
    [new MongoExpiredSessionError('private'), 'EK_RESOURCE_CLOSED', 'SESSION_CLOSED'],
    [
      Object.assign(new Error('private'), { name: 'MongoWaitQueueTimeoutError' }),
      'EK_DATABASE_POOL_TIMEOUT',
      'POOL_TIMEOUT',
    ],
  ] as const;
  for (const [cause, code, vendor] of cases) {
    const error = mongoError(cause);
    assert.equal(error.code, code);
    assert.equal(error.details.vendorCode, vendor);
    assert.equal(error.cause, cause);
    assert.equal(error.message.includes('private'), false);
  }
  assert.equal(mongoError(new Error('private')).code, 'EK_DOCUMENT_OPERATION');
  const nativeBsonCode = new MongoServerError({ message: 'private', code: new BSON.Int32(11000) });
  assert.equal(mongoError(nativeBsonCode).code, 'EK_DATABASE_CONSTRAINT');
  assert.equal(
    mongoError(nativeBsonCode, {
      write: true,
      submitted: true,
      acknowledged: false,
      atomic: true,
    }).details.outcome,
    undefined,
  );
});

test('MongoDB retains unknown submitted mutations, acknowledged constraints and potentially partial aggregations', () => {
  const network = new MongoNetworkError('Lost acknowledgment');
  const submitted = { write: true, submitted: true, acknowledged: false };
  assert.equal(mongoError(network, submitted).details.outcome, 'unknown');
  assert.equal(mongoError(network, submitted).retryable, false);
  assert.equal(mongoError(network, { ...submitted, submitted: false }).details.outcome, undefined);
  const duplicate = new MongoServerError({ message: 'Duplicate', code: 11000 });
  assert.equal(mongoError(duplicate, { ...submitted, atomic: true }).details.outcome, undefined);
  assert.equal(mongoError(duplicate, { ...submitted, atomic: false }).details.outcome, 'unknown');
  assert.equal(
    mongoError(network, { ...submitted, acknowledged: true, outcome: 'acknowledged' }).details
      .outcome,
    'acknowledged',
  );
  const domain = new KitError({ code: 'EK_INTERNAL', message: 'Domain failure' });
  assert.equal(mongoError(domain), domain);
  assert.equal(
    mongoError(domain, { ...submitted, acknowledged: true, outcome: 'rolled_back' }).details
      .outcome,
    'rolled_back',
  );
});

test('MongoDB maps the native AbortSignal reason to cancellation instead of treating it as a server rejection', () => {
  const controller = new AbortController(),
    reason = new MongoServerError({ code: 11000, message: 'Caller supplied this reason' });
  controller.abort(reason);
  const error = mongoError(reason, {
    signal: controller.signal,
    write: true,
    submitted: true,
    acknowledged: false,
    atomic: true,
  });
  assert.equal(error.code, 'EK_ABORTED');
  assert.equal(error.details.outcome, 'unknown');
  assert.equal(error.details.vendorCode, 'CANCELLED');
  const deadline = new AbortController(),
    timeout = new KitError({ code: 'EK_TIMEOUT', message: 'The operation deadline expired' });
  deadline.abort(timeout);
  assert.equal(
    mongoError(timeout, {
      signal: deadline.signal,
      write: true,
      submitted: true,
      acknowledged: false,
    }).code,
    'EK_TIMEOUT',
  );
});
