// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  GRPCUnavailableError,
  GRPCCancelledError,
  GRPCDeadlineExceededError,
  GRPCInvalidArgumentError,
  GRPCNotFoundError,
  GRPCAlreadyExistsError,
  GRPCFailedPreconditionError,
  GRPCOutOfRangeError,
  GRPCUnauthenticatedError,
  GRPCAbortedError,
  GRPCResourceExhastedError,
  EtcdLeaseInvalidError,
  EtcdPermissionDeniedError,
  EtcdAuthenticationFailedError,
  EtcdInvalidAuthTokenError,
} from 'etcd3';
import { KitError } from '@arkenivajs/core';
import {
  etcdVendor,
  etcdError,
  etcdAcknowledgedFailure,
  permanentEtcdError,
} from '../../dist/errors.js';

test('EK-SEC-001 etcd recognizes bounded native classes/statuses without copying private server messages into labels', () => {
  const cases = [
    [new GRPCCancelledError('private'), 'CANCELLED'],
    [new GRPCDeadlineExceededError('private'), 'DEADLINE_EXCEEDED'],
    [new GRPCUnavailableError('private'), 'UNAVAILABLE'],
    [new GRPCInvalidArgumentError('private'), 'INVALID_ARGUMENT'],
    [new GRPCNotFoundError('private'), 'NOT_FOUND'],
    [new GRPCAlreadyExistsError('private'), 'ALREADY_EXISTS'],
    [new GRPCFailedPreconditionError('private'), 'FAILED_PRECONDITION'],
    [new GRPCOutOfRangeError('private'), 'OUT_OF_RANGE'],
    [new GRPCUnauthenticatedError('private'), 'UNAUTHENTICATED'],
    [new GRPCAbortedError('private'), 'ABORTED'],
    [new GRPCResourceExhastedError('private'), 'RESOURCE_EXHAUSTED'],
    [new EtcdLeaseInvalidError('private'), 'LEASE_INVALID'],
    [new EtcdPermissionDeniedError('private'), 'PERMISSION_DENIED'],
    [new EtcdAuthenticationFailedError('private'), 'AUTHENTICATION_FAILED'],
    [new EtcdInvalidAuthTokenError('private'), 'INVALID_AUTH_TOKEN'],
  ] as const;
  for (const [cause, expected] of cases) {
    assert.equal(etcdVendor(cause), expected);
    assert.equal(etcdError(cause).cause, cause);
    assert.ok(!etcdError(cause).message.includes('private'));
  }
  assert.equal(
    etcdVendor(Object.assign(new Error('Private server details'), { code: 14 })),
    'UNAVAILABLE',
  );
  for (const value of [undefined, null, {}, 'private', new Error('private')])
    assert.equal(etcdVendor(value), undefined);
  const kit = new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid input' });
  assert.equal(etcdVendor(kit), undefined);
  assert.equal(etcdError(kit), kit);
});

test('EK-DB-002 etcd keeps acknowledged server failures distinct from unacknowledged write effects', () => {
  assert.equal(etcdError(new GRPCCancelledError('Cancelled')).code, 'EK_ABORTED');
  assert.equal(etcdError(new GRPCDeadlineExceededError('Timed out')).code, 'EK_TIMEOUT');
  for (const error of [
    new EtcdLeaseInvalidError('1'),
    new GRPCAlreadyExistsError('Exists'),
    new GRPCAbortedError('Conflict'),
  ])
    assert.equal(etcdError(error).code, 'EK_KV_CONFLICT');
  const transport = new GRPCUnavailableError('Disconnected');
  assert.equal(etcdError(transport).retryable, true);
  assert.equal(etcdError(transport, true, false).details.outcome, undefined);
  const unknown = etcdError(transport, true, true);
  assert.equal(unknown.details.outcome, 'unknown');
  assert.equal(unknown.retryable, false);
  const acknowledged = new EtcdPermissionDeniedError('Denied');
  assert.equal(etcdAcknowledgedFailure(acknowledged), true);
  assert.equal(etcdError(acknowledged, true, true).details.outcome, undefined);
  const kit = new KitError({ code: 'EK_TIMEOUT', message: 'Deadline', retryable: true });
  assert.equal(etcdError(kit).retryable, true);
  assert.equal(etcdError(kit, true, true).retryable, false);
  assert.equal(etcdError(kit, true, true).details.outcome, 'unknown');
  assert.equal(permanentEtcdError(acknowledged), true);
  assert.equal(permanentEtcdError(etcdError(acknowledged, true, true)), true);
  assert.equal(
    permanentEtcdError(
      new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Invalid metadata',
        details: { vendorCode: 7 },
      }),
    ),
    false,
  );
  assert.equal(permanentEtcdError(transport), false);
  assert.equal(etcdError(new Error('Unexpected')).retryable, false);
});
