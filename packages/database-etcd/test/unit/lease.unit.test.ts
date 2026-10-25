// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { Etcd3, LeaseClient, EtcdLeaseInvalidError, GRPCUnavailableError } from 'etcd3';
import type {
  IDuplexStream,
  ILeaseKeepAliveRequest,
  ILeaseKeepAliveResponse,
  ILeaseGrantRequest,
  ILeaseRevokeRequest,
} from 'etcd3';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { EtcdOwnedLease } from '../../dist/lease.js';
import type { EtcdLeaseAttempt } from '../../dist/lease.js';
import { etcdOptions } from '../../dist/common.js';
import { etcdError } from '../../dist/errors.js';
import type { EtcdCallScope } from '../../dist/transport.js';
import { deferred } from '../fixtures/native-double.js';

/** Simulate stream faults at the exported SDK boundary without replacing the production transport. */
class Heartbeat extends EventEmitter {
  writes = 0;
  ends = 0;
  cancels = 0;
  endFailure = false;
  cancelFailure = false;
  constructor(readonly response: unknown = { ID: '123', TTL: '30' }) {
    super();
  }
  write(request: ILeaseKeepAliveRequest) {
    assert.equal(request.ID, '123');
    this.writes++;
    setImmediate(() => {
      if (this.response instanceof Error) this.emit('error', this.response);
      else if (this.response === 'end') this.emit('end');
      else this.emit('data', this.response);
    });
    return true;
  }
  end() {
    this.ends++;
    if (this.endFailure) throw new Error('Injected heartbeat half-close failure');
  }
  cancel() {
    this.cancels++;
    this.emit('status', {});
    if (this.cancelFailure) throw new Error('Injected heartbeat cancellation failure');
  }
}

async function eventually(check: () => boolean) {
  const expires = performance.now() + 3000;
  while (!check()) {
    assert.ok(performance.now() < expires, 'The SDK lease boundary did not settle');
    await delay(5);
  }
}

function fixture(context: TestContext, ttl = 30, id = '123') {
  const parent = new AbortController(),
    calls: string[] = [],
    revoked: string[] = [],
    losses: KitError[] = [];
  const controls: {
    grant: (request: ILeaseGrantRequest) => Promise<unknown>;
    revoke: (request: ILeaseRevokeRequest) => Promise<unknown>;
    heartbeat: () => Promise<Heartbeat>;
    diagnosticsFail: boolean;
  } = {
    grant: async (request: ILeaseGrantRequest): Promise<unknown> => ({
      ID: request.ID,
      TTL: '30',
      error: '',
    }),
    revoke: async (): Promise<unknown> => ({}),
    heartbeat: async (): Promise<Heartbeat> => new Heartbeat(),
    diagnosticsFail: false,
  };
  context.mock.method(LeaseClient.prototype, 'leaseGrant', (request: ILeaseGrantRequest) =>
    controls.grant(request),
  );
  context.mock.method(LeaseClient.prototype, 'leaseRevoke', (request: ILeaseRevokeRequest) => {
    revoked.push(String(request.ID));
    return controls.revoke(request);
  });
  context.mock.method(
    LeaseClient.prototype,
    'leaseKeepAlive',
    async () =>
      (await controls.heartbeat()) as unknown as IDuplexStream<
        ILeaseKeepAliveRequest,
        ILeaseKeepAliveResponse
      >,
  );
  const attempt: EtcdLeaseAttempt = async (operation, input, work, cleanup = false) => {
    calls.push(operation);
    const captured = etcdOptions(input),
      controller = new AbortController();
    const scope: EtcdCallScope = {
      signal: AbortSignal.any([
        controller.signal,
        ...(cleanup ? [] : [parent.signal]),
        ...(captured.signal ? [captured.signal] : []),
      ]),
      timeoutMs: captured.timeoutMs,
      // The exported SDK double acknowledges that this test crossed the native submission boundary.
      submitted: true,
    };
    try {
      return await within(() => work(scope), {
        timeoutMs: captured.timeoutMs,
        signal: scope.signal,
      });
    } catch (cause) {
      controller.abort(cause);
      throw etcdError(cause, true, scope.submitted);
    }
  };
  let closed = 0,
    expectedCleanupFailure = false;
  const owner = new EtcdOwnedLease(
    { prefix: '/scope/', native: { hosts: ['http://127.0.0.1:1'] } },
    ttl,
    parent.signal,
    attempt,
    (failure) => {
      losses.push(failure);
      if (controls.diagnosticsFail) throw new Error('Loss diagnostic failure');
    },
    () => {
      closed++;
      if (controls.diagnosticsFail) throw new Error('Close diagnostic failure');
    },
    id,
  );
  context.after(async () => {
    try {
      await owner.dispose();
    } catch (cause) {
      if (!expectedCleanupFailure) throw cause;
    }
  });
  return {
    owner,
    parent,
    controls,
    calls,
    revoked,
    losses,
    get closed() {
      return closed;
    },
    allowCleanupFailure() {
      expectedCleanupFailure = true;
    },
  };
}

test('lease rejects invalid TTL and duplicate grant attempts before allocating another identity', async (context) => {
  for (const ttl of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN]) {
    await context.test('invalid portable TTL is rejected', async (child) => {
      const f = fixture(child, ttl);
      await assert.rejects(f.owner.grant(), { code: 'EK_CONFIG_INVALID' });
      assert.equal(f.calls.length, 0);
    });
  }
  const f = fixture(context);
  await f.owner.grant();
  await assert.rejects(f.owner.grant(), { code: 'EK_LIFECYCLE_STATE' });
  assert.equal(f.calls.filter((name) => name === 'grantLease').length, 1);
});

test('decoded lease rejection remains acknowledged and never revokes a colliding identity', async (context) => {
  const f = fixture(context);
  f.controls.grant = async () => ({ ID: '123', TTL: '0', error: 'Private backend rejection' });
  await assert.rejects(
    f.owner.grant(),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_KV_CONFLICT' &&
      cause.details.outcome === undefined &&
      !cause.message.includes('Private'),
  );
  await f.owner.dispose();
  assert.deepEqual(f.revoked, []);
});

test('mismatched grant replies retain only the requested identity for unknown-outcome cleanup', async (context) => {
  const f = fixture(context);
  f.controls.grant = async () => ({ ID: '999', TTL: '30', error: '' });
  await assert.rejects(
    f.owner.grant(),
    (cause: unknown) => cause instanceof KitError && cause.details.outcome === 'unknown',
  );
  await f.owner.dispose();
  assert.deepEqual(f.revoked, ['123']);
});

test('lease disposal coalesces and waits for a late grant before its single owned revocation', async (context) => {
  const f = fixture(context),
    gate = deferred();
  f.controls.grant = async () => {
    await gate.promise;
    return { ID: '123', TTL: '30', error: '' };
  };
  const granting = f.owner.grant();
  await eventually(() => f.calls.includes('grantLease'));
  const closing = f.owner.dispose();
  assert.equal(f.owner.dispose(), closing);
  gate.resolve();
  await granting;
  await closing;
  assert.deepEqual(f.revoked, ['123']);
  assert.equal(f.closed, 1);
  assert.throws(() => f.owner.assertUsable(), { code: 'EK_RESOURCE_CLOSED' });
});

test('lease keepAlive is explicit and repeated calls share one renewal loop', async (context) => {
  const f = fixture(context),
    stream = new Heartbeat();
  f.controls.heartbeat = async () => stream;
  const handle = await f.owner.grant();
  assert.equal(Object.isFrozen(handle), true);
  assert.equal(f.calls.includes('keepAlive'), false);
  handle.keepAlive();
  handle.keepAlive();
  await eventually(() => stream.cancels === 1);
  assert.equal(stream.writes, 1);
  assert.equal(stream.ends, 1);
  await Promise.all([handle.revoke(), handle.revoke()]);
  await handle.revoke();
  assert.deepEqual(f.revoked, ['123']);
  assert.equal(f.closed, 1);
});

test('expired heartbeat acknowledgments terminate renewal without silently granting a replacement', async (context) => {
  for (const ttl of ['0', '-1']) {
    await context.test('server reports the owned lease as expired', async (child) => {
      const f = fixture(child),
        stream = new Heartbeat({ ID: '123', TTL: ttl });
      f.controls.diagnosticsFail = true;
      f.controls.heartbeat = async () => stream;
      const handle = await f.owner.grant();
      handle.keepAlive();
      await eventually(() => f.losses.length === 1);
      assert.equal(f.losses[0]?.code, 'EK_KV_CONFLICT');
      assert.throws(() => handle.keepAlive(), { code: 'EK_KV_CONFLICT' });
      assert.equal(f.calls.filter((name) => name === 'grantLease').length, 1);
      await f.owner.dispose();
      assert.equal(f.closed, 1);
    });
  }
});

test('permanent heartbeat failure terminates renewal and parent abort prevents new attachments', async (context) => {
  const f = fixture(context);
  const { EtcdPermissionDeniedError } = await import('etcd3');
  f.controls.heartbeat = async () => {
    throw new EtcdPermissionDeniedError('Denied');
  };
  (await f.owner.grant()).keepAlive();
  await eventually(() => f.losses.length === 1);
  f.parent.abort();
  assert.throws(() => f.owner.assertUsable(), { code: 'EK_RESOURCE_CLOSED' });
  await assert.rejects(f.owner.handle.revoke(), { code: 'EK_RESOURCE_CLOSED' });
  await f.owner.dispose();
  assert.deepEqual(f.revoked, ['123']);
});

test('lease revocation accepts an already missing backend identity', async (context) => {
  const f = fixture(context),
    handle = await f.owner.grant();
  f.controls.revoke = async () => {
    throw new EtcdLeaseInvalidError('Missing');
  };
  await handle.revoke();
  await handle.revoke();
  assert.deepEqual(f.revoked, ['123']);
});

test('lost revocation acknowledgment stays unknown and disposal retries only the same owned ID', async (context) => {
  const f = fixture(context),
    handle = await f.owner.grant();
  f.controls.revoke = async () => {
    throw new GRPCUnavailableError('Lost acknowledgment');
  };
  await assert.rejects(
    handle.revoke(),
    (cause: unknown) =>
      cause instanceof KitError && cause.details.outcome === 'unknown' && !cause.retryable,
  );
  f.controls.revoke = async () => ({});
  await f.owner.dispose();
  assert.deepEqual(f.revoked, ['123', '123']);
});

test('lease disposal reports revocation and native-close failures without leaking diagnostics', async (context) => {
  const f = fixture(context);
  f.allowCleanupFailure();
  f.controls.diagnosticsFail = true;
  await f.owner.grant();
  f.controls.revoke = async () => {
    throw new GRPCUnavailableError('Disconnected');
  };
  context.mock.method(Etcd3.prototype, 'close', () => {
    throw new Error('Native close failure');
  });
  await assert.rejects(
    f.owner.dispose(),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.cause instanceof AggregateError &&
      cause.cause.errors.length === 2,
  );
  assert.equal(f.closed, 1);
});

test('acknowledged revocation retains its outcome when closing the native client fails', async (context) => {
  const f = fixture(context),
    handle = await f.owner.grant();
  f.allowCleanupFailure();
  context.mock.method(Etcd3.prototype, 'close', () => {
    throw new Error('Native close failure');
  });
  await assert.rejects(
    handle.revoke(),
    (cause: unknown) => cause instanceof KitError && cause.details.outcome === 'acknowledged',
  );
  assert.deepEqual(f.revoked, ['123']);
});

test('transient and malformed heartbeat replies recover only the existing lease within its validity', async (context) => {
  for (const reply of [
    new GRPCUnavailableError('Disconnected'),
    'end',
    { ID: '999', TTL: '30' },
    { ID: '123', TTL: 'invalid' },
  ]) {
    await context.test('failed heartbeat does not authorize a replacement grant', async (child) => {
      const f = fixture(child),
        first = new Heartbeat(reply),
        second = new Heartbeat();
      let attempts = 0;
      f.controls.heartbeat = async () => (++attempts === 1 ? first : second);
      const handle = await f.owner.grant();
      handle.keepAlive();
      await eventually(() => second.cancels === 1);
      assert.equal(f.calls.filter((operation) => operation === 'grantLease').length, 1);
      assert.equal(f.losses.length, 0);
      await handle.revoke();
      assert.equal(first.cancels, 1);
    });
  }
});

test('heartbeat half-close and cancellation faults retain causes while owned disposal still revokes', async (context) => {
  const f = fixture(context),
    first = new Heartbeat(),
    second = new Heartbeat({ ID: '123', TTL: '0' });
  first.endFailure = true;
  first.cancelFailure = true;
  let attempts = 0;
  f.controls.heartbeat = async () => (++attempts === 1 ? first : second);
  (await f.owner.grant()).keepAlive();
  await eventually(() => f.losses.length === 1);
  assert.equal(first.ends, 1);
  assert.equal(first.cancels, 1);
  await f.owner.dispose();
  assert.deepEqual(f.revoked, ['123']);
});

test('aborted owner stops a pending heartbeat retry and prevents a fresh native grant', async (context) => {
  const f = fixture(context),
    first = new Heartbeat(new GRPCUnavailableError('Disconnected'));
  f.controls.heartbeat = async () => first;
  (await f.owner.grant()).keepAlive();
  await eventually(() => first.cancels === 1);
  f.parent.abort();
  await f.owner.dispose();
  await assert.rejects(f.owner.grant(), { code: 'EK_LIFECYCLE_STATE' });
  assert.equal(f.calls.filter((operation) => operation === 'grantLease').length, 1);
});
