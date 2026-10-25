// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { LeaseClient, GRPCUnavailableError } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { etcdConfiguration } from '../../dist/config.js';
import { etcdOptions } from '../../dist/common.js';
import { etcdError } from '../../dist/errors.js';
import { EtcdTransport } from '../../dist/transport.js';
import type { EtcdCallScope } from '../../dist/transport.js';
import { EtcdOwnedLease } from '../../dist/lease.js';
import type { EtcdLeaseAttempt } from '../../dist/lease.js';

function fixture(context: TestContext) {
  assert.equal(
    process.env.ARKENIVA_ETCD_DISPOSABLE,
    '1',
    'Only a dedicated disposable etcd fixture is permitted',
  );
  assert.ok(process.env.ARKENIVA_ETCD_URL, 'An authenticated TLS fixture URL is required');
  const configuration = etcdConfiguration(
    { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' },
    'test',
  );
  const parent = new AbortController(),
    writer = new EtcdTransport(configuration, new AbortController().signal);
  const owners: EtcdOwnedLease[] = [],
    keys = new Set<string>(),
    calls: string[] = [],
    losses: KitError[] = [];
  let closed = 0;
  const attempt: EtcdLeaseAttempt = async (operation, input, work, cleanup = false) => {
    const captured = etcdOptions(input),
      controller = new AbortController();
    const signal = AbortSignal.any([
      controller.signal,
      ...(cleanup ? [] : [parent.signal]),
      ...(captured.signal ? [captured.signal] : []),
    ]);
    const scope: EtcdCallScope = { signal, timeoutMs: captured.timeoutMs, submitted: false };
    calls.push(operation);
    try {
      return await within(() => work(scope), { timeoutMs: captured.timeoutMs, signal });
    } catch (cause) {
      controller.abort(cause);
      throw etcdError(cause, true, scope.submitted);
    }
  };
  context.after(async () => {
    try {
      await Promise.all(owners.map((owner) => owner.dispose()));
      for (const key of keys) await writer.client.delete().key(key);
    } finally {
      parent.abort();
      writer.client.close();
    }
  });
  return {
    parent,
    writer,
    calls,
    losses,
    get closed() {
      return closed;
    },
    owner(ttl: number, id?: string) {
      const owner = new EtcdOwnedLease(
        configuration,
        ttl,
        parent.signal,
        attempt,
        (failure) => {
          losses.push(failure);
        },
        () => {
          closed++;
        },
        id,
      );
      owners.push(owner);
      return owner;
    },
    key() {
      const key = configuration.prefix + 'lease:' + randomUUID();
      keys.add(key);
      return key;
    },
  };
}

async function eventually(check: () => boolean | Promise<boolean>, budget = 10_000) {
  const expires = performance.now() + budget;
  while (!(await check())) {
    if (performance.now() >= expires)
      assert.fail('The lease condition did not complete within its budget');
    await delay(25);
  }
}

test(
  'EK-DB-002 live etcd leases expire without implicit renewal and revocation remains idempotent',
  { timeout: 20_000 },
  async (context) => {
    const f = fixture(context),
      owner = f.owner(1),
      handle = await owner.grant(),
      key = f.key();
    assert.ok(Object.isFrozen(handle));
    assert.equal(handle.id, owner.id);
    owner.assertUsable();
    await f.writer.client
      .put(key)
      .lease(handle.id)
      .value(Buffer.from([0, 255]));
    await eventually(async () => (await f.writer.client.get(key).exec()).kvs.length === 0);
    assert.equal(f.calls.filter((name) => name === 'keepAlive').length, 0);
    assert.throws(
      () => handle.keepAlive(),
      (error) => error instanceof KitError && error.code === 'EK_KV_CONFLICT',
    );
    await handle.revoke();
    await handle.revoke();
    assert.equal(f.calls.filter((name) => name === 'revoke').length, 1);
    assert.equal(f.closed, 1);
  },
);

test(
  'EK-DB-002 live etcd explicit keepAlive renews an owned lease until an idempotent revoke removes its keys',
  { timeout: 20_000 },
  async (context) => {
    const f = fixture(context),
      owner = f.owner(1),
      handle = await owner.grant(),
      key = f.key();
    await f.writer.client.put(key).lease(handle.id).value('owned');
    const initial = await f.writer.client.leaseClient.leaseTimeToLive({ ID: handle.id });
    assert.ok(BigInt(initial.grantedTTL) > 0n && BigInt(initial.grantedTTL) <= 5n);
    assert.equal(handle.keepAlive(), undefined);
    handle.keepAlive();
    await delay(Number(initial.grantedTTL) * 1000 + 500);
    assert.deepEqual((await f.writer.client.get(key).exec()).kvs[0]!.value, Buffer.from('owned'));
    owner.assertUsable();
    assert.ok(f.calls.filter((name) => name === 'keepAlive').length >= 2);
    assert.deepEqual(f.losses, []);
    await Promise.all([handle.revoke(), handle.revoke()]);
    assert.deepEqual((await f.writer.client.get(key).exec()).kvs, []);
    const count = f.calls.length;
    await delay(400);
    assert.equal(f.calls.length, count);
    await handle.revoke();
    assert.equal(f.calls.filter((name) => name === 'revoke').length, 1);
  },
);

test(
  'EK-DB-002 real etcd lease loss is surfaced without automatically granting a replacement',
  { timeout: 15_000 },
  async (context) => {
    const f = fixture(context),
      owner = f.owner(2),
      handle = await owner.grant();
    handle.keepAlive();
    await eventually(() => f.calls.includes('keepAlive'));
    await f.writer.client.leaseClient.leaseRevoke({ ID: handle.id });
    await eventually(() => f.losses.length > 0);
    assert.throws(
      () => handle.keepAlive(),
      (error) => error instanceof KitError && error.code === 'EK_KV_CONFLICT',
    );
    assert.equal(f.calls.filter((name) => name === 'grantLease').length, 1);
    await handle.revoke();
  },
);

test(
  'EK-CORE-001 real etcd shutdown cancels renewal and revokes the known lease after its parent signal ends',
  { timeout: 15_000 },
  async (context) => {
    const f = fixture(context),
      owner = f.owner(30),
      handle = await owner.grant(),
      key = f.key();
    await f.writer.client.put(key).lease(handle.id).value('temporary');
    handle.keepAlive();
    f.parent.abort('Application stopped');
    await owner.dispose();
    assert.deepEqual((await f.writer.client.get(key).exec()).kvs, []);
    assert.equal((await f.writer.client.leaseClient.leaseTimeToLive({ ID: handle.id })).TTL, '-1');
    assert.equal(f.closed, 1);
    await handle.revoke();
  },
);

test(
  'EK-DB-002 a native grant acknowledgment fault retains its selected ID for real owned cleanup without replay',
  { timeout: 15_000 },
  async (context) => {
    const f = fixture(context),
      owner = f.owner(30),
      original = LeaseClient.prototype.leaseGrant;
    let grants = 0;
    const fault = context.mock.method(
      LeaseClient.prototype,
      'leaseGrant',
      async function (this: LeaseClient, ...args: Parameters<LeaseClient['leaseGrant']>) {
        const result = await Reflect.apply(original, this, args);
        if (args[0].ID === owner.id) {
          grants++;
          throw new GRPCUnavailableError('Injected lost acknowledgment');
        }
        return result;
      },
    );
    await assert.rejects(
      owner.grant(),
      (error) =>
        error instanceof KitError &&
        error.details.outcome === 'unknown' &&
        error.retryable === false,
    );
    fault.mock.restore();
    assert.equal(grants, 1);
    assert.ok(
      BigInt((await f.writer.client.leaseClient.leaseTimeToLive({ ID: owner.id })).TTL) >= 0n,
    );
    await owner.dispose();
    assert.equal((await f.writer.client.leaseClient.leaseTimeToLive({ ID: owner.id })).TTL, '-1');
  },
);

test(
  'EK-DB-002 a real duplicate lease ID rejection never revokes the already existing lease',
  { timeout: 15_000 },
  async (context) => {
    const f = fixture(context),
      first = f.owner(30),
      handle = await first.grant(),
      second = f.owner(30, handle.id);
    await assert.rejects(second.grant());
    await second.dispose();
    assert.ok(
      BigInt((await f.writer.client.leaseClient.leaseTimeToLive({ ID: handle.id })).TTL) >= 0n,
    );
    first.assertUsable();
    await handle.revoke();
  },
);
