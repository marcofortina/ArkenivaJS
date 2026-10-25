import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { Etcd3, LeaseClient, WatchClient } from 'etcd3';
import type { ILeaseGrantRequest, IWatchRequest, IWatchResponse, IDuplexStream } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { Logger } from '@arkenivajs/core';
import { nativeDouble, header } from '../fixtures/native-double.js';

/** Resource admission tests keep the actual SDK clients and replace only their exported RPC boundary. */
class ResourceStream extends EventEmitter {
  cancels = 0;
  broken = false;
  constructor(private readonly compacted = false) {
    super();
  }
  write(request: IWatchRequest) {
    if (request.create_request)
      setImmediate(() =>
        this.emit('data', {
          header,
          events: [],
          compact_revision: this.compacted ? '9' : '0',
          created: !this.compacted,
          canceled: this.compacted,
        }),
      );
    return true;
  }
  cancel() {
    this.cancels++;
    this.emit('status', {});
    if (this.broken) throw new Error('Owned stream cleanup failed');
  }
}

function watchBoundary(context: TestContext, make = () => new ResourceStream()) {
  const streams: ResourceStream[] = [];
  context.mock.method(WatchClient.prototype, 'watch', async () => {
    const stream = make();
    streams.push(stream);
    return stream as unknown as IDuplexStream<IWatchRequest, IWatchResponse>;
  });
  return streams;
}

test('etcd independently bounds owned watches and leases and releases every admitted SDK resource', async (context) => {
  const f = nativeDouble(context),
    streams = watchBoundary(context),
    revocations: string[] = [];
  context.mock.method(LeaseClient.prototype, 'leaseGrant', async (request: ILeaseGrantRequest) => ({
    ID: request.ID,
    TTL: '30',
    error: '',
  }));
  context.mock.method(LeaseClient.prototype, 'leaseRevoke', async (request: { ID: string }) => {
    revocations.push(request.ID);
    return {};
  });
  await f.connection.start();
  const watches = await Promise.all(
    Array.from({ length: 64 }, (_, index) => f.connection.watch('resource:' + index)),
  );
  await assert.rejects(f.connection.watch('overflow'), { code: 'EK_BACKEND_UNAVAILABLE' });
  const leases = await Promise.all(Array.from({ length: 64 }, () => f.connection.grantLease(30)));
  await assert.rejects(f.connection.grantLease(30), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(new Set(leases.map((lease) => lease.id)).size, 64);
  await f.connection.close();
  assert.equal(revocations.length, 64);
  assert.ok(streams.every((stream) => stream.cancels === 1));
  assert.deepEqual(await watches[0]![Symbol.asyncIterator]().next(), {
    done: true,
    value: undefined,
  });
});

test('etcd retains acquisition history gaps and reports owned cleanup faults at shutdown', async (context) => {
  const warnings: string[] = [];
  const f = nativeDouble(context, {
    logger: {
      warn: (message: string) => {
        warnings.push(message);
      },
    } as unknown as Logger,
  });
  f.allowCloseFailure();
  watchBoundary(context, () => {
    const stream = new ResourceStream(true);
    stream.broken = true;
    return stream;
  });
  await f.connection.start();
  await assert.rejects(
    f.connection.watch('gap'),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_KV_CONFLICT' &&
      cause.details.watchGap === true &&
      cause.cause instanceof AggregateError,
  );
  await assert.rejects(f.connection.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.ok(warnings.includes('etcd resource cleanup failed'));
});

test('etcd rejects malformed readiness and closes a failed watch acquisition without hiding its outcome', async (context) => {
  await context.test('readiness must return a bounded keys-only response', async (child) => {
    const f = nativeDouble(child);
    f.plan('range', { value: { header, kvs: [1, 2] } });
    await assert.rejects(f.connection.start(), { code: 'EK_BACKEND_UNAVAILABLE' });
  });
  await context.test(
    'known rejected grant releases its client without revoking another identity',
    async (child) => {
      const f = nativeDouble(child),
        revoked: string[] = [];
      child.mock.method(LeaseClient.prototype, 'leaseGrant', async () => ({
        error: 'Rejected',
        ID: '1',
        TTL: '0',
      }));
      child.mock.method(LeaseClient.prototype, 'leaseRevoke', async (request: { ID: string }) => {
        revoked.push(request.ID);
        return {};
      });
      await f.connection.start();
      await assert.rejects(
        f.connection.grantLease(30),
        (cause: unknown) =>
          cause instanceof KitError &&
          cause.code === 'EK_KV_CONFLICT' &&
          cause.details.outcome === undefined,
      );
      assert.deepEqual(revoked, []);
    },
  );
  await context.test('failed watch open closes its admitted resource', async (child) => {
    const f = nativeDouble(child);
    watchBoundary(child, () => new ResourceStream(true));
    await f.connection.start();
    await assert.rejects(f.connection.watch('gap'), { code: 'EK_KV_CONFLICT' });
    await f.connection.close();
  });
});

test('etcd failed grant retains its requested ID when client cleanup also fails', async (context) => {
  const f = nativeDouble(context);
  f.allowCloseFailure();
  await f.connection.start();
  const primary = f.connection.native(),
    close = Etcd3.prototype.close;
  context.mock.method(Etcd3.prototype, 'close', function (this: Etcd3) {
    if (this !== primary) throw new Error('Owned client close failed');
    return close.call(this);
  });
  context.mock.method(LeaseClient.prototype, 'leaseGrant', async () => ({
    ID: '0',
    TTL: '30',
    error: '',
  }));
  context.mock.method(LeaseClient.prototype, 'leaseRevoke', async () => ({}));
  await assert.rejects(
    f.connection.grantLease(30),
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_BACKEND_UNAVAILABLE' &&
      typeof cause.details.leaseId === 'string' &&
      cause.cause instanceof AggregateError,
  );
  await assert.rejects(f.connection.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
});

test('etcd counts recovered watches without replaying portable operations', async (context) => {
  const f = nativeDouble(context),
    streams = watchBoundary(context);
  await f.connection.start();
  const watch = await f.connection.watch('recovery');
  streams[0]!.emit('end');
  const expires = performance.now() + 3000;
  while (streams.length < 2) {
    assert.ok(performance.now() < expires, 'The owned watch did not reconnect');
    await delay(5);
  }
  assert.equal(f.connection.stats().reconnects, 1);
  await watch.close();
});
