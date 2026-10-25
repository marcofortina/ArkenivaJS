import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { InterceptingCall } from '@grpc/grpc-js';
import type { Interceptor } from '@grpc/grpc-js';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { etcdConfiguration } from '../../dist/config.js';
import { EtcdTransport, etcdCallOptions } from '../../dist/transport.js';
import type { EtcdCallScope } from '../../dist/transport.js';

function fixture(context: TestContext) {
  assert.equal(
    process.env.ARKENIVA_ETCD_DISPOSABLE,
    '1',
    'An explicitly disposable etcd fixture is required',
  );
  assert.ok(process.env.ARKENIVA_ETCD_URL, 'The authenticated TLS fixture is required');
  const configuration = etcdConfiguration(
    { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' },
    'test',
  );
  const lifetime = new AbortController(),
    transport = new EtcdTransport(configuration, lifetime.signal);
  context.after(() => {
    lifetime.abort();
    transport.client.close();
  });
  return { transport, key: configuration.prefix + 'transport:' + randomUUID() };
}

function held(scope: EtcdCallScope) {
  let release = () => {};
  let submitted!: () => void;
  const ready = new Promise<void>((resolve) => {
    submitted = resolve;
  });
  const hold: Interceptor = (options, nextCall) =>
    new InterceptingCall(nextCall(options), {
      sendMessage(message, next) {
        let forwarded = false;
        release = () => {
          if (forwarded) return;
          forwarded = true;
          next(message);
        };
        submitted();
      },
    });
  const options = etcdCallOptions(scope);
  return {
    options: {
      ...options,
      interceptors: [...options.interceptors!, hold],
    },
    ready,
    release: () => release(),
  };
}

for (const kind of ['abort', 'deadline'] as const) {
  test(
    `EK-CORE-001 real etcd ${kind} cancels one native call without resetting another in-flight request`,
    { timeout: 15_000 },
    async (context) => {
      const { transport, key } = fixture(context);
      const firstAbort = new AbortController(),
        secondAbort = new AbortController();
      const firstScope: EtcdCallScope = {
        signal: firstAbort.signal,
        timeoutMs: kind === 'deadline' ? 250 : 5000,
        submitted: false,
      };
      const secondScope: EtcdCallScope = {
        signal: secondAbort.signal,
        timeoutMs: 5000,
        submitted: false,
      };
      const first = held(firstScope),
        second = held(secondScope);
      const abandoned = transport.run(firstScope, () =>
        transport.client.get(key).options(first.options).exec(),
      );
      const retained = transport.run(secondScope, () =>
        transport.client.get(key).options(second.options).exec(),
      );
      void abandoned.catch(() => undefined);
      void retained.catch(() => undefined);
      try {
        await within(() => Promise.all([first.ready, second.ready]), { timeoutMs: 2000 });
        if (kind === 'abort') firstAbort.abort('Caller stopped');
        await assert.rejects(
          abandoned,
          (error) =>
            error instanceof KitError &&
            error.code === (kind === 'abort' ? 'EK_ABORTED' : 'EK_TIMEOUT'),
        );
        assert.equal(firstScope.submitted, true);
        second.release();
        const response = await retained;
        assert.deepEqual(response.kvs, []);
        assert.equal(secondScope.submitted, true);
        const next = await transport.client.get(key).exec();
        assert.deepEqual(next.kvs, []);
      } finally {
        firstAbort.abort();
        secondAbort.abort();
        first.release();
        second.release();
        await Promise.allSettled([abandoned, retained]);
      }
    },
  );
}
