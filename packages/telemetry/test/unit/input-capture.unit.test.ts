// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { createTelemetry } from '@arkenivajs/telemetry';

const service = { name: 'telemetry-capture-test', version: '1.0.0', environment: 'test' as const };
const invalid = { code: 'EK_CONFIG_INVALID' };

function watched<T extends object>(value: T, effect: () => void): T {
  return new Proxy(value, {
    getPrototypeOf(target) {
      effect();
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      effect();
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, key) {
      effect();
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
    get(target, key, receiver) {
      effect();
      return Reflect.get(target, key, receiver);
    },
  });
}

test('Telemetry captures configuration before policy reads and rejects nested executable data without side effects', () => {
  let effects = 0;
  const effect = () => {
    effects++;
  };
  const accessor = Object.defineProperty({ service }, 'mode', {
    enumerable: true,
    get() {
      effect();
      return 'off';
    },
  });
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  for (const input of [
    accessor,
    watched({ service, mode: 'off' }, effect),
    { service: watched(service, effect), mode: 'off' },
    { service, mode: 'off', labelValues: { route: watched(['/known'], effect) } },
    revoked.proxy,
  ])
    assert.throws(() => createTelemetry(input as never), invalid);
  assert.equal(effects, 0);
});

test('Remote context accepts only inert own W3C fields and never reads unrelated baggage or identity accessors', async () => {
  const telemetry = createTelemetry({ service, mode: 'off' });
  const traceparent = '00-' + '1'.repeat(32) + '-' + '2'.repeat(16) + '-01';
  let effects = 0,
    callbacks = 0;
  const effect = () => {
    effects++;
  };
  const accessor = Object.defineProperty({}, 'traceparent', {
    enumerable: true,
    get() {
      effect();
      return traceparent;
    },
  });
  const stateAccessor = Object.defineProperty({ traceparent }, 'tracestate', {
    get() {
      effect();
      return 'vendor=value';
    },
  });
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  try {
    for (const headers of [
      accessor,
      stateAccessor,
      watched({ traceparent }, effect),
      revoked.proxy,
      Object.create({ traceparent }),
      { traceparent: watched({}, effect) },
    ])
      assert.throws(
        () =>
          telemetry.withRemoteContext(headers as never, () => {
            callbacks++;
          }),
        invalid,
      );
    assert.equal(effects, 0);
    assert.equal(callbacks, 0);
    const headers = Object.defineProperties(
      { traceparent },
      {
        baggage: {
          get() {
            effect();
            throw new Error('Baggage must not be inspected');
          },
        },
        authorization: {
          get() {
            effect();
            throw new Error('Identity must not be inspected');
          },
        },
      },
    );
    assert.equal(
      telemetry.withRemoteContext(headers, () => {
        assert.equal(telemetry.currentTraceId(), '1'.repeat(32));
        return 42;
      }),
      42,
    );
    assert.equal(telemetry.currentTraceId(), undefined);
    assert.equal(
      telemetry.withRemoteContext(
        Object.assign(Object.create(null) as Record<string, string>, { traceparent }),
        () => telemetry.currentTraceId(),
      ),
      '1'.repeat(32),
    );
    assert.equal(
      telemetry.withRemoteContext({ traceparent: 'invalid' }, () => 7),
      7,
    );
    assert.equal(effects, 0);
  } finally {
    await telemetry.close();
  }
});

test('Span and measurement attributes reject executable wrappers before callbacks and preserve later actual SDK exports', async () => {
  const exports: unknown[] = [];
  const receiver = createServer((request, response) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      exports.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown);
      response.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    })().catch(() => response.writeHead(500).end());
  });
  await new Promise<void>((done) => receiver.listen(0, '127.0.0.1', done));
  const address = receiver.address();
  assert.ok(address && typeof address === 'object');
  const telemetry = createTelemetry({
    service,
    mode: 'detailed',
    endpoint: 'http://127.0.0.1:' + address.port,
    allowInsecureLoopback: true,
    samplingRatio: 1,
    exportIntervalMs: 60000,
  });
  let effects = 0,
    callbacks = 0;
  const effect = () => {
    effects++;
  };
  const accessor = Object.defineProperty({}, 'attributes', {
    enumerable: true,
    get() {
      effect();
      return {};
    },
  });
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  try {
    for (const method of ['withSpan', 'measure'] as const)
      for (const input of [
        accessor,
        watched({ attributes: {} }, effect),
        { attributes: watched({}, effect) },
        { attributes: revoked.proxy },
      ])
        await assert.rejects(
          telemetry[method](
            'capture.invalid',
            () => {
              callbacks++;
            },
            input as never,
          ),
          invalid,
        );
    assert.equal(effects, 0);
    assert.equal(callbacks, 0);
    assert.equal(telemetry.stats().spansStarted, 0);
    for (const method of ['addCounter', 'recordHistogram', 'setGauge'] as const)
      assert.throws(() => telemetry[method]('capture.invalid', 1, watched({}, effect)), invalid);
    assert.equal(effects, 0);
    assert.equal(telemetry.stats().instruments, 0);
    assert.equal(
      await telemetry.measure('capture.healthy', () => 'owned-private-business-value'),
      'owned-private-business-value',
    );
    await telemetry.flush();
    assert.ok(JSON.stringify(exports).includes('capture.healthy'));
    assert.ok(!JSON.stringify(exports).includes('owned-private-business-value'));
  } finally {
    try {
      await telemetry.close();
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((done) => receiver.close(() => done()));
    }
  }
});
