// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, send } from '../fixture.js';

test('Native 503 responses are never retried, including non-idempotent POST requests', async () => {
  let calls = 0;
  const f = await fixture({}, (request, response) => {
    calls++;
    request.resume();
    response.writeHead(503);
    response.end('unavailable');
  });
  try {
    const authorization = await f.token();
    for (const method of ['GET', 'POST']) {
      const result = await send(f.origin, '/orders', method, { authorization });
      assert.equal(result.status, 503, result.body);
    }
    assert.equal(calls, 2);
  } finally {
    await f.close();
  }
});

test(
  'The finite admission ceiling rejects excess requests while native streams remain physically held',
  { timeout: 10000 },
  async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = await fixture(
      {
        timeoutMs: 3000,
        auth: { required: false, reason: 'The owned admission fixture has no protected data' },
      },
      (_request, response) => {
        void held.then(() => response.end('released'));
      },
    );
    const pending = Array.from({ length: 64 }, () => send(f.origin, '/orders'));
    const results = Promise.all(pending);
    void results.catch(() => undefined);
    try {
      const deadline = Date.now() + 2000;
      while (f.service.stats().activeRequests < 64 && Date.now() < deadline) await delay(2);
      assert.equal(f.service.stats().activeRequests, 64);
      const excess = await send(f.origin, '/orders');
      assert.equal(excess.status, 503, excess.body);
      assert.equal(JSON.parse(excess.body).error.code, 'EK_BACKEND_UNAVAILABLE');
      release();
      assert.ok((await results).every((result) => result.status === 200));
      await delay(0);
      assert.equal(f.service.stats().activeRequests, 0);
    } finally {
      release();
      await Promise.allSettled(pending);
      await f.close();
    }
  },
);

test('Application shutdown drains an existing upstream stream and invalidates readiness', async () => {
  let entered!: () => void, release!: () => void;
  const active = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  const f = await fixture({}, (_request, response) => {
    entered();
    void held.then(() => response.end('drained'));
  });
  try {
    const result = send(f.origin, '/orders', 'GET', { authorization: await f.token() });
    await active;
    let stopped = false;
    const stopping = f.app.stop().then(() => {
      stopped = true;
    });
    await delay(20);
    assert.equal(stopped, false);
    assert.equal(f.service.health().ready, false);
    release();
    assert.equal((await result).body, 'drained');
    await stopping;
    assert.equal(f.service.stats().activeRequests, 0);
    assert.equal(f.service.health().ready, false);
  } finally {
    release();
    await f.close();
  }
});

test('An unavailable upstream reports a fixed 502 and recovers after the same owned server restarts', async () => {
  const f = await fixture();
  try {
    const address = f.upstream.address();
    assert.ok(address && typeof address === 'object');
    f.upstream.closeAllConnections();
    await new Promise<void>((resolve) => f.upstream.close(() => resolve()));
    const authorization = await f.token();
    const unavailable = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(unavailable.status, 502, unavailable.body);
    assert.equal(JSON.parse(unavailable.body).error.code, 'EK_PROXY_UPSTREAM');
    await new Promise<void>((resolve) => f.upstream.listen(address.port, '127.0.0.1', resolve));
    const recovered = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(recovered.status, 200, recovered.body);
  } finally {
    await f.close();
  }
});

test('The native HTTP parser rejects conflicting framing before any upstream operation', async () => {
  const f = await fixture({
    auth: { required: false, reason: 'The owned framing test accepts no protected data' },
  });
  try {
    const origin = new URL(f.origin);
    const response = await new Promise<string>((resolve, reject) => {
      const socket = connect({ host: origin.hostname, port: Number(origin.port) });
      let received = '';
      socket.setTimeout(2000, () =>
        socket.destroy(new Error('The native framing check exceeded its deadline')),
      );
      socket.on('data', (chunk) => {
        received += chunk.toString('latin1');
      });
      socket.once('error', reject);
      socket.once('close', () => resolve(received));
      socket.once('connect', () =>
        socket.end(
          'POST /orders HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n',
        ),
      );
    });
    assert.match(response, /^HTTP\/1\.1 400/);
    assert.equal(f.received.length, 0);
  } finally {
    await f.close();
  }
});

test('Alternate encoded traversal and absolute request targets never alter the fixed destination', async () => {
  const f = await fixture();
  try {
    const authorization = await f.token();
    for (const path of [
      '/orders/%2e%2e/private',
      '/orders/%2f%2fevil.invalid',
      '/orders/%252e%252e/private',
      '/orders/a%5c..%5cprivate',
    ]) {
      const response = await send(f.origin, path, 'GET', { authorization });
      assert.equal(response.status, 403, response.body);
    }
    assert.equal(f.received.length, 0);
  } finally {
    await f.close();
  }
});
