// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, send } from '../fixture.js';

test('An oversized declared upstream response is rejected without forwarding its body', async () => {
  const f = await fixture({ maxResponseBytes: 4 }, (_request, response) => {
    response.writeHead(200, { 'content-length': '8' });
    response.end('12345678');
  });
  try {
    const result = await send(f.origin, '/orders', 'GET', { authorization: await f.token() });
    assert.equal(result.status, 413, result.body);
    assert.match(result.body, /EK_PROXY_BODY_LIMIT/);
    assert.ok(!result.body.includes('12345678'));
  } finally {
    await f.close();
  }
});

test('A response overflowing after committed headers terminates the stream without a second JSON reply', async () => {
  const f = await fixture({ maxResponseBytes: 4 }, (_request, response) => {
    response.write('1234');
    setTimeout(() => response.end('5678'), 30);
  });
  try {
    const token = await f.token();
    const result = await new Promise<{ status: number; body: string; complete: boolean }>(
      (resolve, reject) => {
        const outgoing = request(
          f.origin + '/orders',
          { headers: { authorization: token } },
          (response) => {
            const chunks: Buffer[] = [];
            let complete = false;
            response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            response.on('error', () => undefined);
            response.once('end', () => {
              complete = true;
            });
            response.once('close', () =>
              resolve({
                status: response.statusCode!,
                body: Buffer.concat(chunks).toString(),
                complete,
              }),
            );
          },
        );
        outgoing.once('error', reject);
        outgoing.end();
      },
    );
    assert.equal(result.status, 200);
    assert.equal(result.complete, false);
    assert.equal(result.body, '1234');
    await delay(0);
    assert.equal(f.service.stats().activeRequests, 0);
  } finally {
    await f.close();
  }
});

test('Parallel real streams remain isolated and release actual admission after completion', async () => {
  const f = await fixture({}, (request, response) => {
    request.pipe(response);
  });
  try {
    const authorization = await f.token();
    const results = await Promise.all(
      Array.from({ length: 24 }, async (_, index) => {
        const body = Buffer.alloc(65536, index);
        const result = await send(
          f.origin,
          '/orders/' + index,
          'POST',
          { authorization, 'content-type': 'application/octet-stream' },
          [body.subarray(0, 32768), body.subarray(32768)],
        );
        assert.equal(result.status, 200, result.body.slice(0, 64));
        assert.deepEqual(Buffer.from(result.body), body);
        return result;
      }),
    );
    assert.equal(results.length, 24);
    await delay(0);
    const stats = f.service.stats();
    assert.equal(stats.activeRequests, 0);
    assert.equal(stats.forwardedRequests, 24);
    assert.equal(stats.observedRequestBytes, 24 * 65536);
    assert.equal(stats.observedResponseBytes, 24 * 65536);
  } finally {
    await f.close();
  }
});

test('A client abort cancels the upstream stream and permits subsequent requests', async () => {
  let upstreamClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    upstreamClosed = resolve;
  });
  const f = await fixture({}, (request, response) => {
    if (request.url?.endsWith('/healthy')) {
      response.end('healthy');
      return;
    }
    response.write('first');
    const timer = setInterval(() => response.write('more'), 10);
    response.once('close', () => {
      clearInterval(timer);
      upstreamClosed();
    });
  });
  try {
    const authorization = await f.token();
    await new Promise<void>((resolve, reject) => {
      const outgoing = request(
        f.origin + '/orders/slow',
        { headers: { authorization } },
        (response) => {
          response.once('data', () => {
            response.destroy();
            resolve();
          });
          response.on('error', () => undefined);
        },
      );
      outgoing.once('error', reject);
      outgoing.end();
    });
    await closed;
    const healthy = await send(f.origin, '/orders/healthy', 'GET', { authorization });
    assert.equal(healthy.body, 'healthy');
  } finally {
    await f.close();
  }
});
