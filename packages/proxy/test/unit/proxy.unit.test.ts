// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, send } from '../fixture.js';
import { proxyPlugin } from '../../dist/index.js';

test('Actual official proxy preserves fixed path/query and content while removing spoofed identity headers', async () => {
  const f = await fixture();
  try {
    const token = await f.token();
    const result = await send(
      f.origin,
      '/orders/123?a=one%20two&a=three&upstream=http%3A%2F%2F169.254.169.254',
      'POST',
      {
        authorization: token,
        cookie: 'private-cookie',
        'x-forwarded-user': 'forged',
        'x-forwarded-host': 'foreign.invalid',
        'x-tenant-id': 'tenant-b',
        'proxy-authorization': 'private-proxy',
        traceparent: '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01',
        baggage: 'subject=private',
        'content-type': 'application/json',
        host: 'foreign.invalid',
      },
      [Buffer.from('{"hello":"world"}')],
    );
    assert.equal(result.status, 200, result.body);
    const echoed = JSON.parse(result.body) as {
      url: string;
      headers: Record<string, string>;
      bytes: number;
    };
    assert.equal(
      echoed.url,
      '/api/orders/123?a=one%20two&a=three&upstream=http%3A%2F%2F169.254.169.254',
    );
    assert.equal(echoed.bytes, 17);
    for (const header of [
      'authorization',
      'cookie',
      'x-forwarded-user',
      'x-forwarded-host',
      'x-tenant-id',
      'proxy-authorization',
      'traceparent',
      'baggage',
    ])
      assert.equal(echoed.headers[header], undefined, header);
    assert.equal(echoed.headers['content-type'], 'application/json');
    assert.equal(result.headers['cache-control'], 'no-store');
    await delay(0);
    assert.equal(f.service.stats().activeRequests, 0);
    assert.equal(f.service.stats().forwardedRequests, 1);
    assert.ok(f.service.stats().observedResponseBytes > 0);
    assert.ok(!f.logs().includes(token));
    assert.ok(!f.logs().includes('private-cookie'));
  } finally {
    await f.close();
  }
});

test('Actual JWT authentication and scopes reject before any upstream request', async () => {
  const f = await fixture();
  try {
    for (const [authorization, expected] of [
      [undefined, 401],
      ['Bearer invalid', 401],
      [await f.token('orders:write'), 403],
    ] as const) {
      const result = await send(f.origin, '/orders', 'GET', authorization ? { authorization } : {});
      assert.equal(result.status, expected, result.body);
    }
    assert.equal(f.received.length, 0);
    assert.equal(f.service.stats().forwardedRequests, 0);
    assert.equal(f.service.stats().rejectedRequests, 3);
  } finally {
    await f.close();
  }
});

test('Declared and streamed request byte limits cannot reach an upstream as successful oversized bodies', async () => {
  const f = await fixture({ maxRequestBytes: 4 });
  try {
    const authorization = await f.token();
    for (const extra of [{ 'content-length': '8' }, {}]) {
      const result = await send(
        f.origin,
        '/orders',
        'POST',
        { authorization, 'content-type': 'application/octet-stream', ...extra },
        [Buffer.from('12345678')],
      );
      assert.equal(result.status, 413, result.body);
      assert.equal(JSON.parse(result.body).error.code, 'EK_PROXY_BODY_LIMIT');
    }
    assert.ok(f.received.every((entry) => entry.bytes <= 4));
  } finally {
    await f.close();
  }
});

test('An unresponsive upstream reaches a finite sanitized deadline and does not prevent a later request', async () => {
  let slow = true;
  const f = await fixture({ timeoutMs: 80 }, (_request, response) => {
    if (!slow) response.end('healthy');
  });
  try {
    const authorization = await f.token();
    const expired = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(expired.status, 504, expired.body);
    assert.match(expired.body, /EK_PROXY_TIMEOUT/);
    assert.ok(!expired.body.includes(f.route.upstreamOrigin));
    slow = false;
    const recovered = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(recovered.status, 200, recovered.body);
    assert.equal(recovered.body, 'healthy');
  } finally {
    await f.close();
  }
});

test('An upstream redirect is never followed and cannot expose an internal Location or cookie', async () => {
  const f = await fixture({}, (_request, response) => {
    response.writeHead(302, {
      location: 'http://169.254.169.254/private',
      'set-cookie': 'private-cookie=secret',
    });
    response.end('redirect');
  });
  try {
    const result = await send(f.origin, '/orders', 'GET', { authorization: await f.token() });
    assert.equal(result.status, 302, result.body);
    assert.equal(result.headers.location, undefined);
    assert.equal(result.headers['set-cookie'], undefined);
  } finally {
    await f.close();
  }
});

test('Unsafe private targets, alternate IP forms and missing delegation providers fail at configuration', () => {
  const base = {
    routeId: 'route',
    prefix: '/orders',
    upstreamOrigin: 'http://127.0.0.1',
    methods: ['GET'] as const,
    auth: { required: false as const, reason: 'An owned fixture contains no protected data' },
    maxRequestBytes: 1,
    maxResponseBytes: 1,
    timeoutMs: 1,
    destinationPolicy: { kind: 'public-only' as const },
  };
  for (const origin of [
    'http://127.0.0.1',
    'http://169.254.169.254',
    'http://[::1]',
    'http://2130706433',
    'http://0x7f000001',
    'http://localhost/path',
    'http://user:password@example.test',
  ])
    assert.throws(() => proxyPlugin({ routes: [{ ...base, upstreamOrigin: origin }] }));
  assert.throws(
    () =>
      proxyPlugin({
        routes: [
          {
            ...base,
            upstreamOrigin: 'https://example.test',
            identityDelegation: 'validated-service-credential',
            serviceCredentialSecretRef: 'fixture/service',
          },
        ],
      }),
    { code: 'EK_PROXY_CONFIG' },
  );
});
