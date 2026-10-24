import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { RequestListener } from 'node:http';
import { createApplication, KitError } from '@arkenivajs/core';
import { createHttpClient, httpPlugin } from '@arkenivajs/http';
import type { HttpObservation } from '@arkenivajs/http';

const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
async function endpoint(handler: RequestListener) {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    port: address.port,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

test('EK-HTTP-002 real GET/POST use bounded responses and safe observations', async () => {
  const events: HttpObservation[] = [];
  const server = await endpoint(async (req, res) => {
    const chunks = [];
    for await (const part of req) chunks.push(part);
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        method: req.method,
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      }),
    );
  });
  const traceparent = '00-1234567890abcdef1234567890abcdef-1234567890abcdef-01';
  const client = createHttpClient({
    allowedOrigins: [server.origin],
    allowPrivateNetwork: true,
    traceHeaders: () => ({ traceparent }),
    serviceToken: async (origin, signal) => {
      assert.equal(origin, server.origin);
      assert.equal(signal.aborted, false);
      return 'fake-service-token';
    },
    onObservation(event) {
      assert.ok(Object.isFrozen(event));
      events.push(event);
    },
  });
  try {
    const get = await client.request(server.origin, {
      headers: {
        'x-tenant-id': 'fake-forged',
        baggage: 'tenant=fake-forged',
        authorization: 'Bearer fake-inbound',
      },
    });
    const data = await get.json();
    assert.equal(get.url, server.origin + '/');
    assert.equal(data.method, 'GET');
    assert.equal(data.headers.traceparent, traceparent);
    assert.equal(data.headers.authorization, 'Bearer fake-service-token');
    assert.equal(data.headers['x-tenant-id'], undefined);
    assert.equal(data.headers.baggage, undefined);
    const post = await client.post(server.origin, { value: 3 }, { idempotencyKey: 'example-key' });
    const posted = await post.json();
    assert.equal(posted.body, '{"value":3}');
    assert.equal(posted.headers['idempotency-key'], 'example-key');
    assert.equal(client.stats().completed, 2);
    assert.equal(client.stats().active, 0);
    assert.ok(events.every((event) => event.durationMs >= 0 && event.responseBytes! > 0));
    assert.ok(!JSON.stringify(events).includes('fake-'));
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 HEAD, empty statuses and redirects retain explicit Response semantics', async () => {
  let calls = 0;
  const server = await endpoint((req, res) => {
    calls++;
    if (req.url === '/redirect') {
      res.statusCode = 302;
      res.setHeader('location', 'http://169.254.169.254/');
    } else res.statusCode = 204;
    res.end();
  });
  const client = createHttpClient({ allowedOrigins: [server.origin], allowPrivateNetwork: true });
  try {
    assert.equal((await client.get(server.origin)).status, 204);
    assert.equal(await (await client.request(server.origin, { method: 'HEAD' })).text(), '');
    const redirect = await client.get(server.origin + '/redirect');
    assert.equal(redirect.status, 302);
    assert.equal(calls, 3);
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 deadlines cover headers and body, signals cancel actual transports', async () => {
  const server = await endpoint((req, res) => {
    if (req.url === '/body') {
      res.writeHead(200);
      res.write('partial');
    }
  });
  const client = createHttpClient({
    allowedOrigins: [server.origin],
    allowPrivateNetwork: true,
    timeoutMs: 20,
  });
  try {
    for (const path of ['', '/body'])
      await assert.rejects(
        client.get(server.origin + path),
        (error) =>
          error instanceof KitError &&
          error.code === 'EK_TIMEOUT' &&
          error.details.upstream === true,
      );
    await assert.rejects(
      client.get(server.origin, { signal: AbortSignal.abort() }),
      code('EK_ABORTED'),
    );
    const controller = new AbortController();
    const pending = client.get(server.origin, { signal: controller.signal, timeoutMs: 1000 });
    controller.abort();
    await assert.rejects(pending, code('EK_ABORTED'));
    assert.equal(client.stats().active, 0);
    await assert.rejects(client.get(server.origin, { timeoutMs: 0 }), code('EK_CONFIG_INVALID'));
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 oversized bodies and broken responses fail without partial success', async () => {
  const server = await endpoint((req, res) => {
    if (req.url === '/broken') {
      res.write('a');
      res.destroy(new Error('fake-private-network'));
    } else res.end('12345678');
  });
  const client = createHttpClient({
    allowedOrigins: [server.origin],
    allowPrivateNetwork: true,
    maxResponseBytes: 4,
  });
  try {
    await assert.rejects(
      client.get(server.origin),
      (error) =>
        error instanceof KitError &&
        error.code === 'EK_HTTP_UPSTREAM' &&
        error.details.limitExceeded === true,
    );
    await assert.rejects(client.get(server.origin + '/broken'), code('EK_HTTP_UPSTREAM'));
    assert.equal(client.stats().failed, 2);
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 retries are opt-in, bounded and never replay POST with an idempotency key', async () => {
  let calls = 0;
  const server = await endpoint((_req, res) => {
    calls++;
    res.statusCode = calls % 2 ? 503 : 200;
    res.end('ok');
  });
  const ordinary = createHttpClient({ allowedOrigins: [server.origin], allowPrivateNetwork: true });
  const retry = createHttpClient({
    allowedOrigins: [server.origin],
    allowPrivateNetwork: true,
    retry: { attempts: 2, delayMs: 0 },
    onObservation() {
      throw new Error('fake-observer');
    },
  });
  try {
    assert.equal((await ordinary.get(server.origin)).status, 503);
    assert.equal(calls, 1);
    calls = 0;
    assert.equal((await retry.get(server.origin)).status, 200);
    assert.equal(calls, 2);
    calls = 0;
    assert.equal((await retry.post(server.origin, {}, { idempotencyKey: 'safe-key' })).status, 503);
    assert.equal(calls, 1);
    assert.equal(retry.stats().observerFailures, 2);
    await assert.rejects(
      retry.request(server.origin, { method: 'PUT', body: new FormData() }),
      code('EK_CONFIG_INVALID'),
    );
  } finally {
    await ordinary.close();
    await retry.close();
    await server.close();
  }
});

test('EK-HTTP-002 network retry uses the same bounded deadline and stops on failure', async () => {
  let calls = 0;
  const server = await endpoint((_req, res) => {
    calls++;
    if (calls === 1) res.destroy();
    else res.end('recovered');
  });
  const client = createHttpClient({
    allowedOrigins: [server.origin],
    allowPrivateNetwork: true,
    retry: { attempts: 2, delayMs: 0 },
  });
  try {
    assert.equal(await (await client.get(server.origin)).text(), 'recovered');
    assert.equal(calls, 2);
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 destination policy rejects alternate IP spellings and metadata endpoints', async () => {
  const mutable = { allowedOrigins: ['https://127.0.0.1'], allowPrivateNetwork: false };
  const snapshotClient = createHttpClient(mutable);
  mutable.allowPrivateNetwork = true;
  try {
    await assert.rejects(snapshotClient.get('https://127.0.0.1'), code('EK_CONFIG_INVALID'));
  } finally {
    await snapshotClient.close();
  }
  for (const origin of [
    'https://127.0.0.1',
    'https://0177.0.0.1',
    'https://[::1]',
    'https://[::ffff:127.0.0.1]',
    'https://[64:ff9b::7f00:1]',
    'https://[2002:7f00:1::]',
    'https://[2001::1]',
    'https://169.254.169.254',
    'https://10.0.0.1',
    'https://192.168.1.2',
  ]) {
    const client = createHttpClient({ allowedOrigins: [origin] });
    try {
      await assert.rejects(client.get(origin), code('EK_CONFIG_INVALID'));
    } finally {
      await client.close();
    }
  }
  const client = createHttpClient({ allowedOrigins: ['https://example.invalid'] });
  try {
    for (const url of [
      'not a URL',
      'https://other.invalid',
      'https://user:fake-secret@example.invalid',
      'https://example.invalid/#fragment',
    ])
      await assert.rejects(client.get(url), code('EK_CONFIG_INVALID'));
  } finally {
    await client.close();
  }
});

test('EK-HTTP-002 connection-time DNS guard rejects rebinding, empty answers and resolver errors', async () => {
  for (const resolve of [
    async () => [{ address: '127.0.0.1', family: 4 as const }],
    async () => [{ address: '8.8.8.8', family: 6 as const }],
    async () => [],
    async () => undefined as never,
    () => {
      throw new Error('fake-sync-dns-secret');
    },
    async () => {
      throw new Error('fake-dns-secret');
    },
  ]) {
    const client = createHttpClient({ allowedOrigins: ['https://allowed.invalid'], resolve });
    try {
      await assert.rejects(client.get('https://allowed.invalid'), code('EK_HTTP_UPSTREAM'));
    } finally {
      await client.close();
    }
  }
  const server = await endpoint((_req, res) => res.end('resolved'));
  const origin = `http://allowed.invalid:${server.port}`;
  const client = createHttpClient({
    allowedOrigins: [origin],
    allowPrivateNetwork: true,
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  });
  try {
    assert.equal(await (await client.get(origin)).text(), 'resolved');
  } finally {
    await client.close();
    await server.close();
  }
});

test('EK-HTTP-002 malformed options and unsafe request policies reject before transport', async () => {
  for (const values of [
    { resolve: 1 },
    { timeoutMs: 0 },
    { maxResponseBytes: 0 },
    { maxResponseBytes: 67_108_865 },
    { connections: 65 },
    { retry: { attempts: 4 } },
    { retry: { attempts: 1, delayMs: -1 } },
    { allowPrivateNetwork: 'yes' },
  ])
    assert.throws(
      () => createHttpClient({ allowedOrigins: [], ...values } as never),
      code('EK_CONFIG_INVALID'),
    );
  for (const origin of [
    'bad',
    'file:///tmp/test',
    'http://example.invalid',
    'https://u:p@example.invalid',
    'https://example.invalid/path',
    'https://example.invalid/?a=b',
  ])
    assert.throws(() => createHttpClient({ allowedOrigins: [origin] }), code('EK_CONFIG_INVALID'));
  const client = createHttpClient({ allowedOrigins: ['https://example.invalid'] });
  try {
    for (const init of [
      undefined,
      { method: 'CONNECT' },
      { redirect: 'follow' },
      { idempotencyKey: 'bad\nkey' },
      { headers: { traceparent: '00-' + '0'.repeat(32) + '-1234567890abcdef-01' } },
      { headers: { traceparent: 'bad' } },
    ])
      await assert.rejects(
        client.request('https://example.invalid', init as never),
        code('EK_CONFIG_INVALID'),
      );
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    await assert.rejects(client.post('https://example.invalid', cycle), code('EK_CONFIG_INVALID'));
  } finally {
    await client.close();
  }
  await assert.rejects(client.get('https://example.invalid'), code('EK_RESOURCE_CLOSED'));
  await client.close();
});

test('EK-HTTP-002 close aborts active work and one factory keeps applications isolated', async () => {
  const server = await endpoint(() => {});
  const plugin = httpPlugin({ allowedOrigins: [server.origin], allowPrivateNetwork: true });
  const options = {
    service: { name: 'http-test', version: '1.0.0', environment: 'test' as const },
    plugins: [plugin],
  };
  const first = await createApplication(options),
    second = await createApplication(options);
  try {
    await first.start();
    await second.start();
    assert.notEqual(first.http, second.http);
    const request = first.http.get(server.origin);
    const rejected = assert.rejects(request, code('EK_ABORTED'));
    await first.stop();
    await rejected;
    await second.stop();
  } finally {
    await first.stop();
    await second.stop();
    await server.close();
  }
});
