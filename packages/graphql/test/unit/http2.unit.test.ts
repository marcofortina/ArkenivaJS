// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { connect, constants } from 'node:http2';
import type { ClientHttp2Session, IncomingHttpHeaders } from 'node:http2';
import { setImmediate } from 'node:timers/promises';
import { fixture, send, tlsFiles } from '../fixture.js';

function request(session: ClientHttp2Session, query: string, headers: Record<string, string> = {}) {
  const stream = session.request({
    ':path': '/graphql',
    ':method': 'POST',
    'content-type': 'application/json',
    ...headers,
  });
  const response = new Promise<{ status: number; headers: IncomingHttpHeaders; body: string }>(
    (resolve, reject) => {
      let received: IncomingHttpHeaders | undefined;
      const chunks: Buffer[] = [];
      stream.once('response', (headers) => {
        received = headers;
      });
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.once('error', reject);
      stream.once('end', () => {
        if (!received) return reject(new Error('HTTP2 GraphQL stream ended without headers'));
        resolve({
          status: Number(received[':status']),
          headers: received,
          body: Buffer.concat(chunks).toString(),
        });
      });
      stream.setTimeout(5000, () => stream.destroy(new Error('HTTP2 GraphQL fixture timed out')));
    },
  );
  stream.end(JSON.stringify({ query }));
  return { stream, response };
}

test('GraphQL negotiates verified h2 and isolates signed tenants, mutations and browser policy on the shared listener', async () => {
  const tls = await tlsFiles(),
    values = new Map<string, number>();
  const f = await fixture(
    {
      schema: 'type Query { value: Int! } type Mutation { increment: Int! }',
      resolvers: {
        Query: { value: (_parent, _args, context) => values.get(context.auth!.tenantId) ?? 0 },
        Mutation: {
          increment: (_parent, _args, context) => {
            const tenant = context.auth!.tenantId,
              next = (values.get(tenant) ?? 0) + 1;
            values.set(tenant, next);
            return next;
          },
        },
      },
      security: { authorizeField: () => true },
    },
    { tls: tls.tls, http2: true },
  );
  const session = connect(f.origin, { ca: tls.ca });
  session.on('error', () => {});
  try {
    await once(session, 'connect');
    assert.equal(session.alpnProtocol, 'h2');
    const a = await f.token(),
      b = await f.token('tenant-b');
    const changed = await request(session, 'mutation { increment }', { authorization: a }).response;
    assert.equal(changed.status, 200, changed.body);
    assert.deepEqual(JSON.parse(changed.body), { data: { increment: 1 } });
    assert.equal(changed.headers.connection, undefined);
    const [first, second] = await Promise.all([
      request(session, '{ value }', { authorization: a, 'x-tenant-id': 'tenant-b' }).response,
      request(session, '{ value }', { authorization: b, 'x-tenant-id': 'tenant-a' }).response,
    ]);
    assert.deepEqual(JSON.parse(first.body), { data: { value: 1 } });
    assert.deepEqual(JSON.parse(second.body), { data: { value: 0 } });
    assert.equal(
      (
        await request(session, 'mutation { increment }', { authorization: 'Bearer forged' })
          .response
      ).status,
      401,
    );
    assert.equal((await request(session, 'mutation { increment }').response).status, 401);
    for (const headers of [
      { cookie: 'session=untrusted' },
      { origin: 'https://foreign.invalid' },
      { 'sec-fetch-site': 'cross-site' },
    ]) {
      const denied = await request(session, 'mutation { increment }', {
        authorization: a,
        ...headers,
      }).response;
      assert.equal(denied.status, 403, denied.body);
    }
    assert.equal(values.get('tenant-a'), 1);
    const fallback = await send(
      f.origin,
      { query: '{ value }' },
      { ca: tls.ca, headers: { authorization: a } },
    );
    assert.equal(fallback.status, 200, fallback.body);
    assert.deepEqual(fallback.json(), { data: { value: 1 } });
    assert.equal(f.service.stats().operations, 9);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.equal(f.api.stats().completed, 9);
    assert.doesNotMatch(f.logs(), /Bearer |session=untrusted/);
  } finally {
    session.destroy();
    await f.close();
    await tls.close();
  }
});

test(
  'GraphQL drains an accepted h2 operation before closing the existing listener',
  { timeout: 15000 },
  async () => {
    const tls = await tlsFiles();
    let entered!: () => void, release!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = await fixture(
      {
        schema: 'type Query { delayed: String! }',
        resolvers: {
          Query: {
            delayed: async () => {
              entered();
              await gate;
              return 'settled';
            },
          },
        },
        security: { authorizeField: () => true },
      },
      { tls: tls.tls, http2: true },
    );
    const native = f.api.native();
    const session = connect(f.origin, { ca: tls.ca });
    session.on('error', () => {});
    try {
      await once(session, 'connect');
      const pending = request(session, '{ delayed }', { authorization: await f.token() }).response;
      await started;
      assert.equal(f.service.stats().activeOperations, 1);
      const stopping = f.app.stop({ timeoutMs: 2000 });
      release();
      const result = await pending;
      assert.equal(result.status, 200, result.body);
      assert.deepEqual(JSON.parse(result.body), { data: { delayed: 'settled' } });
      await stopping;
      assert.equal(f.app.state, 'CLOSED');
      assert.equal(native.server.listening, false);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(f.service.health().ready, false);
    } finally {
      release();
      session.destroy();
      await f.close();
      await tls.close();
    }
  },
);

test(
  'Resetting one h2 stream cancels its resolver and leaves the multiplexed session usable',
  { timeout: 15000 },
  async () => {
    const tls = await tlsFiles();
    let entered!: () => void, cancelled!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const aborted = new Promise<void>((resolve) => {
      cancelled = resolve;
    });
    const f = await fixture(
      {
        schema: 'type Query { delayed: String ping: String! }',
        resolvers: {
          Query: {
            ping: () => 'pong',
            delayed: async (_parent, _args, context) => {
              entered();
              await new Promise<void>((resolve) =>
                context.signal.addEventListener(
                  'abort',
                  () => {
                    cancelled();
                    resolve();
                  },
                  { once: true },
                ),
              );
              return null;
            },
          },
        },
        security: { authorizeField: () => true },
      },
      { tls: tls.tls, http2: true },
    );
    const session = connect(f.origin, { ca: tls.ca });
    session.on('error', () => {});
    try {
      await once(session, 'connect');
      const authorization = await f.token();
      const pending = request(session, '{ delayed }', { authorization });
      const rejected = assert.rejects(pending.response);
      await started;
      pending.stream.close(constants.NGHTTP2_CANCEL);
      await Promise.all([aborted, rejected]);
      await setImmediate();
      const next = await request(session, '{ ping }', { authorization }).response;
      assert.equal(next.status, 200, next.body);
      assert.deepEqual(JSON.parse(next.body), { data: { ping: 'pong' } });
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(session.destroyed, false);
    } finally {
      session.destroy();
      await f.close();
      await tls.close();
    }
  },
);
