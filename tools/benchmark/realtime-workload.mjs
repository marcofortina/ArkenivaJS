// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { get } from 'node:http';
import { once } from 'node:events';
import Fastify from 'fastify';
import websocket from '@fastify/websocket';
import { fastifySSE } from '@fastify/sse';
import WebSocket from 'ws';
import { SseCursorError } from '@arkenivajs/realtime';
import { nativeAuth, authConnection } from './auth-workload.mjs';

const data = ['Unicode: π 😀', 'first\nsecond\n', ''];
export const realtimePolicy = {
  requireAuth: true,
  maxConnectionsPerTenant: 2,
  maxMessageBytes: 32768,
  maxBufferBytes: 65536,
  heartbeatMs: 1000,
  idleTimeoutMs: 5000,
};

function cursorIndex(tenant, cursor) {
  if (cursor === undefined) return 0;
  if (cursor === tenant + '_expired') throw new SseCursorError('expired');
  const ids = [1, 2, 3].map((i) => tenant + '_' + i);
  const index = ids.indexOf(cursor);
  if (index < 0) throw new SseCursorError('invalid');
  return index + 1;
}

export function realtimeSettings(fixture) {
  authConnection(fixture);
  return {
    routes: [
      { kind: 'websocket', path: '/socket', policyKey: 'owned', handlerKey: 'echo' },
      { kind: 'sse', path: '/events', policyKey: 'owned', sourceKey: 'events' },
    ],
    policies: { owned: realtimePolicy },
    websocketHandlers: {
      async echo(session) {
        for await (const message of session.receive()) await session.send(message);
      },
    },
    sseSources: {
      events: {
        usage: 'test-only',
        kind: 'durable',
        async validateCursor(context) {
          cursorIndex(context.tenant.tenantId, context.lastEventId);
        },
        async *subscribe(context) {
          for (
            let i = cursorIndex(context.tenant.tenantId, context.lastEventId);
            i < data.length;
            i++
          ) {
            if (context.signal.aborted) return;
            yield { id: context.tenant.tenantId + '_' + (i + 1), type: 'update', data: data[i] };
          }
        },
      },
    },
    policy: { maxConcurrent: 8, timeoutMs: 1000 },
  };
}

/** Real JOSE admission precedes the native Fastify WebSocket and SSE route handlers. */
export async function nativeRealtime(fixture) {
  const auth = nativeAuth(fixture),
    server = Fastify({ logger: false });
  try {
    await server.register(websocket, { options: { maxPayload: realtimePolicy.maxMessageBytes } });
    await server.register(fastifySSE, {
      heartbeatInterval: 1000,
      maxBufferBytes: 65536,
      serializer: (value) => value,
    });
    server.addHook('onRequest', async (request, reply) => {
      try {
        const identity = await auth.verifyBearer(request.headers.authorization);
        request.ownedTenant = auth.tenantFrom(identity).tenantId;
      } catch {
        return reply.code(401).send({ error: 'Authentication failed' });
      }
    });
    server.get('/socket', { websocket: true }, (socket) => {
      socket.on('error', () => undefined);
      socket.on('message', (bytes) => socket.send(bytes, { binary: false }));
    });
    server.get('/events', { sse: 'only' }, async (request, reply) => {
      let index;
      try {
        index = cursorIndex(request.ownedTenant, request.headers['last-event-id']);
      } catch {
        return reply
          .code(request.headers['last-event-id'] === request.ownedTenant + '_expired' ? 410 : 409)
          .send({ error: 'Cursor rejected' });
      }
      for (let i = index; i < data.length; i++)
        await reply.sse.send({
          id: request.ownedTenant + '_' + (i + 1),
          event: 'update',
          data: data[i],
        });
      reply.sse.close();
      return reply;
    });
    await server.listen({ host: '127.0.0.1', port: 0 });
    return {
      address: () => 'http://127.0.0.1:' + server.server.address().port,
      close: () => server.close(),
    };
  } catch (cause) {
    await server.close();
    throw cause;
  }
}

function realtimeOrigin(service) {
  const url = new URL(service.address());
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port);
  return url.origin;
}

export function readSse(service, headers) {
  const origin = realtimeOrigin(service);
  return new Promise((done, reject) => {
    const outgoing = get(
      origin + '/events',
      {
        agent: false,
        signal: AbortSignal.timeout(4000),
        headers: { accept: 'text/event-stream', ...headers },
      },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          body += chunk;
          if (Buffer.byteLength(body) > 4096)
            response.destroy(new Error('The owned SSE response exceeded its bound'));
        });
        response.once('error', reject);
        response.once('end', () =>
          done({ status: response.statusCode, body, headers: response.headers }),
        );
      },
    );
    outgoing.once('error', reject);
  });
}

async function rejectUpgrade(service, token) {
  const socket = new WebSocket(realtimeOrigin(service).replace('http:', 'ws:') + '/socket', {
    ...(token ? { headers: { authorization: 'Bearer ' + token } } : {}),
    handshakeTimeout: 3000,
  });
  try {
    return await new Promise((done, reject) => {
      socket.on('error', () => undefined);
      socket.once('unexpected-response', (_request, response) => {
        response.resume();
        socket.terminate();
        done(response.statusCode);
      });
      socket.once('open', () => {
        socket.terminate();
        reject(new Error('An unauthorized WebSocket upgrade was accepted'));
      });
    });
  } finally {
    socket.terminate();
  }
}

export async function verifyRealtime(service, fixture) {
  assert.equal((await readSse(service, {})).status, 401);
  assert.equal(
    (await readSse(service, { authorization: 'Bearer ' + fixture.invalidToken })).status,
    401,
  );
  assert.equal(
    (await readSse(service, { authorization: 'Bearer ' + fixture.foreignTenantToken })).status,
    401,
  );
  const headers = { authorization: 'Bearer ' + fixture.token };
  const full = await readSse(service, headers);
  assert.equal(full.status, 200);
  assert.equal(full.headers['content-type'], 'text/event-stream');
  const frames = data.map(
    (value, i) =>
      `id: ${fixture.tenant}_${i + 1}\nevent: update\n` +
      value
        .split('\n')
        .map((line) => 'data: ' + line + '\n')
        .join('') +
      '\n',
  );
  assert.equal(full.body, frames.join(''));
  const resumed = await readSse(service, { ...headers, 'last-event-id': fixture.tenant + '_2' });
  assert.equal(resumed.status, 200);
  assert.equal(resumed.body, frames[2]);
  for (const [cursor, status] of [
    ['foreign_1', 409],
    [fixture.tenant + '_unknown', 409],
    [fixture.tenant + '_expired', 410],
  ])
    assert.equal((await readSse(service, { ...headers, 'last-event-id': cursor })).status, status);
  assert.equal(await rejectUpgrade(service), 401);
  assert.equal(await rejectUpgrade(service, fixture.invalidToken), 401);
  assert.equal(await rejectUpgrade(service, fixture.foreignTenantToken), 401);
  const socket = new WebSocket(realtimeOrigin(service).replace('http:', 'ws:') + '/socket', {
    headers,
    handshakeTimeout: 3000,
  });
  try {
    await once(socket, 'open');
    const message = {
      channel: 'updates',
      payload: Buffer.from([0, 255, 128, 1]).toString('base64url'),
      id: 'owned_realtime_message',
    };
    const answer = once(socket, 'message');
    socket.send(JSON.stringify(message));
    const [frame] = await answer;
    assert.deepEqual(JSON.parse(String(frame)), message);
    const closed = once(socket, 'close');
    socket.close();
    await closed;
  } finally {
    socket.terminate();
  }
  return {
    authenticatedWebSocketEcho: true,
    unauthenticatedTransportsRejected: true,
    unauthorizedTenantRejected: true,
    actualSseFrames: 3,
    exactUnicodeMultilineAndEmptyData: true,
    ownedResumeVerified: true,
    foreignUnknownAndExpiredCursorsRejected: true,
  };
}
