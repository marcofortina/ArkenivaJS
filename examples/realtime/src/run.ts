// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { get } from 'node:https';
import { once } from 'node:events';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import WebSocket from 'ws';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { realtimePlugin, REALTIME_CAPABILITY } from '@arkenivajs/realtime';
import type { RealtimeService } from '@arkenivajs/realtime';
import { tlsFixture } from './tls.js';

/** Owned test-only identity and TLS listeners demonstrate public protocol APIs without persistent host services. */
export async function runRealtimeExample() {
  const tls = await tlsFixture(),
    keys = await generateKeyPair('ES256');
  const jwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'realtime-tutorial',
    alg: 'ES256',
    use: 'sig',
  };
  let authority = '',
    app: Awaited<ReturnType<typeof createApplication>> | undefined,
    socket: WebSocket | undefined;
  const issuer = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [jwk] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  try {
    await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
    const address = issuer.address();
    if (!address || typeof address !== 'object')
      throw new Error('The owned tutorial issuer is unavailable');
    authority = 'http://127.0.0.1:' + address.port;
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    if (!reserved || typeof reserved !== 'object')
      throw new Error('The owned tutorial port is unavailable');
    app = await createApplication({
      service: { name: 'realtime-tutorial', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      security: { issuer: authority, audience: 'api://realtime-tutorial', algorithms: ['ES256'] },
      http: { host: '127.0.0.1', port: reserved.port, protocol: 'https', tls: tls.files },
      plugins: [
        loggingPlugin(),
        securityPlugin({ allowInsecureLoopback: true }),
        apiPlugin({ dependencies: ['security'] }),
        realtimePlugin({
          routes: [
            { kind: 'websocket', path: '/socket', handlerKey: 'echo', policyKey: 'bounded' },
            { kind: 'sse', path: '/events', sourceKey: 'updates', policyKey: 'bounded' },
          ],
          websocketHandlers: {
            async echo(session) {
              for await (const message of session.receive()) await session.send(message);
            },
          },
          sseSources: {
            updates: {
              kind: 'pubsub',
              usage: 'test-only',
              async *subscribe(context) {
                if (!context.signal.aborted)
                  yield { id: 'tutorial_1', type: 'update', data: 'hello' };
              },
            },
          },
          policies: {
            bounded: {
              requireAuth: true,
              maxConnectionsPerTenant: 2,
              maxMessageBytes: 16384,
              maxBufferBytes: 32768,
              heartbeatMs: 100,
              idleTimeoutMs: 5000,
            },
          },
          policy: { maxConcurrent: 8, timeoutMs: 2000 },
        }),
      ],
    });
    await app.start();
    const origin = (app.api as ManagedApiServer).address()!;
    const authorization =
      'Bearer ' +
      (await new SignJWT({ tenant_id: 'tutorial-tenant' })
        .setProtectedHeader({ alg: 'ES256', kid: 'realtime-tutorial', typ: 'JWT' })
        .setIssuer(authority)
        .setAudience('api://realtime-tutorial')
        .setSubject('tutorial-account')
        .setExpirationTime('2m')
        .sign(keys.privateKey));
    const read = (headers: Record<string, string>, trusted = true) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const request = get(
          origin + '/events',
          {
            ...(trusted ? { ca: tls.ca } : {}),
            rejectUnauthorized: true,
            headers: { accept: 'text/event-stream', ...headers },
          },
          (response) => {
            let body = '';
            response.on('data', (chunk: Buffer) => {
              body += chunk.toString('utf8');
            });
            response.once('error', reject);
            response.once('end', () => resolve({ status: response.statusCode!, body }));
          },
        );
        request.once('error', reject);
      });
    let untrustedCertificateRejected = false;
    try {
      await read({}, false);
    } catch {
      untrustedCertificateRejected = true;
    }
    const unauthorized = await read({}),
      event = await read({ authorization }),
      resumed = await read({ authorization, 'last-event-id': 'tutorial_1' });
    socket = new WebSocket(origin.replace('https:', 'wss:') + '/socket', {
      ca: tls.ca,
      rejectUnauthorized: true,
      headers: { authorization },
    });
    await once(socket, 'open');
    const answer = once(socket, 'message');
    socket.send(
      JSON.stringify({
        channel: 'updates',
        payload: Buffer.from([0, 128, 255]).toString('base64url'),
      }),
    );
    const echoed = JSON.parse(String((await answer)[0])) as { channel: string; payload: string };
    const closed = once(socket, 'close');
    socket.close();
    await closed;
    const realtime = app.resolve<RealtimeService>(REALTIME_CAPABILITY);
    await realtime.close();
    return {
      untrustedCertificateRejected,
      anonymousRejected: unauthorized.status === 401,
      exactSseEvent:
        event.status === 200 && event.body === 'id: tutorial_1\nevent: update\ndata: hello\n\n',
      unsupportedReplayRejected: resumed.status === 409,
      websocketBytes: [...Buffer.from(echoed.payload, 'base64url')],
    };
  } finally {
    socket?.terminate();
    try {
      await app?.stop();
    } finally {
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
      await tls.close();
    }
  }
}
