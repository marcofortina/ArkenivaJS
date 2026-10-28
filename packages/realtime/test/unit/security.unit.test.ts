// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import type { VerifiedTenantContext } from '@arkenivajs/core';
import { fixture, sseRequest } from '../fixture.js';

async function rejectUpgrade(origin: string, headers: Record<string, string>): Promise<number> {
  const socket = new WebSocket(origin.replace('http:', 'ws:') + '/socket', { headers });
  return new Promise((resolve, reject) => {
    socket.once('unexpected-response', (_request, response) => {
      response.resume();
      socket.terminate();
      resolve(response.statusCode!);
    });
    socket.on('error', () => undefined);
    socket.once('open', () => {
      socket.terminate();
      reject(new Error('The rejected upgrade was accepted'));
    });
  });
}
test('Cookie-bearing upgrades reject absent or foreign Origin before authenticating a connection', async () => {
  const f = await fixture({ allowedOrigins: ['https://browser.fixture.invalid'] });
  let socket: WebSocket | undefined;
  try {
    const authorization = await f.token();
    assert.equal(
      await rejectUpgrade(f.origin, { authorization, cookie: 'session=synthetic' }),
      403,
    );
    assert.equal(
      await rejectUpgrade(f.origin, {
        authorization,
        cookie: 'session=synthetic',
        origin: 'https://foreign.fixture.invalid',
      }),
      403,
    );
    socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: {
        authorization,
        cookie: 'session=synthetic',
        origin: 'https://browser.fixture.invalid',
      },
    });
    await once(socket, 'open');
  } finally {
    socket?.terminate();
    await f.close();
  }
});

test('Tenant connection limits do not exclude another tenant and late registration always fails', async () => {
  const f = await fixture();
  const sockets: WebSocket[] = [];
  try {
    const authorization = await f.token();
    for (let index = 0; index < 2; index++) {
      const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization },
      });
      sockets.push(socket);
      await once(socket, 'open');
    }
    assert.equal(await rejectUpgrade(f.origin, { authorization }), 429);
    const other = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token('tenant-b') },
    });
    sockets.push(other);
    await once(other, 'open');
    assert.throws(
      () =>
        f.service.websocket(
          '/late',
          {
            requireAuth: true,
            maxConnectionsPerTenant: 1,
            maxMessageBytes: 100,
            maxBufferBytes: 100,
            heartbeatMs: 1,
            idleTimeoutMs: 100,
          },
          async () => {},
        ),
      { code: 'EK_LIFECYCLE_STATE' },
    );
    await assert.rejects(
      f.service.publish('updates', new Uint8Array(), {} as VerifiedTenantContext),
      { code: 'EK_REALTIME_AUTH' },
    );
  } finally {
    for (const socket of sockets) socket.terminate();
    await f.close();
  }
});

test('A manually constructed tenant from a custom authority cannot establish an authenticated stream', async () => {
  const f = await fixture({
    identityAuthority: {
      async authenticate() {
        return {
          tenantId: 'tenant-a',
          identity: { issuer: 'https://forged.invalid', subject: 'forged' },
          source: 'oidc',
          verifiedAt: new Date().toISOString(),
        } as VerifiedTenantContext;
      },
    },
  });
  try {
    const result = await sseRequest(f.origin, { authorization: await f.token() });
    assert.equal(result.status, 401, result.body);
  } finally {
    await f.close();
  }
});

test('Pubsub sources cannot silently accept a resume cursor or fabricate retained events', async () => {
  let reads = 0;
  const f = await fixture({
    sseSources: {
      events: {
        kind: 'pubsub',
        async *subscribe() {
          reads++;
          yield { id: 'event_1', type: 'event', data: 'live' };
        },
      },
    },
  });
  try {
    const result = await sseRequest(f.origin, {
      authorization: await f.token(),
      'last-event-id': 'event_1',
    });
    assert.equal(result.status, 409, result.body);
    assert.equal(reads, 0);
  } finally {
    await f.close();
  }
});
