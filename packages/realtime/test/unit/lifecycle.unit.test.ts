// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { get } from 'node:http';
import WebSocket from 'ws';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { REALTIME_CAPABILITY } from '../../dist/index.js';
import type { RealtimeService } from '../../dist/index.js';
import { fixture, policy, sseRequest } from '../fixture.js';

test('Dependency initialization registers imperative listeners before listen and route collisions fail startup', async () => {
  const registration: Plugin = {
    id: 'consumer-registration',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['realtime'],
    init(context) {
      context
        .require<RealtimeService>(REALTIME_CAPABILITY)
        .websocket('/registered', policy, async (session) => {
          for await (const message of session.receive()) await session.send(message);
        });
      const service = context.require<RealtimeService>(REALTIME_CAPABILITY);
      const source = {
        kind: 'pubsub' as const,
        async *subscribe() {
          yield { id: 'registered_1', type: 'update', data: 'registered' };
        },
      };
      service.sse('/registered-events', policy, source);
      assert.throws(() => service.sse('/registered-events', policy, source), {
        code: 'EK_CONFIG_INVALID',
      });
    },
    close() {},
  };
  const f = await fixture({}, undefined, [registration]);
  let socket: WebSocket | undefined;
  try {
    socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/registered', {
      headers: { authorization: await f.token() },
    });
    await once(socket, 'open');
    const answer = once(socket, 'message');
    socket.send('{"channel":"init","payload":"aGk"}');
    assert.equal(JSON.parse(String((await answer)[0])).channel, 'init');
    const event = await sseRequest(
      f.origin,
      { authorization: await f.token() },
      '/registered-events',
    );
    assert.equal(event.status, 200);
    assert.equal(event.body, 'id: registered_1\nevent: update\ndata: registered\n\n');
  } finally {
    socket?.terminate();
    await f.close();
  }
  const collision: Plugin = {
    id: 'colliding-listener',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['api'],
    init(context) {
      context
        .require<ManagedApiServer>(COMPONENTS.api)
        .native()
        .get('/socket', async () => 'occupied');
    },
    close() {},
  };
  await assert.rejects(fixture({}, undefined, [collision]));
});

test(
  'A live stream reauthenticates its trusted authority and closes after authorization is revoked',
  { timeout: 5000 },
  async () => {
    let enabled = true,
      calls = 0;
    const f = await fixture({
      identityAuthority: {
        async authenticate(request, options) {
          calls++;
          if (!enabled || !auth)
            throw new KitError({
              code: 'EK_AUTH_FORBIDDEN',
              message: 'The session is no longer authorized',
            });
          return auth.tenantFrom(await auth.verifyBearer(request.headers.authorization, options));
        },
      },
    });
    const auth = f.app.auth;
    let socket: WebSocket | undefined;
    try {
      socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token() },
      });
      await once(socket, 'open');
      const closed = once(socket, 'close');
      enabled = false;
      await closed;
      assert.ok(calls >= 2);
    } finally {
      socket?.terminate();
      await f.close();
    }
  },
);

test(
  'Client disconnect cancels a blocked SSE source and shutdown observes its actual cleanup',
  { timeout: 5000 },
  async () => {
    let aborted = false,
      returned = false;
    const f = await fixture({
      sseSources: {
        events: {
          kind: 'pubsub',
          async *subscribe(context) {
            try {
              yield { id: 'first', type: 'ready', data: 'connected' };
              await new Promise<void>((resolve) => {
                context.signal.addEventListener(
                  'abort',
                  () => {
                    aborted = true;
                    resolve();
                  },
                  { once: true },
                );
                if (context.signal.aborted) {
                  aborted = true;
                  resolve();
                }
              });
            } finally {
              returned = true;
            }
          },
        },
      },
    });
    try {
      const authorization = await f.token();
      await new Promise<void>((resolve, reject) => {
        const request = get(
          f.origin + '/events',
          { headers: { authorization, accept: 'text/event-stream' } },
          (response) => {
            response.on('error', () => undefined);
            response.once('data', () => {
              response.destroy();
              resolve();
            });
          },
        );
        request.once('error', reject);
      });
      await f.service.close();
      assert.equal(aborted, true);
      assert.equal(returned, true);
    } finally {
      await f.close();
    }
  },
);

test('Durable cursor provider failure returns a safe explicit error before SSE headers', async () => {
  let subscribed = false;
  const f = await fixture({
    sseSources: {
      events: {
        kind: 'durable',
        async validateCursor() {
          throw new Error('private-storage-detail');
        },
        async *subscribe() {
          subscribed = true;
          yield { id: 'invalid', type: 'event', data: 'unreachable' };
        },
      },
    },
  });
  try {
    const response = await sseRequest(f.origin, {
      authorization: await f.token(),
      'last-event-id': 'owned_1',
    });
    assert.equal(response.status, 503);
    assert.equal(subscribed, false);
    assert.ok(!response.body.includes('private-storage-detail'));
    assert.equal(response.headers['content-type'], 'application/json; charset=utf-8');
  } finally {
    await f.close();
  }
});
