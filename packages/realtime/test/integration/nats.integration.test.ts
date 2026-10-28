// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { messagingPlugin } from '@arkenivajs/messaging';
import { fixture } from '../fixture.js';
import { sharedProcess } from '../shared-process.js';

test(
  'NATS delivers tenant-isolated realtime events between separate Node processes',
  { timeout: 15000 },
  () => sharedProcess('nats'),
);

test(
  'Actual shared NATS broadcasts across independent applications and isolates verified tenants',
  { timeout: 20000 },
  async () => {
    assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_NATS_URL);
    const failures: unknown[] = [];
    const broker = () =>
      messagingPlugin({
        connectionStringEnv: 'ARKENIVA_NATS_URL',
        onError: async (failure) => {
          failures.push(failure);
        },
      });
    const settings = { pubsub: { provider: 'nats' as const, connectionName: 'messaging' } };
    const first = await fixture(settings, undefined, [broker()]);
    let second: Awaited<ReturnType<typeof fixture>> | undefined;
    const sockets: WebSocket[] = [];
    try {
      second = await fixture(settings, undefined, [broker()], { issuer: first.issuer });
      const authorization = await first.token(),
        otherAuthorization = await first.token('tenant-b');
      for (const [origin, token] of [
        [first.origin, authorization],
        [second.origin, authorization],
        [second.origin, otherAuthorization],
      ] as const) {
        const socket = new WebSocket(origin.replace('http:', 'ws:') + '/socket', {
          headers: { authorization: token },
        });
        sockets.push(socket);
        await once(socket, 'open');
      }
      const received: string[] = [];
      sockets[2]!.on('message', (message) => received.push(String(message)));
      const tenant = first.app.auth!.tenantFrom(await first.app.auth!.verifyBearer(authorization));
      const answers = sockets.slice(0, 2).map((socket) => once(socket, 'message'));
      await first.service.publish('updates', new Uint8Array([0, 255, 128]), tenant);
      for (const [frame] of await Promise.all(answers))
        assert.deepEqual(JSON.parse(String(frame)), { channel: 'updates', payload: 'AP-A' });
      await delay(40);
      assert.deepEqual(received, []);
      await assert.rejects(second.service.publish('updates', new Uint8Array(), tenant), {
        code: 'EK_REALTIME_AUTH',
      });
      assert.deepEqual(failures, []);
    } finally {
      for (const socket of sockets) socket.terminate();
      await second?.close();
      await first.close();
    }
  },
);
