// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { redisPlugin, REDIS_PUBSUB_CAPABILITY } from '@arkenivajs/database-redis';
import type { RedisPubsubProvider } from '@arkenivajs/database-redis';
import { fixture } from '../fixture.js';
import { sharedProcess } from '../shared-process.js';

test(
  'Redis delivers tenant-isolated realtime events between separate Node processes',
  { timeout: 15000 },
  () => sharedProcess('redis'),
);

test(
  'Actual shared Redis broadcasts use dedicated scoped subscribers and isolate independent applications',
  { timeout: 20000 },
  async () => {
    assert.equal(process.env.ARKENIVA_REDIS_DISPOSABLE, '1');
    const databases = {
      shared: { driver: 'redis' as const, connectionStringEnv: 'ARKENIVA_REDIS_URL' },
    };
    const settings = { pubsub: { provider: 'redis' as const, connectionName: 'shared' } };
    const first = await fixture(settings, undefined, [redisPlugin()], { databases });
    let second: Awaited<ReturnType<typeof fixture>> | undefined;
    const sockets: WebSocket[] = [];
    try {
      second = await fixture(settings, undefined, [redisPlugin()], {
        databases,
        issuer: first.issuer,
      });
      assert.equal(
        first.app.resolve<RedisPubsubProvider>(REDIS_PUBSUB_CAPABILITY).connectionName,
        'shared',
      );
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
      const leaked: string[] = [];
      sockets[2]!.on('message', (message) => leaked.push(String(message)));
      const tenant = first.app.auth!.tenantFrom(await first.app.auth!.verifyBearer(authorization));
      const answers = sockets.slice(0, 2).map((socket) => once(socket, 'message'));
      await first.service.publish('updates', new Uint8Array([0, 255, 128]), tenant);
      for (const [frame] of await Promise.all(answers))
        assert.deepEqual(JSON.parse(String(frame)), { channel: 'updates', payload: 'AP-A' });
      await delay(40);
      assert.deepEqual(leaked, []);
      // The dedicated subscription connection must not put ordinary application commands in subscriber mode.
      assert.equal(await first.app.redis!.get('realtime-missing-' + process.pid), null);
      await assert.rejects(second.service.publish('updates', new Uint8Array(), tenant), {
        code: 'EK_REALTIME_AUTH',
      });
    } finally {
      for (const socket of sockets) socket.terminate();
      await second?.close();
      await first.close();
    }
  },
);
