// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import type { Socket } from 'node:net';
import { Writable } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { healthPlugin } from '@arkenivajs/health';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';

test(
  'Real Redis health gates HTTP readiness, bounds delayed TLS replies and recovers without restarting the application',
  { timeout: 20000 },
  async () => {
    assert.equal(
      process.env.ARKENIVA_REDIS_DISPOSABLE,
      '1',
      'Only a dedicated disposable fixture is permitted',
    );
    assert.ok(process.env.ARKENIVA_REDIS_URL);
    const url = new URL(process.env.ARKENIVA_REDIS_URL);
    assert.ok(
      ['127.0.0.1', 'localhost'].includes(url.hostname),
      'The relay only connects to the loopback disposable fixture',
    );
    const upstreamPort = Number(url.port);
    assert.ok(Number.isSafeInteger(upstreamPort) && upstreamPort > 0);
    const sockets = new Set<Socket>(),
      replies = new Set<Socket>();
    const relay = createServer((client) => {
      const upstream = connect({ host: '127.0.0.1', port: upstreamPort });
      sockets.add(client);
      sockets.add(upstream);
      replies.add(upstream);
      const destroy = () => {
        client.destroy();
        upstream.destroy();
      };
      client.on('error', destroy);
      upstream.on('error', destroy);
      client.on('close', () => {
        sockets.delete(client);
        upstream.destroy();
      });
      upstream.on('close', () => {
        sockets.delete(upstream);
        replies.delete(upstream);
        client.destroy();
      });
      client.pipe(upstream);
      upstream.pipe(client);
    });
    await new Promise<void>((resolve, reject) => {
      relay.once('error', reject);
      relay.listen(0, '127.0.0.1', () => {
        relay.removeListener('error', reject);
        resolve();
      });
    });
    const relayAddress = relay.address();
    assert.ok(relayAddress && typeof relayAddress === 'object');
    url.port = String(relayAddress.port);
    const variable = 'ARKENIVA_HEALTH_RELAY_' + randomBytes(12).toString('hex').toUpperCase();
    process.env[variable] = url.href;
    const reserve = createServer();
    await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
    const address = reserve.address();
    assert.ok(address && typeof address === 'object');
    await new Promise<void>((resolve, reject) =>
      reserve.close((error) => (error ? reject(error) : resolve())),
    );
    const app = await createApplication({
      service: { name: 'health-redis-live', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: address.port },
      databases: { cache: { driver: 'redis', connectionStringEnv: variable } },
      plugins: [
        apiPlugin(),
        healthPlugin({ timeoutMs: 50 }),
        redisPlugin(),
        loggingPlugin({
          destination: new Writable({
            write(_chunk, _encoding, done) {
              done();
            },
          }),
        }),
      ],
    });
    const health = app.health;
    try {
      await app.start();
      const api = app.api as ManagedApiServer;
      assert.equal((await fetch(api.address() + '/readyz')).status, 200);
      for (const socket of replies) socket.pause();
      const response = await fetch(api.address() + '/readyz');
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { status: 'not_ready' });
      assert.deepEqual(await health.ready(), {
        status: 'not_ready',
        failing: ['plugin.database-redis'],
      });
      const live = await fetch(api.address() + '/livez');
      assert.equal(live.status, 200);
      assert.deepEqual(await live.json(), { status: 'live' });
      for (const socket of replies) socket.resume();
      const deadline = performance.now() + 5000;
      while ((await health.ready()).status !== 'ready') {
        assert.ok(
          performance.now() < deadline,
          'Native readiness did not recover within its budget',
        );
        await delay(10);
      }
      assert.equal((await fetch(api.address() + '/readyz')).status, 200);
    } finally {
      for (const socket of replies) socket.resume();
      try {
        await app.stop();
      } finally {
        delete process.env[variable];
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve, reject) =>
          relay.close((error) => (error ? reject(error) : resolve())),
        );
      }
    }
    assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['application'] });
  },
);
