// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import { fixture } from './fixture.js';
import { counterPort } from './counter-port.js';

test(
  'Installed public subscription example keeps tenant events on authenticated WSS and retires owned iterators',
  { timeout: 15000 },
  async () => {
    const delivery = counterPort(() => authority);
    const f = await fixture(delivery.port);
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth);
    const service = f.service();
    const sockets: WebSocket[] = [];
    async function connect(authorization: string) {
      const socket = new WebSocket(
        f.origin.replace('https:', 'wss:') + '/graphql',
        'graphql-transport-ws',
        {
          ca: f.ca,
          origin: 'https://portal.example.test',
        },
      );
      sockets.push(socket);
      await once(socket, 'open');
      const ack = once(socket, 'message');
      socket.send(JSON.stringify({ type: 'connection_init', payload: { authorization } }));
      assert.equal(JSON.parse(String((await ack)[0])).type, 'connection_ack');
      const frames: unknown[] = [];
      socket.on('message', (data) => {
        const frame = JSON.parse(String(data));
        if (frame.type === 'ping') socket.send('{"type":"pong"}');
        else if (frame.type !== 'pong') frames.push(frame);
      });
      socket.send(
        JSON.stringify({
          type: 'subscribe',
          id: 'counter',
          payload: { query: 'subscription { counterChanged(tenantHint:"tenant-b") }' },
        }),
      );
      return { socket, frames };
    }
    const until = async (predicate: () => boolean) => {
      const deadline = performance.now() + 3000;
      while (!predicate()) {
        assert.ok(performance.now() < deadline, 'The counter event exceeded its delivery deadline');
        await delay(5);
      }
    };
    try {
      const a = await f.token(),
        b = await f.token('tenant-b');
      const first = await connect(a),
        second = await connect(b);
      await until(() => delivery.active() === 2);
      assert.deepEqual(JSON.parse((await f.send({ query: 'mutation { increment }' }, a)).body), {
        data: { increment: 1 },
      });
      await until(() => first.frames.length === 1);
      assert.deepEqual(second.frames, []);
      assert.deepEqual(first.frames, [
        { type: 'next', id: 'counter', payload: { data: { counterChanged: 1 } } },
      ]);
      assert.deepEqual(JSON.parse((await f.send({ query: 'mutation { increment }' }, b)).body), {
        data: { increment: 1 },
      });
      await until(() => second.frames.length === 1);
      assert.deepEqual(second.frames, first.frames);
      const tenant = authority.tenantFrom(await authority.verifyBearer(a));
      await assert.rejects(delivery.port.publish('counter', 2, { ...tenant }));
      assert.throws(() => delivery.port.subscribe('counter', { ...tenant }));
      await assert.rejects(delivery.port.publish('unknown', 2, tenant));
      const closed = once(first.socket, 'close');
      first.socket.close();
      await closed;
      await until(() => delivery.active() === 1 && service.stats().activeSubscriptions === 1);
      assert.equal(service.stats().activeSubscriptions, 1);
      assert.doesNotMatch(f.logs(), /Bearer /);
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
    }
    assert.equal(delivery.active(), 0);
    assert.equal(service.stats().activeSubscriptions, 0);
  },
);
