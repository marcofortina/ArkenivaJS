// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { MessageBus, MessageEnvelope, Plugin } from '@arkenivajs/core';
import { fixture, policy } from '../fixture.js';

function broker(bus: MessageBus): Plugin {
  return {
    id: 'messaging',
    version: '1.0.0',
    capabilities: new Set(['messaging']),
    init(context) {
      context.provide(COMPONENTS.messaging, bus);
    },
    close() {},
  };
}

test(
  'Failed broker admission denies the native upgrade without poisoning a later authenticated connection',
  { timeout: 10000 },
  async () => {
    let available = false,
      attempts = 0,
      retired = 0;
    const bus: MessageBus = {
      async publish() {
        return { messageId: 'fixture', acknowledged: false };
      },
      async subscribe<T>(topic: string, handler: (message: MessageEnvelope<T>) => Promise<void>) {
        attempts++;
        if (!available) throw new Error('Private broker subscription diagnostic');
        await handler({
          messageId: 'fixture',
          topic,
          payload: { channel: 'updates', payload: 'AQ' } as T,
        });
        return {
          async close() {
            retired++;
          },
        };
      },
    };
    const f = await fixture(
      { pubsub: { provider: 'nats', connectionName: 'messaging' } },
      undefined,
      [broker(bus)],
    );
    const sockets: WebSocket[] = [];
    try {
      const authorization = await f.token();
      const denied = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization },
      });
      sockets.push(denied);
      denied.on('error', () => undefined);
      await new Promise<void>((resolve, reject) => {
        denied.once('open', () =>
          reject(new Error('An unavailable subscription must not upgrade')),
        );
        denied.once('unexpected-response', (_request, response) => {
          let body = '';
          response.on('data', (chunk: Buffer) => {
            body += chunk.toString('utf8');
          });
          response.once('error', reject);
          response.once('end', () => {
            try {
              assert.equal(response.statusCode, 503);
              assert.equal(JSON.parse(body).error.code, 'EK_BACKEND_UNAVAILABLE');
              assert.doesNotMatch(body, /Private broker|realtime\.v1\./);
              resolve();
            } catch (error) {
              reject(error);
            }
          });
        });
      });
      available = true;
      const live = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization },
      });
      sockets.push(live);
      let frames = 0;
      live.on('message', () => {
        frames++;
      });
      await once(live, 'open');
      assert.equal(frames, 0);
      const echoed = once(live, 'message');
      live.send(JSON.stringify({ channel: 'echo', payload: 'Ag' }));
      assert.deepEqual(JSON.parse(String((await echoed)[0])), { channel: 'echo', payload: 'Ag' });
      assert.equal(attempts, 2);
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
    }
    assert.equal(retired, 1);
  },
);

test(
  'Native authenticated upgrades enforce tenant subscription capacity and retire unused subscriptions',
  { timeout: 20000 },
  async () => {
    let subscriptions = 0,
      retired = 0,
      firstRetirement!: () => void;
    const released = new Promise<void>((resolve) => {
      firstRetirement = resolve;
    });
    const bus: MessageBus = {
      async publish() {
        return { messageId: 'fixture', acknowledged: false };
      },
      async subscribe() {
        subscriptions++;
        return {
          async close() {
            retired++;
            if (retired === 1) firstRetirement();
          },
        };
      },
    };
    const f = await fixture(
      {
        pubsub: { provider: 'nats', connectionName: 'messaging' },
        policy: { maxConcurrent: 64, timeoutMs: 1000 },
      },
      undefined,
      [broker(bus)],
    );
    const sockets: WebSocket[] = [];
    const connect = async (tenant: string) => {
      const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token(tenant) },
      });
      socket.on('error', () => undefined);
      sockets.push(socket);
      return socket;
    };
    try {
      for (let index = 0; index < 32; index++) await once(await connect('tenant-' + index), 'open');
      assert.equal(subscriptions, 32);
      const rejected = await connect('tenant-overflow');
      await new Promise<void>((resolve, reject) => {
        rejected.once('open', () => reject(new Error('Exceeded tenant capacity must not upgrade')));
        rejected.once('unexpected-response', (_request, response) => {
          try {
            assert.equal(response.statusCode, 429);
            response.resume();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
      assert.equal(subscriptions, 32);
      const closed = once(sockets[0]!, 'close');
      sockets[0]!.terminate();
      await closed;
      await released;
      await once(await connect('tenant-replacement'), 'open');
      assert.equal(subscriptions, 33);
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
    }
    assert.equal(retired, subscriptions);
  },
);

test(
  'A bounded subscriber failure closes only that native peer and preserves another tenant',
  { timeout: 10000 },
  async () => {
    const callbacks: ((message: MessageEnvelope<unknown>) => Promise<void>)[] = [];
    let retired = 0;
    const bus: MessageBus = {
      async publish() {
        return { messageId: 'fixture', acknowledged: false };
      },
      async subscribe<T>(_topic: string, handler: (message: MessageEnvelope<T>) => Promise<void>) {
        callbacks.push(handler as (typeof callbacks)[number]);
        return {
          async close() {
            retired++;
          },
        };
      },
    };
    const f = await fixture(
      {
        pubsub: { provider: 'nats', connectionName: 'messaging' },
        routes: [
          { kind: 'websocket', path: '/small', handlerKey: 'echo', policyKey: 'small' },
          { kind: 'websocket', path: '/large', handlerKey: 'echo', policyKey: 'large' },
        ],
        policies: { small: { ...policy, maxMessageBytes: 32 }, large: policy },
      },
      undefined,
      [broker(bus)],
    );
    const sockets: WebSocket[] = [];
    try {
      for (const [path, tenant] of [
        ['/small', 'tenant-a'],
        ['/large', 'tenant-a'],
        ['/large', 'tenant-b'],
      ] as const) {
        const socket = new WebSocket(f.origin.replace('http:', 'ws:') + path, {
          headers: { authorization: await f.token(tenant) },
        });
        sockets.push(socket);
        await once(socket, 'open');
      }
      assert.equal(callbacks.length, 2);
      const closed = once(sockets[0]!, 'close');
      const delivered = once(sockets[1]!, 'message');
      let leaked = false;
      sockets[2]!.on('message', () => {
        leaked = true;
      });
      await callbacks[0]!({
        messageId: 'fixture',
        topic: 'untrusted-envelope-topic',
        payload: { channel: 'updates', payload: 'AQ', id: 'event_1' },
      });
      await closed;
      assert.deepEqual(JSON.parse(String((await delivered)[0])), {
        channel: 'updates',
        payload: 'AQ',
        id: 'event_1',
      });
      assert.equal(sockets[1]!.readyState, WebSocket.OPEN);
      assert.equal(sockets[2]!.readyState, WebSocket.OPEN);
      assert.equal(leaked, false);
      assert.equal(retired, 0);
    } finally {
      for (const socket of sockets) socket.terminate();
      await f.close();
    }
    assert.equal(retired, 2);
  },
);
