// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import { createNatsBus } from '@arkenivajs/messaging';
import { SharedCounterProvider } from '../dist/shared-counter.js';
import { fixture } from './fixture.js';

/** Actual mTLS broker client and public example; all resources remain owned by this fixture. */
export async function sharedFixture(namespace: string, issuer?: string) {
  assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_NATS_URL);
  let failures = 0;
  const bus = await createNatsBus({
    connectionStringEnv: 'ARKENIVA_NATS_URL',
    async onError() {
      failures++;
      throw new Error('The counter broker fixture failed');
    },
  });
  const provider = new SharedCounterProvider(namespace),
    sockets = new Set<WebSocket>();
  let f: Awaited<ReturnType<typeof fixture>> | undefined;
  const close = async () => {
    for (const socket of sockets) socket.terminate();
    try {
      await f?.close();
    } finally {
      try {
        await provider.port.close();
      } finally {
        await bus.close();
      }
    }
  };
  try {
    f = await fixture(provider.port, issuer);
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth);
    provider.bind(authority, bus);
    const origin = f.origin,
      ca = f.ca;
    return {
      f,
      provider,
      bus,
      authority,
      close,
      failures: () => failures,
      async connect(authorization: string) {
        const socket = new WebSocket(
          origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          { ca, origin: 'https://portal.example.test' },
        );
        sockets.add(socket);
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
            payload: { query: 'subscription { counterChanged(tenantHint:"spoofed") }' },
          }),
        );
        return { socket, frames };
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}

export async function until(predicate: () => boolean) {
  const deadline = performance.now() + 5000;
  while (!predicate()) {
    assert.ok(performance.now() < deadline, 'The shared counter operation exceeded its deadline');
    await delay(5);
  }
}
