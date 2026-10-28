// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { get } from 'node:http';
import { setImmediate } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { MessageBus, Plugin } from '@arkenivajs/core';
import { fixture, sseRequest } from '../fixture.js';

test(
  'Disconnect retains initial authentication capacity until the actual authority settles',
  { timeout: 5000 },
  async () => {
    let entered!: () => void,
      release!: () => void,
      aborted!: () => void,
      settled!: () => void,
      first = true;
    const called = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      }),
      cancelled = new Promise<void>((resolve) => {
        aborted = resolve;
      }),
      completed = new Promise<void>((resolve) => {
        settled = resolve;
      });
    const f = await fixture({
      policy: { maxConcurrent: 1, timeoutMs: 1000 },
      identityAuthority: {
        async authenticate(request, options) {
          if (first) {
            first = false;
            options?.signal?.addEventListener('abort', aborted, { once: true });
            entered();
            await gate;
          }
          const tenant = f.app.auth!.tenantFrom(
            await f.app.auth!.verifyBearer(request.headers.authorization),
          );
          settled();
          return tenant;
        },
      },
    });
    try {
      const authorization = await f.token();
      const outgoing = get(f.origin + '/events', {
        headers: { authorization, accept: 'text/event-stream' },
      });
      outgoing.on('error', () => undefined);
      await called;
      outgoing.destroy();
      await cancelled;
      assert.equal((await sseRequest(f.origin, { authorization })).status, 429);
      release();
      await completed;
      await setImmediate();
      assert.equal((await sseRequest(f.origin, { authorization })).status, 200);
    } finally {
      release();
      await f.close();
    }
  },
);

test(
  'Backend cleanup failure remains visible through service and application shutdown',
  { timeout: 5000 },
  async () => {
    let cleaned = false;
    const backend: MessageBus = {
      async publish() {
        return { messageId: 'fixture', acknowledged: false };
      },
      async subscribe() {
        return {
          async close() {
            cleaned = true;
            throw new Error('private-backend-detail');
          },
        };
      },
    };
    const broker: Plugin = {
      id: 'messaging',
      version: '1.0.0',
      capabilities: new Set(['messaging']),
      init(context) {
        context.provide(COMPONENTS.messaging, backend);
      },
      close() {},
    };
    const f = await fixture(
      { pubsub: { provider: 'nats', connectionName: 'messaging' } },
      undefined,
      [broker],
    );
    let socket: WebSocket | undefined;
    try {
      socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token() },
      });
      await once(socket, 'open');
      await assert.rejects(f.service.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
      assert.equal(cleaned, true);
      assert.ok(!f.logs().includes('private-backend-detail'));
    } finally {
      socket?.terminate();
      await assert.rejects(f.close());
    }
  },
);
