// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import { fixture, sseRequest } from '../fixture.js';

test(
  'Actual authenticated SSE streams preserve IDs, types and text without anonymous access',
  { timeout: 10000 },
  async () => {
    const f = await fixture();
    try {
      const denied = await sseRequest(f.origin);
      assert.equal(denied.status, 401, denied.body);
      const accepted = await sseRequest(f.origin, { authorization: await f.token() });
      assert.equal(accepted.status, 200, accepted.body);
      assert.equal(accepted.headers['content-type'], 'text/event-stream');
      assert.equal(accepted.headers['cache-control'], 'no-store');
      assert.equal(
        accepted.body,
        'id: tenant-a_1\nevent: update\ndata: event 1\n\nid: tenant-a_2\nevent: update\ndata: event 2\n\n',
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Durable SSE resumes strictly after an owned cursor and rejects unknown, foreign and expired cursors',
  { timeout: 10000 },
  async () => {
    const f = await fixture();
    try {
      const authorization = await f.token();
      const resumed = await sseRequest(f.origin, { authorization, 'last-event-id': 'tenant-a_1' });
      assert.equal(resumed.status, 200, resumed.body);
      assert.ok(!resumed.body.includes('tenant-a_1'));
      assert.ok(resumed.body.includes('tenant-a_2'));
      for (const [cursor, status] of [
        ['tenant-b_1', 409],
        ['tenant-a_unknown', 409],
        ['tenant-a_expired', 410],
        ['unsafe cursor', 409],
      ] as const) {
        const result = await sseRequest(f.origin, { authorization, 'last-event-id': cursor });
        assert.equal(result.status, status, result.body);
        assert.ok(!result.body.includes(cursor));
      }
    } finally {
      await f.close();
    }
  },
);

test(
  'Native WebSocket upgrade requires actual JWT verification and roundtrips bounded binary payloads',
  { timeout: 10000 },
  async () => {
    const f = await fixture();
    let socket: WebSocket | undefined;
    try {
      socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token() },
      });
      await once(socket, 'open');
      const answer = once(socket, 'message');
      socket.send(
        JSON.stringify({
          channel: 'updates',
          payload: Buffer.from([0, 255, 1, 128]).toString('base64url'),
          id: 'message_1',
        }),
      );
      const [frame] = await answer;
      assert.deepEqual(JSON.parse(String(frame)), {
        channel: 'updates',
        payload: 'AP8BgA',
        id: 'message_1',
      });
      const closed = once(socket, 'close');
      socket.close();
      await closed;
      const denied = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket');
      const status = await new Promise<number>((resolve, reject) => {
        denied.once('unexpected-response', (_request, response) => {
          response.resume();
          denied.terminate();
          resolve(response.statusCode!);
        });
        denied.once('error', () => undefined);
        denied.once('open', () => reject(new Error('An anonymous upgrade was accepted')));
      });
      assert.equal(status, 401);
    } finally {
      socket?.terminate();
      await f.close();
    }
  },
);
