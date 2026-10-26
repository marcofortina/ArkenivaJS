// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, body, send, boundary } from './fixture.js';

const file = {
  name: 'file',
  filename: 'fixture.pdf',
  type: 'application/pdf',
  value: Buffer.from('%PDF-owned'),
};
async function until(test: () => boolean) {
  for (let index = 0; index < 200; index++) {
    if (test()) return;
    await delay(10);
  }
  assert.ok(test(), 'The owned request did not reach its expected lifecycle state');
}

test(
  'A slow incomplete body times out with a safe response and frees its owned native parser',
  { timeout: 10000 },
  async (t) => {
    const f = await fixture({}, 300);
    t.after(f.close);
    const req = request(f.origin + '/uploads', {
      method: 'POST',
      headers: {
        authorization: await f.token(),
        'content-type': 'multipart/form-data; boundary=' + boundary,
      },
    });
    req.on('error', () => {
      /* The server deliberately terminates the incomplete body. */
    });
    t.after(() => req.destroy());
    const received = new Promise<{ status: number; data: string }>((resolve, reject) => {
      req.once('response', (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          data += chunk;
        });
        res.once('error', reject);
        res.once('end', () => resolve({ status: res.statusCode!, data }));
      });
    });
    req.write(body([file], false));
    const result = await received;
    assert.equal(result.status, 408, result.data);
    assert.match(result.data, /EK_TIMEOUT/);
    await until(() => f.stats().activeRequests === 0);
    assert.equal(f.stats().rejectedRequests, 1);
  },
);

test(
  'Disconnecting midway through a file cancels the handler and releases physical admission after settlement',
  { timeout: 10000 },
  async (t) => {
    let entered = false,
      cancelled = false;
    const f = await fixture({
      async handler(input) {
        entered = true;
        input.context.signal.addEventListener(
          'abort',
          () => {
            cancelled = true;
          },
          { once: true },
        );
        for await (const part of input.parts)
          if (part.kind === 'file') for await (const chunk of part.stream) void chunk;
        return { files: 1, bytes: 0, order: [] };
      },
    });
    t.after(f.close);
    const req = request(f.origin + '/uploads', {
      method: 'POST',
      headers: {
        authorization: await f.token(),
        'content-type': 'multipart/form-data; boundary=' + boundary,
      },
    });
    req.on('error', () => {
      /* Disposable client cancellation is the tested condition. */
    });
    t.after(() => req.destroy());
    req.write(body([file], false));
    await until(() => entered);
    req.destroy();
    await until(() => cancelled && f.stats().activeRequests === 0);
    assert.equal(f.stats().successfulRequests, 0);
    assert.equal(f.stats().rejectedRequests, 1);
  },
);

test(
  'There is no admission queue and canceled uncooperative handlers retain all 32 physical reservations',
  { timeout: 15000 },
  async (t) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = await fixture({
      async handler() {
        await gate;
        return { files: 0, bytes: 0, order: [] };
      },
    });
    t.after(async () => {
      release();
      await f.close();
    });
    const token = await f.token(),
      cancelled = new AbortController();
    const calls = Array.from({ length: 32 }, () =>
      fetch(f.origin + '/uploads', {
        method: 'POST',
        headers: {
          authorization: token,
          'content-type': 'multipart/form-data; boundary=' + boundary,
        },
        body: new Uint8Array(body([file])),
        signal: cancelled.signal,
      }).catch(() => undefined),
    );
    await until(() => f.calls() === 32);
    assert.equal(f.stats().activeRequests, 32);
    assert.equal((await send(f.origin, body([file]), token)).status, 503);
    cancelled.abort();
    await Promise.all(calls);
    await until(() => f.stats().rejectedRequests >= 33);
    assert.equal(f.stats().activeRequests, 32);
    assert.equal((await send(f.origin, body([file]), token)).status, 503);
    release();
    await until(() => f.stats().activeRequests === 0);
    assert.equal((await send(f.origin, body([file]), token)).status, 400);
  },
);

test(
  'Application shutdown aborts active upload scopes and awaits actual handler settlement without touching another application',
  { timeout: 10000 },
  async (t) => {
    let release!: () => void, signal: AbortSignal | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const first = await fixture({
        async handler(input) {
          signal = input.context.signal;
          await gate;
          return {};
        },
      }),
      second = await fixture();
    t.after(async () => {
      release();
      await first.close();
      await second.close();
    });
    const pending = send(first.origin, body([file]), await first.token()).catch(() => undefined);
    await until(() => signal !== undefined);
    const stopping = first.app.stop({ timeoutMs: 2000 });
    void stopping.catch(() => undefined);
    await until(() => signal!.aborted);
    release();
    await stopping;
    await pending;
    const result = await send(second.origin, body([file]), await second.token());
    assert.equal(result.status, 200, result.body);
    await first.app.stop();
    assert.equal(first.stats().activeRequests, 0);
  },
);

test('A handler result that violates the response schema cannot acknowledge an otherwise consumed upload', async (t) => {
  const f = await fixture({
    async handler(input) {
      for await (const part of input.parts) if (part.kind === 'file') await part.discard();
      return { files: 'not an integer', bytes: 1, order: [] };
    },
  });
  t.after(f.close);
  const result = await send(f.origin, body([file]), await f.token());
  assert.equal(result.status, 400, result.body);
  assert.match(result.body, /EK_HTTP_VALIDATION/);
  assert.equal(f.stats().successfulRequests, 0);
});
