// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import { fixture } from './fixture.js';

assert.equal(process.env.ARKENIVA_PROXY_PRESSURE_DISPOSABLE, '1');
assert.ok(process.send, 'The pressure worker requires an owned IPC parent');
const gib = 1024 ** 3;
let close: () => Promise<void>;
let stats: () => unknown;
let ready: object;

/** Native backpressure waits end on physical closure as well as successful drains. */
function drain(response: ServerResponse): Promise<boolean> {
  if (response.destroyed) return Promise.resolve(false);
  return new Promise((resolve) => {
    const finish = (writable: boolean) => {
      response.off('drain', resumed);
      response.off('close', closed);
      response.off('error', closed);
      resolve(writable);
    };
    const resumed = () => finish(true),
      closed = () => finish(false);
    response.once('drain', resumed);
    response.once('close', closed);
    response.once('error', closed);
  });
}

if (process.argv[2] === 'upstream') {
  let active = 0,
    producing = 0,
    started = 0,
    completed = 0,
    aborted = 0,
    peakQueuedBytes = 0;
  const chunk = Buffer.alloc(65536, 97);
  const server = createServer((request, response) => {
    started++;
    active++;
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers.cookie, undefined);
    assert.equal(request.headers['x-tenant-id'], undefined);
    response.once('close', () => {
      active--;
      if (response.writableFinished) completed++;
      else aborted++;
    });
    void (async () => {
      if (request.url?.endsWith('/healthy')) {
        response.end('healthy');
      } else if (request.method === 'POST') {
        const hash = createHash('sha256');
        let bytes = 0;
        for await (const part of request) {
          bytes += (part as Buffer).length;
          hash.update(part as Buffer);
        }
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ bytes, digest: hash.digest('hex') }));
      } else {
        producing++;
        try {
          response.setHeader('content-type', 'application/octet-stream');
          for (let bytes = 0; bytes < gib && !response.destroyed; bytes += chunk.length) {
            const writable = response.write(chunk);
            peakQueuedBytes = Math.max(peakQueuedBytes, response.writableLength);
            if (!writable && !(await drain(response))) return;
          }
          if (!response.destroyed) response.end();
        } finally {
          producing--;
        }
      }
    })().catch(() => {
      // A disconnected peer cannot receive a fabricated successful receipt.
      response.destroy();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  ready = { origin: 'http://127.0.0.1:' + address.port };
  stats = () => ({ active, producing, started, completed, aborted, peakQueuedBytes });
  close = async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
} else {
  assert.equal(process.argv[2], 'proxy');
  const upstreamOrigin = process.argv[3]!;
  assert.equal(new URL(upstreamOrigin).hostname, '127.0.0.1');
  const f = await fixture({
    upstreamOrigin,
    maxRequestBytes: gib,
    maxResponseBytes: gib,
    timeoutMs: 30000,
  });
  ready = {
    origin: f.origin,
    authorization: await f.token(),
    otherAuthorization: await f.token('orders:read', 'tenant-b'),
  };
  stats = () => ({ proxy: f.service.stats() });
  close = async () => {
    await f.close();
    assert.equal(
      /Bearer |forged-tenant|a{128}/.test(f.logs()),
      false,
      'Private proxy inputs reached logs',
    );
  };
}

const baseline = process.memoryUsage();
const peak = {
  heapUsed: baseline.heapUsed,
  arrayBuffers: baseline.arrayBuffers,
  rss: baseline.rss,
};
const sample = () => {
  const memory = process.memoryUsage();
  for (const key of ['heapUsed', 'arrayBuffers', 'rss'] as const)
    peak[key] = Math.max(peak[key], memory[key]);
};
const timer = setInterval(sample, 10);
let closing = false;
async function stop() {
  if (closing) return;
  closing = true;
  clearInterval(timer);
  await close();
}
process.once('disconnect', () => {
  void stop();
});
process.on('message', (message: { kind: string; id: number }) => {
  if (message.kind === 'stats') {
    sample();
    process.send!({ id: message.id, ...(stats() as object), baseline, peak });
  } else if (message.kind === 'stop') {
    void stop().then(() =>
      process.send!({ id: message.id, stopped: true }, () => process.disconnect!()),
    );
  }
});
process.send!({ kind: 'ready', ...ready });
