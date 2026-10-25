// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runDistributedExample } from '../../src/main.js';

async function receiver() {
  const frames: string[] = [];
  const server = createServer(async (request, reply) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    frames.push(Buffer.concat(chunks).toString());
    reply.setHeader('content-type', 'application/json');
    reply.end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    frames,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
test('Distributed guide emits correlated HTTP hops and measured process quantities without claiming tenant attribution', async () => {
  const target = await receiver();
  const logs: string[] = [];
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs.push(chunk.toString());
      done();
    },
  });
  try {
    const result = await runDistributedExample(target.endpoint, sink);
    assert.equal(result.value, 'ok');
    assert.equal(result.traceId, result.downstreamTraceId);
    assert.match(result.traceId, /^[0-9a-f]{32}$/);
    const wire = target.frames.join('');
    for (const name of [
      'http.server.request.duration',
      'http.client.request.duration',
      'http.server.active_requests',
      'arkenivajs.process.cpu.time',
      'arkenivajs.process.memory.rss',
      'arkenivajs.runtime.event_loop.utilization',
    ])
      assert.ok(wire.includes(name));
    assert.ok(logs.every((line) => !line.includes('untrusted-example')));
  } finally {
    sink.destroy();
    await target.close();
  }
});
test('Documented distributed CLI exports and closes both services before exiting', async () => {
  const target = await receiver();
  try {
    const result = await promisify(execFile)(process.execPath, ['dist/main.js'], {
      timeout: 15000,
      env: { ...process.env, ARKENIVAJS_OTLP_ENDPOINT: target.endpoint },
    });
    const last = result.stdout.trim().split('\n').at(-1)!;
    const data = JSON.parse(last) as { value: string; traceId: string; downstreamTraceId: string };
    assert.equal(data.value, 'ok');
    assert.equal(data.traceId, data.downstreamTraceId);
    assert.deepEqual(JSON.parse(result.stderr), {
      event: 'configuration.override.applied',
      source: 'environment',
      keyCount: 1,
    });
  } finally {
    await target.close();
  }
});
test('Distributed guide rejects a metadata endpoint before binding application listeners', async () => {
  await assert.rejects(runDistributedExample('http://169.254.169.254'));
});
