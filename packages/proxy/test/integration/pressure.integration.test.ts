// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { request } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import type { ProxyService } from '../../dist/index.js';

assert.equal(
  process.env.ARKENIVA_PROXY_PRESSURE_DISPOSABLE,
  '1',
  'Large proxy streaming tests require an owned disposable VM or CI runner',
);
const gib = 1024 ** 3;
interface State {
  active: number;
  producing: number;
  started: number;
  completed: number;
  aborted: number;
  peakQueuedBytes: number;
  proxy: ReturnType<ProxyService['stats']>;
  baseline: { heapUsed: number; arrayBuffers: number; rss: number };
  peak: { heapUsed: number; arrayBuffers: number; rss: number };
}

async function worker(t: TestContext, role: string, origin?: string) {
  const child = fork(
    new URL('../pressure-worker.js', import.meta.url),
    [role, ...(origin ? [origin] : [])],
    {
      execArgv: ['--max-old-space-size=128'],
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    },
  );
  let stderr = '',
    next = 0;
  child.stderr!.on('data', (part: Buffer) => {
    stderr += part.toString();
    assert.ok(stderr.length < 16384, 'The owned worker exceeded its diagnostic budget');
  });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  });
  const first = await Promise.race([
    once(child, 'message'),
    exited.then(() => {
      throw new Error('The owned worker exited before readiness');
    }),
  ]);
  const ready = first[0] as {
    kind: string;
    origin: string;
    authorization: string;
    otherAuthorization: string;
  };
  assert.equal(ready.kind, 'ready');
  const rpc = (kind: string) =>
    new Promise<State>((resolve, reject) => {
      const id = ++next;
      const finish = () => {
        clearTimeout(timer);
        child.off('message', receive);
        child.off('exit', lost);
      };
      const lost = () => {
        finish();
        reject(new Error('The owned worker exited during a command'));
      };
      const receive = (message: unknown) => {
        if (!message || typeof message !== 'object' || !('id' in message) || message.id !== id)
          return;
        finish();
      resolve(message as unknown as State);
      };
      const timer = setTimeout(() => {
        finish();
        reject(new Error('The owned worker command exceeded its deadline'));
      }, 5000);
      child.on('message', receive);
      child.once('exit', lost);
      child.send({ kind, id });
    });
  return {
    ...ready,
    rpc,
    async stop() {
      await rpc('stop');
      const [code, signal] = await exited;
      assert.equal(code, 0, stderr);
      assert.equal(signal, null);
    },
  };
}

async function until(work: () => Promise<State>, predicate: (value: State) => boolean) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const state = await work();
    if (predicate(state)) return state;
    await delay(10);
  }
  throw new Error('The owned proxy did not reach its physical lifecycle state');
}

function open(t: TestContext, origin: string, path: string, authorization: string, method = 'GET') {
  const outgoing = request(origin + '/orders/' + path, {
    method,
    agent: false,
    signal: AbortSignal.timeout(45000),
    headers: {
      authorization,
      'x-tenant-id': 'forged-tenant',
      cookie: 'untrusted=excluded',
      ...(method === 'POST' ? { 'content-type': 'application/octet-stream' } : {}),
    },
  });
  const response = new Promise<IncomingMessage>((resolve, reject) => {
    outgoing.once('error', reject);
    outgoing.once('response', resolve);
  });
  void response.catch(() => undefined);
  t.after(() => outgoing.destroy());
  if (method === 'GET') outgoing.end();
  return { outgoing, response };
}

async function receipt(response: IncomingMessage) {
  assert.equal(response.statusCode, 200);
  let body = '';
  for await (const part of response) {
    body += (part as Buffer).toString();
    assert.ok(body.length <= 4096);
  }
  return body;
}

function bounded(t: TestContext, state: State, direction: string) {
  // Conservative process observations are functional ceilings, not release performance budgets.
  assert.ok(state.peak.heapUsed - state.baseline.heapUsed < 96 * 1024 ** 2);
  assert.ok(state.peak.arrayBuffers - state.baseline.arrayBuffers < 128 * 1024 ** 2);
  assert.ok(state.peak.rss - state.baseline.rss < 192 * 1024 ** 2);
  t.diagnostic(
    JSON.stringify({
      direction,
      bytes: gib,
      baseline: state.baseline,
      peak: state.peak,
      releaseGate: false,
    }),
  );
}

test(
  'A 1 GiB proxied response remains bounded with a slow downstream, an aborted peer and an independent healthy tenant',
  { timeout: 90000 },
  async (t) => {
    const upstream = await worker(t, 'upstream'),
      proxy = await worker(t, 'proxy', upstream.origin);
    const aborted = await open(t, proxy.origin, 'abort', proxy.authorization).response;
    aborted.on('error', () => undefined);
    aborted.pause();
    const main = await open(t, proxy.origin, 'large', proxy.authorization).response;
    assert.equal(main.statusCode, 200);
    main.pause();
    await until(
      () => upstream.rpc('stats'),
      (value) => value.active === 2 && value.producing === 2,
    );
    await delay(100);
    assert.equal(
      await receipt(await open(t, proxy.origin, 'healthy', proxy.otherAuthorization).response),
      'healthy',
    );
    aborted.destroy();
    await until(
      () => upstream.rpc('stats'),
      (value) => value.active === 1 && value.producing === 1 && value.aborted === 1,
    );
    const hash = createHash('sha256');
    let bytes = 0,
      nextPause = 2 * 1024 ** 2;
    for await (const part of main) {
      const chunk = part as Buffer;
      bytes += chunk.length;
      hash.update(chunk);
      if (bytes >= nextPause) {
        nextPause += 2 * 1024 ** 2;
        await delay(1);
      }
    }
    assert.equal(bytes, gib);
    const expected = createHash('sha256'),
      chunk = Buffer.alloc(65536, 97);
    for (let count = 0; count < gib; count += chunk.length) expected.update(chunk);
    assert.equal(hash.digest('hex'), expected.digest('hex'));
    assert.equal(
      await receipt(await open(t, proxy.origin, 'healthy', proxy.otherAuthorization).response),
      'healthy',
    );
    const source = await until(
      () => upstream.rpc('stats'),
      (value) => value.active === 0 && value.producing === 0,
    );
    assert.equal(source.started, 4);
    assert.equal(source.completed, 3);
    assert.equal(source.aborted, 1);
    assert.ok(source.peakQueuedBytes <= 131072);
    const final = await until(
      () => proxy.rpc('stats'),
      (value) => value.proxy.activeRequests === 0,
    );
    assert.ok(final.proxy.observedResponseBytes >= gib);
    bounded(t, final, 'response');
    await proxy.stop();
    await upstream.stop();
  },
);

test(
  'A 1 GiB proxied request stays bounded beside held request bodies and retires an aborted upstream exactly once',
  { timeout: 90000 },
  async (t) => {
    const upstream = await worker(t, 'upstream'),
      proxy = await worker(t, 'proxy', upstream.origin);
    const chunk = Buffer.alloc(65536, 97);
    const held = [
      open(t, proxy.origin, 'held-one', proxy.authorization, 'POST'),
      open(t, proxy.origin, 'held-two', proxy.authorization, 'POST'),
    ];
    const aborted = open(t, proxy.origin, 'abort', proxy.authorization, 'POST');
    for (const peer of [...held, aborted]) peer.outgoing.write(chunk);
    await until(
      () => upstream.rpc('stats'),
      (value) => value.active === 3,
    );
    const main = open(t, proxy.origin, 'ingest', proxy.authorization, 'POST'),
      hash = createHash('sha256');
    let waits = 0,
      peakQueuedBytes = 0;
    for (let bytes = 0; bytes < gib; bytes += chunk.length) {
      hash.update(chunk);
      const writable = main.outgoing.write(chunk);
      peakQueuedBytes = Math.max(peakQueuedBytes, main.outgoing.writableLength);
      if (!writable) {
        waits++;
        await once(main.outgoing, 'drain');
      }
      if (bytes === gib / 2) {
        assert.equal((await upstream.rpc('stats')).active, 4);
        aborted.outgoing.destroy();
        await assert.rejects(aborted.response);
        await until(
          () => upstream.rpc('stats'),
          (value) => value.active === 3 && value.aborted === 1,
        );
        assert.equal(
          await receipt(await open(t, proxy.origin, 'healthy', proxy.otherAuthorization).response),
          'healthy',
        );
      }
    }
    main.outgoing.end();
    assert.deepEqual(JSON.parse(await receipt(await main.response)), {
      bytes: gib,
      digest: hash.digest('hex'),
    });
    assert.ok(waits > 0);
    assert.ok(peakQueuedBytes <= 131072);
    for (const peer of held) {
      peer.outgoing.end();
      assert.deepEqual(JSON.parse(await receipt(await peer.response)), {
        bytes: chunk.length,
        digest: createHash('sha256').update(chunk).digest('hex'),
      });
    }
    const source = await until(
      () => upstream.rpc('stats'),
      (value) => value.active === 0,
    );
    assert.equal(source.started, 5);
    assert.equal(source.completed, 4);
    assert.equal(source.aborted, 1);
    const final = await until(
      () => proxy.rpc('stats'),
      (value) => value.proxy.activeRequests === 0,
    );
    assert.ok(final.proxy.observedRequestBytes >= gib + 3 * chunk.length);
    bounded(t, final, 'request');
    await proxy.stop();
    await upstream.stop();
  },
);
