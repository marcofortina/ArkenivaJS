// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import type { UploadStats } from '../../dist/index.js';
import { boundary } from '../unit/fixture.js';

interface Snapshot {
  stats: UploadStats;
  active: number;
  peakActive: number;
  aborted: number;
  baseline: { heapUsed: number; rss: number; arrayBuffers: number };
  peak: { heapUsed: number; rss: number; arrayBuffers: number };
}

assert.equal(
  process.env.ARKENIVA_UPLOAD_PRESSURE_DISPOSABLE,
  '1',
  'Run large streaming pressure only on an explicitly disposable VM or CI runner',
);

test(
  'An authenticated 1 GiB stream stays bounded beside slow clients and an aborted peer',
  { timeout: 120000 },
  async (t) => {
    const child = fork(new URL('../pressure-worker.js', import.meta.url), [], {
      execArgv: ['--max-old-space-size=128'],
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    });
    let stderr = '',
      sequence = 0;
    child.stderr!.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
      assert.ok(stderr.length <= 16384, 'The owned server exceeded its diagnostic budget');
    });
    const exited = once(child, 'exit');
    // Failure cleanup is registered before waiting for the first IPC message.
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited;
    });
    const first = await Promise.race([
      once(child, 'message'),
      exited.then(() => {
        throw new Error('The owned pressure server exited before readiness');
      }),
    ]);
    const ready = first[0] as { kind: string; origin: string; authorization: string };
    assert.equal(ready.kind, 'ready');
    assert.equal(new URL(ready.origin).hostname, '127.0.0.1');
    const rpc = <T>(kind: string) =>
      new Promise<T>((resolve, reject) => {
        const id = ++sequence;
        const finish = () => {
          clearTimeout(timer);
          child.off('message', receive);
          child.off('exit', lost);
        };
        const lost = () => {
          finish();
          reject(new Error('The owned pressure server exited during a command'));
        };
        const receive = (message: unknown) => {
          if (!message || typeof message !== 'object' || !('id' in message) || message.id !== id)
            return;
          finish();
          resolve(message as T);
        };
        const timer = setTimeout(() => {
          finish();
          reject(new Error('The pressure command exceeded its deadline'));
        }, 5000);
        child.on('message', receive);
        child.once('exit', lost);
        child.send({ id, kind });
      });
    const until = async (predicate: (snapshot: Snapshot) => boolean) => {
      for (let attempt = 0; attempt < 200; attempt++) {
        const value = await rpc<Snapshot>('stats');
        if (predicate(value)) return value;
        await delay(10);
      }
      throw new Error('The upload did not reach its physical lifecycle state');
    };
    const prefix = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="large.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`,
    );
    const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
    const chunk = Buffer.alloc(65536, 97);
    const open = () => {
      const outgoing = request(ready.origin + '/uploads', {
        method: 'POST',
        agent: false,
        signal: AbortSignal.timeout(100000),
        headers: {
          authorization: ready.authorization,
          'content-type': 'multipart/form-data; boundary=' + boundary,
          'x-tenant-id': 'forged-tenant',
        },
      });
      t.after(() => outgoing.destroy());
      const receipt = new Promise<{ status: number; body: string }>((resolve, reject) => {
        outgoing.once('error', reject);
        outgoing.once('response', (response) => {
          let body = '';
          response.setEncoding('utf8');
          response.on('data', (part: string) => {
            body += part;
            if (body.length > 4096)
              response.destroy(new Error('The upload receipt exceeded its bound'));
          });
          response.once('error', reject);
          response.once('end', () => resolve({ status: response.statusCode!, body }));
        });
      });
      void receipt.catch(() => undefined);
      outgoing.write(prefix);
      return { outgoing, receipt };
    };
    const slow = [open(), open()],
      aborted = open();
    for (const peer of [...slow, aborted]) peer.outgoing.write(chunk);
    await until((value) => value.active === 3 && value.stats.activeRequests === 3);
    const main = open(),
      hash = createHash('sha256');
    let backpressureWaits = 0,
      peakQueuedBytes = 0;
    const gib = 1024 ** 3;
    for (let bytes = 0; bytes < gib; bytes += chunk.length) {
      hash.update(chunk);
      const flowing = main.outgoing.write(chunk);
      peakQueuedBytes = Math.max(peakQueuedBytes, main.outgoing.writableLength);
      if (!flowing) {
        backpressureWaits++;
        await once(main.outgoing, 'drain');
      }
      if (bytes === gib / 2) {
        const concurrent = await rpc<Snapshot>('stats');
        assert.equal(concurrent.active, 4);
        aborted.outgoing.destroy();
        await assert.rejects(aborted.receipt);
        await until(
          (value) => value.active === 3 && value.stats.activeRequests === 3 && value.aborted === 1,
        );
      }
    }
    main.outgoing.end(suffix);
    const receipt = await main.receipt;
    assert.equal(receipt.status, 200, receipt.body);
    assert.deepEqual(JSON.parse(receipt.body), {
      bytes: gib,
      digest: hash.digest('hex'),
      tenant: 'tenant-a',
    });
    assert.ok(backpressureWaits > 0, 'The native client must honor actual socket backpressure');
    assert.ok(peakQueuedBytes <= 131072, 'The sender must retain at most two fixed chunks');
    await until((value) => value.active === 2 && value.stats.activeRequests === 2);
    for (const peer of slow) {
      peer.outgoing.end(suffix);
      const result = await peer.receipt;
      assert.equal(result.status, 200, result.body);
      assert.deepEqual(JSON.parse(result.body), {
        bytes: chunk.length,
        digest: createHash('sha256').update(chunk).digest('hex'),
        tenant: 'tenant-a',
      });
    }
    const final = await until((value) => value.active === 0 && value.stats.activeRequests === 0);
    assert.equal(final.peakActive, 4);
    assert.equal(final.aborted, 1);
    assert.equal(final.stats.successfulRequests, 3);
    assert.equal(final.stats.rejectedRequests, 1);
    assert.equal(final.stats.receivedRequests, 4);
    assert.ok(final.stats.observedBytes >= gib + 3 * chunk.length);
    // Independent server observations are ceilings, not production capacity or asymptotic proofs.
    assert.ok(final.peak.heapUsed - final.baseline.heapUsed < 96 * 1024 ** 2);
    assert.ok(final.peak.arrayBuffers - final.baseline.arrayBuffers < 128 * 1024 ** 2);
    assert.ok(final.peak.rss - final.baseline.rss < 192 * 1024 ** 2);
    t.diagnostic(
      JSON.stringify({
        bytes: gib,
        peakQueuedBytes,
        backpressureWaits,
        memory: final.peak,
        baseline: final.baseline,
        releaseGate: false,
      }),
    );
    await rpc('stop');
    const [code, signal] = await exited;
    assert.equal(code, 0, stderr);
    assert.equal(signal, null);
    assert.doesNotMatch(stderr, /Bearer |forged-tenant|large\.bin/);
  },
);
