// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createProxySampling } from '../proxy-workload.mjs';

const bytes = Buffer.from('unit');
const response = () => ({
  status: 200,
  body: bytes,
  headers: { 'content-type': 'application/octet-stream' },
});
const records = (values = Array(100).fill(1)) => [
  {
    operation: 'forwardedGet',
    sampleCount: 100,
    warmupIterations: 20,
    rawLatency: { unit: 'milliseconds', values },
  },
];

test('Proxy entry rejects unmarked sampling before creating PKI or evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-proxy-entry-')),
    output = join(directory, 'unmarked'),
    env = { ...process.env };
  delete env.ARKENIVA_PROXY_BENCHMARK_DISPOSABLE;
  try {
    await assert.rejects(
      promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../proxy.mjs', import.meta.url)), '--smoke', output],
        { env, timeout: 5000 },
      ),
      (error) => {
        assert.match(
          error.stderr,
          /Proxy smoke requires an explicitly disposable measurement environment/,
        );
        return true;
      },
    );
    await assert.rejects(access(output));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Proxy sampling retains actual Tinybench receipts without retaining response buffers or admitting extra work', async () => {
  let calls = 0;
  const sampling = createProxySampling(async () => {
      calls++;
      return response();
    }, bytes),
    callback = sampling.workload.forwardedGet;
  const bench = new Bench({
    time: 0,
    iterations: 100,
    warmupTime: 0,
    warmupIterations: 20,
    retainSamples: true,
  });
  bench.add('forwardedGet', callback, { async: true });
  await bench.run();
  const values = bench.tasks[0].result.latency.samples;
  assert.equal(values.length, 100);
  assert.equal(calls, 120);
  await assert.rejects(callback());
  assert.equal(calls, 120);
  const completion = sampling.complete({ measure: true, records: records(values) });
  assert.equal(completion.checkedResponses, 120);
  assert.equal(completion.actualResponsePayloadBytes, 480);
  assert.equal(completion.retainedResponseBuffers, 0);
  assert.equal(completion.peakRetainedReceipts, 120);
  assert.equal(completion.maximumRetainedReceipts, 128);
  assert.doesNotMatch(JSON.stringify(completion), /digest|unit/);
  await assert.rejects(callback());
});

test('Proxy receipt validation rejects changed status, equal-length corrupted bytes, length and media type', async () => {
  for (const changed of [
    { ...response(), status: 503 },
    { ...response(), body: Buffer.from('nope') },
    { ...response(), body: Buffer.from('uni') },
    { ...response(), headers: { 'content-type': 'text/plain' } },
  ]) {
    const sampling = createProxySampling(async () => changed, bytes);
    for (let index = 0; index < 120; index++) await sampling.workload.forwardedGet();
    assert.throws(() => sampling.complete({ measure: true, records: records() }));
    await assert.rejects(sampling.workload.forwardedGet());
  }
});

test('Proxy sampling awaits physical exchange completion without queueing another request', async () => {
  let release,
    entered,
    calls = 0;
  const held = new Promise((done) => {
      release = done;
    }),
    started = new Promise((done) => {
      entered = done;
    });
  const sampling = createProxySampling(async () => {
    calls++;
    entered();
    await held;
    return response();
  }, bytes);
  let settled = false;
  const pending = sampling.workload.forwardedGet().finally(() => {
    settled = true;
  });
  try {
    await started;
    await nextTurn();
    assert.equal(settled, false);
    await assert.rejects(sampling.workload.forwardedGet());
    assert.equal(calls, 1);
  } finally {
    release();
    await pending;
  }
  assert.throws(() => sampling.complete({ measure: true, records: records() }));
  await assert.rejects(sampling.workload.forwardedGet());
});

test('Untimed proxy verification cannot invoke a sampling callback', () => {
  const sampling = createProxySampling(() => {
    throw new Error('Untimed verification cannot execute measured proxy requests');
  }, bytes);
  assert.deepEqual(sampling.complete({ measure: false, records: [] }), {
    sampledGets: 0,
    warmupGets: 0,
    checkedResponses: 0,
  });
});
