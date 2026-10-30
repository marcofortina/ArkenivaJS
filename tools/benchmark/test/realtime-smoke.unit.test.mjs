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
import { createRealtimeSampling, realtimeObserver } from '../realtime-workload.mjs';

const receipt = () => ({
  actualHttpStatus: 200,
  actualEvents: 3,
  actualUtf8Bytes: 128,
  tenantScopedFramesVerified: true,
  physicalSocketClosed: true,
});
const records = (values = Array(100).fill(1)) => [
  {
    operation: 'finiteSseResponse',
    sampleCount: 100,
    warmupIterations: 20,
    rawLatency: { unit: 'milliseconds', values },
  },
];

test('Realtime entry rejects unmarked sampling before issuer or evidence allocation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-realtime-entry-')),
    output = join(directory, 'unmarked'),
    env = { ...process.env };
  delete env.ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE;
  try {
    await assert.rejects(
      promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../realtime.mjs', import.meta.url)), '--smoke', output],
        { env, timeout: 5000 },
      ),
      (error) => {
        assert.match(
          error.stderr,
          /Realtime smoke requires an explicitly disposable measurement environment/,
        );
        return true;
      },
    );
    await assert.rejects(access(output));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Realtime observer rejects foreign and ambiguous bridge endpoints before I/O', () => {
  for (const observerUrl of [
    'http://foreign.invalid:1/observe',
    'https://127.0.0.1:1/observe',
    'http://u:p@127.0.0.1:1/observe',
    'http://127.0.0.1:1/observe?override=true',
    'http://127.0.0.1:1/other',
  ])
    assert.throws(() => realtimeObserver({ observerUrl }));
});

test('Realtime accounting retains actual Tinybench receipts while bounding calls and event-body retention', async () => {
  let calls = 0;
  const sampling = createRealtimeSampling(async () => {
      calls++;
      return receipt();
    }, 128),
    callback = sampling.workload.finiteSseResponse;
  const bench = new Bench({
    time: 0,
    iterations: 100,
    warmupTime: 0,
    warmupIterations: 20,
    retainSamples: true,
  });
  bench.add('finiteSseResponse', callback, { async: true });
  await bench.run();
  const values = bench.tasks[0].result.latency.samples;
  assert.equal(values.length, 100);
  assert.equal(calls, 120);
  await assert.rejects(callback());
  assert.equal(calls, 120);
  const completion = sampling.complete({ measure: true, records: records(values) });
  assert.equal(completion.checkedStreams, 120);
  assert.equal(completion.actualEvents, 360);
  assert.equal(completion.actualUtf8Bytes, 15360);
  assert.equal(completion.peakRetainedReceipts, 120);
  assert.equal(completion.maximumRetainedReceipts, 128);
  assert.equal(completion.retainedEventBodies, 0);
  await assert.rejects(callback());
});

test('Realtime completion refuses wrong status, event count, bytes, tenant ownership or unretired sockets', async () => {
  for (const changed of [
    { ...receipt(), actualHttpStatus: 401 },
    { ...receipt(), actualEvents: 2 },
    { ...receipt(), actualUtf8Bytes: 127 },
    { ...receipt(), tenantScopedFramesVerified: false },
    { ...receipt(), physicalSocketClosed: false },
  ]) {
    const sampling = createRealtimeSampling(async () => changed, 128);
    for (let index = 0; index < 120; index++) await sampling.workload.finiteSseResponse();
    assert.throws(() => sampling.complete({ measure: true, records: records() }));
    await assert.rejects(sampling.workload.finiteSseResponse());
  }
});

test('Realtime accounting awaits physical independent-observer completion without queueing another stream', async () => {
  let release,
    entered,
    calls = 0;
  const held = new Promise((done) => {
      release = done;
    }),
    started = new Promise((done) => {
      entered = done;
    });
  const sampling = createRealtimeSampling(async () => {
    calls++;
    entered();
    await held;
    return receipt();
  }, 128);
  let settled = false;
  const pending = sampling.workload.finiteSseResponse().finally(() => {
    settled = true;
  });
  try {
    await started;
    await nextTurn();
    assert.equal(settled, false);
    await assert.rejects(sampling.workload.finiteSseResponse());
    assert.equal(calls, 1);
  } finally {
    release();
    await pending;
  }
  assert.throws(() => sampling.complete({ measure: true, records: records() }));
  await assert.rejects(sampling.workload.finiteSseResponse());
});
