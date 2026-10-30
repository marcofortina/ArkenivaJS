// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { createMtlsSampling } from '../mtls-workload.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

test('mTLS entry rejects unmarked sampling before creating a PKI fixture or evidence directory', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mtls-entry-')),
    output = join(directory, 'unmarked'),
    env = { ...process.env };
  delete env.ARKENIVA_MTLS_BENCHMARK_DISPOSABLE;
  try {
    await assert.rejects(
      promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../mtls.mjs', import.meta.url)), '--smoke', output],
        { env, timeout: 5000 },
      ),
      (error) => {
        assert.match(
          error.stderr,
          /mTLS smoke requires an explicitly disposable measurement environment/,
        );
        return true;
      },
    );
    await assert.rejects(access(output));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

const result = () => ({
  actualMutualTlsHandshake: true,
  negotiatedHttp2: true,
  asynchronousPeerCrlVerifiedBeforeRequest: true,
  actualAuthorizedResponse: true,
});
const records = (values = Array(100).fill(1)) => [
  {
    operation: 'freshHandshake',
    sampleCount: 100,
    warmupIterations: 20,
    rawLatency: { unit: 'milliseconds', values },
  },
];

test('mTLS sampling accounts for actual Tinybench callbacks and closes its bounded result corpus', async () => {
  let calls = 0;
  const sampling = createMtlsSampling(async () => {
    calls++;
    return result();
  });
  const callback = sampling.workload.freshHandshake;
  const bench = new Bench({
    time: 0,
    iterations: 100,
    warmupTime: 0,
    warmupIterations: 20,
    retainSamples: true,
  });
  bench.add('freshHandshake', callback, { async: true });
  await bench.run();
  const values = bench.tasks[0].result.latency.samples;
  assert.equal(values.length, 100);
  assert.equal(calls, 120);
  await assert.rejects(callback());
  assert.equal(calls, 120);
  const completion = sampling.complete({ measure: true, records: records(values) });
  assert.equal(completion.checkedExchanges, 120);
  assert.equal(completion.peakRetainedResults, 120);
  assert.equal(completion.maximumRetainedResults, 128);
  assert.equal(completion.activeCallbacks, 0);
  await assert.rejects(callback());
});

test('mTLS completion refuses missing peer authorization or an unsuccessful application response', async () => {
  for (const flag of [
    'actualMutualTlsHandshake',
    'negotiatedHttp2',
    'asynchronousPeerCrlVerifiedBeforeRequest',
    'actualAuthorizedResponse',
  ]) {
    const sampling = createMtlsSampling(async () => ({ ...result(), [flag]: false }));
    for (let index = 0; index < 120; index++) await sampling.workload.freshHandshake();
    assert.throws(() => sampling.complete({ measure: true, records: records() }));
    await assert.rejects(sampling.workload.freshHandshake());
  }
});

test('mTLS sampling retains physical exchange ownership without admitting another callback', async () => {
  let release,
    entered,
    calls = 0;
  const held = new Promise((done) => {
      release = done;
    }),
    started = new Promise((done) => {
      entered = done;
    });
  const sampling = createMtlsSampling(async () => {
    calls++;
    entered();
    await held;
    return result();
  });
  let settled = false;
  const pending = sampling.workload.freshHandshake().finally(() => {
    settled = true;
  });
  try {
    await started;
    await nextTurn();
    assert.equal(settled, false);
    await assert.rejects(sampling.workload.freshHandshake());
    assert.equal(calls, 1);
  } finally {
    release();
    await pending;
  }
  assert.throws(() => sampling.complete({ measure: true, records: records() }));
  await assert.rejects(sampling.workload.freshHandshake());
});

test('Untimed mTLS verification never executes a sampling callback', () => {
  const sampling = createMtlsSampling(() => {
    throw new Error('An untimed comparison cannot execute sampled exchanges');
  });
  assert.deepEqual(sampling.complete({ measure: false, records: [] }), {
    sampledHandshakes: 0,
    warmupHandshakes: 0,
    checkedExchanges: 0,
  });
});
