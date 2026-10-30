// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fork, spawn } from 'node:child_process';
import { once } from 'node:events';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { serialize } from 'node:v8';
import { runSupervisedWorker } from '../supervised-resources.mjs';

const worker = new URL('./fixtures/supervised-worker.mjs', import.meta.url),
  input = { mode: 'normal', bytes: Buffer.from([0, 1, 254, 255]), number: 42n };

async function retired(resource) {
  assert.equal(resource.scope, 'whole-supervised-lifecycle');
  assert.equal(resource.allChildrenWaited, true);
  assert.equal(resource.remainingOwnedProcesses, 0);
  assert.equal(resource.pythonObserverIncluded, false);
  assert.equal(resource.externalServerResourcesIncluded, false);
  assert.ok(resource.samplingRounds > 0 && resource.samplingRounds <= 10000);
  assert.ok(Number.isSafeInteger(resource.rssReadQuality.inaccessibleReads));
  assert.ok(Number.isSafeInteger(resource.rssReadQuality.vanishedBeforeRead));
  assert.equal(
    resource.rssReadQuality.allObservedReadsAccessible,
    resource.rssReadQuality.inaccessibleReads === 0,
  );
  for (const pid of resource.observedPids) await assert.rejects(access('/proc/' + pid));
}

async function sentinel(t) {
  const child = fork(new URL('./fixtures/supervised-sentinel.mjs', import.meta.url), [], {
    execPath: process.execPath,
    execArgv: [],
    env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
    serialization: 'advanced',
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  let beats = 0;
  child.on('message', () => {
    beats++;
  });
  t.after(async () => {
    const closed = once(child, 'close');
    child.send({ stop: true });
    const timeout = setTimeout(() => child.kill('SIGKILL'), 1000);
    await closed;
    clearTimeout(timeout);
  });
  await once(child, 'message');
  return {
    beats: () => beats,
    assertAlive(before) {
      process.kill(child.pid, 0);
      assert.ok(beats > before, 'An unrelated owned sentinel lost its heartbeat');
    },
  };
}

test(
  'Supervised Linux resources include waited native-descendant CPU and preserve advanced Node IPC',
  { timeout: 15000 },
  async () => {
    const { message, resource } = await runSupervisedWorker(worker, input, { timeoutMs: 5000 });
    assert.deepEqual(message.bytes, input.bytes);
    assert.equal(message.number, 42n);
    assert.equal(message.waitedLeafExit, true);
    const reportedCpu =
      message.ownCpu.user + message.ownCpu.system + message.leafCpu.user + message.leafCpu.system;
    assert.ok((resource.userCpuSeconds + resource.systemCpuSeconds) * 1e6 >= reportedCpu * 0.99);
    assert.equal(resource.reapedProcessCount, 1);
    assert.ok(resource.peakConcurrentProcesses >= 3);
    assert.ok(
      resource.sampledSummedRssPeakBytes > resource.sampledLargestSingleRssBytes + 16 * 1048576,
    );
    assert.ok(resource.sampledSummedRssPeakBytes > resource.largestSingleProcessRssBytes);
    await retired(resource);
  },
);

test(
  'Sequential native processes retire their owned handles without exhausting active tracking slots',
  { timeout: 20000 },
  async () => {
    const { message, resource } = await runSupervisedWorker(
      worker,
      { mode: 'churn' },
      {
        timeoutMs: 12000,
        sampleIntervalMs: 5,
      },
    );
    assert.deepEqual(message, { completedChildren: 70 });
    assert.ok(resource.observedProcessCount > 64);
    assert.ok(resource.peakConcurrentProcesses <= 3);
    await retired(resource);
  },
);

test(
  'Inaccessible native-process RSS is explicitly partial rather than silently reported complete',
  { timeout: 15000 },
  async () => {
    const { message, resource } = await runSupervisedWorker(
      worker,
      { mode: 'rss-inaccessible' },
      { timeoutMs: 5000 },
    );
    assert.deepEqual(message, { completed: true });
    const capabilities = (await readFile('/proc/self/status', 'utf8')).match(
      /^CapEff:\s+([a-f0-9]+)/m,
    );
    const canTrace = (BigInt('0x' + capabilities[1]) & (1n << 19n)) !== 0n;
    if (!canTrace) {
      assert.ok(resource.rssReadQuality.inaccessibleReads > 0);
      assert.equal(resource.rssReadQuality.allObservedReadsAccessible, false);
    }
    await retired(resource);
  },
);

for (const mode of ['hang', 'detached-hang'])
  test(
    `Supervised timeout reaps the ${mode} tree without signaling an unrelated IPC sentinel`,
    { timeout: 15000 },
    async (t) => {
      const control = await sentinel(t),
        before = control.beats();
      const error = await runSupervisedWorker(worker, { ...input, mode }, { timeoutMs: 1500 }).then(
        () => assert.fail('The uncooperative worker unexpectedly completed'),
        (cause) => cause,
      );
      assert.equal(error.code, 'ERR_BENCHMARK_TIMEOUT');
      assert.ok(error.resource.peakConcurrentProcesses >= 3);
      assert.ok(error.resource.reapedProcessCount >= 2);
      assert.equal(error.resource.detachedProcessObserved, mode === 'detached-hang');
      control.assertAlive(before);
      await retired(error.resource);
    },
  );

test(
  'Supervised abort waits for physical descendants after their actual readiness boundary',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-abort-')),
      readyFile = join(directory, 'ready.json'),
      controller = new AbortController();
    const pending = runSupervisedWorker(
      worker,
      { ...input, mode: 'detached-hang', readyFile },
      { timeoutMs: 5000, signal: controller.signal },
    );
    const rejected = pending.then(
      () => assert.fail('The aborted worker completed'),
      (cause) => cause,
    );
    try {
      let ready;
      for (let attempt = 0; attempt < 300; attempt++) {
        try {
          ready = JSON.parse(await readFile(readyFile, 'utf8'));
          break;
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        await delay(10);
      }
      assert.ok(ready, 'The owned descendant never reached readiness');
      controller.abort();
      const error = await rejected;
      assert.equal(error.code, 'ERR_BENCHMARK_ABORTED');
      await retired(error.resource);
      for (const pid of Object.values(ready)) await assert.rejects(access('/proc/' + pid));
    } finally {
      controller.abort();
      await rejected;
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Supervised policies and pre-aborted work reject before worker effects; errors never expose payloads',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-policy-')),
      readyFile = join(directory, 'never-created.json'),
      privateValue = 'owned-private-fixture-value';
    try {
      let traps = 0;
      const proxy = new Proxy(
        {},
        {
          ownKeys() {
            traps++;
            throw new Error(privateValue);
          },
          get() {
            traps++;
            throw new Error(privateValue);
          },
          getPrototypeOf() {
            traps++;
            throw new Error(privateValue);
          },
        },
      );
      const revoked = Proxy.revocable({}, {});
      revoked.revoke();
      for (const options of [proxy, revoked.proxy])
        await assert.rejects(runSupervisedWorker(worker, input, options), {
          code: 'ERR_BENCHMARK_POLICY',
        });

      assert.equal(traps, 0);
      for (const options of [
        { timeoutMs: 0 },
        { timeoutMs: null },
        { maxMessageBytes: 63 },
        { sampleIntervalMs: 0 },
        { signal: {} },
        { signal: false },
        { extra: true },
      ])
        await assert.rejects(runSupervisedWorker(worker, { ...input, readyFile }, options), {
          code: 'ERR_BENCHMARK_POLICY',
        });
      const controller = new AbortController();
      controller.abort();
      await assert.rejects(
        runSupervisedWorker(worker, { ...input, readyFile }, { signal: controller.signal }),
        { code: 'ERR_BENCHMARK_ABORTED' },
      );
      const duringPreparation = new AbortController();
      const preparing = runSupervisedWorker(
        worker,
        { ...input, readyFile },
        {
          signal: duringPreparation.signal,
        },
      );
      duringPreparation.abort();
      await assert.rejects(preparing, { code: 'ERR_BENCHMARK_ABORTED' });
      await assert.rejects(
        runSupervisedWorker(worker, { privateValue: 'x'.repeat(4096) }, { maxMessageBytes: 512 }),
        { code: 'ERR_BENCHMARK_POLICY' },
      );
      await assert.rejects(access(readyFile));
      for (const mode of ['oversize', 'failure']) {
        const signal = new AbortController().signal;
        for (const key of ['addEventListener', 'removeEventListener'])
          Object.defineProperty(signal, key, {
            get() {
              traps++;
              throw new Error(privateValue);
            },
          });
        const error = await runSupervisedWorker(
          worker,
          { mode, privateValue },
          { maxMessageBytes: 512, signal },
        ).then(
          () => assert.fail('An invalid worker result completed'),
          (cause) => cause,
        );
        assert.equal(error.code, 'ERR_BENCHMARK_WORKER');
        assert.equal(String(error).includes(privateValue), false);
        await retired(error.resource);
      }
      assert.equal(traps, 0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Stalled bridge input and early startup failures remain bounded and physically clean',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-supervised-startup-'));
    try {
      for (const stalled of [true, false]) {
        const child = spawn(
          '/usr/bin/python3',
          [fileURLToPath(new URL('../supervised-resources.py', import.meta.url))],
          {
            env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
            stdio: ['pipe', 'pipe', 'pipe'],
          },
        );
        let output = '',
          error = '';
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (chunk) => {
          output += chunk;
          assert.ok(output.length < 3145728);
        });
        child.stderr.on('data', (chunk) => {
          error += chunk;
          assert.ok(error.length < 65536);
        });
        const closed = once(child, 'close');
        child.stdin.end(
          JSON.stringify({
            node: process.execPath,
            bridge: stalled ? fileURLToPath(worker) : join(directory, 'missing-bridge.mjs'),
            worker: fileURLToPath(worker),
            inputBase64: serialize(Buffer.alloc(stalled ? 1000000 : 16, 173)).toString('base64'),
            timeoutMs: 300,
            cleanupGraceMs: 50,
            sampleIntervalMs: 5,
            maxMessageBytes: 1048576,
          }),
        );
        const [code] = await closed;
        assert.equal(code, 0, error);
        assert.equal(error, '');
        const result = JSON.parse(output);
        assert.equal(result.status, stalled ? 'timeout' : 'failed');
        if (stalled)
          assert.ok(result.resource.inputBytesTransferred < result.resource.inputBytesTotal);
        await retired(result.resource);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
