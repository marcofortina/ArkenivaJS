// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork, spawn } from 'node:child_process';
import { once } from 'node:events';
import { writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { setInterval } from 'node:timers';

const held = [];
function exercise(mebibytes, micros) {
  held.push(Buffer.alloc(mebibytes * 1048576, 173));
  const before = process.cpuUsage();
  let value = 1;
  while (true) {
    for (let index = 0; index < 100000; index++) value = Math.sqrt(value + index + 1);
    const cpu = process.cpuUsage(before);
    if (cpu.user + cpu.system >= micros) return { ...cpu, value };
  }
}
process.on('SIGTERM', () => {});
if (typeof process.send !== 'function') {
  // A deliberately stalled bridge must not block the supervisor's input timeout.
  process.stdin.pause();
  setInterval(() => {}, 1000);
}
process.once('message', async (input) => {
  if (input.mode === 'rss-inaccessible') {
    // This changes only the owned synthetic process, never a system setting.
    const child = spawn(
      '/usr/bin/python3',
      ['-c', 'import ctypes,time; assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0; time.sleep(0.25)'],
      {
        env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
        stdio: 'ignore',
      },
    );
    const [code] = await once(child, 'close');
    assert.equal(code, 0);
    process.send({ completed: true }, () => process.disconnect());
    return;
  }
  if (input.mode === 'churn-leaf') {
    process.send({ pid: process.pid });
    await delay(25);
    process.disconnect();
    return;
  }
  if (input.mode === 'churn') {
    for (let index = 0; index < 70; index++) {
      const leaf = fork(new URL(import.meta.url), ['leaf'], {
        execPath: process.execPath,
        execArgv: ['--max-old-space-size=32'],
        env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
        serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      const closed = once(leaf, 'close');
      leaf.send({ mode: 'churn-leaf' });
      const [code] = await closed;
      assert.equal(code, 0);
    }
    process.send({ completedChildren: 70 }, () => process.disconnect());
    return;
  }
  if (input.mode === 'oversize') {
    process.send({ value: Buffer.alloc(4096) }, () => process.disconnect());
    return;
  }
  if (input.mode === 'failure') {
    process.stdout.write(input.privateValue);
    process.stderr.write(input.privateValue);
    process.exitCode = 1;
    process.disconnect();
    return;
  }
  assert.ok(Buffer.isBuffer(input.bytes));
  assert.equal(input.number, 42n);
  if (process.argv[2] === 'leaf') {
    const cpu = exercise(32, 100000);
    process.send({ cpu, pid: process.pid, bytes: input.bytes, number: input.number });
    process.once('message', () => process.disconnect());
    return;
  }
  const cpu = exercise(24, 80000),
    leaf = fork(new URL(import.meta.url), ['leaf'], {
      execPath: process.execPath,
      execArgv: ['--max-old-space-size=96'],
      env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
      serialization: 'advanced',
      detached: input.mode === 'detached-hang',
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    }),
    exited = once(leaf, 'exit');
  leaf.once('message', async (proof) => {
    assert.deepEqual(proof.bytes, input.bytes);
    assert.equal(proof.number, input.number);
    if (input.readyFile)
      await writeFile(input.readyFile, JSON.stringify({ worker: process.pid, leaf: leaf.pid }), {
        mode: 0o600,
        flag: 'wx',
      });
    if (input.mode !== 'normal') return;
    await delay(100);
    leaf.send({ finish: true });
    const [code] = await exited;
    assert.equal(code, 0);
    process.send(
      {
        bytes: proof.bytes,
        number: proof.number,
        ownCpu: cpu,
        leafCpu: proof.cpu,
        workerPid: process.pid,
        leafPid: leaf.pid,
        waitedLeafExit: true,
      },
      () => process.disconnect(),
    );
  });
  leaf.send(input);
});
