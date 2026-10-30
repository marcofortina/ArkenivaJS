// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { runPureWorker } from '../../pure-worker.mjs';

const safeEnvironment = { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
  key = Symbol('synthetic-comparison-resource'),
  held = [];
const safe = () =>
  ['DATABASE_URL', 'NODE_OPTIONS', 'ARKENIVA_SUPERVISION_FORBIDDEN_FIXTURE'].every(
    (name) => process.env[name] === undefined,
  );

if (process.argv[2] === 'leaf') {
  held.push(Buffer.alloc(16 * 1048576, 173));
  const began = process.cpuUsage();
  let value = 1,
    cpu,
    count = 0;
  do {
    for (let index = 0; index < 100000; index++) value = Math.sqrt(value + index + 1);
    cpu = process.cpuUsage(began);
  } while (cpu.user + cpu.system < 50000);
  process.on('message', (message) => {
    if (message.kind === 'stop') process.disconnect();
    else
      process.send({
        id: message.id,
        count: message.kind === 'read' ? count : ++count,
        bytes: message.bytes,
      });
  });
  process.send({ ready: true, cpu, safeEnvironment: safe(), value });
} else {
  async function probe(fixture) {
    if (fixture.inaccessible) {
      const hidden = fork(new URL('./supervised-worker.mjs', import.meta.url), [], {
        execPath: process.execPath,
        execArgv: [],
        env: safeEnvironment,
        serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      const exited = once(hidden, 'close');
      hidden.send({ mode: 'rss-inaccessible' });
      const [code] = await exited;
      assert.equal(code, 0);
    }
    const child = fork(new URL(import.meta.url), ['leaf'], {
      execPath: process.execPath,
      execArgv: ['--max-old-space-size=64'],
      env: safeEnvironment,
      serialization: 'advanced',
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const [ready] = await once(child, 'message');
    assert.equal(ready.ready, true);
    let sequence = 0,
      count = 0;
    async function request(kind, bytes) {
      const received = once(child, 'message'),
        id = ++sequence;
      child.send({ id, kind, bytes });
      const [reply] = await received;
      assert.equal(reply.id, id);
      if (bytes) assert.deepEqual(reply.bytes, bytes);
      count = reply.count;
      return count;
    }
    return {
      ready,
      directParent: process.ppid === fixture.controllerPid,
      safeEnvironment: safe(),
      work: (bytes) => request('work', bytes),
      read: () => request('read'),
      count: () => count,
      async close() {
        const closed = once(child, 'close');
        child.send({ kind: 'stop' });
        const [code] = await closed;
        assert.equal(code, 0);
      },
    };
  }
  runPureWorker({
    name: 'synthetic-resource',
    asynchronous: true,
    iterations: 10,
    warmupIterations: 2,
    retainRawSamples: true,
    native: probe,
    framework(fixture) {
      let service;
      return {
        key,
        plugin: {
          id: 'synthetic-resource',
          version: '0.1.0',
          capabilities: new Set(),
          async init(context) {
            service = await probe(fixture);
            context.provide(key, service);
          },
          async close() {
            await service?.close();
          },
        },
      };
    },
    async verify(service, fixture) {
      assert.equal(await service.work(Buffer.from(fixture.marker)), 1);
      assert.equal(service.safeEnvironment, true);
      assert.equal(service.ready.safeEnvironment, true);
      return {
        actualNativeChildVerified: true,
        privateEnvironmentAbsent: true,
        directParent: service.directParent,
        childCpuMicros: service.ready.cpu.user + service.ready.cpu.system,
      };
    },
    workload: (service, fixture) => ({ echo: () => service.work(Buffer.from(fixture.marker)) }),
    async complete(service, { measure, records }) {
      const expected = measure ? 13 : 1;
      assert.equal(await service.read(), expected);
      assert.equal(service.count(), expected);
      if (measure) {
        assert.equal(records.length, 1);
        assert.equal(records[0].sampleCount, 10);
      }
      return { observedNativeWork: expected };
    },
    close: (service) => service.close(),
  });
}
