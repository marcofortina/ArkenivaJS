// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';

for (const scenario of ['stable', 'replacement', 'mtime', 'ctime'] as const)
  test(`Native descriptor capture preserves uint64 identity and nanosecond stability: ${scenario}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkeniva-grpc-identity-')),
      entry = join(directory, 'service.proto'),
      events: { event?: string; ok?: boolean; bigint?: boolean }[] = [];
    let worker: Worker | undefined;
    try {
      assert.equal(Number(2n ** 53n), Number(2n ** 53n + 1n));
      await writeFile(entry, 'syntax="proto3"; message Owned { string value=1; }', { mode: 0o600 });
      worker = new Worker(new URL('../fixtures/descriptor-identity-preload.js', import.meta.url), {
        workerData: { entry, scenario },
        execArgv: [],
      });
      const current = worker;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('Descriptor identity worker exceeded its deadline')),
          5000,
        );
        current.on('message', (event: (typeof events)[number]) => events.push(event));
        current.once('error', reject);
        current.once('exit', (code) => {
          clearTimeout(timer);
          if (code === 0) resolve();
          else reject(new Error('Descriptor identity worker failed'));
        });
      });
      assert.equal(events.at(-1)?.ok, scenario === 'stable');
      assert.ok(events.some((event) => event.event === 'capture'));
      if (scenario === 'replacement')
        assert.equal(events.filter((event) => event.event === 'actual-replacement').length, 1);
      if (scenario === 'mtime' || scenario === 'ctime')
        assert.equal(events.filter((event) => event.event === 'actual-write').length, 1);
    } finally {
      await worker?.terminate();
      await rm(directory, { recursive: true, force: true });
    }
  });
