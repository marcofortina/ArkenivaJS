// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { test } from 'node:test';
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Synchronous benchmark callbacks execute exactly warmup plus measured iterations',
  { timeout: 10000 },
  async () => {
    for (const measure of [false, true]) {
      const worker = fork(new URL('./fixtures/counted-sync-worker.mjs', import.meta.url), [], {
        execArgv: [],
        serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
      });
      let message;
      const completed = new Promise((resolve, reject) => {
        worker.once('error', reject);
        worker.on('message', (value) => {
          assert.equal(message, undefined);
          message = value;
        });
        worker.once('close', (code, signal) => {
          try {
            assert.equal(code, 0);
            assert.equal(signal, null);
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
      const timeout = setTimeout(() => worker.kill('SIGKILL'), 8000);
      try {
        worker.send({ mode: 'BASELINE', fixture: {}, measure });
        await completed;
        assert.equal(message.ok, true);
        const result = message.result;
        assert.equal(result.verification.callsBeforeWorkload, 0);
        assert.equal(result.completion.actualCalls, measure ? 120 : 0);
        assert.equal(result.records.length, measure ? 1 : 0);
        if (measure) {
          assert.equal(result.records[0].sampleCount, 100);
          assert.equal(result.records[0].warmupIterations, 20);
          assertRawLatencySamples(result.records[0]);
        }
      } finally {
        clearTimeout(timeout);
        if (worker.exitCode === null && worker.signalCode === null) {
          worker.kill('SIGKILL');
          await completed;
        }
      }
    }
  },
);
