// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

for (const mode of ['drain', 'completion'])
  test(
    `Rejected native worker termination retains physical ownership and fails closed during ${mode}`,
    { timeout: 20000 },
    async () => {
      // Constructor injection is isolated from every other test and preserves real native signatures.
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [new URL('../fixtures/worker-termination.js', import.meta.url).pathname, mode],
        { timeout: 15000, maxBuffer: 16384 },
      );
      assert.deepEqual(JSON.parse(stdout.trim()), {
        settledBeforeDrain: false,
        drained: false,
        exited: false,
      });
    },
  );
