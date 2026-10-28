#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runRegistryCli } from './registry-cli.js';

const controller = new AbortController(),
  abort = () => controller.abort();
process.once('SIGINT', abort);
process.once('SIGTERM', abort);
try {
  process.exitCode = await runRegistryCli(
    process.argv.slice(2),
    {
      stdout: (value) => {
        process.stdout.write(value);
      },
      stderr: (value) => {
        process.stderr.write(value);
      },
    },
    { signal: controller.signal, timeoutMs: 30000 },
  );
} finally {
  process.off('SIGINT', abort);
  process.off('SIGTERM', abort);
}
