// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { spawnSync } from 'node:child_process';
for (const args of [
  ['-r', 'build'],
  ['exec', 'tsc', '-p', 'tsconfig.json'],
]) {
  const result = spawnSync('pnpm', args, { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
