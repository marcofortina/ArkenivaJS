// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runRealtimeExample } from './run.js';
try {
  console.log(JSON.stringify(await runRealtimeExample(), null, 2));
} catch {
  console.error('The disposable authenticated realtime example failed');
  process.exitCode = 1;
}
