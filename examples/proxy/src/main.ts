// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runProxyExample } from './run.js';
try {
  console.log(JSON.stringify(await runProxyExample(), null, 2));
} catch {
  console.error('The disposable HTTPS proxy example failed');
  process.exitCode = 1;
}
