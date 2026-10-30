// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import {
  nativeDiagnostics,
  diagnosticsSettings,
  verifyDiagnostics,
  diagnosticsWorkload,
} from './diagnostics-workload.mjs';
runPureWorker({
  name: 'diagnostics',
  retainRawSamples: true,
  native: nativeDiagnostics,
  async framework() {
    const { diagnosticsPlugin } = await import('@arkenivajs/diagnostics');
    const { COMPONENTS } = await import('@arkenivajs/core');
    return { plugin: diagnosticsPlugin(diagnosticsSettings), key: COMPONENTS.diagnostics };
  },
  verify: verifyDiagnostics,
  workload: diagnosticsWorkload,
  close: (service) => service.close(),
});
