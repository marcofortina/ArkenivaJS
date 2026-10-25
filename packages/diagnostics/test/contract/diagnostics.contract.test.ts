// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDiagnostics } from '@arkenivajs/diagnostics';
import type { Diagnostics, ProcessSnapshot } from '@arkenivajs/diagnostics';

test('Diagnostics returns the public process snapshot without tenant attribution fields', () => {
  const managed = createDiagnostics();
  const collector: Diagnostics = managed;
  const snapshot: ProcessSnapshot = collector.snapshot();
  assert.ok(snapshot.cpuUserMicros >= 0);
  assert.equal('tenantId' in snapshot, false);
  assert.equal('requestCpuMicros' in snapshot, false);
  managed.close();
});
