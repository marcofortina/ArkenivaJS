// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runUtilities } from '../dist/main.js';

test('Public utilities preserve formats, explicit policies and streaming text without external services', async () => {
  assert.deepEqual(await runUtilities(), {
    v4Version: 4,
    v7Version: 7,
    malformedRejected: true,
    canonicalPolicyEnforced: true,
    emailNormalized: true,
    ipNormalized: true,
    privateUrlRejected: true,
    schemaAccepted: true,
    dstCalendarPreserved: true,
    elapsedHoursPreserved: true,
    csvTextPreserved: true,
    csvRoundtripRows: 2,
  });
});
