// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runRealtimeExample } from '../../dist/run.js';

test(
  'Public installed packages run verified HTTPS SSE and authenticated WSS with byte fidelity and explicit replay rejection',
  { timeout: 15000 },
  async () => {
    assert.deepEqual(await runRealtimeExample(), {
      untrustedCertificateRejected: true,
      anonymousRejected: true,
      exactSseEvent: true,
      unsupportedReplayRejected: true,
      websocketBytes: [0, 128, 255],
    });
  },
);
