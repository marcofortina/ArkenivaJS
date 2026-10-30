// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { sessionsPlugin, SESSIONS_CAPABILITY } from '@arkenivajs/security-sessions';
import { runPureWorker } from './pure-worker.mjs';
import { nativeSessions, sessionsSettings, verifySessions } from './sessions-workload.mjs';

runPureWorker({
  name: 'sessions',
  native: nativeSessions,
  framework: (fixture) => ({
    plugin: sessionsPlugin(sessionsSettings(fixture)),
    key: SESSIONS_CAPABILITY,
  }),
  verify: verifySessions,
});
