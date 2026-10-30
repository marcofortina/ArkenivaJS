// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativePassword, passwordSettings, verifyPassword } from './password-workload.mjs';
runPureWorker({
  name: 'password',
  native: nativePassword,
  async framework(fixture) {
    const { passwordPlugin, PASSWORD_CAPABILITY } = await import('@arkenivajs/security-password');
    return { plugin: passwordPlugin(passwordSettings(fixture)), key: PASSWORD_CAPABILITY };
  },
  verify: verifyPassword,
});
