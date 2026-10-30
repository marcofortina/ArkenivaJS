// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { setInterval, clearInterval } from 'node:timers';

process.send({ ready: true });
const timer = setInterval(() => process.send({ heartbeat: true }), 25);
process.once('message', () => {
  clearInterval(timer);
  process.disconnect();
});
