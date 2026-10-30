// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { socketPlugin, SOCKET_CAPABILITY } from '@arkenivajs/socket';
import { runPureWorker } from './pure-worker.mjs';
import { nativeSocket, verifySocket } from './socket-workload.mjs';

runPureWorker({
  name: 'socket',
  native: nativeSocket,
  framework: () => ({ plugin: socketPlugin(), key: SOCKET_CAPABILITY }),
  verify: verifySocket,
  close: (service) => service?.close(),
});
