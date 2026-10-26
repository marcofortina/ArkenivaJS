// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import sharp from 'sharp';
import { KitError } from '@arkenivajs/core';
import { execute } from './codec.js';
import type { Job } from './codec.js';

// These native settings affect this private process only, never the application's image library.
sharp.cache(false);
sharp.concurrency(1);
let busy = false;
process.on('message', (input: { id: number; job: Job }) => {
  if (busy) {
    process.exitCode = 1;
    process.disconnect();
    return;
  }
  busy = true;
  void execute(input.job).then(
    (result) => {
      busy = false;
      process.send?.({ id: input.id, result });
    },
    (cause) => {
      busy = false;
      process.send?.({
        id: input.id,
        error: cause instanceof KitError ? cause.code : 'EK_CODE_DECODE',
      });
    },
  );
});
process.on('disconnect', () => process.exit(0));
process.send?.({ ready: true });
