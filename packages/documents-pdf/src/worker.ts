// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { perform } from './backend.js';
import type { Work } from './backend.js';

const failures = new Set(['EK_PDF_PARSE', 'EK_PDF_LIMIT', 'EK_PDF_SIGNED']);
process.once('message', (input: Work) => {
  const started = performance.now(),
    cpu = process.cpuUsage();
  let peak = process.memoryUsage().rss;
  const sampling = setInterval(() => {
    peak = Math.max(peak, process.memoryUsage().rss);
  }, 10);
  const send = (value: object) =>
    new Promise<void>((resolve, reject) => {
      if (!process.send || !process.connected)
        return reject(new Error('Document worker is disconnected'));
      process.send(value, (error) =>
        error ? reject(new Error('Document worker delivery failed')) : resolve(),
      );
    });
  void (async () => {
    try {
      let pages = 0;
      const value = await perform(input, (count) => {
          pages = count;
        }),
        used = process.cpuUsage(cpu);
      peak = Math.max(peak, process.memoryUsage().rss);
      await send({
        type: 'result',
        value,
        memoryBytes: peak,
        pages,
        durationMs: performance.now() - started,
        cpuMs: (used.user + used.system) / 1000,
      });
    } catch (error) {
      await send({
        type: 'error',
        code: error instanceof KitError && failures.has(error.code) ? error.code : 'EK_PDF_PARSE',
      });
    } finally {
      clearInterval(sampling);
      for (const value of input.inputs) value.fill(0);
      for (const value of Object.values(input.fonts)) value.fill(0);
      if (process.connected) process.disconnect();
    }
  })().catch(() => {
    if (process.connected) process.disconnect();
  });
});
