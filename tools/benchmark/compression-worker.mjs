// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeCompression,
  compressionSettings,
  verifyCompression,
  compressionWorkload,
  compressionObservations,
} from './compression-workload.mjs';
export const compressionAdapter = {
  name: 'compression',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeCompression,
  async framework() {
    const { dataCompressionPlugin, COMPRESSION_CAPABILITY } =
      await import('@arkenivajs/data-compression');
    return { plugin: dataCompressionPlugin(compressionSettings), key: COMPRESSION_CAPABILITY };
  },
  verify: verifyCompression,
  workload: compressionWorkload,
  complete: compressionObservations,
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(compressionAdapter);
