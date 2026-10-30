// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import {
  nativeCompression,
  compressionSettings,
  verifyCompression,
} from './compression-workload.mjs';
runPureWorker({
  name: 'compression',
  native: nativeCompression,
  async framework() {
    const { dataCompressionPlugin, COMPRESSION_CAPABILITY } =
      await import('@arkenivajs/data-compression');
    return { plugin: dataCompressionPlugin(compressionSettings), key: COMPRESSION_CAPABILITY };
  },
  verify: verifyCompression,
});
