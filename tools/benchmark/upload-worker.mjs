// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { uploadPlugin } from '@arkenivajs/upload';
import { runPureWorker } from './pure-worker.mjs';
import { nativeUpload, uploadSettings, verifyUpload } from './upload-workload.mjs';

runPureWorker({
  name: 'upload',
  asynchronous: true,
  native: nativeUpload,
  framework(_fixture, mode) {
    return {
      plugin: uploadPlugin(uploadSettings()),
      plugins: [apiPlugin({ dependencies: mode === 'FRAMEWORK' ? [] : ['telemetry'] })],
      http: { host: '127.0.0.1', port: 0, requestTimeoutMs: 5000 },
      telemetryOptions: { labelValues: { route: ['/uploads'] } },
      key: COMPONENTS.api,
    };
  },
  verify: verifyUpload,
  workload() {
    throw new Error(
      'Streaming sampling requires first-byte, backpressure and peak-buffer measurements',
    );
  },
  close: (service) => service.close(),
});
