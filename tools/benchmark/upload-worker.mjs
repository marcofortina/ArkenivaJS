// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { uploadPlugin, UPLOAD_CAPABILITY } from '@arkenivajs/upload';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeUpload,
  uploadSettings,
  verifyUpload,
  uploadObservation,
  prepareUpload,
  uploadWorkload,
  completeUpload,
} from './upload-workload.mjs';

const UPLOAD_COMPARISON = Symbol('upload-comparison');

runPureWorker({
  name: 'upload',
  asynchronous: true,
  native: nativeUpload,
  framework(_fixture, mode) {
    const observation = uploadObservation();
    return {
      plugin: {
        id: 'upload-comparison-probe',
        version: '0.1.0',
        capabilities: new Set(),
        dependencies: ['api', 'upload'],
        init(context) {
          const api = context.require(COMPONENTS.api),
            upload = context.require(UPLOAD_CAPABILITY);
          context.provide(UPLOAD_COMPARISON, {
            address: () => api.address(),
            stats: () => api.stats(),
            uploadStats: () => upload.stats(),
            observation,
          });
        },
        close() {},
      },
      plugins: [
        apiPlugin({ dependencies: mode === 'FRAMEWORK' ? [] : ['telemetry'] }),
        uploadPlugin(uploadSettings(observation)),
      ],
      http: { host: '127.0.0.1', port: 0, requestTimeoutMs: 5000 },
      telemetryOptions: { labelValues: { route: ['/uploads'] } },
      key: UPLOAD_COMPARISON,
    };
  },
  async verify(service, fixture) {
    const result = await verifyUpload(service, fixture);
    if (fixture.sampleMultipart) prepareUpload(service, fixture);
    return result;
  },
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  workload: uploadWorkload,
  complete: completeUpload,
  close: (service) => service.close(),
});
