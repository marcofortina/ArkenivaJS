// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import { runPureWorker } from './pure-worker.mjs';
import {
  mtlsSettings,
  nativeMtls,
  verifyMtls,
  createMtlsSampling,
  mtlsIterations,
  mtlsWarmupIterations,
} from './mtls-workload.mjs';

const sampling = new WeakMap();

runPureWorker({
  name: 'mtls',
  native: nativeMtls,
  framework: (fixture) => ({ plugin: mtlsPlugin(mtlsSettings(fixture)), key: MTLS_CAPABILITY }),
  async verify(service, fixture) {
    const result = await verifyMtls(service, fixture);
    sampling.set(
      service,
      createMtlsSampling(() => verifyMtls(service, fixture)),
    );
    return result;
  },
  asynchronous: true,
  iterations: mtlsIterations,
  warmupIterations: mtlsWarmupIterations,
  retainRawSamples: true,
  workload: (service) => sampling.get(service).workload,
  complete(service, context) {
    try {
      return sampling.get(service).complete(context);
    } finally {
      sampling.delete(service);
    }
  },
});
