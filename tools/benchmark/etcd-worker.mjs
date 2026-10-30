// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { etcdPlugin } from '@arkenivajs/database-etcd';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeEtcd,
  etcdConnection,
  verifyEtcd,
  selectEtcdProfile,
  etcdWorkload,
  completeEtcdWorkload,
  etcdIterations,
  etcdWarmupIterations,
} from './etcd-workload.mjs';

runPureWorker({
  name: 'etcd',
  native(fixture) {
    Object.assign(fixture, selectEtcdProfile(fixture, 'BASELINE'));
    return nativeEtcd(fixture);
  },
  framework(fixture, mode) {
    Object.assign(fixture, selectEtcdProfile(fixture, mode));
    etcdConnection(fixture);
    process.env.ARKENIVA_ETCD_COMPARISON_URL = fixture.url;
    return {
      plugin: etcdPlugin(),
      key: COMPONENTS.etcd,
      databases: {
        configuration: { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_COMPARISON_URL' },
      },
    };
  },
  verify: verifyEtcd,
  asynchronous: true,
  iterations: etcdIterations,
  warmupIterations: etcdWarmupIterations,
  retainRawSamples: true,
  workload: etcdWorkload,
  complete: completeEtcdWorkload,
  close: (service) => service?.close(),
});
