// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { etcdPlugin } from '@arkenivajs/database-etcd';
import { runPureWorker } from './pure-worker.mjs';
import { nativeEtcd, etcdConnection, verifyEtcd } from './etcd-workload.mjs';

runPureWorker({
  name: 'etcd',
  native: nativeEtcd,
  framework(fixture) {
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
  close: (service) => service?.close(),
});
