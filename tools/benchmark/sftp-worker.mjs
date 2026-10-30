// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '@arkenivajs/sftp';
import { runPureWorker } from './pure-worker.mjs';
import {
  sftpSettings,
  nativeSftp,
  verifySftp,
  sftpWorkload,
  sftpObservations,
} from './sftp-workload.mjs';

const key = Symbol('sftp-comparison');
runPureWorker({
  name: 'sftp',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeSftp,
  framework(fixture) {
    const owner = sftpSettings(fixture);
    return {
      plugins: [sftpPlugin(owner.settings)],
      key,
      dispose: owner.close,
      plugin: {
        id: 'sftp-comparison',
        version: '1.0.0',
        capabilities: new Set(),
        dependencies: ['sftp'],
        init(context) {
          context.provide(key, {
            files: context.require(SFTP_CAPABILITY),
            commands: context.require(SSH_CAPABILITY),
          });
        },
        close() {},
      },
    };
  },
  verify: verifySftp,
  workload: sftpWorkload,
  complete: sftpObservations,
  close: (service) => service.close(),
});
